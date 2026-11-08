// The synthesis rules: what maintainer scripts would have made, as a table (DESIGN.md 10.1).
//
// Each rule in rules is named, applies to a tree when its packages ask for it, says what it made
// through the log, and returns whether it applied; synthesise runs them in order and logs the
// names of those that did. A new effect of a maintainer script is a new rule here, never an
// option, and nothing here runs a script. What the rules do not make is reported by notes: each
// package's trigger interests, the paths whose caches and indexes a maintainer script would have
// built, are read from the package (dpkg's `triggers` file, apk's `triggers` field) and named
// against the interests table, and a postinst that calls `update-alternatives` in a form the
// alternatives rule cannot read is noted too.

package unpack

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"exclave/unpack/apk"
	"exclave/unpack/ldcache"
	"exclave/unpack/reader"
	"exclave/unpack/root"
)

// rule is a synthesis rule: its name in the log, and the function that makes what it makes.
type rule struct {
	name  string
	apply func(r *root.Root, packages []*Package, log logger) (bool, error)
}

// link makes a symlink at a virtual path, unless something stands there. With replace, as
// alternatives --install does, a file or link standing there gives way; a directory never does.
// Fedora's binutils needs this: it ships gold at /usr/bin/ld and removes it in %post before
// installing the alternative.
func link(r *root.Root, at, target string, log logger, replace bool) (bool, error) {
	if r.Lexists(at) {
		if !replace || (r.IsDir(at) && !r.IsLink(at)) {
			return false, nil
		}
		if r.IsLink(at) {
			if t, err := r.Readlink(at); err == nil && t == target {
				return false, nil
			}
		}
		if err := r.Remove(at); err != nil {
			return false, err
		}
	}
	if err := r.Symlink(target, at); err != nil {
		return false, err
	}
	log(fmt.Sprintf("synthesised %s -> %s", at, target))
	return true, nil
}

// linkRelative makes the link at `at` to `target`, both absolute tree paths, with a relative text, so that a
// link run from outside the exclave stays in the tree and reaches the wrapper there rather than a host file
// of the same name (13 item 37); inside, a relative link resolves in virtual space the same way.
func linkRelative(r *root.Root, at, target string, log logger, replace bool) (bool, error) {
	text, err := filepath.Rel(filepath.Dir(at), target)
	if err != nil {
		return false, err
	}
	return link(r, at, text, log, replace)
}

// ---------------------------------------------------------------- update-alternatives
// Debian's and rpm's spellings
var (
	uaRe = regexp.MustCompile(
		`(?:update-)?alternatives\s+(?:--(?:quiet|verbose|force)\s+)*--install\s+` +
			`(\S+)\s+(\S+)\s+(\S+)\s+(\d+)((?:\s+--slave\s+\S+\s+\S+\s+\S+)*)`)
	uaSetRe = regexp.MustCompile(`(?:update-)?alternatives\s+(?:--(?:quiet|verbose|force)\s+)*--set\s+(\S+)\s+(\S+)`)
	uaAnyRe = regexp.MustCompile(`(?:update-)?alternatives\s+--(?:install|set)\b`)
	slaveRe = regexp.MustCompile(`--slave\s+(\S+)\s+(\S+)\s+(\S+)`)
	forRe   = regexp.MustCompile(`\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([^;\n]*?)\s*(?:;|\n)\s*do\b`)
	doRe    = regexp.MustCompile(`\b(?:do|done)\b`)
)

// unrolledMax bounds the text unrollLoops makes, and unrollsMax the loops it unrolls, each of which
// scans the text again: nested loops multiply, and eight of ten words in a kilobyte of script
// would unroll to a hundred million copies. The largest real postinst unrolls a few loops to a
// few kilobytes.
const (
	unrolledMax = 1 << 20
	unrollsMax  = 1024
)

// unrollLoops repeats the body of every `for VAR in WORDS; do ... done` whose words are literal,
// once per word with $VAR and ${VAR} replaced by it, outermost first, as the shell would run it;
// a loop over anything else, a variable, a glob or a command's output, is left as it is.
// ImageMagick's postinst installs its alternatives in such a loop over its programs' names.
// ok is false when the text would grow past unrolledMax or take more than unrollsMax loops.
func unrollLoops(text string) (_ string, ok bool) {
	for unrolls := 0; ; unrolls++ {
		if unrolls > unrollsMax {
			return "", false
		}
		changed := false
		for _, m := range forRe.FindAllStringSubmatchIndex(text, -1) {
			words := strings.Fields(text[m[4]:m[5]])
			if len(words) == 0 || strings.ContainsAny(text[m[4]:m[5]], "$`*?[\"'\\") {
				continue
			}
			// the body ends at the done that closes this do, nested loops counted
			depth, end := 1, -1
			for _, d := range doRe.FindAllStringIndex(text[m[1]:], -1) {
				if text[m[1]+d[0]:m[1]+d[1]] == "do" {
					depth++
				} else if depth--; depth == 0 {
					end = m[1] + d[0]
					break
				}
			}
			if end < 0 {
				continue
			}
			body := text[m[1]:end]
			name := text[m[2]:m[3]]
			ref := regexp.MustCompile(`\$\{` + name + `\}|\$` + name + `\b`)
			// the size the copies would have, each word in place of every reference, before any is made
			refs, size := len(ref.FindAllStringIndex(body, -1)), len(text)-(end+len("done")-m[0])
			for _, w := range words {
				if size += len(body) + 1 + refs*len(w); size > unrolledMax {
					return "", false
				}
			}
			var out strings.Builder
			for _, w := range words {
				out.WriteString(ref.ReplaceAllLiteralString(body, w))
				out.WriteString("\n")
			}
			text = text[:m[0]] + out.String() + text[end+len("done"):]
			changed = true
			break
		}
		if !changed {
			return text, true
		}
	}
}

// postinstText is a package's postinst as the rules read it: continued lines joined, and loops over
// literal words unrolled; a script that would unroll past unrolledMax is refused.
func postinstText(pkg *Package) (string, error) {
	_, scripts, err := readerFor(pkg.Path).Control(pkg.Path)
	if err != nil {
		return "", err
	}
	text, ok := unrollLoops(strings.ReplaceAll(scripts["postinst"], "\\\n", " "))
	if !ok {
		return "", refuse("%s's postinst unrolls its loops past %d bytes or %d loops", pkg.Name, unrolledMax,
			unrollsMax)
	}
	return text, nil
}

// alternative is one `alternatives --install` line: its priority first, so the greatest wins.
type alternative struct {
	priority string // decimal digits
	link     string
	target   string
	slaves   [][3]string // (link, name, target)
}

// less orders alternatives as Python orders the tuples (priority, link, target, slaves).
func (a alternative) less(b alternative) bool {
	if c := reader.CmpNum(a.priority, b.priority); c != 0 {
		return c < 0
	}
	if a.link != b.link {
		return a.link < b.link
	}
	if a.target != b.target {
		return a.target < b.target
	}
	for i := 0; i < len(a.slaves) && i < len(b.slaves); i++ {
		for k := range 3 {
			if a.slaves[i][k] != b.slaves[i][k] {
				return a.slaves[i][k] < b.slaves[i][k]
			}
		}
	}
	return len(a.slaves) < len(b.slaves)
}

// alternatives makes every `update-alternatives --install` line in a postinst, with its slaves.
// The highest priority wins, unless a `--set` names a candidate. A loop over literal words is
// unrolled first; a line the rule still cannot read, one built from other shell variables, is
// noted, since its alternatives are not made. The links are relative (linkRelative).
func alternatives(r *root.Root, packages []*Package, log logger) (bool, error) {
	groups := map[string][]alternative{}
	var order []string
	chosen := map[string]string{}
	for _, pkg := range packages {
		text, err := postinstText(pkg)
		if err != nil {
			return false, err
		}
		matched := 0
		for _, m := range uaRe.FindAllStringSubmatch(text, -1) {
			at, gname, target, prio := m[1], m[2], m[3], m[4]
			matched++
			if strings.Contains(at+gname+target, "$") {
				matched--
				continue
			}
			var slaves [][3]string
			absolute := strings.HasPrefix(at, "/") && strings.HasPrefix(target, "/")
			for _, s := range slaveRe.FindAllStringSubmatch(m[5], -1) {
				absolute = absolute && strings.HasPrefix(s[1], "/") && strings.HasPrefix(s[3], "/")
				slaves = append(slaves, [3]string{s[1], s[2], s[3]})
			}
			// update-alternatives refuses a link or a path that is not absolute, so such a line made nothing
			if !absolute || !r.Lexists(target) {
				continue
			}
			if _, ok := groups[gname]; !ok {
				order = append(order, gname)
			}
			groups[gname] = append(groups[gname], alternative{prio, at, target, slaves})
		}
		for _, m := range uaSetRe.FindAllStringSubmatch(text, -1) {
			matched++
			chosen[m[1]] = m[2]
		}
		if uaAnyRe.MatchString(text) && matched == 0 {
			log(fmt.Sprintf("note: %s's postinst calls update-alternatives in a form the "+
				"alternatives rule does not read, shell variables: its alternatives are made "+
				"only where another rule makes them", pkg.Name))
		}
	}
	made := false
	for _, gname := range order {
		cands := groups[gname]
		best := cands[0]
		for _, c := range cands[1:] {
			if best.less(c) {
				best = c
			}
		}
		if want, ok := chosen[gname]; ok {
			for _, c := range cands {
				if c.target == want {
					best = c
				}
			}
		}
		for _, l := range [][2]string{
			{"/etc/alternatives/" + gname, best.target}, {best.link, "/etc/alternatives/" + gname},
		} {
			ok, err := linkRelative(r, l[0], l[1], log, true)
			if err != nil {
				return false, err
			}
			made = made || ok
		}
		for _, s := range best.slaves {
			slink, sname, starget := s[0], s[1], s[2]
			if r.Lexists(starget) {
				for _, l := range [][2]string{
					{"/etc/alternatives/" + sname, starget}, {slink, "/etc/alternatives/" + sname},
				} {
					ok, err := linkRelative(r, l[0], l[1], log, true)
					if err != nil {
						return false, err
					}
					made = made || ok
				}
			}
		}
	}
	return made, nil
}

var (
	jinfoPrioRe = regexp.MustCompile(`(?m)^priority=(\d+)$`)
	jinfoToolRe = regexp.MustCompile(`(?m)^(?:jre|jdk|hl|jdkhl)\s+(\S+)\s+(/\S+)$`)
)

// javaJinfo makes Debian's JDKs' alternatives, those a /usr/lib/jvm/.*.jinfo file lists.
//
// The JDK's postinst makes them in a loop the alternatives rule cannot read; the file it ships
// for update-java-alternatives names the JDK's priority and, a line each, every tool and its
// path. Each tool's /usr/bin link goes through /etc/alternatives to the highest priority's path,
// where nothing stands there already, relative (linkRelative).
func javaJinfo(r *root.Root, _ []*Package, log logger) (bool, error) {
	type best struct{ prio, target string }
	bests := map[string]best{}
	if !r.IsDir("/usr/lib/jvm") {
		return false, nil
	}
	for _, name := range r.Listdir("/usr/lib/jvm") {
		if !(strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".jinfo")) {
			continue
		}
		text, err := r.ReadText("/usr/lib/jvm/" + name)
		if err != nil {
			return false, err
		}
		prio := "0"
		if m := jinfoPrioRe.FindStringSubmatch(text); m != nil {
			prio = m[1]
		}
		for _, t := range jinfoToolRe.FindAllStringSubmatch(text, -1) {
			tool, target := t[1], t[2]
			if b, ok := bests[tool]; r.Lexists(target) && (!ok || reader.CmpNum(prio, b.prio) > 0) {
				bests[tool] = best{prio, target}
			}
		}
	}
	tools := make([]string, 0, len(bests))
	for t := range bests {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	made := false
	for _, tool := range tools {
		for _, l := range [][2]string{
			{"/etc/alternatives/" + tool, bests[tool].target}, {"/usr/bin/" + tool, "/etc/alternatives/" + tool},
		} {
			ok, err := linkRelative(r, l[0], l[1], log, false)
			if err != nil {
				return false, err
			}
			made = made || ok
		}
	}
	return made, nil
}

// ---------------------------------------------------------------- the other rules

// busyboxApplets makes Alpine's busybox applet links, those its post-install makes from
// /etc/busybox-paths.d: one path per line, each a link to /bin/busybox. The links are relative,
// as the dash rule makes /usr/bin/sh, so that a link run from outside the exclave reaches the
// wrapper in the tree and not a host file of the same name; inside, a relative link resolves in
// virtual space the same way. A path is a member's: `..` and .real are refused.
func busyboxApplets(r *root.Root, _ []*Package, log logger) (bool, error) {
	bbd := "/etc/busybox-paths.d"
	if !(r.IsDir(bbd) && r.IsFile("/bin/busybox")) {
		return false, nil
	}
	n := 0
	for _, f := range r.Listdir(bbd) {
		text, err := r.ReadText(bbd + "/" + f)
		if err != nil {
			return false, err
		}
		for line := range strings.SplitSeq(text, "\n") {
			rel, err := safeRel(strings.TrimSpace(line))
			if err != nil {
				return false, err
			}
			if rel != "" && !r.Lexists(rel) {
				target, _ := filepath.Rel(filepath.Dir("/"+rel), "/bin/busybox")
				if err := r.Symlink(target, rel); err != nil {
					return false, err
				}
				n++
			}
		}
	}
	log(fmt.Sprintf("synthesised %d busybox applet links from /etc/busybox-paths.d", n))
	return true, nil
}

// apkDatabase writes apk's database of installed packages, /lib/apk/db/installed, as apk-tools
// writes it when it installs them: one record per package from its .PKGINFO, in the order of
// the packages' names, each keyed by its control section's checksum (C:), and /etc/apk/world,
// which apk reads with it. It is where an Alpine system records each package's licence, by name,
// and its origin, the source package, since Alpine ships few licence texts (13 item 47), and where
// SBOM and vulnerability scanners read an Alpine system's packages. The files a package owns (F:
// and R:) are not recorded, since prune removes files. A database or a world the packages ship
// already is left as it is.
func apkDatabase(r *root.Root, packages []*Package, log logger) (bool, error) {
	var apks []*Package
	for _, p := range packages {
		if packageFormat(p.Path) == "apk" {
			apks = append(apks, p)
		}
	}
	const db = "/lib/apk/db/installed"
	if len(apks) == 0 || r.Lexists(db) {
		return false, nil
	}
	sort.Slice(apks, func(i, j int) bool { return apks[i].Name < apks[j].Name })
	var b, world strings.Builder
	for _, p := range apks {
		st, err := os.Stat(p.Path)
		if err != nil {
			return false, err
		}
		sum, err := apk.ControlChecksum(p.Path)
		if err != nil {
			return false, err
		}
		world.WriteString(p.Name + "\n")
		arch := p.Arch()
		if arch == "all" {
			arch = "noarch"
		}
		for _, kv := range [][2]string{
			{"C", sum}, {"P", p.Name}, {"V", p.Version()}, {"A", arch}, {"S", strconv.FormatInt(st.Size(), 10)},
			{"I", p.Fields["Installed-Size"]}, {"T", p.Fields["Description"]}, {"U", p.Fields["Homepage"]},
			{"L", p.Fields["License"]}, {"o", p.Fields["Origin"]}, {"m", p.Fields["Maintainer"]},
			{"t", p.Fields["Build-Date"]}, {"c", p.Fields["Commit"]}, {"D", p.Fields["Depends"]},
			{"p", p.Fields["Provides"]}, {"i", p.Fields["Install-If"]}, {"r", p.Fields["Replaces"]},
		} {
			if kv[1] != "" {
				b.WriteString(kv[0] + ":" + kv[1] + "\n")
			}
		}
		b.WriteString("\n")
	}
	if err := r.Makedirs("lib/apk/db"); err != nil {
		return false, err
	}
	if err := r.WriteBytes(db, []byte(b.String()), 0o644); err != nil {
		return false, err
	}
	// the packages asked for, which apk reads with its database: every package, since a closure
	// does not say which of them were asked for
	if !r.Lexists("/etc/apk/world") {
		if err := r.Makedirs("etc/apk"); err != nil {
			return false, err
		}
		if err := r.WriteBytes("/etc/apk/world", []byte(world.String()), 0o644); err != nil {
			return false, err
		}
	}
	log(fmt.Sprintf("wrote %s: %d packages, their licences by name", db, len(apks)))
	return true, nil
}

var debFieldRe = regexp.MustCompile(`^([!-9;-~][!-9;-~]*):`)

// statusStanza is a .deb's control file as dpkg's database records the package once configured:
// the file's fields as they stand, its Status, `install ok installed`, after the Package field.
// dpkg puts the fields in its own order when it rewrites the database, and dpkg-query reads them
// in any. A control file that is not one stanza of fields, one that repeats a field, its name's
// case aside, as dpkg refuses, or one that carries a Status or no Package, is refused.
func statusStanza(control string) (string, error) {
	text := strings.TrimRight(strings.ReplaceAll(control, "\r\n", "\n"), "\n")
	seen := map[string]bool{}
	var b strings.Builder
	for i, line := range strings.Split(text, "\n") {
		switch m := debFieldRe.FindStringSubmatch(line); {
		case strings.TrimSpace(line) == "":
			return "", fmt.Errorf("a blank line at line %d: more than one stanza", i+1)
		case line[0] == ' ' || line[0] == '\t':
			if i == 0 {
				return "", fmt.Errorf("a continuation before any field")
			}
			b.WriteString(line + "\n")
		case m == nil:
			return "", fmt.Errorf("line %d is not a field", i+1)
		default:
			name := strings.ToLower(m[1])
			if seen[name] {
				return "", fmt.Errorf("the field %s twice", m[1])
			}
			seen[name] = true
			if name == "status" {
				return "", fmt.Errorf("a Status field of its own")
			}
			b.WriteString(line + "\n")
			if name == "package" {
				b.WriteString("Status: install ok installed\n")
			}
		}
	}
	if !seen["package"] {
		return "", fmt.Errorf("no Package field")
	}
	return b.String(), nil
}

// dpkgDatabase writes dpkg's database of installed packages, /var/lib/dpkg/status, as dpkg writes
// it once it has configured them: each package's control file with its Status (statusStanza), in
// the order of the packages' names. dpkg-query reads it, and through it the scripts that ask
// whether a package is configured before they act, as TeX's update-language does, and so do SBOM
// and vulnerability scanners. The files a package owns and its conffiles' checksums are not
// recorded, since prune removes files and nothing here is configured twice. A database the
// packages ship already is left as it is; a control file statusStanza refuses is refused.
func dpkgDatabase(r *root.Root, packages []*Package, log logger) (bool, error) {
	var debs []*Package
	for _, p := range packages {
		if packageFormat(p.Path) == "deb" {
			debs = append(debs, p)
		}
	}
	const db = "/var/lib/dpkg/status"
	if len(debs) == 0 || r.Lexists(db) {
		return false, nil
	}
	sort.Slice(debs, func(i, j int) bool { return debs[i].Name < debs[j].Name })
	var b strings.Builder
	for _, p := range debs {
		_, files, err := readerFor(p.Path).Control(p.Path)
		if err != nil {
			return false, err
		}
		stanza, err := statusStanza(files[reader.ControlText])
		if err != nil {
			return false, refuse("%s's control file: %s; dpkg's database cannot record it", p.Name, err)
		}
		b.WriteString(stanza + "\n")
	}
	if err := r.Makedirs("var/lib/dpkg"); err != nil {
		return false, err
	}
	if err := r.WriteBytes(db, []byte(b.String()), 0o644); err != nil {
		return false, err
	}
	log(fmt.Sprintf("wrote %s: %d packages", db, len(debs)))
	return true, nil
}

// sbinMerge does what Fedora 42's filesystem does in its %posttrans: it replaces /usr/sbin and
// /usr/local/sbin by a link to bin when every entry there is a link ../bin/<name>; the script says
// so in Lua, and this is its effect.
func sbinMerge(r *root.Root, packages []*Package, log logger) (bool, error) {
	made := false
	for _, pkg := range packages {
		if pkg.Name != "filesystem" {
			continue
		}
		_, scripts, err := readerFor(pkg.Path).Control(pkg.Path)
		if err != nil {
			return false, err
		}
		if !strings.Contains(scripts["posttrans"], `posix.symlink("bin", path)`) {
			continue
		}
		for _, sb := range []string{"/usr/sbin", "/usr/local/sbin"} {
			if !r.IsDir(sb) || r.IsLink(sb) {
				continue
			}
			entries := r.Listdir(sb)
			all := true
			for _, e := range entries {
				t, err := r.Readlink(sb + "/" + e)
				if !r.IsLink(sb+"/"+e) || err != nil || t != "../bin/"+e {
					all = false
				}
			}
			if !all {
				continue
			}
			for _, e := range entries {
				if err := r.Remove(sb + "/" + e); err != nil {
					return false, err
				}
			}
			if err := r.Rmdir(sb); err != nil {
				return false, err
			}
			if err := r.Symlink("bin", sb); err != nil {
				return false, err
			}
			log(fmt.Sprintf("synthesised %s -> bin as filesystem's %%posttrans does", sb))
			made = true
		}
	}
	return made, nil
}

func names(packages []*Package) map[string]bool {
	out := map[string]bool{}
	for _, p := range packages {
		out[p.Name] = true
	}
	return out
}

// dashSh makes dash's /bin/sh, which its postinst makes and the package does not ship.
func dashSh(r *root.Root, packages []*Package, log logger) (bool, error) {
	if names(packages)["dash"] && r.Lexists("/usr/bin/dash") {
		return link(r, "/usr/bin/sh", "dash", log, false)
	}
	return false, nil
}

// caCertificates makes Debian's ca-certificates bundle, which update-ca-certificates makes from
// the enabled ones.
func caCertificates(r *root.Root, packages []*Package, log logger) (bool, error) {
	conf := "/etc/ca-certificates.conf"
	if !names(packages)["ca-certificates"] || !r.Exists(conf) {
		return false, nil
	}
	text, err := r.ReadText(conf)
	if err != nil {
		return false, err
	}
	var pems [][]byte
	for raw := range strings.SplitSeq(text, "\n") {
		line := strings.TrimSpace(raw)
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "!") {
			cert := "/usr/share/ca-certificates/" + line
			if r.Exists(cert) {
				data, err := r.ReadBytes(cert)
				if err != nil {
					return false, err
				}
				pems = append(pems, append([]byte(strings.TrimRight(string(data), "\n")), '\n'))
			}
		}
	}
	if err := r.Makedirs("/etc/ssl/certs"); err != nil {
		return false, err
	}
	var bundle []byte
	for _, p := range pems {
		bundle = append(bundle, p...)
	}
	if err := r.WriteBytes("/etc/ssl/certs/ca-certificates.crt", bundle, 0o666); err != nil {
		return false, err
	}
	log(fmt.Sprintf("synthesised /etc/ssl/certs/ca-certificates.crt from %d certificates", len(pems)))
	return true, nil
}

// enabledCertificates are the certificates update-ca-certificates links into /etc/ssl/certs, by
// virtual path: those /etc/ca-certificates.conf enables, or, where there is none, every .crt
// under /usr/share/ca-certificates, which the package's postinst enables on a first install
// (debconf's default trusts every certificate it offers); then every .crt under
// /usr/local/share/ca-certificates. In the order of their paths' bytes.
func enabledCertificates(r *root.Root) ([]string, error) {
	var certs []string
	var walk func(dir string)
	walk = func(dir string) {
		for _, n := range r.Listdir(dir) {
			switch p := dir + "/" + n; {
			case r.IsDir(p):
				walk(p)
			case strings.HasSuffix(n, ".crt") && r.IsFile(p):
				certs = append(certs, p)
			}
		}
	}
	if conf := "/etc/ca-certificates.conf"; r.Exists(conf) {
		text, err := r.ReadText(conf)
		if err != nil {
			return nil, err
		}
		for raw := range strings.SplitSeq(text, "\n") {
			line := strings.TrimSpace(raw)
			if p := "/usr/share/ca-certificates/" + line; line != "" && !strings.HasPrefix(line, "#") &&
				!strings.HasPrefix(line, "!") && r.IsFile(p) {
				certs = append(certs, p)
			}
		}
	} else {
		walk("/usr/share/ca-certificates")
	}
	walk("/usr/local/share/ca-certificates")
	sort.Strings(certs)
	return certs, nil
}

// pemAlias is the name update-ca-certificates links a certificate under in /etc/ssl/certs, which
// ca-certificates-java takes for its alias.
var pemAlias = strings.NewReplacer(" ", "_", "(", "=", ")", "=", ",", "_")

// javaCacerts makes the Java keystore ca-certificates-java's postinst makes on a first install,
// /etc/ssl/certs/java/cacerts, which a Debian JDK's lib/security/cacerts links to and without
// which Java trusts no authority: a JKS keystore of each enabled certificate (enabledCertificates)
// as a trusted entry under the alias "debian:NAME.pem", NAME the certificate's file name as
// update-ca-certificates spells it, the first certificate of each file, with the store password
// the package's default, "changeit". An entry's date is the epoch, so the tree is the same on
// every run, and the entries are in their aliases' order.
func javaCacerts(r *root.Root, packages []*Package, log logger) (bool, error) {
	store := "/etc/ssl/certs/java/cacerts"
	if !names(packages)["ca-certificates-java"] || r.Lexists(store) {
		return false, nil
	}
	certs, err := enabledCertificates(r)
	if err != nil {
		return false, err
	}
	type entry struct {
		alias string
		der   []byte
	}
	var entries []entry
	for _, c := range certs {
		data, err := r.ReadBytes(c)
		if err != nil {
			return false, err
		}
		for rest := data; ; {
			var b *pem.Block
			if b, rest = pem.Decode(rest); b == nil {
				log("note: " + c + " holds no PEM certificate; java-cacerts passed over it")
				break
			}
			if b.Type == "CERTIFICATE" {
				name := strings.TrimSuffix(filepath.Base(c), ".crt")
				entries = append(entries, entry{"debian:" + strings.ToLower(pemAlias.Replace(name)) + ".pem", b.Bytes})
				break
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].alias < entries[j].alias })
	var ks bytes.Buffer
	u32 := func(v uint32) { ks.Write(binary.BigEndian.AppendUint32(nil, v)) }
	utf := func(s string) { ks.Write(binary.BigEndian.AppendUint16(nil, uint16(len(s)))); ks.WriteString(s) }
	u32(0xfeedfeed) // JKS, version 2
	u32(2)
	u32(uint32(len(entries)))
	for i, e := range entries {
		if i > 0 && e.alias == entries[i-1].alias {
			return false, fmt.Errorf("%s: two certificates named %s", store, e.alias)
		}
		u32(2) // a trusted certificate
		utf(e.alias)
		ks.Write(make([]byte, 8)) // its date, the epoch in milliseconds
		utf("X.509")
		u32(uint32(len(e.der)))
		ks.Write(e.der)
	}
	// the keyed digest: SHA-1 over the password in UTF-16, "Mighty Aphrodite" and the store
	h := sha1.New()
	for _, c := range "changeit" {
		h.Write([]byte{0, byte(c)})
	}
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(ks.Bytes())
	ks.Write(h.Sum(nil))
	if err := r.Makedirs(filepath.Dir(store)); err != nil {
		return false, err
	}
	if err := r.WriteBytes(store, ks.Bytes(), 0o644); err != nil {
		return false, err
	}
	log(fmt.Sprintf("synthesised %s from %d certificates", store, len(entries)))
	return true, nil
}

var pemRe = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----`)

// caTrust makes Fedora's and RHEL's ca-certificates bundle, which update-ca-trust extracts in
// %post. The consumers' paths are links to /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem,
// extracted from the p11-kit trust source; the CA anchors trusted there are concatenated the same
// way. The bundle is an identity file (8.4): the host's where it has one.
func caTrust(r *root.Root, _ []*Package, log logger) (bool, error) {
	extracted := "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
	var sources []string
	for _, dp := range [][2]string{
		{"/usr/share/pki/ca-trust-source", "*.p11-kit"}, {"/etc/pki/ca-trust/source/anchors", "*"},
	} {
		for _, n := range r.Listdir(dp[0]) {
			if !strings.HasPrefix(n, ".") && ldcache.Fnmatch(dp[1], n) {
				sources = append(sources, dp[0]+"/"+n)
			}
		}
	}
	sort.Strings(sources)
	if len(sources) == 0 || r.Lexists(extracted) {
		return false, nil
	}
	var certs []string
	have := map[string]bool{}
	for _, src := range sources {
		text, err := r.ReadText(src)
		if err != nil {
			return false, err
		}
		if !strings.Contains(text, "[p11-kit-object-v1]") {
			if strings.Contains(text, "-----BEGIN CERTIFICATE-----") {
				certs = append(certs, strings.TrimSpace(text)+"\n")
				have[strings.TrimSpace(text)+"\n"] = true
			}
			continue
		}
		// a certificate object: trust attributes, then its PEM
		for _, obj := range strings.Split(text, "[p11-kit-object-v1]")[1:] {
			head, _, _ := strings.Cut(obj, "-----BEGIN")
			if !strings.Contains(head, "trusted: true") || strings.Contains(head, "x-distrusted: true") {
				continue
			}
			// one object per purpose in the source: one PEM in the bundle
			if m := pemRe.FindString(obj); m != "" && !have[m+"\n"] {
				certs = append(certs, m+"\n")
				have[m+"\n"] = true
			}
		}
	}
	if err := r.Makedirs(filepath.Dir(extracted)); err != nil {
		return false, err
	}
	if err := r.WriteBytes(extracted, []byte(strings.Join(certs, "")), 0o666); err != nil {
		return false, err
	}
	log(fmt.Sprintf("synthesised /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem from %d trusted certificates",
		len(certs)))
	return true, nil
}

// sslPaths makes OpenSSL's compiled-in trust paths, /usr/lib/ssl/cert.pem and /usr/lib/ssl/certs.
// They are symlinks the openssl and ca-certificates packages ship and a library's closure lacks;
// without them the host's bundle at the identity path (8.4) is never consulted.
func sslPaths(r *root.Root, packages []*Package, log logger) (bool, error) {
	libssl := false
	for _, p := range packages {
		if strings.HasPrefix(p.Name, "libssl") {
			libssl = true
		}
	}
	if !libssl {
		return false, nil
	}
	a, err := link(r, "/usr/lib/ssl/certs", "/etc/ssl/certs", log, false)
	if err != nil {
		return false, err
	}
	b, err := link(r, "/usr/lib/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", log, false)
	if err != nil {
		return false, err
	}
	return a || b, nil
}

// basePasswd makes /etc/passwd and /etc/group, which come from update-passwd, not the package.
// The host's are used unless an own record names them (8.4), but the files must exist for tools
// that list /etc.
func basePasswd(r *root.Root, packages []*Package, log logger) (bool, error) {
	made := false
	for _, nm := range [][2]string{{"passwd", "passwd.master"}, {"group", "group.master"}} {
		src, dst := "/usr/share/base-passwd/"+nm[1], "/etc/"+nm[0]
		if names(packages)["base-passwd"] && r.Exists(src) && !r.Lexists(dst) {
			data, err := r.ReadBytes(src)
			if err != nil {
				return false, err
			}
			if err := r.WriteBytes(dst, data, 0o666); err != nil {
				return false, err
			}
			log(fmt.Sprintf("synthesised /etc/%s from base-passwd", nm[0]))
			made = true
		}
	}
	return made, nil
}

// ldconfigRule writes ld.so.cache as the exclave's own static ldconfig would write it, without
// running it. Package ldcache reads the tree as ldconfig reads it, so a tree of any architecture
// gets its cache here, before wrapping, so that the cache never indexes the launcher; Fedora 42
// has merged sbin into bin. The aux-cache is removed, since it records inodes and mtimes: never
// reproducible, never needed.
func ldconfigRule(r *root.Root, packages []*Package, log logger) (bool, error) {
	ld := ldcache.FindLdconfig(r)
	if ld == "" {
		if names(packages)["libc-bin"] {
			log("libc-bin present but no static ldconfig found; no ld.so.cache")
		}
		return false, nil
	}
	run, err := ldcache.Write(r, ld, ldcache.Log(log))
	if err != nil {
		return false, err
	}
	made := run != nil
	if made {
		log("synthesised /etc/ld.so.cache as the exclave's ldconfig writes it")
	}
	aux := "/var/cache/ldconfig"
	if r.IsDir(aux) && !r.IsLink(aux) {
		if err := r.Rmtree(aux); err != nil {
			return false, err
		}
	}
	return made, nil
}

// shells writes /etc/shells as debianutils' update-shells writes it on a fresh system, from its
// template and the shells.d files packages ship, which its trigger reads: the template's lines,
// then each listed shell, and its spelling with the directory resolved in the tree where that
// differs (/bin/bash and /usr/bin/bash on a merged /usr), that the template does not list. A tree
// that ships /etc/shells keeps it.
func shells(r *root.Root, _ []*Package, log logger) (bool, error) {
	const template, dir, target = "/usr/share/debianutils/shells", "/usr/share/debianutils/shells.d", "/etc/shells"
	if !r.IsFile(template) || r.Lexists(target) {
		return false, nil
	}
	sources := []string{template}
	if r.IsDir(dir) {
		ents := r.Listdir(dir)
		sort.Strings(ents)
		for _, e := range ents {
			sources = append(sources, dir+"/"+e)
		}
	}
	var listed []string
	for _, src := range sources {
		if !r.IsFile(src) {
			continue
		}
		text, err := r.ReadText(src)
		if err != nil {
			return false, err
		}
		for raw := range strings.SplitSeq(text, "\n") {
			line, _, _ := strings.Cut(raw, "#")
			if line == "" {
				continue
			}
			listed = append(listed, line)
			if real, err := r.Realpath(filepath.Dir(line)); err == nil {
				if real = strings.TrimSuffix(real, "/") + "/" + filepath.Base(line); real != line {
					listed = append(listed, real)
				}
			}
		}
	}
	text, err := r.ReadText(template)
	if err != nil {
		return false, err
	}
	var out strings.Builder
	present := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSuffix(text, "\n"), "\n") {
		shell, _, _ := strings.Cut(line, "#")
		if shell == "" || !present[shell] {
			out.WriteString(line + "\n")
			present[shell] = true
		}
	}
	for _, shell := range listed {
		if !present[shell] {
			out.WriteString(shell + "\n")
		}
	}
	if err := r.WriteBytes(target, []byte(out.String()), 0o666); err != nil {
		return false, err
	}
	log(fmt.Sprintf("synthesised %s from %d files", target, len(sources)))
	return true, nil
}

// ---------------------------------------------------------------- ucf

var (
	ucfRe     = regexp.MustCompile(`^\s*ucf\s+((?:--?[a-z-]+\s+)*)(\S+)\s+(\S+)\s*;?\s*$`)
	ucfCallRe = regexp.MustCompile(`(?:^|[;&|(]|\bthen|\belse|\bdo)\s*ucf\s`)
	trailRe   = regexp.MustCompile(`\s*(?:\|\|\s*(?:true|:)|[0-9]?>>?\s*/dev/null|[0-9]?>&[0-9])\s*;?\s*$`)
	assignRe  = regexp.MustCompile(`^\s*(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*)=(\S*)\s*;?\s*$`)
	catToRe   = regexp.MustCompile(`^\s*cat\s+(\S+)\s*>\s*(\S+)\s*;?\s*$`)
	cpToRe    = regexp.MustCompile(`^\s*cp\s+(\S+)\s+(\S+)\s*;?\s*$`)
	varRefRe  = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
)

// expand replaces each $NAME and ${NAME} the shell variables vars hold, and strips the quotes
// around a word.
func expand(word string, vars map[string]string) string {
	word = varRefRe.ReplaceAllStringFunc(word, func(m string) string {
		n := varRefRe.FindStringSubmatch(m)
		name := n[1] + n[2]
		if v, ok := vars[name]; ok {
			return v
		}
		return m
	})
	return strings.Trim(word, `"'`)
}

var keywordRe = regexp.MustCompile(`^\s*(?:(?:then|else|do|\{)\s+)+`)

// commands splits a script into its simple commands as far as the rule reads them: at each line's
// end and at each semicolon, a then, else, do or brace before a command dropped, so that a
// one-line if is read as its branches. A semicolon in a quoted word splits it too.
func commands(text string) []string {
	var out []string
	for line := range strings.SplitSeq(text, "\n") {
		for part := range strings.SplitSeq(line, ";") {
			out = append(out, keywordRe.ReplaceAllString(part, ""))
		}
	}
	return out
}

// ucfInstall is one configuration file a postinst installs with ucf: its source and destination.
type ucfInstall struct{ src, dest string }

// readUcf reads a postinst's `ucf SOURCE DEST` lines as the shell would run them as far as literal
// words go: variables assigned literal words substituted (loops are unrolled before), and a file
// filled from a template by `cat TEMPLATE > FILE` or `cp TEMPLATE FILE` taken for the template. A
// trailing `|| true` or redirection to /dev/null is passed over. Neither an if's nor a case's
// branches are evaluated: every branch is read, and where two lines name one destination the first
// wins. notes say what the rule cannot read: a ucf line built from other shell variables or of
// another form, a second line for one destination, and a template file edited after it was filled,
// which is installed without the edit.
func readUcf(text string) (installs []ucfInstall, notes []string) {
	vars := map[string]string{}
	filled := map[string]string{} // a variable naming a file, and the template it was filled from
	edited := map[string]bool{}
	dests := map[string]bool{}
	for _, line := range commands(text) {
		if m := assignRe.FindStringSubmatch(line); m != nil {
			if v := expand(m[2], vars); !strings.ContainsAny(v, "$`()") {
				vars[m[1]] = v
			} else {
				delete(vars, m[1])
			}
			delete(filled, "$"+m[1])
			continue
		}
		m := catToRe.FindStringSubmatch(line)
		if m == nil {
			m = cpToRe.FindStringSubmatch(line)
		}
		if m != nil {
			if src := expand(m[1], vars); strings.HasPrefix(src, "/") && !strings.Contains(src, "$") {
				f := strings.Trim(m[2], `"'`)
				filled[f], edited[f] = src, false
			}
			continue
		}
		if !ucfCallRe.MatchString(line) {
			// any other line naming a filled file may edit it, as R's sed of its Renviron does, but for
			// those that change only its mode or remove it
			if w := strings.Fields(line); len(w) > 0 && (w[0] == "chmod" || w[0] == "chown" || w[0] == "rm") {
				continue
			}
			for f := range filled {
				if strings.Contains(line, f) || strings.Contains(line, "${"+strings.TrimPrefix(f, "$")+"}") {
					edited[f] = true
				}
			}
			continue
		}
		if strings.Contains(line, "--purge") {
			continue
		}
		bare := line
		for {
			t := trailRe.ReplaceAllString(bare, "")
			if t == bare {
				break
			}
			bare = t
		}
		u := ucfRe.FindStringSubmatch(bare)
		if u == nil {
			notes = append(notes, "calls ucf in a form the ucf rule does not read ("+cut(strings.TrimSpace(line), 80)+
				"): the tree lacks what it installs")
			continue
		}
		src, dest := expand(u[2], vars), expand(u[3], vars)
		f := strings.Trim(u[2], `"'`)
		if t, ok := filled[f]; ok {
			src = t
			if edited[f] {
				notes = append(notes, "edits the template it installs as "+dest+" before ucf installs it: "+
					"installed from "+t+" without the edit")
			}
		}
		if !strings.HasPrefix(src, "/") || !strings.HasPrefix(dest, "/") || strings.Contains(src+dest, "$") {
			notes = append(notes, "installs a configuration file with ucf from shell variables the ucf rule does "+
				"not read ("+cut(strings.TrimSpace(line), 80)+"): the tree lacks it")
			continue
		}
		if dests[dest] {
			notes = append(notes, "installs "+dest+" with ucf on more than one line, of which the rule, "+
				"evaluating no condition, takes the first")
			continue
		}
		dests[dest] = true
		installs = append(installs, ucfInstall{src, dest})
	}
	return installs, notes
}

// ucfFiles installs the configuration files a postinst installs with `ucf SOURCE DEST`, which
// copies a template the package ships to a path under /etc that no package ships: R's Renviron,
// PHP's php.ini and the ini files of its modules, as readUcf reads them, the first line for a
// destination winning, since no condition is evaluated. A DEST that stands already is left; one
// whose source the tree lacks is noted, as is what readUcf cannot read.
func ucfFiles(r *root.Root, packages []*Package, log logger) (bool, error) {
	made := false
	for _, pkg := range packages {
		text, err := postinstText(pkg)
		if err != nil {
			return false, err
		}
		installs, notes := readUcf(text)
		for _, n := range notes {
			log(fmt.Sprintf("note: %s's postinst %s", pkg.Name, n))
		}
		for _, u := range installs {
			if r.Lexists(u.dest) {
				continue
			}
			if !r.IsFile(u.src) {
				log(fmt.Sprintf("note: %s's postinst installs %s with ucf from %s, which the tree lacks", pkg.Name,
					u.dest, u.src))
				continue
			}
			data, err := r.ReadBytes(u.src)
			if err != nil {
				return false, err
			}
			if err := r.WriteBytes(u.dest, data, 0o644); err != nil {
				return false, err
			}
			log(fmt.Sprintf("synthesised %s from %s", u.dest, u.src))
			made = true
		}
	}
	return made, nil
}

// ---------------------------------------------------------------- php-modules

var phpPrioRe = regexp.MustCompile(`(?m)^;\s*priority\s*=\s*([0-9]+)\s*$`)

// phpModules enables Debian's PHP modules as phpenmod does for each package's postinst, which
// enables every module it installs in every SAPI: for each ini file in /etc/php/VERSION/mods-
// available, a link PRIORITY-MODULE.ini to it in every /etc/php/VERSION/SAPI/conf.d, the
// priority from the file's `; priority=` line, 20 without one. Without them PHP loads none of
// the modules its packages ship as shared objects, ctype, iconv, phar and tokenizer among them.
func phpModules(r *root.Root, _ []*Package, log logger) (bool, error) {
	made := false
	if !r.IsDir("/etc/php") {
		return false, nil
	}
	versions := r.Listdir("/etc/php")
	sort.Strings(versions)
	for _, v := range versions {
		avail := "/etc/php/" + v + "/mods-available"
		if !r.IsDir(avail) {
			continue
		}
		mods := r.Listdir(avail)
		sort.Strings(mods)
		sapis := r.Listdir("/etc/php/" + v)
		sort.Strings(sapis)
		for _, ini := range mods {
			mod, ok := strings.CutSuffix(ini, ".ini")
			if !ok || mod == "" || !r.IsFile(avail+"/"+ini) {
				continue
			}
			text, err := r.ReadText(avail + "/" + ini)
			if err != nil {
				return false, err
			}
			prio := "20"
			if m := phpPrioRe.FindStringSubmatch(text); m != nil {
				prio = m[1]
			}
			for _, sapi := range sapis {
				confd := "/etc/php/" + v + "/" + sapi + "/conf.d"
				if sapi == "mods-available" || !r.IsDir(confd) {
					continue
				}
				ok, err := link(r, confd+"/"+prio+"-"+ini, avail+"/"+ini, log, false)
				if err != nil {
					return false, err
				}
				made = made || ok
			}
		}
	}
	return made, nil
}

var rules = []rule{
	{"alternatives", alternatives},
	{"java-jinfo", javaJinfo},
	{"busybox-applets", busyboxApplets},
	{"apk-database", apkDatabase},
	{"dpkg-database", dpkgDatabase},
	{"sbin-merge", sbinMerge},
	{"dash-sh", dashSh},
	{"ca-certificates", caCertificates},
	{"java-cacerts", javaCacerts},
	{"ca-trust", caTrust},
	{"ssl-paths", sslPaths},
	{"base-passwd", basePasswd},
	{"shells", shells},
	{"ucf", ucfFiles},
	{"php-modules", phpModules},
	{"ldconfig", ldconfigRule},
}

// synthesise makes what the packages' maintainer scripts would have made, without running them
// (10.1). The rules are the table above, run in order, each logging what it made; the names of
// those that applied are logged last. Runs before wrapping, so that the tree's own ldconfig can
// run unwrapped. Every path a rule reads or writes resolves with the tree as its root.
func synthesise(rootPath string, packages []*Package, log logger) error {
	r, err := root.Open(rootPath)
	if err != nil {
		return err
	}
	defer r.Close()
	var applied []string
	for _, rule := range rules {
		ok, err := rule.apply(r, packages, log)
		if err != nil {
			return refusing(err)
		}
		if ok {
			applied = append(applied, rule.name)
		}
	}
	if len(applied) == 0 {
		log("synthesis rules applied: none")
	} else {
		log("synthesis rules applied: " + strings.Join(applied, ", "))
	}
	return nil
}

// ---------------------------------------------------------------- what the rules do not make

// interests are the trigger interests, matched by the longest pattern: what a maintainer script
// would have built there and the tree lacks; "" for what nothing needs, or what a rule makes.
// texNote is the note for what TeX's triggers would have built.
const texNote = "TeX's file index and formats are not generated (mktexlsr, fmtutil); exclave caches makes them"

var interests = [][2]string{
	{"/usr/lib/python3*", "Python bytecode: __pycache__ is not generated, so Python compiles each module on import; " +
		"exclave caches makes it"},
	{"/usr/share/glib-2.0/schemas", "GSettings schemas are not compiled (gschemas.compiled); " +
		"exclave caches compiles them"},
	{"/usr/share/mime*", "the MIME database is not built (mime.cache and the index files); exclave caches builds it"},
	{"/usr/share/fonts*", "font caches are not built (/var/cache/fontconfig); exclave caches builds them"},
	{"/etc/fonts*", "font caches are not built (/var/cache/fontconfig); exclave caches builds them"},
	{"/usr/share/icons*", "icon caches are not built (icon-theme.cache); exclave caches builds them"},
	{"/usr/share/applications", "the desktop database is not built (mimeinfo.cache); exclave caches builds it"},
	{"/usr/lib/*/gio/modules", "GIO's module cache is not generated (giomodule.cache); exclave caches makes it"},
	{"/usr/lib/gio/modules", "GIO's module cache is not generated (giomodule.cache); exclave caches makes it"},
	{"/usr/lib/*/gdk-pixbuf-2.0*", "gdk-pixbuf's loader cache is not generated (loaders.cache); " +
		"exclave caches makes it"},
	{"/usr/lib/gdk-pixbuf-2.0*", "gdk-pixbuf's loader cache is not generated (loaders.cache); " +
		"exclave caches makes it"},
	{"/usr/share/texmf*", texNote},
	{"/usr/share/texlive*", texNote},
	{"texmf-format", texNote},
	{"texmf-hyphen", texNote},
	{"texmf-map", "TeX's font maps are not generated (updmap-sys); exclave caches makes them"},
	{"/usr/share/man*", ""},
	{"/usr/man", ""},
	{"/usr/local/man", ""},
	{"/usr/local/share/man", ""},
	{"/usr/X11R6/man", ""},
	{"/opt/man", ""},
	{"/usr/share/debianutils/shells.d", ""},
	{"lib32", ""},
	{"libo32", ""},
	{"libx32", ""},
	{"update-ca-certificates*", ""},
	{"/usr/share/info*", ""},
	{"/usr/share/doc*", ""},
	{"/usr/share/lintian*", ""},
	{"/usr/share/bug*", ""},
	{"ldconfig", ""},
	{"/usr/share/ca-certificates*", ""},
	{"/usr/local/share/ca-certificates*", ""},
	{"/etc/ca-certificates*", ""},
	{"/etc/ld.so.conf.d", ""},
	{"/usr/lib/*/pkgconfig", ""},
}

// notes is what the packages' trigger interests say the tree lacks, one line each.
func notes(packages []*Package) ([]string, error) {
	var out []string
	for _, pkg := range packages {
		paths, err := readerFor(pkg.Path).Interests(pkg.Path)
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			what := "a cache or index its trigger would have built; the tree lacks it"
			best := -1
			for _, pt := range interests {
				if len(pt[0]) > best && (path == pt[0] || ldcache.Fnmatch(pt[0], path)) {
					best, what = len(pt[0]), pt[1]
				}
			}
			if what != "" {
				out = append(out, fmt.Sprintf("note: %s triggers on %s: %s", pkg.Name, path, what))
			}
		}
	}
	return out, nil
}
