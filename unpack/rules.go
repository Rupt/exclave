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
package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"exclave/unpack/apk"
	"exclave/unpack/ldcache"
	"exclave/unpack/root"
)

// rule is a synthesis rule: its name in the log, what it makes, and the function that makes it.
type rule struct {
	name  string
	what  string
	apply func(r *root.Root, packages []*Package, log Log) (bool, error)
}

// link makes a symlink at a virtual path, unless something stands there. With replace, as
// alternatives --install does, a file or link standing there gives way; a directory never does.
// Fedora's binutils needs this: it ships gold at /usr/bin/ld and removes it in %post before
// installing the alternative.
func link(r *root.Root, at, target string, log Log, replace bool) (bool, error) {
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

// ---------------------------------------------------------------- update-alternatives
// Debian's and rpm's spellings
var (
	uaRe = regexp.MustCompile(
		`(?:update-)?alternatives\s+(?:--(?:quiet|verbose|force)\s+)*--install\s+` +
			`(\S+)\s+(\S+)\s+(\S+)\s+(\d+)((?:\s+--slave\s+\S+\s+\S+\s+\S+)*)`)
	uaSetRe = regexp.MustCompile(`(?:update-)?alternatives\s+(?:--(?:quiet|verbose|force)\s+)*--set\s+(\S+)\s+(\S+)`)
	uaAnyRe = regexp.MustCompile(`(?:update-)?alternatives\s+--(?:install|set)\b`)
	slaveRe = regexp.MustCompile(`--slave\s+(\S+)\s+(\S+)\s+(\S+)`)
)

// alternative is one `alternatives --install` line: its priority first, so the greatest wins.
type alternative struct {
	priority string // decimal digits
	link     string
	target   string
	slaves   [][3]string // (link, name, target)
}

// less orders alternatives as Python orders the tuples (priority, link, target, slaves).
func (a alternative) less(b alternative) bool {
	if c := apk.CmpNum(a.priority, b.priority); c != 0 {
		return c < 0
	}
	if a.link != b.link {
		return a.link < b.link
	}
	if a.target != b.target {
		return a.target < b.target
	}
	for i := 0; i < len(a.slaves) && i < len(b.slaves); i++ {
		for k := 0; k < 3; k++ {
			if a.slaves[i][k] != b.slaves[i][k] {
				return a.slaves[i][k] < b.slaves[i][k]
			}
		}
	}
	return len(a.slaves) < len(b.slaves)
}

// alternatives makes every `update-alternatives --install` line in a postinst, with its slaves.
// The highest priority wins, unless a `--set` names a candidate; a line the rule cannot read, one
// built from shell variables or in a loop, is noted, since its alternatives are not made.
func alternatives(r *root.Root, packages []*Package, log Log) (bool, error) {
	groups := map[string][]alternative{}
	var order []string
	chosen := map[string]string{}
	for _, pkg := range packages {
		_, scripts, err := readerFor(pkg.Path).Control(pkg.Path)
		if err != nil {
			return false, err
		}
		text := strings.ReplaceAll(scripts["postinst"], "\\\n", " ")
		matched := 0
		for _, m := range uaRe.FindAllStringSubmatch(text, -1) {
			at, gname, target, prio := m[1], m[2], m[3], m[4]
			matched++
			if strings.Contains(at+gname+target, "$") {
				matched--
				continue
			}
			if !r.Lexists(target) {
				continue
			}
			var slaves [][3]string
			for _, s := range slaveRe.FindAllStringSubmatch(m[5], -1) {
				slaves = append(slaves, [3]string{s[1], s[2], s[3]})
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
				"alternatives rule does not read, variables or a loop: its alternatives are made "+
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
			ok, err := link(r, l[0], l[1], log, true)
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
					ok, err := link(r, l[0], l[1], log, true)
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
// where nothing stands there already.
func javaJinfo(r *root.Root, _ []*Package, log Log) (bool, error) {
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
			if b, ok := bests[tool]; r.Lexists(target) && (!ok || apk.CmpNum(prio, b.prio) > 0) {
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
			ok, err := link(r, l[0], l[1], log, false)
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
func busyboxApplets(r *root.Root, _ []*Package, log Log) (bool, error) {
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
		for _, line := range strings.Split(text, "\n") {
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

// sbinMerge does what Fedora 42's filesystem does in its %posttrans: it replaces /usr/sbin and
// /usr/local/sbin by a link to bin when every entry there is a link ../bin/<name>; the script says
// so in Lua, and this is its effect.
func sbinMerge(r *root.Root, packages []*Package, log Log) (bool, error) {
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
func dashSh(r *root.Root, packages []*Package, log Log) (bool, error) {
	if names(packages)["dash"] && r.Lexists("/usr/bin/dash") {
		return link(r, "/usr/bin/sh", "dash", log, false)
	}
	return false, nil
}

// caCertificates makes Debian's ca-certificates bundle, which update-ca-certificates makes from
// the enabled ones.
func caCertificates(r *root.Root, packages []*Package, log Log) (bool, error) {
	conf := "/etc/ca-certificates.conf"
	if !names(packages)["ca-certificates"] || !r.Exists(conf) {
		return false, nil
	}
	text, err := r.ReadText(conf)
	if err != nil {
		return false, err
	}
	var pems [][]byte
	for _, raw := range strings.Split(text, "\n") {
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

var pemRe = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----`)

// caTrust makes Fedora's and RHEL's ca-certificates bundle, which update-ca-trust extracts in
// %post. The consumers' paths are links to /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem,
// extracted from the p11-kit trust source; the CA anchors trusted there are concatenated the same
// way. The bundle is an identity file (8.4): the host's where it has one.
func caTrust(r *root.Root, _ []*Package, log Log) (bool, error) {
	extracted := "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
	var sources []string
	for _, dp := range [][2]string{
		{"/usr/share/pki/ca-trust-source", "*.p11-kit"}, {"/etc/pki/ca-trust/source/anchors", "*"},
	} {
		for _, n := range r.Listdir(dp[0]) {
			if !strings.HasPrefix(n, ".") && fnmatch(dp[1], n) {
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
	log(fmt.Sprintf("synthesised /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem from %d trusted certificates", len(certs)))
	return true, nil
}

// sslPaths makes OpenSSL's compiled-in trust paths, /usr/lib/ssl/cert.pem and /usr/lib/ssl/certs.
// They are symlinks the openssl and ca-certificates packages ship and a library's closure lacks;
// without them the host's bundle at the identity path (8.4) is never consulted.
func sslPaths(r *root.Root, packages []*Package, log Log) (bool, error) {
	any := false
	for _, p := range packages {
		if strings.HasPrefix(p.Name, "libssl") {
			any = true
		}
	}
	if !any {
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
func basePasswd(r *root.Root, packages []*Package, log Log) (bool, error) {
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
func ldconfigRule(r *root.Root, packages []*Package, log Log) (bool, error) {
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

var rules = []rule{
	{"alternatives", "the links of every update-alternatives --install line, --set honoured", alternatives},
	{"java-jinfo", "a JDK's tool links from its /usr/lib/jvm/.*.jinfo file", javaJinfo},
	{"busybox-applets", "busybox's applet links from /etc/busybox-paths.d", busyboxApplets},
	{"sbin-merge", "Fedora's /usr/sbin and /usr/local/sbin as links to bin", sbinMerge},
	{"dash-sh", "dash's /bin/sh", dashSh},
	{"ca-certificates", "Debian's ca-certificates.crt from the enabled certificates", caCertificates},
	{"ca-trust", "Fedora's tls-ca-bundle.pem from the p11-kit trust source", caTrust},
	{"ssl-paths", "OpenSSL's compiled-in trust paths as links to /etc/ssl", sslPaths},
	{"base-passwd", "/etc/passwd and /etc/group from base-passwd's masters", basePasswd},
	{"ldconfig", "ld.so.cache as the exclave's own ldconfig writes it", ldconfigRule},
}

// synthesise makes what the packages' maintainer scripts would have made, without running them
// (10.1). The rules are the table above, run in order, each logging what it made; the names of
// those that applied are logged last. Runs before wrapping, so that the tree's own ldconfig can
// run unwrapped. Every path a rule reads or writes resolves with the tree as its root.
func synthesise(rootPath string, packages []*Package, log Log) error {
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
var interests = [][2]string{
	{"/usr/lib/python3*", "Python bytecode: __pycache__ is not generated, so Python compiles each module on import"},
	{"/usr/share/glib-2.0/schemas", "GSettings schemas are not compiled (gschemas.compiled)"},
	{"/usr/share/mime", "the MIME database is not built (mime.cache and the index files)"},
	{"/usr/share/fonts*", "font caches are not built; fontconfig builds its own under the user's cache"},
	{"/etc/fonts*", "font caches are not built; fontconfig builds its own under the user's cache"},
	{"/usr/share/icons*", "icon caches are not built (icon-theme.cache)"},
	{"/usr/share/applications", "the desktop database is not built (mimeinfo.cache)"},
	{"/usr/lib/*/gio/modules", "GIO's module cache is not generated (giomodule.cache)"},
	{"/usr/lib/gio/modules", "GIO's module cache is not generated (giomodule.cache)"},
	{"/usr/lib/*/gdk-pixbuf-2.0*", "gdk-pixbuf's loader cache is not generated (loaders.cache)"},
	{"/usr/share/texmf*", "TeX's file index and formats are not generated (mktexlsr, fmtutil)"},
	{"/usr/share/texlive*", "TeX's file index and formats are not generated (mktexlsr, fmtutil)"},
	{"/usr/share/man*", ""},
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

// fnmatch matches name against a shell pattern as Python's fnmatchcase does: `*` and `?` match
// any character, `/` included.
func fnmatch(pattern, name string) bool {
	var re strings.Builder
	re.WriteString("^")
	for _, c := range pattern {
		switch c {
		case '*':
			re.WriteString(".*")
		case '?':
			re.WriteString(".")
		default:
			re.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	re.WriteString("$")
	return regexp.MustCompile("(?s)" + re.String()).MatchString(name)
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
				if len(pt[0]) > best && (path == pt[0] || fnmatch(pt[0], path)) {
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
