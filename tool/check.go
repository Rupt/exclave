// The static and dynamic checks of an exclave's ELF files, and the check command (DESIGN.md 10.3).
//
// The static check reads every ELF file under tree/ outside data directories, taking originals in
// place of wrappers. All of them must name one interpreter, resolved through the tree's symlinks;
// every DT_NEEDED must resolve inside the tree by the loader's own search; and every library
// reached must depend on that loader's libc and no other. A library that would load from the
// host, or a mix of libcs, is an error that refuses the exclave. Static executables are counted.
//
// The dynamic check reads the EXCLAVE_LOG files a workload wrote. Every library opened must lie on
// a path the exclave owns, and NSS modules that this host's nsswitch.conf names but the exclave
// lacks are reported.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"exclave/tool/format"
)

// objectKey is an object and the RPATHs it inherited, as one key.
func objectKey(vpath string, rpaths []string) string {
	var k strings.Builder
	for _, s := range append([]string{vpath}, rpaths...) {
		fmt.Fprintf(&k, "%d:%s", len(s), s)
	}
	return k.String()
}

// A report is a check's findings: the objects the static check followed, and the log lines the
// dynamic check read.
type report struct {
	errors, warnings, statics []string
	seen, lines               int
}

func (r *report) errorf(format string, a ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, a...))
}
func (r *report) warnf(format string, a ...any) {
	r.warnings = append(r.warnings, fmt.Sprintf(format, a...))
}

// ---------------------------------------------------------------- the static check

type object struct {
	vpath string
	e     *elfFile
}

type scan struct {
	root                         string
	data                         []string
	own                          *ownership
	l                            *listing // the tree listed once, and which files are ELF
	rep                          *report
	executables, libraries       []object
	interpR, interpText, interpV []string // each loader resolved, as named, and by whom, first come
}

func (s *scan) file(vpath string, st *unix.Stat_t, real string) {
	rep := s.rep
	if isLnk(st) {
		if treeResolve(s.root, vpath, true, nil) == "" {
			target, _ := os.Readlink(real)
			rep.warnf("dangling symlink %s -> %s", vpath, target)
		}
		return
	}
	if !isReg(st) {
		return
	}
	pay := s.l.payload(treeReal(s.root, vpath))
	elf, known := s.l.isELF(vpath) // a file the tree hash read is not opened again to tell
	if !known {
		f, err := os.Open(pay)
		if err != nil {
			if !isErrno(err, syscall.EACCES) && !isErrno(err, syscall.EPERM) {
				failErrno(pay, err)
			}
			rep.errorf("unreadable file %s: chmod u+r it; no copy of the exclave can carry it and the tree hash "+
				"needs it (10.3)", vpath)
			return
		}
		head := make([]byte, 4)
		k, _ := f.Read(head)
		f.Close()
		elf = k == 4 && string(head) == "\x7fELF"
	}
	if !elf {
		return
	}
	e, rc, why, err := elfRead(pay)
	switch {
	case rc == elfOS:
		failErrno(pay, err)
	case rc == elfForeign:
		rep.warnf("%s: %s", vpath, why) // Fedora's gcc ships 32-bit crt objects beside the 64-bit ones
		return
	case rc == elfBad:
		rep.errorf("%s: %s", vpath, why)
		return
	case e.machine != launcherMachine.eMachine:
		rep.warnf("%s: not %s: a foreign object, not checked (13)", vpath, launcherMachine.uname)
		return
	case e.debugOnly: // debug information, which nothing loads or runs
		return
	}
	if e.interp == nil && e.typ != etDyn {
		rep.statics = append(rep.statics, vpath)
	} else if e.interp != nil {
		r := treeResolve(s.root, *e.interp, true, nil)
		switch {
		case r == "":
			rep.errorf("%s wants interpreter %s, which does not resolve in the tree", vpath, *e.interp)
		case underAny(r, s.data):
			rep.errorf("%s wants interpreter %s, which resolves into the data directory %s: never executed or "+
				"loaded (6.2)", vpath, *e.interp, r)
		case hostOwned(r, s.own):
			rep.errorf("%s wants interpreter %s, which resolves to %s, a path the exclave does not own: the launcher "+
				"refuses a host loader (7.4.5)", vpath, *e.interp, r)
		case !slices.Contains(s.interpR, r):
			s.interpR = append(s.interpR, r)
			s.interpText = append(s.interpText, *e.interp)
			s.interpV = append(s.interpV, vpath)
		}
	}
	if e.interp != nil || e.typ != etDyn {
		s.executables = append(s.executables, object{vpath, e})
	} else {
		s.libraries = append(s.libraries, object{vpath, e})
	}
}

// dir scans every entry under dir outside data directories, .real/ directories aside, each
// directory's entries in the order of their bytes; a directory that cannot be read is passed over.
func (s *scan) dir(dir, rel string) {
	if underAny(rel, s.data) {
		return
	}
	e, err := s.l.list(dir)
	if err != nil {
		return
	}
	for i := range e {
		// a link the host would take for a directory is a link here, judged in the tree
		if e[i].isDir && !isLnk(&e[i].st) {
			continue
		}
		s.file(rel+"/"+e[i].name, &e[i].st, pathJoin(dir, e[i].name))
	}
	for i := range e {
		if !e[i].isDir || isLnk(&e[i].st) || e[i].name == ".real" {
			continue
		}
		s.dir(pathJoin(dir, e[i].name), rel+"/"+e[i].name)
	}
}

type walkCtx struct {
	root          string
	data          []string
	search        *search
	libcSoname    string
	rep           *report
	seen, reached map[string]bool
	libraries     []object // every library in the tree, for a soname no search finds
	candidate     bool     // walking from a library nothing reaches, which only a dlopen loads
}

// bySoname is a library of the tree whose DT_SONAME is name, outside the data directories, or "";
// a name with a slash is a path, which the loader opens and never matches by soname.
func (w *walkCtx) bySoname(name string) string {
	if strings.Contains(name, "/") {
		return ""
	}
	for _, o := range w.libraries {
		if o.e.soname != nil && *o.e.soname == name && !underAny(o.vpath, w.data) {
			return o.vpath
		}
	}
	return ""
}

// object checks the DT_NEEDED entries of an object the walk has reached through chain, and theirs.
func (w *walkCtx) object(vpath string, e *elfFile, rpaths, chain []string) {
	key := objectKey(vpath, rpaths)
	if w.seen[key] {
		return
	}
	w.seen[key] = true
	w.rep.seen++
	if len(chain) > 0 {
		w.reached[vpath] = true
	}
	var below []string
	if e.runpath == nil && e.rpath != nil {
		below = append(below, *e.rpath)
	}
	below = append(below, rpaths...)
	next := append(append([]string(nil), chain...), vpath)
	if e.runpath != nil { // RUNPATH ends the inheritance: what reaches it passes on as it came
		below = append([]string(nil), rpaths...)
	}
	for _, n := range e.needed {
		var hits []string
		s := *w.search
		s.hostHits = &hits
		found := findLibrary(&s, n, e, vpath, rpaths)
		for _, h := range hits {
			w.rep.errorf("%s searches %s for %s, a directory the exclave does not own: the host's library would load",
				vpath, h, n)
		}
		if found == "" {
			path := strings.Join(next, " > ")
			// no search finds it, so no host library can stand in for it either: an error when the tree lacks it,
			// a package missing; a warning when the tree has it elsewhere, which loads only when a program has
			// opened it first by its path, as the JVM opens its libjvm.so (10.3)
			if elsewhere := w.bySoname(n); elsewhere != "" {
				w.rep.warnf("%s needs %s, which no search finds; the tree has it at %s, loaded only once a "+
					"program has opened it by its path (chain %s)", vpath, n, elsewhere, path)
			} else if w.candidate {
				// a plugin whose package only recommends what it needs, as iproute2's tc modules and
				// libcaca's GL driver: on a host without that package its dlopen fails as it does here
				w.rep.warnf("%s needs %s, which the tree lacks: a dlopen of it fails (chain %s)", vpath, n, path)
			} else {
				w.rep.errorf("%s needs %s, which does not resolve in the tree (chain %s)", vpath, n, path)
			}
			continue
		}
		if underAny(found, w.data) {
			w.rep.errorf("%s needs %s, which resolves into the data directory %s: never loaded (6.2)", vpath, n, found)
			continue
		}
		if strings.HasPrefix(n, "libc.") && n != w.libcSoname {
			w.rep.errorf("%s needs %s: a libc other than the loader's %s", vpath, n, w.libcSoname)
		}
		fe, rc, why, err := elfRead(treePayload(w.root, found))
		switch {
		case rc == elfOS:
			w.rep.errorf("%s: %s", found, errnoText(err))
		case rc != elfOK:
			w.rep.errorf("%s: %s", found, why)
		default:
			w.object(found, fe, below, next)
		}
	}
}

// trustWarnings names each file the tree ships in a trust directory, as the tree resolves it,
// other than the identity files there: the host's directory hides it wherever the host has one,
// and an own record keeps it (10.3). The links a trust tool made there are the host's to replace,
// and a name an own record already keeps draws nothing.
func trustWarnings(root string, owns []string, rep *report) {
	var seen []string
	for _, d := range trustDirs {
		r := treeResolve(root, d, true, nil)
		if r == "" || slices.Contains(seen, r) || !isDir(treeReal(root, r)) {
			continue
		}
		seen = append(seen, r)
		names, err := dirNames(treeReal(root, r))
		if err != nil {
			continue
		}
		for _, n := range names {
			st, err := lstat(pathJoin(treeReal(root, r), n))
			if err != nil || isLnk(&st) {
				continue
			}
			v := pathJoin(d, n)
			if slices.ContainsFunc(owns, func(o string) bool { return v == o || strings.HasPrefix(v, o+"/") }) {
				continue
			}
			if slices.ContainsFunc(identityFiles, func(f string) bool {
				return f == v || strings.HasPrefix(f, v+"/") || f == pathJoin(r, n) ||
					strings.HasPrefix(f, pathJoin(r, n)+"/")
			}) {
				continue
			}
			rep.warnf("%s: the tree ships it in a trust directory, which the host's hides where the host has "+
				"one (8.1 rule 5); own %s keeps it", v, format.Quote(v))
		}
	}
}

func staticCheck(ex string, own *ownership, data []string, l *listing) *report {
	rep := &report{}
	// a level its launcher does not know stops every program at its start (7.7)
	for _, cpu := range valuesOf(manifestOf(ex), "cpu") {
		if !slices.Contains(launcherMachine.cpus, cpu) {
			rep.errorf("cpu %s: not a level the %s launcher knows (%s): no program would start",
				format.Quote(cpu), launcherMachine.uname, strings.Join(launcherMachine.cpus, ", "))
		}
	}
	// the tree is read as its launcher's machine's loader reads it (10.1): nothing of it runs
	root := pathJoin(ex, "tree")
	cache, hasCache := readCache(root)
	switch {
	case hostOwned("/etc", own): // the loader would read the host's cache and preload list
		rep.errorf("/etc is the host's: the loader would read the host's /etc/ld.so.cache and /etc/ld.so.preload; " +
			"the tree must own /etc")
	case !hasCache:
		// musl has no cache; glibc without one searches its defaults only
		r := treeResolve(root, "/lib/ld-musl-"+launcherMachine.uname+".so.1", true, nil)
		if !(r != "" && isPayloadFile(root, r)) {
			rep.warnf("no /etc/ld.so.cache: only the loader's default directories are searched at run time")
		}
	default:
		for i := range cache { // no cache entry may name the launcher (10.3), by soname in order
			first := true
			for j := 0; j < i && first; j++ {
				first = cache[j].soname != cache[i].soname
			}
			if !first {
				continue
			}
			for j := i; j < len(cache); j++ {
				if cache[j].soname != cache[i].soname {
					continue
				}
				r := treeResolve(root, cache[j].path, true, nil)
				if r == "" || !isPayloadFile(root, r) {
					continue
				}
				e, rc, _, _ := elfRead(treePayload(root, r))
				if rc == elfOK && e.soname == nil && e.typ == etDyn && len(e.needed) == 0 {
					rep.errorf("ld.so.cache entry %s names %s, which is not a shared library (the launcher?)",
						cache[i].soname, cache[j].path)
				}
			}
		}
	}
	trustWarnings(root, valuesOf(manifestOf(ex), "own"), rep)
	s := scan{root: root, data: data, own: own, rep: rep, l: l}
	s.dir(root, "")
	// one loader, and so one libc, per exclave (7.3): read from the ELF files, not declared anywhere
	if len(s.interpR) > 1 {
		order := make([]int, len(s.interpR))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(a, b int) bool { return s.interpR[order[a]] < s.interpR[order[b]] })
		var mixed []string
		for _, i := range order {
			mixed = append(mixed, s.interpText[i]+" ("+s.interpV[i]+")")
		}
		rep.errorf("the tree mixes loaders %s (one world inside an exclave, 7.3)", strings.Join(mixed, ", "))
	}
	var interp *string
	if len(s.interpText) > 0 {
		interp = &s.interpText[0]
	}
	musl := interp != nil && strings.Contains(basenameOf(*interp), "musl")
	defaults, assumed := loaderDirs(root, interp)
	if assumed != "" {
		rep.warnings = append(rep.warnings, assumed)
	}
	// 6.2: the locale inside an exclave is C.UTF-8, built into glibc 2.35 and later and into musl; an older glibc
	// needs the C.utf8 directory or every program runs in the plain C locale, and bash and perl say so
	if interp != nil && !musl {
		if major, minor, ok := glibcVersion(root); ok && (major < 2 || (major == 2 && minor < 35)) {
			has := false
			for _, l := range []string{"/usr/lib/locale/C.utf8", "/usr/lib/locale/C.UTF-8"} {
				if r := treeResolve(root, l, true, nil); r != "" && isDir(treeReal(root, r)) {
					has = true
					break
				}
			}
			if !has {
				rep.warnf("glibc %d.%d predates the built-in C.UTF-8 locale and the tree has no "+
					"/usr/lib/locale/C.utf8: programs will run in the plain C locale", major, minor)
			}
		}
	}
	if !hasCache {
		cache = nil
	}
	libc := "libc.so.6"
	if musl {
		libc = "libc.musl-" + launcherMachine.uname + ".so.1"
	}
	w := walkCtx{root: root, data: data, libcSoname: libc, rep: rep, libraries: s.libraries,
		search: &search{root: root, cache: cache, defaults: defaults, interp: interp, own: own},
		seen:   map[string]bool{}, reached: map[string]bool{}}
	for _, o := range s.executables { // executables first, so that RPATH inheritance is seen
		w.object(o.vpath, o.e, nil, nil)
	}
	w.candidate = true
	for _, o := range s.libraries { // a library nothing reaches is a dlopen candidate: checked alone
		if !w.reached[o.vpath] {
			w.object(o.vpath, o.e, nil, nil)
		}
	}
	return rep
}

// ---------------------------------------------------------------- the dynamic check

// libraryName reports whether a path ends in .so and any version numbers after it.
func libraryName(p string) bool {
	n := len(p)
	for {
		if n >= 3 && p[n-3:n] == ".so" {
			return true
		}
		k := n
		for k > 0 && isDigit(p[k-1]) {
			k--
		}
		if k == n || k == 0 || p[k-1] != '.' {
			return false
		}
		n = k - 1
	}
}

func dynamicCheck(ex string, logs []string, own *ownership) *report {
	rep := &report{}
	var libs, cwds []string
	for _, l := range logs {
		lines := readLogs(l)
		rep.lines += len(lines)
		for _, x := range lines {
			const given = "cwd given to the host "
			// 8.1 rule 4 as the launcher applied it; the plain cwd line is a diagnostic and gives nothing
			if x.what == "launcher" && strings.HasPrefix(x.path, given) {
				if x.path[len(given):] != "/" {
					cwds = append(cwds, x.path[len(given):])
				}
			} else if x.what == "launcher" && strings.HasPrefix(x.path, "cwd ") &&
				!strings.HasPrefix(x.path, "cwd given") && volatilePath(x.path[4:]) {
				// a working directory under a volatile prefix is the host's already (8.1 rule 3), so the launcher
				// logs no given line for it; it is the workload's own all the same
				cwds = append(cwds, x.path[4:])
			}
			if x.what == "open" && x.result >= 0 && libraryName(x.path) && !slices.Contains(libs, x.path) {
				libs = append(libs, x.path)
			}
		}
	}
	sort.Strings(libs)
	for _, lib := range libs {
		mine := false // the workload's own build directory: the host's by 8.1 rule 4, whatever prefix it lies under
		for _, c := range cwds {
			c = strings.TrimRight(c, "/")
			if strings.HasPrefix(lib, c) && len(lib) > len(c) && lib[len(c)] == '/' {
				mine = true
				break
			}
		}
		if mine {
			rep.warnf("library opened under the workload's working directory, its own output presumably: %s", lib)
		} else if hostOwned(lib, own) {
			rep.errorf("library opened on the host: %s", lib)
		}
	}
	root := pathJoin(ex, "tree")
	var mods []string
	userDB := map[string]bool{} // a module named for passwd or group, which musl reaches through nscd
	if _, err := os.Stat("/etc/nsswitch.conf"); err == nil {
		for line := range strings.FieldsFuncSeq(cString(readFile("/etc/nsswitch.conf")),
			func(r rune) bool { return r == '\r' || r == '\n' }) {
			if hash := strings.IndexByte(line, '#'); hash >= 0 {
				line = line[:hash]
			}
			colon := strings.IndexByte(line, ':')
			if colon < 0 {
				continue
			}
			db := strings.TrimSpace(line[:colon])
			// a module name, mdns4_minimal included; not [NOTFOUND=return]
			for _, word := range strings.FieldsFunc(line[colon+1:], func(r rune) bool {
				return r == ' ' || r == '\t' || r == '\v' || r == '\f'
			}) {
				ok := len(word) < 256
				for j := 0; j < len(word) && ok; j++ {
					ok = isAlnum(word[j]) || word[j] == '_'
				}
				if ok && word != "files" && word != "dns" && !slices.Contains(mods, word) {
					mods = append(mods, word)
				}
				if ok && (db == "passwd" || db == "group") {
					userDB[word] = true
				}
			}
		}
	}
	sort.Strings(mods)
	// a musl tree: musl's loader and not glibc's, since a glibc tree may ship musl beside it
	musl := treeResolve(root, "/lib/ld-musl-"+launcherMachine.uname+".so.1", true, nil) != "" &&
		treeResolve(root, glibcLoaders[launcherMachine.uname], true, nil) == ""
	var lack, lackUsers []string
	for _, m := range mods {
		has := false
		for _, d := range defaultDirs() {
			if treeResolve(root, pathJoin(d, "libnss_"+m+".so.2"), true, nil) != "" {
				has = true
				break
			}
		}
		if has {
			continue
		}
		if musl && userDB[m] {
			lackUsers = append(lackUsers, m)
		} else if musl {
			lack = append(lack, m)
		} else if pkg, ok := nssPackages[m]; ok {
			rep.warnf("this host's nsswitch.conf names %s; the exclave has no libnss_%s.so.2, so what it looks up "+
				"is unknown inside: add %s (8.4)", m, m, pkg)
		} else {
			rep.warnf("this host's nsswitch.conf names %s; the exclave has no libnss_%s.so.2, so what it looks up "+
				"is unknown inside: add the package that ships it (8.4)", m, m)
		}
	}
	if len(lackUsers) > 0 {
		rep.warnf("this host's nsswitch.conf names %s for users or groups; musl loads no NSS modules, so the users "+
			"and groups they know are unknown inside unless the host runs nscd (8.4)", strings.Join(lackUsers, ", "))
	}
	if len(lack) > 0 {
		rep.warnf("this host's nsswitch.conf names %s; musl loads no NSS modules, so what they look up is unknown "+
			"inside (8.4)", strings.Join(lack, ", "))
	}
	return rep
}

// glibcLoaders are glibc's loaders by machine, as their ELF interpreters name them.
var glibcLoaders = map[string]string{"x86_64": "/lib64/ld-linux-x86-64.so.2", "aarch64": "/lib/ld-linux-aarch64.so.1"}

// nssPackages names, for the NSS modules a host's nsswitch.conf commonly names, the packages that
// ship them; each module's client finds its daemon under /run, or SSSD's under /var/lib/sss,
// which are the host's (8.1).
var nssPackages = map[string]string{
	"sss":           "libnss-sss on Debian and Ubuntu, sssd-client on Fedora",
	"systemd":       "libnss-systemd on Debian and Ubuntu, systemd-libs on Fedora",
	"ldap":          "libnss-ldapd on Debian and Ubuntu, nss-pam-ldapd on Fedora",
	"winbind":       "libnss-winbind on Debian and Ubuntu, samba-winbind-clients on Fedora",
	"mdns4_minimal": "libnss-mdns on Debian and Ubuntu, nss-mdns on Fedora",
	"mdns":          "libnss-mdns on Debian and Ubuntu, nss-mdns on Fedora",
	"resolve":       "libnss-resolve on Debian and Ubuntu, systemd-resolved on Fedora",
	"myhostname":    "libnss-myhostname on Debian and Ubuntu, systemd-libs on Fedora",
}

// ---------------------------------------------------------------- the wrappers (6.1)

type launcherID struct {
	path     string
	dev, ino uint64
	size     int64
}

func launcherOf(ex string) launcherID {
	l := launcherID{path: pathJoin(ex, ".exclave/launcher")}
	st, err := stat(l.path)
	if err != nil {
		failErrno(l.path, err)
	}
	l.dev, l.ino, l.size = st.Dev, st.Ino, st.Size
	return l
}

// isWrapper reports a wrapper of this launcher: a hard link to it, or, where a copy split the
// links, a file with its contents that has an original in .real/.
func isWrapper(real string, st *unix.Stat_t, l *launcherID) bool {
	if !isReg(st) {
		return false
	}
	if st.Dev == l.dev && st.Ino == l.ino {
		return true
	}
	if st.Size != l.size {
		return false
	}
	return payloadPath(real) != real && string(readFile(real)) == string(readFile(l.path))
}

// wrapperProblems lists the problems with the tree's wrappers and originals as it stands: a
// stale wrapper (one of another launcher), a wrapper without an original, an executable its user
// cannot run, and an original without a wrapper, a stray under the reserved name. Executables not
// yet wrapped are not problems here.
func wrapperProblems(ex string, data []string, ls *listing) []string {
	l := launcherOf(ex)
	root := pathJoin(ex, "tree")
	var out []string
	ls.walkFiles(root, func(real, v string, st *unix.Stat_t) {
		if !isReg(st) || underAny(v, data) {
			return
		}
		w, hasOrig := isWrapper(real, st, &l), ls.payload(real) != real
		switch {
		case !w && hasOrig:
			out = append(out, fmt.Sprintf("stale wrapper (not this exclave's launcher): %s; run exclave relink", v))
		case st.Mode&0o111 != 0 && !w && unix.Access(real, unix.X_OK) != nil:
			out = append(out, fmt.Sprintf("executable file its user cannot execute: %s (mode %o); a wrapper would "+
				"run as the launcher's mode", v, st.Mode&0o7777))
		}
		if w && !hasOrig {
			out = append(out, "wrapper without original: "+v)
		}
	})
	for _, s := range ls.strays(root) {
		out = append(out, "original without wrapper: "+s+" (.real is reserved for originals, 6.1)")
	}
	return out
}

// locatedLinks lists the tree's symlinks whose text names the exclave's own location (6.1).
// Packages never make one; one added by hand would break when the exclave is moved or copied,
// so wrap and check refuse it, naming the fix.
func locatedLinks(ex string, l *listing) []string {
	cwd, err := unix.Getwd() // the physical directory, as getcwd gives it, never $PWD's spelling
	if err != nil {
		failErrno(".", err)
	}
	joined := pathJoin(cwd, ex)
	if strings.HasPrefix(ex, "/") {
		joined = pathJoin(ex, "")
	}
	abs := normpath(joined)
	places := []string{abs}
	// realpath of the path as given: every link resolved as met, a .. after one taken physically
	if real, err := filepath.EvalSymlinks(joined); err == nil && real != abs {
		places = append(places, real)
	}
	var out []string
	l.walkFiles(pathJoin(ex, "tree"), func(real, v string, st *unix.Stat_t) {
		if !isLnk(st) {
			return
		}
		text, err := os.Readlink(real)
		if err != nil {
			failErrno(real, err)
		}
		for _, place := range places {
			if !under(text, place) {
				continue
			}
			inside := relpath(text, pathJoin(place, "tree"))
			if !strings.HasPrefix(inside, "..") && inside != "." {
				out = append(out, fmt.Sprintf("link naming the exclave's own location: %s -> %s; ln -sfn /%s %s", v,
					text, inside, real))
			} else {
				out = append(out, fmt.Sprintf("link naming the exclave's own location: %s -> %s", v, text))
			}
			break
		}
	})
	return out
}

// shortcutProblems lists the exclave's shortcuts that do not stay in it (6.1). The kernel follows a shortcut by the
// host's resolution, a link inside the tree with an absolute target included, and nothing hashes the shortcuts, so
// each symlink at the top of the exclave must name a path of its tree relatively, and resolve on the host to a file
// of that tree.
// The exclave is made absolute first, so that the verdict is the same however its path is spelled.
func shortcutProblems(ex string) []string {
	names, err := dirNames(ex)
	if err != nil {
		failErrno(ex, err)
	}
	if abs, err := filepath.Abs(ex); err == nil {
		ex = abs
	}
	treeAt, err := filepath.EvalSymlinks(pathJoin(ex, "tree"))
	if err != nil {
		failErrno(pathJoin(ex, "tree"), err)
	}
	var out []string
	for _, name := range names {
		p := pathJoin(ex, name)
		if st, err := lstat(p); err != nil || !isLnk(&st) {
			continue
		}
		text, err := os.Readlink(p)
		if err != nil {
			failErrno(p, err)
		}
		real, rerr := filepath.EvalSymlinks(p)
		switch {
		case strings.HasPrefix(text, "/"):
			out = append(out, fmt.Sprintf("shortcut by an absolute path: %s -> %s; a shortcut names its file in tree/ "+
				"relatively, so that the exclave can move", name, text))
		case !strings.HasPrefix(filepath.Clean(text), "tree/"):
			out = append(out, fmt.Sprintf("shortcut by a path outside tree/: %s -> %s; a shortcut names its file as "+
				"tree/..., so that the exclave can be renamed", name, text))
		case rerr != nil:
			out = append(out, fmt.Sprintf("shortcut that does not resolve: %s -> %s", name, text))
		case !under(real, treeAt) || real == treeAt:
			out = append(out, fmt.Sprintf("shortcut leaving the tree: %s -> %s, which the host resolves to %s; point "+
				"it at the tree's own file", name, text, real))
		}
	}
	return out
}

func printReport(rep *report) {
	for _, w := range rep.warnings {
		fmt.Fprintf(out, "warning: %s\n", w)
	}
	for _, e := range rep.errors {
		fmt.Fprintf(out, "error: %s\n", e)
	}
}

// staticReport runs the static check and prints its report; returns the number of errors. l is
// the tree's listing, or nil for one made here.
func staticReport(ex string, l *listing) int {
	data := dataPrefixes(ex)
	if l == nil {
		l = listTree(pathJoin(ex, "tree"))
	}
	rep := staticCheck(ex, ownershipOf(ex), data, l)
	printReport(rep)
	fmt.Fprintf(out, "static check: %d ELF files, %d static executables, %d warnings, %d errors\n", rep.seen,
		len(rep.statics), len(rep.warnings), len(rep.errors))
	return len(rep.errors)
}

// cmdCheck checks a wrapped exclave: every executable outside data directories wrapped by this
// exclave's launcher, no stray original, the tree as its recorded hash says; then the static
// check, and with EXCLAVE_LOG files the dynamic check.
func cmdCheck(args []string) int {
	if len(args) < 1 {
		usage()
	}
	ex := args[0]
	requireExclave(ex, "check")
	refuseSetAside(ex, "check")
	data := dataPrefixes(ex)
	l := launcherOf(ex)
	root, hashes := pathJoin(ex, "tree"), pathJoin(ex, ".exclave/hashes")
	ls := listTree(root) // the tree is read five times over and not changed: listed once
	problems := append(append(wrapperProblems(ex, data, ls), locatedLinks(ex, ls)...), shortcutProblems(ex)...)
	ls.walkFiles(root, func(real, v string, st *unix.Stat_t) {
		if !isReg(st) || st.Mode&0o111 == 0 || underAny(v, data) || isWrapper(real, st, &l) {
			return
		}
		if ls.payload(real) == real {
			problems = append(problems, "executable not wrapped: "+v)
		}
	})
	if _, err := os.Stat(hashes); err == nil {
		rs, err := format.Parse(readFile(hashes), format.Hashes)
		if err != nil {
			failGrammar(err)
		}
		if recorded := find(rs, "tree"); recorded != nil {
			if actual := ls.treeHash(root); recorded.F[0].V != actual {
				problems = append(problems, fmt.Sprintf("the tree differs from the hashes file: recorded %s, now %s",
					recorded.F[0].V, actual))
			}
		} else {
			problems = append(problems, "an unwrapped exclave: the hashes file has no tree hash; run exclave wrap")
		}
	} else {
		wrapped := false // the third state: wrapped, never finished
		ls.walkFiles(root, func(real, _ string, st *unix.Stat_t) {
			if isWrapper(real, st, &l) {
				wrapped = true
			}
		})
		if wrapped {
			problems = append(problems, "wrappers but no hashes file: wrap never finished; run exclave wrap")
		}
	}
	for _, p := range problems {
		fmt.Fprintln(out, p)
	}
	fmt.Fprintf(out, "%d wrapper problems\n", len(problems))
	errors := staticReport(ex, ls)
	rc := 0
	if len(problems) > 0 || errors > 0 {
		rc = 1
	}
	if len(args) > 1 {
		d := dynamicCheck(ex, args[1:], ownershipOf(ex))
		printReport(d)
		fmt.Fprintf(out, "dynamic check: %d log lines, %d errors\n", d.lines, len(d.errors))
		if len(d.errors) > 0 {
			rc = 1
		}
	}
	return rc
}
