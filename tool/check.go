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
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
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
	pay := treePayload(s.root, vpath)
	f, err := os.Open(pay)
	if err != nil {
		if !isErrno(err, syscall.EACCES) && !isErrno(err, syscall.EPERM) {
			failErrno(pay, err)
		}
		rep.errorf("unreadable file %s: chmod u+r it; no copy of the exclave can carry it and the tree hash needs "+
			"it (10.3)", vpath)
		return
	}
	head := make([]byte, 4)
	k, _ := f.Read(head)
	f.Close()
	if k != 4 || string(head) != "\x7fELF" {
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
	e, err := listDir(dir)
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

func staticCheck(ex string, own *ownership, data []string) *report {
	rep := &report{}
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
	s := scan{root: root, data: data, own: own, rep: rep}
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
	for _, o := range s.libraries { // a library nothing reaches is a dlopen candidate: checked alone
		if !w.reached[o.vpath] {
			w.object(o.vpath, o.e, nil, nil)
		}
	}
	return rep
}

// ---------------------------------------------------------------- the dynamic check

// unescape undoes the path's \n and \\ escapes in one pass from left to right (6.2).
func unescape(p string) string {
	var o strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' && i+1 < len(p) && (p[i+1] == 'n' || p[i+1] == '\\') {
			if p[i+1] == 'n' {
				o.WriteByte('\n')
			} else {
				o.WriteByte('\\')
			}
			i++
		} else {
			o.WriteByte(p[i])
		}
	}
	return o.String()
}

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

// A logLine is one of an EXCLAVE_LOG file's lines (6.2): CALL RESULT PATH, the path's escapes
// undone.
type logLine struct {
	what, path string
	result     int64
}

func readLog(p string) []logLine {
	var out []logLine
	for line := range strings.SplitSeq(string(readFile(p)), "\n") {
		line = cString([]byte(line))
		sp1 := strings.IndexByte(line, ' ')
		if sp1 < 0 {
			continue
		}
		sp2 := strings.IndexByte(line[sp1+1:], ' ')
		if sp2 < 0 {
			continue
		}
		sp2 += sp1 + 1
		// CALL RESULT PATH, the result an integer (6.2)
		num := strings.TrimPrefix(line[sp1+1:sp2], "-")
		if num == "" || strings.Trim(num, "0123456789") != "" {
			continue
		}
		result, err := strconv.ParseInt(line[sp1+1:sp2], 10, 64) // a number past the range saturates, as strtol does
		if err != nil && !strings.HasSuffix(err.Error(), strconv.ErrRange.Error()) {
			continue
		}
		out = append(out, logLine{line[:sp1], unescape(line[sp2+1:]), result})
	}
	return out
}

func dynamicCheck(ex string, logs []string, own *ownership) *report {
	rep := &report{}
	var libs, cwds []string
	for _, l := range logs {
		lines := readLog(l)
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
			}
		}
	}
	sort.Strings(mods)
	for _, m := range mods {
		has := false
		for _, d := range defaultDirs() {
			if treeResolve(root, pathJoin(d, "libnss_"+m+".so.2"), true, nil) != "" {
				has = true
				break
			}
		}
		if !has {
			rep.warnf("this host's nsswitch.conf names %s; the exclave has no libnss_%s.so.2", m, m)
		}
	}
	return rep
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
func wrapperProblems(ex string, data []string) []string {
	l := launcherOf(ex)
	root := pathJoin(ex, "tree")
	var out []string
	walkFiles(root, func(real, v string, st *unix.Stat_t) {
		if !isReg(st) || underAny(v, data) {
			return
		}
		w, hasOrig := isWrapper(real, st, &l), payloadPath(real) != real
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
	for _, s := range strays(root) {
		out = append(out, "original without wrapper: "+s+" (.real is reserved for originals, 6.1)")
	}
	return out
}

// locatedLinks lists the tree's symlinks whose text names the exclave's own location (6.1).
// Packages never make one; one added by hand would break when the exclave is moved or copied,
// so wrap and check refuse it, naming the fix.
func locatedLinks(ex string) []string {
	cwd, err := os.Getwd()
	if err != nil {
		failErrno(".", err)
	}
	joined := pathJoin(cwd, ex)
	if strings.HasPrefix(ex, "/") {
		joined = pathJoin(ex, "")
	}
	abs := normpath(joined)
	places := []string{abs}
	if real, err := filepath.EvalSymlinks(abs); err == nil && real != abs {
		places = append(places, real)
	}
	var out []string
	walkFiles(pathJoin(ex, "tree"), func(real, v string, st *unix.Stat_t) {
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

func printReport(rep *report) {
	for _, w := range rep.warnings {
		fmt.Printf("warning: %s\n", w)
	}
	for _, e := range rep.errors {
		fmt.Printf("error: %s\n", e)
	}
}

// staticReport runs the static check and prints its report; returns the number of errors.
func staticReport(ex string) int {
	data := dataPrefixes(ex)
	rep := staticCheck(ex, ownershipOf(ex), data)
	printReport(rep)
	fmt.Printf("static check: %d ELF files, %d static executables, %d warnings, %d errors\n", rep.seen,
		len(rep.statics), len(rep.warnings), len(rep.errors))
	return len(rep.errors)
}

// cmdCheck checks a wrapped exclave: every executable outside data directories wrapped by this
// exclave's launcher, no stray original, the tree as its recorded hash says; then the static
// check, and with EXCLAVE_LOG files the dynamic check.
func cmdCheck(args []string) int {
	if len(args) < 1 {
		usage("check EXCLAVE [LOG...]")
	}
	ex := args[0]
	requireExclave(ex, "check")
	data := dataPrefixes(ex)
	l := launcherOf(ex)
	root, hashes := pathJoin(ex, "tree"), pathJoin(ex, ".exclave/hashes")
	problems := append(wrapperProblems(ex, data), locatedLinks(ex)...)
	walkFiles(root, func(real, v string, st *unix.Stat_t) {
		if !isReg(st) || st.Mode&0o111 == 0 || underAny(v, data) || isWrapper(real, st, &l) {
			return
		}
		if payloadPath(real) == real {
			problems = append(problems, "executable not wrapped: "+v)
		}
	})
	if _, err := os.Stat(hashes); err == nil {
		rs, err := grammarParse(readFile(hashes), kindHashes)
		if err != nil {
			failGrammar(err)
		}
		if recorded := find(rs, "tree"); recorded != nil {
			if actual := treeHash(root); recorded.f[0].v != actual {
				problems = append(problems, fmt.Sprintf("the tree differs from the hashes file: recorded %s, now %s",
					recorded.f[0].v, actual))
			}
		} else {
			problems = append(problems, "an unwrapped exclave: the hashes file has no tree hash; run exclave wrap")
		}
	} else {
		wrapped := false // the third state: wrapped, never finished
		walkFiles(root, func(real, _ string, st *unix.Stat_t) {
			if isWrapper(real, st, &l) {
				wrapped = true
			}
		})
		if wrapped {
			problems = append(problems, "wrappers but no hashes file: wrap never finished; run exclave wrap")
		}
	}
	for _, p := range problems {
		fmt.Println(p)
	}
	fmt.Printf("%d wrapper problems\n", len(problems))
	errors := staticReport(ex)
	rc := 0
	if len(problems) > 0 || errors > 0 {
		rc = 1
	}
	if len(args) > 1 {
		d := dynamicCheck(ex, args[1:], ownershipOf(ex))
		printReport(d)
		fmt.Printf("dynamic check: %d log lines, %d errors\n", d.lines, len(d.errors))
		if len(d.errors) > 0 {
			rc = 1
		}
	}
	return rc
}
