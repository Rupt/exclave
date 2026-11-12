// The loader's search for a library, as the tree's own loader makes it (DESIGN.md 10.3): the
// machine's default directories, DT_RPATH and DT_RUNPATH with their tokens expanded, ld.so.cache,
// and the directories the loader names for itself; and the glibc a tree carries, by its banner.
// The static check and prune ask it.

package main

import (
	"bytes"
	"math"
	"os"
	"runtime"
	"strings"
)

// ---------------------------------------------------------------- machines (7.1)

type machine struct {
	eMachine       int
	uname, triplet string   // uname -m, which glibc's loader substitutes for $PLATFORM; the multiarch triplet
	hwcaps         []string // the glibc-hwcaps subdirectories searched first, best first
	cpus           []string // the levels a manifest's cpu may name: the ones this machine's launcher knows (7.7)
}

var machines = []machine{
	{62, "x86_64", "x86_64-linux-gnu",
		[]string{"glibc-hwcaps/x86-64-v4", "glibc-hwcaps/x86-64-v3", "glibc-hwcaps/x86-64-v2"},
		[]string{"x86-64", "x86-64-v2", "x86-64-v3", "x86-64-v4"}},
	{183, "aarch64", "aarch64-linux-gnu", nil, []string{"aarch64", "armv8-a", "armv8.1-a", "armv8.2-a"}},
}

// launcherMachine is the exclave's launcher's machine; the command's own build until one is read.
var launcherMachine = ownMachine()

func ownMachine() *machine {
	if runtime.GOARCH == "arm64" {
		return &machines[1]
	}
	return &machines[0]
}

// machineOfLauncher reads the exclave's machine from its launcher (10.1): the checks read the
// tree as that machine's loader would, so an exclave of another architecture is wrapped and
// checked here. A launcher for a machine the table lacks is refused.
func machineOfLauncher(ex string) {
	ld := pathJoin(ex, ".exclave/launcher")
	e, rc, _, _ := elfRead(ld)
	if rc != elfOK {
		return
	}
	for i := range machines {
		if machines[i].eMachine == e.machine {
			launcherMachine = &machines[i]
			return
		}
	}
	fail("%s is a launcher for machine %d, which this command does not know", ld, e.machine)
}

// defaultDirs are glibc's default directories on Debian and Fedora, for a loader that carries no
// table of them.
func defaultDirs() []string {
	t := launcherMachine.triplet
	return []string{"/lib/" + t, "/usr/lib/" + t, "/lib64", "/usr/lib64", "/lib", "/usr/lib"}
}

// expand makes glibc's substitutions in an RPATH, a RUNPATH or a DT_NEEDED path (dl-load.c), each
// made over the whole string in turn.
func expand(s, origin string) string {
	lib := "lib/" + launcherMachine.triplet
	for _, sub := range [][2]string{
		{"$ORIGIN", origin}, {"${ORIGIN}", origin}, {"$LIB", lib}, {"${LIB}", lib},
		{"$PLATFORM", launcherMachine.uname}, {"${PLATFORM}", launcherMachine.uname},
	} {
		s = strings.ReplaceAll(s, sub[0], sub[1])
	}
	return s
}

// ---------------------------------------------------------------- the loader's search

func isPayloadFile(root, v string) bool {
	st, err := os.Stat(treePayload(root, v))
	return err == nil && st.Mode().IsRegular()
}

// searchDir is the first of the tree's files the loader would take in directory d for name, its
// hwcaps subdirectories first.
func searchDir(root, d, name string) string {
	for i := 0; i <= len(launcherMachine.hwcaps); i++ {
		sub := d
		if i < len(launcherMachine.hwcaps) {
			sub = pathJoin(d, launcherMachine.hwcaps[i])
		}
		if r := treeResolve(root, pathJoin(sub, name), true, nil); r != "" && isPayloadFile(root, r) {
			return r
		}
	}
	return ""
}

func splitAdd(out *[]string, list, origin string) {
	for part := range strings.SplitSeq(list, ":") {
		if part != "" { // a part is at most a path's 4095 bytes, as the C's buffer held it
			*out = append(*out, expand(part[:min(len(part), 4095)], origin))
		}
	}
}

// A search is the loader's search in one tree.
type search struct {
	root     string
	cache    []cacheEntry
	defaults []string
	interp   *string    // the loader's virtual path, or nil for a static program
	own      *ownership // with hostHits, to find searched directories that are the host's
	hostHits *[]string
}

// findLibrary is the virtual path the loader would load for a DT_NEEDED entry, or "". The loader
// satisfies its own soname without a search; a name with a slash is loaded as a path; otherwise
// glibc's search: RPATH (with those inherited) unless there is a RUNPATH, then RUNPATH, the cache
// and the default directories.
func findLibrary(s *search, name string, e *elfFile, vpath string, rpaths []string) string {
	if s.interp != nil && name == basenameOf(*s.interp) {
		if r := treeResolve(s.root, *s.interp, true, nil); r != "" {
			return r
		}
	}
	if strings.Contains(name, "/") { // glibc expands the tokens in a path first (dl-load.c); musl does not
		use := name
		if s.interp != nil && !strings.Contains(basenameOf(*s.interp), "musl") {
			use = normpath(expand(name, dirnameOf(vpath)))
		}
		if strings.HasPrefix(use, "/") {
			return treeResolve(s.root, use, true, nil)
		}
		return ""
	}
	origin := dirnameOf(vpath)
	var dirs []string
	if e.runpath == nil {
		if e.rpath != nil {
			splitAdd(&dirs, *e.rpath, origin)
		}
		for _, r := range rpaths {
			splitAdd(&dirs, r, origin)
		}
	} else {
		splitAdd(&dirs, *e.runpath, origin)
	}
	hit := func(d string) {
		if s.hostHits != nil && hostOwned(normpath(d), s.own) {
			*s.hostHits = append(*s.hostHits, d)
		}
	}
	for _, d := range dirs {
		hit(d)
		if found := searchDir(s.root, d, name); found != "" {
			return found
		}
	}
	for _, c := range s.cache {
		if c.soname != name {
			continue
		}
		if r := treeResolve(s.root, c.path, true, nil); r != "" && isPayloadFile(s.root, r) {
			return r
		}
	}
	for _, d := range s.defaults {
		hit(d)
		if found := searchDir(s.root, d, name); found != "" {
			return found
		}
	}
	return ""
}

// ---------------------------------------------------------------- the loader's own directories

// dirsRun is the first run of two or more NUL-terminated strings spelt /.../ in data, each ending
// in a slash, without the trailing slash; none when there is no such run.
func dirsRun(data []byte) []string {
	at, runFrom, run := 0, 0, 0
	for at < len(data) {
		k := bytes.IndexByte(data[at:], 0)
		if k < 0 {
			k = len(data) - at
		}
		if k >= 2 && data[at] == '/' && data[at+k-1] == '/' {
			if run == 0 {
				runFrom = at
			}
			run++
		} else if run >= 2 {
			break
		} else {
			run = 0
		}
		at += k + 1
	}
	if run < 2 {
		return nil
	}
	var out []string
	for i, left := runFrom, run; left > 0; left-- {
		k := bytes.IndexByte(data[i:], 0)
		if k < 0 {
			k = len(data) - i
		}
		v := string(data[i : i+k])
		for len(v) > 1 && v[len(v)-1] == '/' {
			v = v[:len(v)-1]
		}
		out = append(out, v)
		i += k + 1
	}
	return out
}

// dirsTable finds the table in an ELF file's read-only data: its allocated sections that are
// neither code nor writable, in file order, so that a string is one a section holds and not the
// tail of the code before it; a file without section headers is read whole.
func dirsTable(data []byte) []string {
	n := uint64(len(data))
	if n < 64 || string(data[:4]) != "\x7fELF" || (data[4] != 1 && data[4] != 2) {
		return dirsRun(data)
	}
	cls := data[4]
	f := func(off32, n32, off64, n64 int) uint64 {
		if cls == 1 {
			return le(data[off32:], n32)
		}
		return le(data[off64:], n64)
	}
	shoff, shentsize, shnum := f(32, 4, 40, 8), f(46, 2, 58, 2), f(48, 2, 60, 2)
	var found []string
	seen := 0
	entsz := uint64(64)
	if cls == 1 {
		entsz = 40
	}
	for i := uint64(0); i < shnum && found == nil; i++ {
		// the header's place, checked without overflow: shoff and i*shentsize each within the file first
		if shoff > n || i*shentsize > n-shoff || n-shoff-i*shentsize < entsz {
			break
		}
		o := shoff + i*shentsize
		kind := le(data[o+4:], 4)
		var flags, off, size uint64
		if cls == 1 {
			flags, off, size = le(data[o+8:], 4), le(data[o+16:], 4), le(data[o+20:], 4)
		} else {
			flags, off, size = le(data[o+8:], 8), le(data[o+24:], 8), le(data[o+32:], 8)
		}
		// SHT_PROGBITS, SHF_ALLOC, neither SHF_EXECINSTR nor SHF_WRITE
		if kind != 1 || flags&2 == 0 || flags&5 != 0 || off > n || size > n-off {
			continue
		}
		seen++
		found = dirsRun(data[off : off+size])
	}
	if seen == 0 {
		return dirsRun(data)
	}
	return found
}

// loaderDirs reads the default search directories of the tree's loader from the loader file:
// glibc's build writes them into the loader as a table of consecutive strings, each `/.../`, the
// same table `--list-diagnostics` prints as path.system_dirs; musl's are fixed. Nothing of the
// tree runs, so a loader of another machine is read like this one's (10.3). The loader read is
// the file PT_INTERP names in the tree, never a host file an absolute link names. Returns the
// reason when the directories were assumed instead: Debian's and Fedora's defaults, for a loader
// without the table.
func loaderDirs(root string, interp *string) ([]string, string) {
	if interp == nil {
		return defaultDirs(), ""
	}
	if strings.Contains(basenameOf(*interp), "musl") {
		return []string{"/lib", "/usr/local/lib", "/usr/lib"}, ""
	}
	r := treeResolve(root, *interp, true, nil)
	if r == "" {
		r = *interp
	}
	loader := treePayload(root, r)
	var data []byte
	if st, err := os.Stat(loader); err == nil && st.Mode().IsRegular() {
		data = readFile(loader)
	}
	if out := dirsTable(data); len(out) > 0 {
		return out, ""
	}
	out := defaultDirs()
	return out, "the loader " + *interp + " carries no table of search directories (not glibc's?): " +
		strings.Join(out, ":") + " assumed"
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// digits parses the decimal number at data[t:] as the C read it, strtol's long saturating at its
// largest and then cast to int, and says where it ends.
func digits(data []byte, t int) (int, int) {
	var v int64
	end := t
	for end < len(data) && isDigit(data[end]) {
		if d := int64(data[end] - '0'); v > (math.MaxInt64-d)/10 {
			v = math.MaxInt64
		} else {
			v = v*10 + d
		}
		end++
	}
	return int(int32(v)), end
}

// glibcVersion is the major and minor version libc.so.6's banner names, found in the default
// directories: GNU C Library (...) [WORD ]release version M.N, the first such banner.
func glibcVersion(root string) (int, int, bool) {
	for _, d := range defaultDirs() {
		r := treeResolve(root, pathJoin(d, "libc.so.6"), true, nil)
		if r == "" || !isPayloadFile(root, r) {
			continue
		}
		data := readFile(treePayload(root, r))
		n := len(data)
		const lead, rv = "GNU C Library (", "release version "
		for c := 0; ; {
			i := bytes.Index(data[c:], []byte(lead))
			if i < 0 {
				break
			}
			c += i + len(lead)
			q := c
			for q < n && data[q] != ')' {
				q++
			}
			t := q + 1
			if q >= n || t >= n || data[t] != ' ' {
				continue
			}
			t++
			w := t
			for w < n && (isAlnum(data[w]) || data[w] == '_') {
				w++
			}
			if w > t && w < n && data[w] == ' ' && n-(w+1) >= len(rv) && string(data[w+1:w+1+len(rv)]) == rv {
				t = w + 1
			}
			if n-t < len(rv) || string(data[t:t+len(rv)]) != rv {
				continue
			}
			t += len(rv)
			a, end := digits(data, t)
			if end == t || end+1 >= n || data[end] != '.' || !isDigit(data[end+1]) {
				continue
			}
			b, _ := digits(data, end+1)
			return a, b, true
		}
	}
	return 0, 0, false
}
