// An exclave's tree on disk: the refusal of a directory that is none, the tree hash, and the
// walks over its entries (DESIGN.md 6.1, 6.4).

package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
	"lukechampine.com/blake3"

	"exclave/tool/format"
)

// requireExclave refuses ex before anything is read or written unless it holds tree/, and
// .exclave/ too for every command but wrap; a wrapped exclave's launcher names its machine.
func requireExclave(ex, cmd string) {
	hasExclave := isDir(pathJoin(ex, ".exclave"))
	if !isDir(pathJoin(ex, "tree")) {
		fail("refusing: %s has no tree/ directory", ex)
	}
	if cmd != "wrap" && !hasExclave {
		fail("refusing: %s has no .exclave/ directory; wrap makes one", ex)
	}
	if hasExclave {
		machineOfLauncher(ex)
	}
}

func isReg(st *unix.Stat_t) bool  { return st.Mode&unix.S_IFMT == unix.S_IFREG }
func isLnk(st *unix.Stat_t) bool  { return st.Mode&unix.S_IFMT == unix.S_IFLNK }
func isDirM(st *unix.Stat_t) bool { return st.Mode&unix.S_IFMT == unix.S_IFDIR }

// lstat is the file's own status, a link's rather than its target's.
func lstat(p string) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Lstat(p, &st)
	return st, err
}

// stat is the file's status through a link.
func stat(p string) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Stat(p, &st)
	return st, err
}

// ---------------------------------------------------------------- the tree hash (6.4)

// a file's contents to hash, for the entry at index e: its size orders the work, and whether it
// begins with the ELF magic spares the static check an open of every file that does not
type hashJob struct {
	path string
	e    int
	size int64
	hex  string
	elf  bool
	err  error
}

type hashEntry struct {
	rel, kind string
	job       int // the job hashing its contents, or -1
}

type hashing struct {
	l       *listing
	entries []hashEntry
	jobs    []hashJob
}

func unreadable(p string, err error) {
	if isErrno(err, syscall.EACCES) {
		fail("cannot read %s: the tree hash needs every file readable", p)
	}
	failErrno(p, err)
}

// hashFile hashes a job's file with buf, the worker's own: the BLAKE3-256 of its contents as
// lowercase hex, whether its first four bytes are the ELF magic, or the error of a failed read.
func hashFile(j *hashJob, buf []byte) {
	fd, err := retryEINTR(func() (int, error) { return unix.Open(j.path, unix.O_RDONLY|unix.O_CLOEXEC, 0) })
	if err != nil {
		j.err = err
		return
	}
	defer unix.Close(fd)
	h := blake3.New(32, nil) // each write of buf hashed on several goroutines, in pieces of 16 KB
	var head [4]byte
	k := 0
	for {
		n, err := retryEINTR(func() (int, error) { return unix.Read(fd, buf) })
		if err != nil {
			j.err = err
			return
		}
		if n == 0 {
			break
		}
		k += copy(head[k:], buf[:n])
		h.Write(buf[:n])
	}
	var d [32]byte
	j.hex, j.elf = hex.EncodeToString(h.Sum(d[:0])), k == 4 && string(head[:]) == "\x7fELF"
}

// retryEINTR is a system call made again when a signal interrupted it, as the os package does.
func retryEINTR(call func() (int, error)) (int, error) {
	for {
		n, err := call()
		if err != syscall.EINTR {
			return n, err
		}
	}
}

// threads is how many goroutines a walk or the hashing uses, and how many threads run Go at once
// (main): the machine's threads, at most eight, since the machine may be in use beside the
// command.
func threads() int { return min(max(runtime.NumCPU(), 1), 8) }

// hashAll hashes the files' contents on several goroutines after the walk has listed them in
// order, the largest first so that no large file starts last and holds up the end; each job is
// written only by the goroutine that took it, so the listing, and the hash of it, are the walk's
// alone. The first file the walk listed that could not be read is named, as a serial hash would
// name it; the walk is in the order of the names' bytes, so the file named is the same on every
// filesystem.
func (h *hashing) hashAll() {
	order := make([]int, len(h.jobs))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return h.jobs[order[a]].size > h.jobs[order[b]].size })
	var next atomic.Int64
	var wg sync.WaitGroup
	for range min(threads(), max(len(h.jobs), 1)) {
		wg.Go(func() {
			buf := make([]byte, 1<<20)
			for {
				i := int(next.Add(1) - 1)
				if i >= len(order) {
					return
				}
				hashFile(&h.jobs[order[i]], buf)
			}
		})
	}
	wg.Wait()
	for _, j := range h.jobs {
		if j.err != nil {
			unreadable(j.path, j.err)
		}
	}
}

// addEntry lists one entry: path, NUL, kind, NUL, what the kind records, NUL. A regular file
// stands for its original in .real/ when it has one, so a wrapper is hashed with the program it
// runs and its own mode. Sockets, pipes and devices are not in the hash.
func (h *hashing) addEntry(rel, real string, st *unix.Stat_t) {
	switch {
	case isLnk(st):
		target, err := os.Readlink(real)
		if err != nil {
			failErrno(real, err)
		}
		h.entries = append(h.entries, hashEntry{rel, "l\x00" + target, -1})
	case isDirM(st):
		h.entries = append(h.entries, hashEntry{rel, "d\x00", -1})
	case isReg(st):
		k := "f\x00"
		if st.Mode&0o111 != 0 {
			k = "x\x00"
		}
		p, size := h.l.payload(real), st.Size
		if p != real {
			if pst, err := lstat(p); err == nil {
				size = pst.Size // the original's, which is what is read
			}
		}
		h.jobs = append(h.jobs, hashJob{path: p, e: len(h.entries), size: size})
		h.entries = append(h.entries, hashEntry{rel, k, len(h.jobs) - 1})
	}
}

// walk lists every entry under real, a directory, from the listing; .real/ directories are not
// listed, but a .real/ file without a wrapper beside it is, under its own path, so that no file
// goes unhashed. The first entry that cannot be read, in this order, is named.
func (h *hashing) walk(real, rel string) {
	e, err := h.l.list(real)
	if err != nil {
		unreadable(real, err)
	}
	var subdirs []string
	hasReal := false
	for i := range e {
		p, r := pathJoin(real, e[i].name), relJoin(rel, e[i].name)
		if e[i].err != nil {
			failErrno(p, e[i].err)
		}
		if e[i].name == ".real" && e[i].isDir {
			hasReal = true
			continue
		}
		h.addEntry(r, p, &e[i].st)
		if isDirM(&e[i].st) {
			subdirs = append(subdirs, e[i].name)
		}
	}
	if hasReal {
		dotReal := pathJoin(real, ".real")
		re, err := h.l.list(dotReal)
		if err != nil {
			unreadable(dotReal, err)
		}
		for i := range re {
			if hasName(e, re[i].name) { // a wrapper's original, or anything else by its name
				continue
			}
			p := pathJoin(dotReal, re[i].name)
			if re[i].err != nil {
				failErrno(p, re[i].err)
			}
			h.addEntry(relJoin(relJoin(rel, ".real"), re[i].name), p, &re[i].st)
		}
	}
	for _, name := range subdirs {
		h.walk(pathJoin(real, name), relJoin(rel, name))
	}
}

// treeHash is 6.4's hash of the tree at root, "b3:" and hex.
func treeHash(root string) string { return listTree(root).treeHash(root) }

// treeHash is 6.4's hash of the tree at root from the listing; it notes for the static check
// which files begin with the ELF magic.
func (l *listing) treeHash(root string) string {
	h := hashing{l: l}
	h.walk(root, "")
	h.hashAll()
	lines := make([][]byte, len(h.entries))
	l.elf = make(map[string]bool, len(h.jobs))
	for i, e := range h.entries {
		text := e.rel + "\x00" + e.kind
		if e.job >= 0 {
			text += h.jobs[e.job].hex
			l.elf["/"+e.rel] = h.jobs[e.job].elf
		}
		lines[i] = []byte(text + "\x00")
	}
	sort.Slice(lines, func(i, j int) bool { return bytes.Compare(lines[i], lines[j]) < 0 })
	d := blake3.New(32, nil)
	for _, l := range lines {
		d.Write(l)
	}
	return format.DigestText(d.Sum(nil))
}

// ---------------------------------------------------------------- the listing

// A listing is every directory of a tree listed once, on several goroutines, for the commands
// that read the tree several times over without changing it: check, and wrap before it wraps.
// Each pass then walks it in the order a walk of the disk would take, and gives the same answers;
// a directory the listing does not hold is listed from the disk. A nil listing is the disk's.
type listing struct {
	dirs map[string]listed
	elf  map[string]bool // by virtual path, the files the tree hash read: whether each is ELF
}

type listed struct {
	e   []entryInfo
	err error
}

// listTree lists root and every directory below it that is one, not a link to one, .real/ ones
// included.
func listTree(root string) *listing {
	l := &listing{dirs: map[string]listed{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, threads()-1)
	var visit func(dir string)
	visit = func(dir string) {
		e, err := listDir(dir)
		mu.Lock()
		l.dirs[dir] = listed{e, err}
		mu.Unlock()
		for i := range e {
			if !e[i].isDir || isLnk(&e[i].st) {
				continue
			}
			sub := pathJoin(dir, e[i].name)
			select {
			case slots <- struct{}{}:
				wg.Go(func() {
					visit(sub)
					<-slots
				})
			default:
				visit(sub)
			}
		}
	}
	visit(root)
	wg.Wait()
	return l
}

// list is a directory's entries as listDir gives them.
func (l *listing) list(dir string) ([]entryInfo, error) {
	if l != nil {
		if d, ok := l.dirs[dir]; ok {
			return d.e, d.err
		}
	}
	return listDir(dir)
}

// payload is payloadPath's answer: where the directory holds no .real, there is no original to
// look for.
func (l *listing) payload(real string) string {
	if l != nil {
		slash := strings.LastIndexByte(real, '/')
		if d, ok := l.dirs[real[:max(slash, 0)]]; ok && d.err == nil && !hasName(d.e, ".real") {
			return real
		}
	}
	return payloadPath(real)
}

// isELF reports, for a file the tree hash read, whether it begins with the ELF magic; ok is false
// for any other.
func (l *listing) isELF(vpath string) (elf, ok bool) {
	if l == nil {
		return false, false
	}
	elf, ok = l.elf[vpath]
	return elf, ok
}

// hasName reports whether a directory's sorted entries hold name.
func hasName(e []entryInfo, name string) bool {
	i := sort.Search(len(e), func(i int) bool { return e[i].name >= name })
	return i < len(e) && e[i].name == name
}

// ---------------------------------------------------------------- walks

// dirNames is a directory's entries' names, sorted by their bytes. The open is opendir's, a
// directory or ENOTDIR, so a FIFO or a device under a directory's name does not block it.
func dirNames(p string) ([]string, error) {
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

// An entryInfo is a directory's entry: its name, its lstat (zero when it cannot be read, err
// saying why), and whether it is a directory as a walk counts one, a link to a directory included.
type entryInfo struct {
	name  string
	st    unix.Stat_t
	err   error
	isDir bool
}

// listDir is a directory's entries, sorted by their bytes, or the error of reading it.
func listDir(p string) ([]entryInfo, error) {
	names, err := dirNames(p)
	if err != nil {
		return nil, err
	}
	out := make([]entryInfo, 0, len(names))
	for _, name := range names {
		e := entryInfo{name: name}
		full := pathJoin(p, name)
		if st, err := lstat(full); err == nil {
			e.st = st
		} else {
			e.err = err
		}
		if isDirM(&e.st) {
			e.isDir = true
		} else if isLnk(&e.st) {
			if st, err := stat(full); err == nil && isDirM(&st) {
				e.isDir = true
			}
		}
		out = append(out, e)
	}
	return out, nil
}

func relJoin(rel, name string) string {
	if rel == "" {
		return name
	}
	return rel + "/" + name
}

type walkFn func(dir, rel string, e []entryInfo)

func (l *listing) walkDirsAt(dir, rel string, bottomUp bool, fn walkFn) {
	e, err := l.list(dir)
	if err != nil { // unreadable: skipped with what is beneath it
		return
	}
	if !bottomUp {
		fn(dir, rel, e)
	}
	for i := range e {
		if e[i].isDir && !isLnk(&e[i].st) {
			l.walkDirsAt(pathJoin(dir, e[i].name), relJoin(rel, e[i].name), bottomUp, fn)
		}
	}
	if bottomUp {
		// the listing again: what the walk below moved has changed it
		if e, err = listDir(dir); err != nil {
			return
		}
		fn(dir, rel, e)
	}
}

// walkDirs calls fn for every directory under root with its own entries sorted, top-down or
// bottom-up: a link to a directory is listed and not descended, and a directory that cannot be
// read is passed over with everything beneath it. rel is the directory's path from root, "" for
// root itself.
func walkDirs(root string, bottomUp bool, fn walkFn) {
	(*listing)(nil).walkDirsAt(root, "", bottomUp, fn)
}

func isRealDir(dir string) bool { return path.Base(dir) == ".real" }

// strays lists every file in a .real/ directory with no wrapper beside it, as /PATH from root (6.1).
func strays(root string) []string { return (*listing)(nil).strays(root) }

// strays is strays from the listing; a bottom-up walk lists the disk again, so only a top-down
// one reads a listing.
func (l *listing) strays(root string) []string {
	var out []string
	l.walkDirsAt(root, "", false, func(dir, rel string, e []entryInfo) {
		if !isRealDir(dir) {
			return
		}
		parent := dir[:len(dir)-len("/.real")]
		for i := range e {
			if e[i].isDir {
				continue
			}
			if !lexists(pathJoin(parent, e[i].name)) {
				out = append(out, "/"+relJoin(rel, e[i].name))
			}
		}
	})
	return out
}

type fileFn func(real, v string, st *unix.Stat_t)

func (l *listing) walkFilesAt(dir, rel string, fn fileFn) {
	e, err := l.list(dir)
	if err != nil { // unreadable: passed over with what is beneath it
		return
	}
	for i := range e {
		if e[i].isDir && (e[i].name == ".real" || !isLnk(&e[i].st)) {
			continue
		}
		r := relJoin(rel, e[i].name)
		fn(pathJoin(dir, e[i].name), "/"+r, &e[i].st)
	}
	for i := range e {
		if !e[i].isDir || isLnk(&e[i].st) || e[i].name == ".real" {
			continue
		}
		l.walkFilesAt(pathJoin(dir, e[i].name), relJoin(rel, e[i].name), fn)
	}
}

// walkFiles calls fn for every entry under root but a directory, a link to one included, as
// (real path, virtual path, lstat): each directory's entries in the order of their bytes, before
// the directories below it, .real/ directories aside.
func walkFiles(root string, fn fileFn) { (*listing)(nil).walkFiles(root, fn) }

// walkFiles is walkFiles from the listing.
func (l *listing) walkFiles(root string, fn fileFn) { l.walkFilesAt(root, "", fn) }
