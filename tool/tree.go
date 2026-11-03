// An exclave's tree on disk: the refusal of a directory that is none, the tree hash, and the
// walks over its entries (DESIGN.md 6.1, 6.4).

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

// requireExclave refuses ex before anything is read or written unless it holds tree/, and
// .exclave/ too for every command but wrap; a wrapped exclave's launcher names its machine.
func requireExclave(ex, cmd string) {
	hasExclave := isDir(pathJoin(ex, ".exclave"))
	// a can, an exclave in the layout from before the project's rename, is named as one (13 item 45)
	if isDir(pathJoin(ex, ".can")) && !hasExclave {
		fail("refusing: %s is a can, an exclave from before the rename, with .can/ and root/; convert it first "+
			"(docs/DESIGN.md 13 item 45)", ex)
	}
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

// a file's contents to hash, for the entry at index e
type hashJob struct {
	path string
	e    int
	hex  string
	err  error
}

type hashEntry struct {
	rel, kind string
	job       int // the job hashing its contents, or -1
}

type hashing struct {
	entries []hashEntry
	jobs    []hashJob
}

func unreadable(p string, err error) {
	if isErrno(err, syscall.EACCES) {
		fail("cannot read %s: the tree hash needs every file readable", p)
	}
	failErrno(p, err)
}

// hashFile is the BLAKE2b-256 of a file's contents as lowercase hex, or the error of a failed read.
func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h, _ := blake2b.New256(nil)
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// hashAll hashes the files' contents on several goroutines, each taking the next job, after the
// walk has listed them in order; each writes only its own job, so the listing, and the hash of it,
// are the walk's alone. The first file the walk listed that could not be read is named, as a
// serial hash would name it.
func (h *hashing) hashAll() {
	n := min(max(runtime.NumCPU(), 1), 8, max(len(h.jobs), 1))
	var next atomic.Int64
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			for {
				i := int(next.Add(1) - 1)
				if i >= len(h.jobs) {
					return
				}
				h.jobs[i].hex, h.jobs[i].err = hashFile(h.jobs[i].path)
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
		original := pathJoin(path.Dir(real), ".real/"+path.Base(real))
		if _, err := stat(original); err != nil {
			original = real
		}
		h.jobs = append(h.jobs, hashJob{path: original, e: len(h.entries)})
		h.entries = append(h.entries, hashEntry{rel, k, len(h.jobs) - 1})
	}
}

// walk lists every entry under real, a directory; .real/ directories are not listed, but a .real/
// file without a wrapper beside it is, under its own path, so that no file goes unhashed.
func (h *hashing) walk(real, rel string) {
	names, err := dirNames(real)
	if err != nil {
		unreadable(real, err)
	}
	var subdirs []string
	hasReal := false
	for _, name := range names {
		p, r := pathJoin(real, name), relJoin(rel, name)
		st, err := lstat(p)
		if err != nil {
			failErrno(p, err)
		}
		if name == ".real" && isDir(p) {
			hasReal = true
			continue
		}
		h.addEntry(r, p, &st)
		if isDirM(&st) {
			subdirs = append(subdirs, name)
		}
	}
	if hasReal {
		dotReal := pathJoin(real, ".real")
		names, err := dirNames(dotReal)
		if err != nil {
			unreadable(dotReal, err)
		}
		for _, name := range names {
			if _, err := lstat(pathJoin(real, name)); err == nil || !isErrno(err, syscall.ENOENT) {
				continue
			}
			p := pathJoin(dotReal, name)
			st, err := lstat(p)
			if err != nil {
				failErrno(p, err)
			}
			h.addEntry(relJoin(relJoin(rel, ".real"), name), p, &st)
		}
	}
	for _, name := range subdirs {
		h.walk(pathJoin(real, name), relJoin(rel, name))
	}
}

// treeHash is 6.4's hash of the tree at root, "b2:" and hex.
func treeHash(root string) string {
	var h hashing
	h.walk(root, "")
	h.hashAll()
	lines := make([][]byte, len(h.entries))
	for i, e := range h.entries {
		text := e.rel + "\x00" + e.kind
		if e.job >= 0 {
			text += h.jobs[e.job].hex
		}
		lines[i] = []byte(text + "\x00")
	}
	sort.Slice(lines, func(i, j int) bool { return bytes.Compare(lines[i], lines[j]) < 0 })
	d, _ := blake2b.New256(nil)
	for _, l := range lines {
		d.Write(l)
	}
	return "b2:" + fmt.Sprintf("%x", d.Sum(nil))
}

// ---------------------------------------------------------------- walks

// dirNames is a directory's entries' names, sorted by their bytes.
func dirNames(p string) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

// An entryInfo is a directory's entry: its name, its lstat (zero when it cannot be read), and
// whether it is a directory as a walk counts one, a link to a directory included.
type entryInfo struct {
	name  string
	st    unix.Stat_t
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

func walkDirsAt(dir, rel string, bottomUp bool, fn walkFn) {
	e, err := listDir(dir)
	if err != nil { // unreadable: skipped with what is beneath it
		return
	}
	if !bottomUp {
		fn(dir, rel, e)
	}
	for i := range e {
		if e[i].isDir && !isLnk(&e[i].st) {
			walkDirsAt(pathJoin(dir, e[i].name), relJoin(rel, e[i].name), bottomUp, fn)
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
func walkDirs(root string, bottomUp bool, fn walkFn) { walkDirsAt(root, "", bottomUp, fn) }

func isRealDir(dir string) bool { return path.Base(dir) == ".real" }

// strays lists every file in a .real/ directory with no wrapper beside it, as /PATH from root (6.1).
func strays(root string) []string {
	var out []string
	walkDirs(root, false, func(dir, rel string, e []entryInfo) {
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

func walkFilesAt(dir, rel string, fn fileFn) {
	e, err := listDir(dir)
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
		walkFilesAt(pathJoin(dir, e[i].name), relJoin(rel, e[i].name), fn)
	}
}

// walkFiles calls fn for every entry under root but a directory, a link to one included, as
// (real path, virtual path, lstat): each directory's entries in the order of their bytes, before
// the directories below it, .real/ directories aside.
func walkFiles(root string, fn fileFn) { walkFilesAt(root, "", fn) }
