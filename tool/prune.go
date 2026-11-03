// The exclave pruned to what logged workloads touched (DESIGN.md 10.4).

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// A uniq holds distinct strings in the order added, with an index.
type uniq struct {
	list  []string
	index map[string]bool
}

func (u *uniq) add(s string) bool {
	if u.index == nil {
		u.index = map[string]bool{}
	}
	if u.index[s] {
		return false
	}
	u.index[s] = true
	u.list = append(u.list, s)
	return true
}

func (u *uniq) has(s string) bool { return u.index[s] }

// licenceFilesAt lists every file below dir, as virtual paths.
func licenceFilesAt(dir, rel string, out *[]string) {
	e, err := listDir(dir)
	if err != nil {
		return
	}
	for i := range e {
		if !e[i].isDir {
			*out = append(*out, "/"+relJoin(rel, e[i].name))
		}
	}
	for i := range e {
		if e[i].isDir && !isLnk(&e[i].st) {
			licenceFilesAt(pathJoin(dir, e[i].name), relJoin(rel, e[i].name), out)
		}
	}
}

// findShares lists the virtual paths of the packages' licence texts, which prune keeps: under
// every usr/share/ of the tree, a data directory's included, Debian's doc/PKG/copyright and every
// file under common-licenses/ and licenses/, where RPM's %license files and Alpine's -doc packages
// put theirs.
func findShares(dir, rel string, out *[]string) {
	e, err := listDir(dir)
	if err != nil {
		return
	}
	isShare := basenameOf(dir) == "share" && rel != "" && basenameOf(dirnameOf(dir)) == "usr"
	if !isShare {
		for i := range e {
			if e[i].isDir && !isLnk(&e[i].st) {
				findShares(pathJoin(dir, e[i].name), relJoin(rel, e[i].name), out)
			}
		}
		return
	}
	// below a usr/share/, only its licence texts
	doc := pathJoin(dir, "doc")
	if pk, err := listDir(doc); err == nil {
		for i := range pk {
			if pk[i].name[0] == '.' {
				continue
			}
			if lexists(pathJoin(pathJoin(doc, pk[i].name), "copyright")) {
				*out = append(*out, fmt.Sprintf("/%s/doc/%s/copyright", rel, pk[i].name))
			}
		}
	}
	for _, top := range []string{"common-licenses", "licenses"} {
		licenceFilesAt(pathJoin(dir, top), relJoin(rel, top), out)
	}
}

// ---------------------------------------------------------------- the libraries kept ELF files need

type closure struct {
	s    *search
	seen map[string]bool
	out  *uniq
}

func (c *closure) visit(vpath string, e *elfFile, rpaths []string) {
	key := vpath + "\n\x01" + strings.Join(rpaths, "\n\x01")
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	if e.interp != nil {
		c.out.add(*e.interp)
	}
	var below []string
	if e.runpath == nil && e.rpath != nil {
		below = append(below, *e.rpath)
	}
	below = append(below, rpaths...)
	for _, n := range e.needed {
		found := findLibrary(c.s, n, e, vpath, rpaths)
		if found == "" {
			continue
		}
		c.out.add(found)
		if fe, rc, _, _ := elfRead(treePayload(c.s.root, found)); rc == elfOK {
			c.visit(found, fe, below)
		}
	}
}

// neededClosure lists every library the given ELF files reach through DT_NEEDED, each found by the
// loader's search with RPATHs inherited down the chain, and each loader the files name, since the
// launcher loads it and no logged call does (10.4).
func neededClosure(root string, elfs []string) *uniq {
	cache, hasCache := readCache(root)
	var interp *string
	for _, v := range elfs {
		if e, rc, _, _ := elfRead(treePayload(root, v)); rc == elfOK && e.interp != nil {
			interp = e.interp
			break
		}
	}
	defaults, _ := loaderDirs(root, interp)
	if !hasCache {
		cache = nil
	}
	c := closure{&search{root: root, cache: cache, defaults: defaults, interp: interp}, map[string]bool{}, &uniq{}}
	for _, v := range elfs {
		if e, rc, _, _ := elfRead(treePayload(root, v)); rc == elfOK {
			c.visit(v, e, nil)
		}
	}
	return c.out
}

// ---------------------------------------------------------------- prune

// cmdPrune prunes the tree to what the logged workloads touched: the files they touched, the
// entries of directories they opened, the symlink chains that reach kept files, the libraries
// kept ELF files need, the identity files and the licence texts. Directories are never removed,
// so ownership and ls do not change. Then the static check runs on what is left.
func cmdPrune(args []string) int {
	if len(args) < 2 {
		usage("prune EXCLAVE LOG...")
	}
	ex := args[0]
	requireExclave(ex, "prune")
	own := ownershipOf(ex)
	root := pathJoin(ex, "tree")
	var keep, whole uniq
	programs := 0
	for _, l := range args[1:] {
		for _, x := range readLogs(l) {
			if x.what == "launcher" || !strings.HasPrefix(x.path, "/") || x.result < 0 || hostOwned(x.path, own) {
				continue
			}
			var links []string
			final := treeResolve(root, x.path, true, &links)
			for _, k := range links {
				keep.add(k)
			}
			if final == "" {
				continue
			}
			if st, err := os.Stat(treeReal(root, final)); err == nil && st.IsDir() {
				if x.what == "open" { // a directory opened may be listed
					whole.add(final)
				}
			} else {
				keep.add(final)
				if x.what == "exec" || x.what == "load" {
					programs++
				}
			}
		}
	}
	if programs == 0 {
		fail("the logs name no program in this exclave; nothing to prune to")
	}
	for _, f := range append(append([]string(nil), identityFiles...), "/etc/ld.so.cache") {
		if lexists(treeReal(root, f)) {
			keep.add(f)
		}
	}
	var licences []string // the packages' licence texts go with every copy
	findShares(root, "", &licences)
	for _, v := range licences {
		var links []string
		final := treeResolve(root, v, true, &links)
		for _, k := range links {
			keep.add(k)
		}
		if final != "" {
			keep.add(final)
		}
	}
	for _, d := range whole.list { // its own entries: a getdents shows names, nothing below them
		e, err := listDir(treeReal(root, d))
		if err != nil {
			failErrno(treeReal(root, d), err)
		}
		for i := range e {
			if !e[i].isDir || isLnk(&e[i].st) {
				keep.add(pathJoin(d, e[i].name))
			}
		}
	}
	// the libraries every kept ELF needs, by the loader's own search (10.3)
	sorted := append([]string(nil), keep.list...)
	sort.Strings(sorted)
	var elfs []string
	for _, v := range sorted {
		st, err := lstat(treeReal(root, v))
		if err != nil || !isReg(&st) || strings.Contains(v, "/.real/") {
			continue
		}
		pay := treePayload(root, v)
		f, err := os.Open(pay)
		if err != nil {
			failErrno(pay, err)
		}
		head := make([]byte, 4)
		if k, _ := f.Read(head); k == 4 && string(head) == "\x7fELF" {
			elfs = append(elfs, v)
		}
		f.Close()
	}
	for _, v := range neededClosure(root, elfs).list { // the chain of links, then the file they reach
		var links []string
		final := treeResolve(root, v, true, &links)
		for _, k := range links {
			keep.add(k)
		}
		if final != "" {
			keep.add(final)
		}
	}
	// the log names canonical paths, so every alias a program used is a symlink to keep: every
	// symlink that reaches a kept file, or a directory, stays with its chain
	walkFiles(root, func(_, v string, st *unix.Stat_t) {
		if !isLnk(st) || keep.has(v) {
			return
		}
		var chain []string
		final := treeResolve(root, v, true, &chain)
		if final == "" {
			return
		}
		fst, err := os.Stat(treeReal(root, final))
		if keep.has(final) || (err == nil && fst.IsDir()) {
			for _, k := range chain {
				keep.add(k)
			}
			keep.add(v)
		}
	})
	shortcuts := resolvingShortcuts(ex)
	kept, removed := 0, 0
	var freed uint64
	walkDirs(root, false, func(dir, rel string, e []entryInfo) {
		inReal := isRealDir(dir)
		parentRel := rel
		if inReal {
			parentRel = dirnameOf(rel)
		}
		for i := range e {
			if e[i].isDir && !isLnk(&e[i].st) {
				continue
			}
			real := pathJoin(dir, e[i].name)
			if keep.has("/" + relJoin(parentRel, e[i].name)) {
				kept++
				continue
			}
			// originals and plain files; a wrapper is a link to the launcher
			_, err := os.Stat(pathJoin(pathJoin(dir, ".real"), e[i].name))
			isWrap := !inReal && err == nil
			if isReg(&e[i].st) && !isWrap {
				freed += uint64(e[i].st.Size)
			}
			if err := unix.Unlink(real); err != nil {
				failErrno(real, err)
			}
			removed++
		}
	})
	for _, name := range shortcuts { // a shortcut to a file the workloads never touched goes with its file
		if p := pathJoin(ex, name); !reaches(p) {
			if err := unix.Unlink(p); err != nil {
				failErrno(p, err)
			}
			fmt.Fprintf(out, "removed the shortcut %s: no workload touched its file\n", name)
		}
	}
	fmt.Fprintf(out, "pruned %s: kept %d files, removed %d, %d bytes freed\n", ex, kept, removed, freed)
	if hasTreeRecord(ex) {
		writeHashes(ex, "", false, true)
	}
	if staticReport(ex, nil) > 0 {
		return 1
	}
	return 0
}

// resolvingShortcuts are the exclave's top-level symlinks that reach a file, in the order of their bytes.
func resolvingShortcuts(ex string) []string {
	names, err := dirNames(ex)
	if err != nil {
		failErrno(ex, err)
	}
	var out []string
	for _, name := range names {
		p := pathJoin(ex, name)
		if st, err := lstat(p); err == nil && isLnk(&st) && reaches(p) {
			out = append(out, name)
		}
	}
	return out
}

// reaches reports whether path reaches a file, through its links.
func reaches(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
