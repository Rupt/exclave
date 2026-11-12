// An exclave's files beside its tree, the launcher, the README and the hashes file, and the
// commands that move wrappers and originals: wrap, unwrap and relink (DESIGN.md 6.1, 6.4, 10.1).

package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"exclave/tool/format"
)

func writeReadme(ex string) {
	if p := pathJoin(ex, "README"); !lexists(p) {
		writeFile(p, readmeBlob, 0o666)
	}
}

func loadHashes(p string) []format.Record {
	rs, err := format.Parse(readFile(p), format.Hashes)
	if err != nil {
		failGrammar(err)
	}
	return rs
}

func find(rs []format.Record, key string) *format.Record {
	for i := range rs {
		if rs[i].Key == key {
			return &rs[i]
		}
	}
	return nil
}

func hasTreeRecord(ex string) bool {
	p := pathJoin(ex, ".exclave/hashes")
	return lexists(p) && find(loadHashes(p), "tree") != nil
}

// The hashes file has three states, each written by the command that makes it. An unwrapped
// exclave records its packages alone (recordUnwrapped); a wrapped one its launcher, its manifest
// and its tree too (recordWrapped); and a wrapped one whose launcher or tree a command changed
// records them anew and keeps its manifest record as it stands (recordAgain), which says nothing
// of an exclave that was not wrapped.

func recordUnwrapped(ex string) { writeHashes(ex, nil, false) }

func recordWrapped(ex, manifestHash string) { writeHashes(ex, &manifestHash, true) }

func recordAgain(ex string) {
	p := pathJoin(ex, ".exclave/hashes")
	if !lexists(p) {
		return
	}
	old := loadHashes(p)
	if find(old, "tree") == nil {
		return
	}
	var manifestHash *string
	if m := find(old, "manifest"); m != nil { // the record as it stands, whatever it holds
		manifestHash = &m.F[0].V
	}
	writeHashes(ex, manifestHash, true)
}

// writeHashes writes the hashes file: the hashes and tool records, the launcher's hash when the
// exclave is wrapped, the pkg records the file holds already, then the manifest's hash, if there
// is one to record, and the tree hash when tree is set.
func writeHashes(ex string, manifestHash *string, tree bool) {
	p, ld := pathJoin(ex, ".exclave/hashes"), pathJoin(ex, ".exclave/launcher")
	var old []format.Record
	if lexists(p) {
		old = loadHashes(p)
	}
	rs := []format.Record{format.Rec("hashes", format.T("1")), format.Rec("tool", format.S(version))}
	if manifestHash != nil || tree {
		rs = append(rs, format.Rec("launcher", format.S(format.HashText(readFile(ld)))))
	}
	for _, r := range old {
		if r.Key == "pkg" {
			rs = append(rs, format.Rec("pkg", r.F...))
		}
	}
	if manifestHash != nil {
		rs = append(rs, format.Rec("manifest", format.S(*manifestHash)))
	}
	if tree {
		rs = append(rs, format.Rec("tree", format.S(treeHash(pathJoin(ex, "tree")))))
	}
	writeFile(p, format.Dump(rs, format.Hashes), 0o666)
}

// ---------------------------------------------------------------- unwrap

func refuseStrays(ex string) {
	s := strays(pathJoin(ex, "tree"))
	if len(s) == 0 {
		return
	}
	var msg []string
	for _, p := range s {
		msg = append(msg, "original without wrapper: "+p+" (.real is reserved for originals, 6.1)")
	}
	fail("%s", strings.Join(msg, "; "))
}

// cmdUnwrap moves every original back over its wrapper, after refusing an original without one,
// which is not this exclave's; the hashes file keeps its inputs and loses the hashes of a wrapped
// exclave.
func cmdUnwrap(args []string) int {
	if len(args) != 1 {
		usage()
	}
	ex := args[0]
	requireExclave(ex, "unwrap")
	ld := pathJoin(ex, ".exclave/launcher")
	if _, err := os.Stat(ld); err != nil {
		failErrno(ld, err)
	}
	refuseStrays(ex)
	moved := 0
	walkDirs(pathJoin(ex, "tree"), true, func(dir, _ string, e []entryInfo) {
		if !isRealDir(dir) {
			return
		}
		parent := dir[:len(dir)-len("/.real")]
		for i := range e {
			if e[i].isDir {
				continue
			}
			w, orig := pathJoin(parent, e[i].name), pathJoin(dir, e[i].name)
			if lexists(w) {
				if err := unix.Unlink(w); err != nil {
					failErrno(w, err)
				}
			}
			if err := unix.Rename(orig, w); err != nil {
				failErrno(orig, err)
			}
			moved++
		}
		if err := unix.Rmdir(dir); err != nil {
			failErrno(dir, err)
		}
	})
	fmt.Fprintf(out, "unwrapped %d executables\n", moved)
	recordUnwrapped(ex)
	return 0
}

// ---------------------------------------------------------------- relink

// linkOrCopy puts src at dst as a hard link where the filesystem allows it, and as a copy
// otherwise.
func linkOrCopy(src, dst string) {
	if unix.Link(src, dst) == nil {
		return
	}
	data := readFile(src)
	st, err := stat(src)
	if err != nil {
		failErrno(src, err)
	}
	writeFile(dst, data, st.Mode&0o7777)
	if err := unix.Chmod(dst, st.Mode&0o7777); err != nil {
		failErrno(dst, err)
	}
}

// cmdRelink replaces the launcher and every wrapper with it, each wrapper in one rename, so an
// interruption leaves no program missing; with no LAUNCHER, the one this command carries. A
// wrapped exclave's hashes file records the new launcher and tree hashes.
func cmdRelink(args []string) int {
	if len(args) != 1 && len(args) != 2 {
		usage()
	}
	ex := args[0]
	requireExclave(ex, "relink")
	data := launcherBlob
	if len(args) == 2 { // the launcher given, read before anything goes, since it may be the file replaced
		if st, err := os.Stat(args[1]); err != nil || !st.Mode().IsRegular() {
			fail("no launcher at %s", args[1])
		}
		data = readFile(args[1])
	}
	ld, root := pathJoin(ex, ".exclave/launcher"), pathJoin(ex, "tree")
	next := ld + ".new"
	unix.Unlink(next)
	writeFile(next, data, 0o755)
	if err := unix.Chmod(next, 0o755); err != nil {
		failErrno(next, err)
	}
	n := 0
	var left []string
	walkDirs(root, false, func(dir, rel string, e []entryInfo) {
		if !isRealDir(dir) {
			return
		}
		parent := dir[:len(dir)-len("/.real")]
		for i := range e {
			if e[i].isDir {
				continue
			}
			w := pathJoin(parent, e[i].name)
			if !lexists(w) {
				left = append(left, "/"+relJoin(rel, e[i].name))
				continue
			}
			tmp := parent + "/." + e[i].name + ".exclave-relink"
			linkOrCopy(next, tmp)
			if err := unix.Rename(tmp, w); err != nil {
				failErrno(tmp, err)
			}
			n++
		}
	})
	if err := unix.Rename(next, ld); err != nil {
		failErrno(next, err)
	}
	placeholders(root) // the placeholders this build's wrap ships (8.1, 8.4), where an older build's tree lacks them
	writeReadme(ex)
	for _, p := range left {
		fmt.Fprintf(out, "original without wrapper, left alone: %s\n", p)
	}
	recordAgain(ex)
	fmt.Fprintf(out, "relinked %d wrappers to the new launcher\n", n)
	return 0
}

// ---------------------------------------------------------------- wrap

// The conventional top-level names, shipped as empty directories (8.1, 6.1).
var placeholderDirs = []string{"proc", "dev", "sys", "tmp", "run", "var/tmp", "home", "root", "boot", "mnt", "media",
	"opt", "srv"}

// The host identity files (8.4): shipped empty, the host's at run time. The trust bundles and Java's
// keystores come in pairs, Debian's path and Red Hat's.
var identityFiles = []string{
	"/etc/passwd",
	"/etc/group",
	"/etc/nsswitch.conf",
	"/etc/host.conf",
	"/etc/resolv.conf",
	"/etc/hosts",
	"/etc/localtime",
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/certs/java/cacerts",
	"/etc/pki/java/cacerts",
}

// makeDirs makes path a directory, its missing parents with it; one that stands there already is
// enough.
func makeDirs(p string) {
	for c := 1; c <= len(p); c++ {
		if c < len(p) && p[c] != '/' {
			continue
		}
		prefix := p[:c]
		if err := unix.Mkdir(prefix, 0o777); err != nil {
			if !isErrno(err, syscall.EEXIST) {
				failErrno(prefix, err)
			} else if !isDir(prefix) {
				fail("%s: %s", prefix, errnoText(syscall.EEXIST))
			}
		}
	}
}

// placeholders makes the conventional names as empty directories and the identity files as empty
// files, where the tree lacks them.
func placeholders(root string) {
	for _, name := range placeholderDirs {
		if p := pathJoin(root, name); !lexists(p) {
			makeDirs(p)
		}
	}
	for _, f := range identityFiles {
		// the directory as the tree resolves it, as the launcher maps the copy (8.4): Fedora's
		// /etc/ssl/certs is a link into /etc/pki
		rd, why := treeRealDir(root, dirnameOf(f))
		dir := treeReal(root, rd)
		p := pathJoin(dir, basenameOf(f))
		if why == "" && len(p) >= 4096 { // the launcher's PATH_MAX for the copy's real path
			why = "the path is too long"
		}
		if why != "" {
			fmt.Fprintf(out, "identity file %s not placed: %s\n", f, why)
			continue
		}
		if !lexists(p) {
			makeDirs(dir)
			writeFile(p, nil, 0o666)
		}
	}
}

// wrapFiles wraps every executable in tree/ outside data directories: each original moves to
// .real/ beside it, and a hard link to the launcher takes its place (6.1).
func wrapFiles(ex string, data []string) int {
	root, ld := pathJoin(ex, "tree"), pathJoin(ex, ".exclave/launcher")
	lst, err := stat(ld)
	if err != nil {
		failErrno(ld, err)
	}
	var todo [][2]string // the executables to wrap, real path and virtual path
	walkFiles(root, func(real, v string, st *unix.Stat_t) {
		if !isReg(st) || st.Mode&0o111 == 0 || underAny(v, data) {
			return
		}
		if st.Dev == lst.Dev && st.Ino == lst.Ino {
			return
		}
		if st.Size == lst.Size { // a copy of the launcher that has its original: a wrapper already
			if payloadPath(real) != real && bytes.Equal(readFile(real), readFile(ld)) {
				return
			}
		}
		todo = append(todo, [2]string{real, v})
	})
	for _, t := range todo {
		real, v := t[0], t[1]
		rd := pathJoin(dirnameOf(real), ".real")
		orig := pathJoin(rd, basenameOf(real))
		if lexists(orig) {
			fail("%s has an original in .real/ already: a stale wrapper; run exclave relink", v)
		}
		makeDirs(rd)
		if err := unix.Rename(real, orig); err != nil {
			failErrno(real, err)
		}
		linkOrCopy(ld, real)
	}
	return len(todo)
}

// cmdWrap wraps an exclave: the launcher, the placeholders and a manifest where missing; then the
// wrappers and the static check, any problem refusing the exclave before anything is wrapped;
// then every executable wrapped, and the hashes file given the launcher, manifest and tree hashes
// (10.1).
func cmdWrap(args []string) int {
	if len(args) != 1 && len(args) != 2 {
		usage()
	}
	ex, given := args[0], len(args) == 2
	requireExclave(ex, "wrap")
	refuseSetAside(ex, "wrap")
	ld, root, mp := pathJoin(ex, ".exclave/launcher"), pathJoin(ex, "tree"), pathJoin(ex, ".exclave/manifest")
	gdata := launcherBlob
	if given {
		if st, err := os.Stat(args[1]); err != nil || !st.Mode().IsRegular() {
			fail("no launcher at %s", args[1])
		}
		gdata = readFile(args[1])
	}
	if _, err := os.Stat(ld); err != nil { // the launcher given, for its own machine, or the one this command carries
		makeDirs(pathJoin(ex, ".exclave"))
		unix.Unlink(ld)
		writeFile(ld, gdata, 0o755)
		if err := unix.Chmod(ld, 0o755); err != nil {
			failErrno(ld, err)
		}
		machineOfLauncher(ex)
	} else if given { // a launcher already there is kept, since the wrappers are its copies; relink replaces it
		if !bytes.Equal(readFile(ld), gdata) {
			fail("%s has a launcher already, which differs from %s; exclave relink %s %s replaces it", ex, args[1],
				ex, args[1])
		}
	}
	placeholders(root)
	if _, err := os.Stat(mp); err != nil {
		writeFile(mp, []byte("exclave 1\n"), 0o666)
	}
	mdata := readFile(mp)
	rs, err := format.Parse(mdata, format.Manifest)
	if err != nil {
		failGrammar(err)
	}
	if !bytes.Equal(format.Dump(rs, format.Manifest), mdata) {
		fail("refusing: %s is not canonical; run exclave format on it", mp)
	}
	// the launcher's own table of top-level names (8.1): a placeholder takes no slot
	if top := ownedTop(ex); len(top) > 256 {
		fail("tree/ has %d top-level entries; the launcher holds 256", len(top))
	}
	data := dataPrefixes(ex)
	ls := listTree(root) // read three times over before anything is wrapped: listed once
	problems := append(append(wrapperProblems(ex, data, ls), locatedLinks(ex, ls)...), shortcutProblems(ex)...)
	for _, p := range problems {
		fmt.Fprintf(out, "error: %s\n", p)
	}
	errors := staticReport(ex, ls)
	if len(problems) > 0 || errors > 0 {
		fmt.Fprintln(out, "refused: nothing was wrapped")
		return 1
	}
	fmt.Fprintf(out, "wrapped %d executables\n", wrapFiles(ex, data))
	writeReadme(ex)
	recordWrapped(ex, format.HashText(mdata))
	fmt.Fprintf(out, "%s is wrapped\n", ex)
	return 0
}
