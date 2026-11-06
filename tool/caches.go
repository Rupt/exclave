// The caches only a tree's own programs can make, made by them inside the exclave (DESIGN.md
// 10.1, 13 item 48): Python's bytecode, GLib's compiled GSettings schemas and the MIME database.
// unpack and wrap run nothing of the tree, so that an exclave of either architecture is made on
// either; this command runs the tree's generators under the exclave's launcher, on a machine of
// the exclave's architecture, writing to a staging directory in the exclave's own directory,
// which is the host's (8.1 rule 6). Only when every generator has succeeded does it copy what they
// made into the tree, and then it records the tree hash, so a failure leaves the exclave as it was.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// cacheRun is a generator's run inside the exclave: sh, the exclave's shell by its real path, is
// run by the name sh, since a multi-call shell such as busybox chooses its applet by the name,
// and runs argv[0], a virtual path, so that the program is named in the exclave's terms, with env
// alone, which is fixed so that what is made depends on the tree and not on the caller.
type cacheRun struct {
	sh, staging string
}

func (c *cacheRun) run(env []string, argv ...string) (int, string) {
	cmd := &exec.Cmd{Path: c.sh, Args: append([]string{"sh", "-c", `exec "$0" "$@"`}, argv...)}
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + c.staging, "TMPDIR=" + c.staging}, env...)
	cmd.Dir = c.staging
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	if err != nil {
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			return ee.ExitCode(), buf.String()
		}
		fail("%s: %s", argv[0], errnoText(err))
	}
	return 0, buf.String()
}

// say prints what a generator said, each line after its name: a warning it gave on success too,
// such as a schema file it passed over.
func say(name, text string) {
	for line := range strings.SplitSeq(strings.TrimSpace(text), "\n") {
		if line != "" {
			fmt.Fprintf(out, "%s: %s\n", name, line)
		}
	}
}

// cache is what one generator made: each file in the staging directory and the virtual path in
// the tree it becomes.
type cache struct {
	what  string
	files [][2]string
}

// treeDest is the real path at which the tree's virtual path v is written: its directory resolved
// in the tree, so that a link in the tree, an absolute one included, leads inside it and never to
// the host, and the directories it lacks made there.
func treeDest(root, v string) string {
	dir, rest := dirnameOf(v), ""
	for {
		if r := treeResolve(root, dir, true, nil); r != "" {
			at := treeReal(root, r)
			if rest != "" {
				at = pathJoin(at, rest)
			}
			makeDirs(at)
			return pathJoin(at, basenameOf(v))
		}
		if rest == "" {
			rest = basenameOf(dir)
		} else {
			rest = basenameOf(dir) + "/" + rest
		}
		dir = dirnameOf(dir)
	}
}

// placeFile writes data as the tree's file at real, unless a regular file there holds it already,
// through a new file renamed over the old, since a tree's files may be hard links shared with a
// copy (6.1). Reports whether the tree changed.
func placeFile(real string, data []byte) bool {
	if st, err := lstat(real); err == nil && isReg(&st) {
		if old, err := os.ReadFile(real); err == nil && bytes.Equal(old, data) {
			return false
		}
	}
	tmp := real + ".exclave-caches"
	unix.Unlink(tmp)
	writeFile(tmp, data, 0o644)
	if err := unix.Chmod(tmp, 0o644); err != nil {
		failErrno(tmp, err)
	}
	if err := unix.Rename(tmp, real); err != nil {
		unix.Unlink(tmp)
		failErrno(real, err)
	}
	return true
}

// treeDir is the tree's directory at virtual path v, resolved in the tree, or "".
func treeDir(root, v string) string {
	if r := treeResolve(root, v, true, nil); r != "" && isDir(treeReal(root, r)) {
		return r
	}
	return ""
}

// pythonVersion matches the directories of a Python's standard library, usr/lib/python3.N.
var pythonVersion = regexp.MustCompile(`^python3\.[0-9]+$`)

// pythonBytecode compiles, with each Python the tree holds, its standard library and the
// distribution's package directories, into __pycache__ beside each source. The bytecode is
// checked against its source's hash rather than its time, so a copy that loses the times keeps it
// valid and an edited source is compiled again.
func pythonBytecode(c *cacheRun, root string) []cache {
	var names []string
	for _, lib := range []string{"/usr/lib", "/usr/lib64"} {
		if d := treeDir(root, lib); d != "" {
			found, _ := dirNames(treeReal(root, d))
			for _, n := range found {
				if pythonVersion.MatchString(n) && !strings.Contains(strings.Join(names, " ")+" ", n+" ") {
					names = append(names, n)
				}
			}
		}
	}
	sort.Strings(names)
	var made []cache
	for _, name := range names {
		if treeResolve(root, "/usr/bin/"+name, true, nil) == "" {
			continue
		}
		var dirs []string
		for _, d := range []string{"/usr/lib/" + name, "/usr/lib64/" + name, "/usr/lib/python3/dist-packages"} {
			if v := treeDir(root, d); v != "" {
				dirs = append(dirs, v)
			}
		}
		prefix := pathJoin(c.staging, name)
		// one process: compileall's workers need concurrent.futures, which a minimal Python lacks, and
		// a forkserver's socket under the staging directory, whose path can pass the 108 bytes a
		// socket's may have. The prefix and -B through the environment, which is the fixed one; -B,
		// since the interpreter's own imports would write their bytecode by the source's time first,
		// which compileall then takes as up to date; -s leaves out a user's site directory.
		env := []string{"PYTHONPYCACHEPREFIX=" + prefix, "PYTHONDONTWRITEBYTECODE=1"}
		argv := append([]string{"/usr/bin/" + name, "-s", "-m", "compileall", "-q", "-j", "1",
			"--invalidation-mode", "checked-hash"}, dirs...)
		rc, text := c.run(env, argv...)
		// compileall answers 1 when a source does not compile, as test data with bad syntax does; a
		// write it could not make is a failure
		if rc != 0 && (rc != 1 || strings.Contains(text, "Traceback") || strings.Contains(text, "[Errno ")) {
			fail("%s -m compileall exited %d: %s", name, rc, strings.TrimSpace(text))
		}
		say(name, text)
		// the prefix mirrors the sources' directories without the __pycache__ level, which the tree
		// gets back: the prefix's <dir>/x.pyc is the tree's <dir>/__pycache__/x.pyc
		m := cache{what: name + " bytecode"}
		err := filepath.WalkDir(prefix, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(p, ".pyc") {
				rel := strings.TrimPrefix(p, prefix)
				m.files = append(m.files, [2]string{p, pathJoin(dirnameOf(rel), "__pycache__/"+basenameOf(rel))})
			}
			return nil
		})
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fail("%s: %s", prefix, errnoText(err))
		}
		made = append(made, m)
	}
	return made
}

// findTool is the virtual path of the first of names the tree holds, or "".
func findTool(root string, names ...string) string {
	for _, n := range names {
		if v := treeResolve(root, n, true, nil); v != "" {
			return v
		}
	}
	return ""
}

// suffixed lists the names in the tree's directory v that end in suffix.
func suffixed(root, v, suffix string) []string {
	names, _ := dirNames(treeReal(root, v))
	var out []string
	for _, n := range names {
		if strings.HasSuffix(n, suffix) {
			out = append(out, n)
		}
	}
	return out
}

// gsettingsSchemas compiles /usr/share/glib-2.0/schemas into its gschemas.compiled, which GLib
// reads in place of the XML and without which a program's settings are missing.
func gsettingsSchemas(c *cacheRun, root string) []cache {
	dir := treeDir(root, "/usr/share/glib-2.0/schemas")
	tool := findTool(root, "/usr/bin/glib-compile-schemas",
		"/usr/lib/"+launcherMachine.triplet+"/glib-2.0/glib-compile-schemas")
	if tool == "" || dir == "" || len(suffixed(root, dir, ".gschema.xml")) == 0 {
		return nil
	}
	target := pathJoin(c.staging, "gsettings")
	makeDirs(target)
	rc, text := c.run(nil, tool, "--targetdir="+target, dir)
	if rc != 0 {
		fail("%s exited %d: %s", tool, rc, strings.TrimSpace(text))
	}
	say(basenameOf(tool), text)
	made := [2]string{pathJoin(target, "gschemas.compiled"), dir + "/gschemas.compiled"}
	return []cache{{"GSettings schemas", [][2]string{made}}}
}

// mimeDatabase builds the shared MIME database from /usr/share/mime/packages: the generator runs
// on a copy of the packages in the staging directory, since it writes beside them, and every file
// it made there but the packages joins the tree's /usr/share/mime.
func mimeDatabase(c *cacheRun, root string) []cache {
	dir := treeDir(root, "/usr/share/mime")
	tool := findTool(root, "/usr/bin/update-mime-database")
	if tool == "" || dir == "" || treeDir(root, dir+"/packages") == "" {
		return nil
	}
	packages := treeDir(root, dir+"/packages")
	xml := suffixed(root, packages, ".xml")
	if len(xml) == 0 {
		return nil
	}
	db := pathJoin(c.staging, "mime")
	makeDirs(pathJoin(db, "packages"))
	for _, n := range xml {
		v := treeResolve(root, packages+"/"+n, true, nil)
		if v == "" {
			continue // a dangling link, which the static check names
		}
		writeFile(pathJoin(db, "packages/"+n), readFile(treeReal(root, v)), 0o644)
	}
	// its data directories the staging one, which it would otherwise warn is not among them
	rc, text := c.run([]string{"PKGSYSTEM_ENABLE_FSYNC=0", "XDG_DATA_DIRS=" + c.staging}, tool, db)
	if rc != 0 {
		fail("%s exited %d: %s", tool, rc, strings.TrimSpace(text))
	}
	say(basenameOf(tool), text)
	m := cache{what: "MIME database"}
	err := filepath.WalkDir(db, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(p, db)
		if rel == "/packages" && d.IsDir() {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			m.files = append(m.files, [2]string{p, dir + rel})
		}
		return nil
	})
	if err != nil {
		fail("%s: %s", db, errnoText(err))
	}
	return []cache{m}
}

// plural is n and the noun, made plural unless n is 1.
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// cmdCaches makes the caches only the tree's own programs can make (10.1): it runs each
// generator the tree holds inside the exclave, and only when all have succeeded copies their
// output into the tree, replacing what differs, and records the new tree hash. A tree that differs
// from its recorded hash is refused, so that the hash it records vouches for no edit it has not
// seen.
func cmdCaches(args []string) int {
	if len(args) != 1 {
		usage("caches EXCLAVE")
	}
	ex := args[0]
	if abs, err := filepath.Abs(ex); err == nil {
		ex = abs
	}
	requireExclave(ex, "caches")
	if !hasTreeRecord(ex) {
		fail("refusing: %s is not wrapped; its generators run inside it, so exclave wrap comes first", ex)
	}
	if launcherMachine.eMachine != ownMachine().eMachine {
		fail("refusing: %s is an exclave for %s, and its generators run here, on %s: make its caches on an %s "+
			"machine", ex, launcherMachine.uname, ownMachine().uname, launcherMachine.uname)
	}
	root := pathJoin(ex, "tree")
	if rec := find(loadHashes(pathJoin(ex, ".exclave/hashes")), "tree"); treeHash(root) != rec.f[0].v {
		fail("refusing: %s's tree differs from the hash its hashes file records; exclave check reports it, and "+
			"exclave wrap records the tree as it is", ex)
	}
	sh := findTool(root, "/bin/sh")
	if sh == "" {
		fail("refusing: %s has no /bin/sh to run its generators by", ex)
	}
	staging := pathJoin(ex, ".exclave/caches")
	if err := os.RemoveAll(staging); err != nil {
		failErrno(staging, err)
	}
	atFail(func() { os.RemoveAll(staging) })
	makeDirs(staging)
	c := &cacheRun{sh: treeReal(root, sh), staging: staging}
	var made []cache
	made = append(made, pythonBytecode(c, root)...)
	made = append(made, gsettingsSchemas(c, root)...)
	made = append(made, mimeDatabase(c, root)...)
	if len(made) == 0 {
		os.RemoveAll(staging)
		fmt.Fprintf(out, "%s: no generator of Python bytecode, GSettings schemas or the MIME database applies\n", ex)
		return 0
	}
	// every generator has succeeded: now the tree changes
	for _, m := range made {
		changed := 0
		for _, f := range m.files {
			if placeFile(treeDest(root, f[1]), readFile(f[0])) {
				changed++
			}
		}
		fmt.Fprintf(out, "%s: %s, %d new or changed\n", m.what, plural(len(m.files), "file"), changed)
	}
	if err := os.RemoveAll(staging); err != nil {
		failErrno(staging, err)
	}
	writeHashes(ex, "", false, true)
	fmt.Fprintf(out, "%s: the tree hash recorded\n", ex)
	return 0
}
