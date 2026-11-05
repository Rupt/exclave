// The caches only a tree's own programs can make, made by them inside the exclave (DESIGN.md
// 10.1, 13 item 48): Python's bytecode, GLib's compiled GSettings schemas and the MIME database.
// unpack and wrap run nothing of the tree, so that an exclave of either architecture is made on
// either; this command runs the tree's generators under the exclave's launcher, on a machine of
// the exclave's architecture, writing to a staging directory in the exclave's own directory,
// which is the host's (8.1 rule 6), and copies what they made into the tree.

package main

import (
	"bytes"
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

// cacheRun is a generator's run inside the exclave: sh, the exclave's shell by its real path,
// runs argv[0], a virtual path, so that the program is named in the exclave's terms, with env
// alone, which is fixed so that what is made depends on the tree and not on the caller.
type cacheRun struct {
	sh, staging string
}

func (c *cacheRun) run(env []string, argv ...string) (int, string) {
	cmd := exec.Command(c.sh, append([]string{"-c", `exec "$0" "$@"`}, argv...)...)
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + c.staging, "TMPDIR=" + c.staging}, env...)
	cmd.Dir = c.staging
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), buf.String()
		}
		fail("%s: %s", argv[0], errnoText(err))
	}
	return 0, buf.String()
}

// placeFile writes data as the tree's file at real, unless the file holds it already, through a
// new file renamed over the old, since a tree's files may be hard links shared with a copy
// (6.1); its directories are made as needed. Reports whether the tree changed.
func placeFile(real string, data []byte) bool {
	if old, err := os.ReadFile(real); err == nil && bytes.Equal(old, data) {
		return false
	}
	makeDirs(dirnameOf(real))
	tmp := real + ".exclave-caches"
	unix.Unlink(tmp)
	writeFile(tmp, data, 0o644)
	if err := unix.Chmod(tmp, 0o644); err != nil {
		failErrno(tmp, err)
	}
	if err := unix.Rename(tmp, real); err != nil {
		failErrno(real, err)
	}
	return true
}

// pythonVersion matches the directories of a Python's standard library, usr/lib/python3.N.
var pythonVersion = regexp.MustCompile(`^python3\.[0-9]+$`)

// pythonBytecode compiles, with each Python the tree holds, its standard library and the
// distribution's package directories, into __pycache__ beside each source. The bytecode is
// checked against its source's hash rather than its time, so a copy that loses the times keeps it
// valid and an edited source is compiled again.
func pythonBytecode(c *cacheRun, root string, jobs int) []string {
	var lines []string
	libs, _ := dirNames(treeReal(root, "/usr/lib"))
	sort.Strings(libs)
	for _, name := range libs {
		if !pythonVersion.MatchString(name) || treeResolve(root, "/usr/bin/"+name, true, nil) == "" {
			continue
		}
		var dirs []string
		for _, d := range []string{"/usr/lib/" + name, "/usr/lib64/" + name, "/usr/lib/python3/dist-packages"} {
			if v := treeResolve(root, d, true, nil); v != "" && isDir(treeReal(root, v)) {
				dirs = append(dirs, v)
			}
		}
		prefix := pathJoin(c.staging, name)
		// several processes need concurrent.futures, which a minimal Python lacks
		j := jobs
		if treeResolve(root, "/usr/lib/"+name+"/concurrent/futures/process.py", true, nil) == "" {
			j = 1
		}
		// -B, since the interpreter's own imports would write their bytecode by the source's time
		// first, which compileall then takes as up to date
		argv := append([]string{"/usr/bin/" + name, "-I", "-B", "-X", "pycache_prefix=" + prefix, "-m", "compileall",
			"-q", "-j", strconv.Itoa(j), "--invalidation-mode", "checked-hash"}, dirs...)
		rc, text := c.run(nil, argv...)
		if rc != 0 && (rc != 1 || strings.Contains(text, "Traceback")) {
			fail("%s -m compileall exited %d: %s", name, rc, strings.TrimSpace(text))
		}
		// compileall answers 1 when a source does not compile, as test data with bad syntax does
		for line := range strings.SplitSeq(strings.TrimSpace(text), "\n") {
			if line != "" {
				fmt.Fprintf(out, "%s: %s\n", name, line)
			}
		}
		// the prefix mirrors the sources' directories without the __pycache__ level, which the tree
		// gets back: the prefix's <dir>/x.pyc is the tree's <dir>/__pycache__/x.pyc
		made, changed := 0, 0
		filepath.WalkDir(prefix, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				failErrno(p, err)
			}
			if d.IsDir() || !strings.HasSuffix(p, ".pyc") {
				return nil
			}
			rel := strings.TrimPrefix(p, prefix)
			real := treeReal(root, pathJoin(dirnameOf(rel), "__pycache__/"+basenameOf(rel)))
			made++
			if placeFile(real, readFile(p)) {
				changed++
			}
			return nil
		})
		lines = append(lines, fmt.Sprintf("%s bytecode: %d files, %d new or changed", name, made, changed))
	}
	return lines
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

// hasSuffixed reports whether the tree's directory v holds a file whose name ends in suffix.
func hasSuffixed(root, v, suffix string) bool {
	names, _ := dirNames(treeReal(root, v))
	for _, n := range names {
		if strings.HasSuffix(n, suffix) {
			return true
		}
	}
	return false
}

// gsettingsSchemas compiles /usr/share/glib-2.0/schemas into its gschemas.compiled, which GLib
// reads in place of the XML and without which a program's settings are missing.
func gsettingsSchemas(c *cacheRun, root string) []string {
	const dir = "/usr/share/glib-2.0/schemas"
	tool := findTool(root, "/usr/bin/glib-compile-schemas",
		"/usr/lib/"+launcherMachine.triplet+"/glib-2.0/glib-compile-schemas")
	if tool == "" || !hasSuffixed(root, dir, ".gschema.xml") {
		return nil
	}
	target := pathJoin(c.staging, "gsettings")
	makeDirs(target)
	if rc, text := c.run(nil, tool, "--targetdir="+target, dir); rc != 0 {
		fail("%s exited %d: %s", tool, rc, strings.TrimSpace(text))
	}
	changed := placeFile(treeReal(root, dir+"/gschemas.compiled"), readFile(pathJoin(target, "gschemas.compiled")))
	return []string{fmt.Sprintf("GSettings schemas: gschemas.compiled%s", map[bool]string{true: ", new or changed",
		false: ", unchanged"}[changed])}
}

// mimeDatabase builds the shared MIME database from /usr/share/mime/packages: the generator runs
// on a copy of the packages in the staging directory, since it writes beside them, and every file
// it made there but the packages joins the tree's /usr/share/mime.
func mimeDatabase(c *cacheRun, root string) []string {
	const dir = "/usr/share/mime"
	tool := findTool(root, "/usr/bin/update-mime-database")
	if tool == "" || !hasSuffixed(root, dir+"/packages", ".xml") {
		return nil
	}
	db := pathJoin(c.staging, "mime")
	makeDirs(pathJoin(db, "packages"))
	names, err := dirNames(treeReal(root, dir+"/packages"))
	if err != nil {
		failErrno(treeReal(root, dir+"/packages"), err)
	}
	for _, n := range names {
		if strings.HasSuffix(n, ".xml") {
			writeFile(pathJoin(db, "packages/"+n), readFile(treeReal(root, dir+"/packages/"+n)), 0o644)
		}
	}
	if rc, text := c.run([]string{"PKGSYSTEM_ENABLE_FSYNC=0"}, tool, db); rc != 0 {
		fail("%s exited %d: %s", tool, rc, strings.TrimSpace(text))
	}
	made, changed := 0, 0
	filepath.WalkDir(db, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			failErrno(p, err)
		}
		rel := strings.TrimPrefix(p, db)
		if rel == "/packages" && d.IsDir() {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		made++
		if placeFile(treeReal(root, dir+rel), readFile(p)) {
			changed++
		}
		return nil
	})
	return []string{fmt.Sprintf("MIME database: %d files, %d new or changed", made, changed)}
}

// cmdCaches makes the caches only the tree's own programs can make (10.1): it runs each
// generator the tree holds inside the exclave, copies its output into the tree, replacing what
// differs, and records the new tree hash.
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
	sh := findTool(root, "/bin/sh")
	if sh == "" {
		fail("refusing: %s has no /bin/sh to run its generators by", ex)
	}
	staging := pathJoin(ex, ".exclave/caches")
	if err := os.RemoveAll(staging); err != nil {
		failErrno(staging, err)
	}
	makeDirs(staging)
	c := &cacheRun{sh: treeReal(root, sh), staging: staging}
	var made []string
	made = append(made, pythonBytecode(c, root, threads())...)
	made = append(made, gsettingsSchemas(c, root)...)
	made = append(made, mimeDatabase(c, root)...)
	if err := os.RemoveAll(staging); err != nil {
		failErrno(staging, err)
	}
	if len(made) == 0 {
		fmt.Fprintf(out, "%s: no generator of Python bytecode, GSettings schemas or the MIME database applies\n", ex)
		return 0
	}
	for _, m := range made {
		fmt.Fprintln(out, m)
	}
	writeHashes(ex, "", false, true)
	fmt.Fprintf(out, "%s: the tree hash recorded\n", ex)
	return 0
}
