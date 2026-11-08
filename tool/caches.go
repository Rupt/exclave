// The caches only a tree's own programs can make, made by them inside the exclave (DESIGN.md
// 10.1, 13 item 48): Python's bytecode, GLib's compiled GSettings schemas, the MIME database,
// GIO's module cache, gdk-pixbuf's loader cache, icon caches, the desktop database,
// fontconfig's caches, graphviz's plugin configuration and TeX Live's configuration, indexes and
// formats, the last written in place (inPlace).
// unpack and wrap run nothing of the tree, so that an exclave of either architecture is made on
// either; this command runs the tree's generators under the exclave's launcher, on a machine of
// the exclave's architecture, writing to a staging directory in the exclave's own directory,
// which is the host's (8.1 rule 6). Only when every generator has succeeded does it copy what they
// made into the tree, and then it records the tree hash, so a failure leaves the exclave as it was.

package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// cacheRun is a generator's run inside the exclave: sh, the exclave's shell by its real path, is
// run by the name sh, since a multi-call shell such as busybox chooses its applet by the name,
// and runs argv[0], a virtual path, so that the program is named in the exclave's terms, with env
// alone, which is fixed so that what is made depends on the tree and not on the caller.
type cacheRun struct {
	sh, staging string
}

// run runs argv inside the exclave and answers its exit status and what it said on both outputs.
func (c *cacheRun) run(env []string, argv ...string) (int, string) {
	var buf bytes.Buffer
	rc := c.exec(env, &buf, &buf, argv)
	return rc, buf.String()
}

// output runs argv as run does, with its standard output apart from what it says on its error
// output: the cache a generator such as gdk-pixbuf-query-loaders writes there.
func (c *cacheRun) output(env []string, argv ...string) (int, []byte, string) {
	var o, e bytes.Buffer
	rc := c.exec(env, &o, &e, argv)
	return rc, o.Bytes(), e.String()
}

// The signal that interrupted the command, once one has (inPlaceBegun), and the process group of
// the generator running then, which the signal ends.
var (
	interruptMu sync.Mutex
	interrupted os.Signal
	runningPgid int
)

// checkInterrupted fails the command, as a refusal, once a signal has interrupted it.
func checkInterrupted() {
	interruptMu.Lock()
	sig := interrupted
	interruptMu.Unlock()
	if sig != nil {
		fail("interrupted by %s; the tree is as it was", sig)
	}
}

func (c *cacheRun) exec(env []string, stdout, stderr io.Writer, argv []string) int {
	checkInterrupted()
	cmd := &exec.Cmd{Path: c.sh, Args: append([]string{"sh", "-c", `exec "$0" "$@"`}, argv...)}
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + c.staging, "TMPDIR=" + c.staging}, env...)
	cmd.Dir = c.staging
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// a process group of its own, which a signal to the command ends (inPlaceBegun)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	interruptMu.Lock()
	err := cmd.Start()
	if err == nil {
		runningPgid = cmd.Process.Pid
	}
	interruptMu.Unlock()
	if err == nil {
		err = cmd.Wait()
	}
	interruptMu.Lock()
	runningPgid = 0
	interruptMu.Unlock()
	checkInterrupted()
	if err != nil {
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			return ee.ExitCode()
		}
		fail("%s: %s", argv[0], errnoText(err))
	}
	return 0
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
// the tree it becomes; each link it made, by its text and the virtual path; with dirTimes, the
// directory a file lands in is made no newer than it.
type cache struct {
	what     string
	files    [][2]string
	links    [][2]string
	dirTimes bool
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

// placeLink makes real a link with the text target, unless one stands there with it already,
// through a new link renamed over the old. Reports whether the tree changed.
func placeLink(real, target string) bool {
	if t, err := os.Readlink(real); err == nil && t == target {
		return false
	}
	tmp := real + ".exclave-caches"
	unix.Unlink(tmp)
	if err := unix.Symlink(target, tmp); err != nil {
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
	return []cache{{what: "GSettings schemas", files: [][2]string{made}}}
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

// mirror makes dst the tree's directory v in links: a directory for each of its directories, and
// for each other entry keep accepts a link to the entry's virtual path, which the launcher's walk
// follows into the tree, a link of the tree's own included. A generator that writes its cache
// beside what it reads runs on the mirror, so that it writes nothing to the tree and nothing of
// the tree is copied. Reports how many entries were linked.
func mirror(root, v, dst string, keep func(name string) bool) int {
	makeDirs(dst)
	names, err := dirNames(treeReal(root, v))
	if err != nil {
		fail("%s: %s", treeReal(root, v), errnoText(err))
	}
	n := 0
	for _, name := range names {
		if name == ".real" {
			continue // the wrappers' originals, which the launcher hides
		}
		real := treeReal(root, v+"/"+name)
		st, err := lstat(real)
		if err != nil {
			failErrno(real, err)
		}
		switch {
		case isDirM(&st):
			n += mirror(root, v+"/"+name, pathJoin(dst, name), keep)
		case keep(name):
			if err := unix.Symlink(v+"/"+name, pathJoin(dst, name)); err != nil {
				failErrno(pathJoin(dst, name), err)
			}
			n++
		}
	}
	return n
}

// ran fails a generator that exited other than 0 and prints what it said, after its name.
func ran(tool string, rc int, text string) {
	if rc != 0 {
		fail("%s exited %d: %s", tool, rc, strings.TrimSpace(text))
	}
	say(basenameOf(tool), text)
}

// gioModules writes GIO's giomodule.cache for each directory of GIO modules, the extension points
// each module implements, without which GIO loads every module in the directory to ask; the
// generator runs on a mirror of the directory, since it writes beside the modules.
func gioModules(c *cacheRun, root string) []cache {
	t := launcherMachine.triplet
	tool := findTool(root, "/usr/bin/gio-querymodules", "/usr/bin/gio-querymodules-64",
		"/usr/lib/"+t+"/glib-2.0/gio-querymodules")
	if tool == "" {
		return nil
	}
	m := cache{what: "GIO module cache"}
	var seen []string
	for _, d := range []string{"/usr/lib/gio/modules", "/usr/lib/" + t + "/gio/modules", "/usr/lib64/gio/modules"} {
		dir := treeDir(root, d)
		if dir == "" || slices.Contains(seen, dir) {
			continue
		}
		seen = append(seen, dir)
		at := pathJoin(c.staging, "gio/"+strconv.Itoa(len(seen)))
		if mirror(root, dir, at, func(n string) bool { return strings.HasSuffix(n, ".so") }) == 0 {
			continue
		}
		rc, text := c.run(nil, tool, at)
		ran(tool, rc, text)
		m.files = append(m.files, [2]string{pathJoin(at, "giomodule.cache"), dir + "/giomodule.cache"})
	}
	if len(m.files) == 0 {
		return nil
	}
	return []cache{m}
}

// loaderDir is the line of gdk-pixbuf-query-loaders' output that names the loaders' directory.
var loaderDir = regexp.MustCompile(`(?m)^# LoaderDir = (/[^\n]*)$`)

// pixbufLoaders writes gdk-pixbuf's loaders.cache, beside the loaders' directory the generator
// names, which it writes on its standard output; without it gdk-pixbuf knows only the formats
// built into it.
func pixbufLoaders(c *cacheRun, root string) []cache {
	tool := findTool(root, "/usr/bin/gdk-pixbuf-query-loaders", "/usr/bin/gdk-pixbuf-query-loaders-64",
		"/usr/lib/"+launcherMachine.triplet+"/gdk-pixbuf-2.0/gdk-pixbuf-query-loaders")
	if tool == "" {
		return nil
	}
	rc, list, text := c.output(nil, tool)
	ran(tool, rc, text)
	at := loaderDir.FindSubmatch(list)
	if at == nil {
		fail("%s named no loader directory: %s", tool, strings.TrimSpace(string(list)))
	}
	if dir := treeDir(root, string(at[1])); dir == "" || len(suffixed(root, dir, ".so")) == 0 {
		return nil // every loader built in
	}
	file := pathJoin(c.staging, "loaders.cache")
	writeFile(file, list, 0o644)
	made := [2]string{file, dirnameOf(string(at[1])) + "/loaders.cache"}
	return []cache{{what: "gdk-pixbuf loader cache", files: [][2]string{made}}}
}

// namesDirectories reports whether an icon theme's index has a Directories= key with a value.
func namesDirectories(index []byte) bool {
	for line := range strings.SplitSeq(string(index), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Directories="); ok && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// iconCaches writes icon-theme.cache for each theme under /usr/share/icons with an index.theme,
// which an icon lookup reads in place of walking the theme's directories; the generator runs on
// a mirror of the theme, since it writes into it. GTK takes a cache older than its theme's
// directory for stale, so the directory gets the cache's time where its own is later, as the
// generator gives it. A theme whose index names no directory of icons, an empty or absent
// Directories= key, as the cursor theme /usr/share/icons/default's, is passed over: it has no
// icons to index, the generator writes nothing for it, and the maintainer script makes nothing.
// Any other theme the generator writes no cache for fails the run before the tree changes.
func iconCaches(c *cacheRun, root string) []cache {
	base := treeDir(root, "/usr/share/icons")
	tool := findTool(root, "/usr/bin/gtk-update-icon-cache", "/usr/bin/gtk4-update-icon-cache")
	if base == "" || tool == "" {
		return nil
	}
	names, _ := dirNames(treeReal(root, base))
	m := cache{what: "icon caches", dirTimes: true}
	var seen []string
	for _, n := range names {
		theme := treeDir(root, base+"/"+n)
		if theme == "" || slices.Contains(seen, theme) {
			continue
		}
		index := treeResolve(root, theme+"/index.theme", true, nil)
		if index == "" || !namesDirectories(readFile(treeReal(root, index))) {
			continue
		}
		seen = append(seen, theme)
		at := pathJoin(c.staging, "icons/"+strconv.Itoa(len(seen)))
		mirror(root, theme, at, func(n string) bool { return n != "icon-theme.cache" })
		rc, text := c.run(nil, tool, "-q", "-t", "-f", at)
		ran(tool, rc, text)
		m.files = append(m.files, [2]string{pathJoin(at, "icon-theme.cache"), theme + "/icon-theme.cache"})
	}
	if len(m.files) == 0 {
		return nil
	}
	return []cache{m}
}

// desktopDatabase writes /usr/share/applications/mimeinfo.cache, the applications that open each
// MIME type, from the desktop files; the generator runs on a mirror of the directory, since it
// writes beside them.
func desktopDatabase(c *cacheRun, root string) []cache {
	dir := treeDir(root, "/usr/share/applications")
	tool := findTool(root, "/usr/bin/update-desktop-database")
	if dir == "" || tool == "" {
		return nil
	}
	at := pathJoin(c.staging, "applications")
	if mirror(root, dir, at, func(n string) bool { return strings.HasSuffix(n, ".desktop") }) == 0 {
		return nil
	}
	rc, text := c.run(nil, tool, at)
	ran(tool, rc, text)
	made := [2]string{pathJoin(at, "mimeinfo.cache"), dir + "/mimeinfo.cache"}
	return []cache{{what: "desktop database", files: [][2]string{made}}}
}

// graphvizPlugins writes graphviz's plugin configuration, config6a or config6 as its version names
// it, the plugins and the formats each provides, without which dot knows no output format at all.
// dot -c writes it into the directory it finds its plugins in, which it takes from GVBINDIR, so
// the generator runs on a mirror of the plugin directory; in place it could not, since the tree
// is read-only and dot finds the directory from /proc/self/maps, which names the tree's host path
// (13 item 10). The file names each plugin by its file name, relative to its directory, so it is
// valid at the directory's virtual path.
func graphvizPlugins(c *cacheRun, root string) []cache {
	tool := findTool(root, "/usr/bin/dot")
	dir := ""
	for _, d := range []string{"/usr/lib/" + launcherMachine.triplet + "/graphviz", "/usr/lib/graphviz",
		"/usr/lib64/graphviz"} {
		if dir = treeDir(root, d); dir != "" {
			break
		}
	}
	if tool == "" || dir == "" {
		return nil
	}
	at := pathJoin(c.staging, "graphviz")
	plugin := func(n string) bool { return strings.HasPrefix(n, "libgvplugin_") && strings.Contains(n, ".so") }
	if mirror(root, dir, at, plugin) == 0 {
		return nil
	}
	rc, text := c.run([]string{"GVBINDIR=" + at}, tool, "-c")
	ran(tool, rc, text)
	// its name is the configuration format's: config6a for graphviz 2.43, config6 for later ones
	m := cache{what: "graphviz plugin configuration"}
	names, _ := dirNames(at)
	for _, n := range names {
		if st, err := lstat(pathJoin(at, n)); err == nil && isReg(&st) && strings.HasPrefix(n, "config") {
			m.files = append(m.files, [2]string{pathJoin(at, n), dir + "/" + n})
		}
	}
	if len(m.files) != 1 {
		fail("%s -c wrote %d configuration files, not one: %s", tool, len(m.files), strings.TrimSpace(text))
	}
	return []cache{m}
}

// systemCacheDir is the first cache directory a fontconfig configuration names outside the
// user's home, the one the system's caches are read from, or "".
func systemCacheDir(conf []byte) string {
	d := xml.NewDecoder(bytes.NewReader(conf))
	depth, in := 0, false
	for {
		tok, err := d.Token()
		if err != nil {
			return ""
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			in = depth == 2 && t.Name.Local == "cachedir" && !slices.ContainsFunc(t.Attr, func(a xml.Attr) bool {
				return a.Name.Local == "prefix"
			})
		case xml.EndElement:
			depth--
			in = false
		case xml.CharData:
			if s := strings.TrimSpace(string(t)); in && strings.HasPrefix(s, "/") {
				return s
			}
		}
	}
}

// fontCaches writes fontconfig's caches of the system's font directories into the cache
// directory its configuration names, /var/cache/fontconfig, so that a program finds them valid
// and writes none of its own under the user's home. A cache is named by its font directory's
// path and records the directory's modification time, so fc-cache runs inside, where the
// directories have their virtual paths, with a configuration that includes the tree's and names
// the staging directory after its cache directories: theirs are read-only inside, so the staging
// directory is the first writable one, where fc-cache writes, and the last, the one whose cache
// answers fc-cache's check of what it wrote, which a stale cache of the tree's, left by a copy
// that lost the times, would otherwise fail. -f, since the tree's caches from a run before are
// valid and would be passed over; -s, the system's directories alone.
func fontCaches(c *cacheRun, root string) []cache {
	tool := findTool(root, "/usr/bin/fc-cache")
	conf := treeResolve(root, "/etc/fonts/fonts.conf", true, nil)
	if tool == "" || conf == "" {
		return nil
	}
	dir := systemCacheDir(readFile(treeReal(root, conf)))
	if dir == "" {
		fmt.Fprint(out, "font caches: /etc/fonts/fonts.conf names no cache directory outside the home; none made\n")
		return nil
	}
	at := pathJoin(c.staging, "fontconfig")
	var cfg strings.Builder
	cfg.WriteString("<?xml version=\"1.0\"?>\n<fontconfig>\n" +
		"<include ignore_missing=\"no\">/etc/fonts/fonts.conf</include>\n<cachedir>")
	if err := xml.EscapeText(&cfg, []byte(at)); err != nil {
		fail("%s: %s", at, err)
	}
	cfg.WriteString("</cachedir>\n</fontconfig>\n")
	writeFile(pathJoin(c.staging, "fonts.conf"), []byte(cfg.String()), 0o644)
	rc, text := c.run([]string{"FONTCONFIG_FILE=" + pathJoin(c.staging, "fonts.conf")}, tool, "-s", "-f")
	ran(tool, rc, text)
	names, _ := dirNames(at)
	m := cache{what: "font caches"}
	for _, n := range names {
		if st, err := lstat(pathJoin(at, n)); err == nil && isReg(&st) {
			m.files = append(m.files, [2]string{pathJoin(at, n), dir + "/" + n})
		}
	}
	if len(m.files) == 0 {
		return nil
	}
	return []cache{m}
}

// inPlaceDirs are the tree's directories generators write in place, at fixed paths its packages'
// links name, by virtual path; a directory moved aside waits as keep/N, N its index here, and
// nothing else is ever moved, so that a keep/ an exclave arrives with can move nothing elsewhere.
// No one of them lies inside another.
var inPlaceDirs = []string{"/var/lib/texmf", "/etc/texmf/web2c"}

// inPlace is the run of generators that write their caches in place, so that neither a staging
// directory nor a mirror stands in for the path: each directory they write is, for the run, moved
// aside into keep and replaced in the tree by a link to a copy of it in the staging directory,
// staging/inplace/N, which is the host's (8.1 rule 6), so that inside the exclave the path, and
// every link into it, leads to the copy, where the generators write. The directories are put back
// as the run ends: when it succeeds, on a refusal, on SIGINT, SIGTERM or SIGHUP, and on a panic
// (exit1); a run killed otherwise leaves them aside, and the next run puts them back before
// anything else (restoreInPlace), while check and wrap refuse the exclave meanwhile
// (refuseSetAside). What the generators made is then placed in the tree with the other caches. A
// generator that names a file by its real path sees the copy's host path, so a step that matches
// paths against the tree's is followed by one that does not (texLive's last mktexlsr).
type inPlace struct {
	root, staging string
	dirs          []int    // indices into inPlaceDirs
	copies        []string // the copy each is linked to in the run
}

// keepDir is where a directory moved aside waits in the staging directory, beside a file naming
// its virtual path, until it is put back.
func keepDir(staging string) string { return pathJoin(staging, "keep") }

// copyOf is the copy the tree's path of inPlaceDirs[n] is linked to during a run.
func copyOf(staging string, n int) string { return pathJoin(staging, "inplace/"+strconv.Itoa(n)) }

// copyDir copies the directory src to dst, which it makes: directories, regular files by their
// bytes and links by their text, never a hard link, since a generator that rewrites a file in
// place would edit the tree's through it (6.1).
func copyDir(src, dst string) {
	st, err := lstat(src)
	if err != nil {
		failErrno(src, err)
	}
	if err := os.Mkdir(dst, os.FileMode(st.Mode&0o777)); err != nil {
		failErrno(dst, err)
	}
	names, err := dirNames(src)
	if err != nil {
		failErrno(src, err)
	}
	for _, n := range names {
		s, d := pathJoin(src, n), pathJoin(dst, n)
		st, err := lstat(s)
		if err != nil {
			failErrno(s, err)
		}
		switch {
		case isDirM(&st):
			copyDir(s, d)
		case isReg(&st):
			writeFile(d, readFile(s), st.Mode&0o777)
		case st.Mode&unix.S_IFMT == unix.S_IFLNK:
			t, err := os.Readlink(s)
			if err != nil {
				failErrno(s, err)
			}
			if err := unix.Symlink(t, d); err != nil {
				failErrno(d, err)
			}
		}
	}
}

// open moves each directory aside and links its path to a copy, once putting them back is
// registered: N.path is written before the directory moves, so that every point a run can be
// killed at leaves what restoreInPlace undoes.
func (p *inPlace) open() {
	for i, a := range inPlaceDirs {
		for _, b := range inPlaceDirs[:i] {
			if a == b || strings.HasPrefix(a+"/", b+"/") || strings.HasPrefix(b+"/", a+"/") {
				panic("inPlaceDirs overlap: " + a + ", " + b)
			}
		}
	}
	keep := keepDir(p.staging)
	makeDirs(keep)
	makeDirs(pathJoin(p.staging, "inplace"))
	atFail(p.close)
	inPlaceBegun()
	for _, n := range p.dirs {
		v, num := inPlaceDirs[n], strconv.Itoa(n)
		real, cp := treeReal(p.root, v), copyOf(p.staging, n)
		copyDir(real, cp)
		writeFile(pathJoin(keep, num+".path"), []byte(v), 0o644)
		if err := unix.Rename(real, pathJoin(keep, num)); err != nil {
			failErrno(real, err)
		}
		if err := unix.Symlink(cp, real); err != nil {
			failErrno(real, err)
		}
		p.copies = append(p.copies, cp)
	}
}

// close puts every directory moved aside back; a second call does nothing.
func (p *inPlace) close() { restoreInPlace(p.root, p.staging) }

// keepEntries are the names in keep/, none when there is no keep/.
func keepEntries(staging string) []string {
	names, _ := dirNames(keepDir(staging))
	return names
}

// restoreInPlace puts back each directory a run moved aside into keep/, as a run killed before
// it could leaves them, and reports how many. Only what open makes is accepted, since keep/
// arrives with the exclave: N and N.path, N an index of inPlaceDirs and N.path its path exactly,
// whose directories in the tree are no links, keep/N a directory by lstat, and the tree's path
// absent or the link open made, to staging/inplace/N exactly. Anything else is refused by name,
// and nothing is moved.
func restoreInPlace(root, staging string) int {
	keep := keepDir(staging)
	names := keepEntries(staging)
	for _, name := range names {
		num := strings.TrimSuffix(name, ".path")
		n, err := strconv.Atoi(num)
		if err != nil || n < 0 || n >= len(inPlaceDirs) || strconv.Itoa(n) != num {
			fail("refusing: %s holds %s, which no run of exclave caches makes; remove it by hand", keep, name)
		}
	}
	restored := 0
	for n, v := range inPlaceDirs {
		num := strconv.Itoa(n)
		pathFile, kept := pathJoin(keep, num+".path"), pathJoin(keep, num)
		_, hasPath := lstat(pathFile)
		kst, hasKept := lstat(kept)
		if hasPath != nil && hasKept != nil {
			continue
		}
		if hasPath != nil {
			fail("refusing: %s has no %s naming where it belongs; remove it by hand", kept, pathFile)
		}
		if string(readFile(pathFile)) != v {
			fail("refusing: %s names %q, not %s; remove %s by hand", pathFile, string(readFile(pathFile)), v, keep)
		}
		if treeResolve(root, dirnameOf(v), true, nil) != dirnameOf(v) {
			fail("refusing: %s's directory is a link in the tree, so %s cannot be put back there", v, kept)
		}
		real := treeReal(root, v)
		st, errReal := lstat(real)
		if hasKept != nil {
			// killed before the directory moved: it is still in the tree
			if errReal != nil || !isDirM(&st) {
				fail("refusing: %s names %s, which is neither in the tree nor aside in %s", pathFile, v, keep)
			}
			if err := unix.Unlink(pathFile); err != nil {
				failErrno(pathFile, err)
			}
			continue
		}
		if !isDirM(&kst) {
			fail("refusing: %s is not a directory; remove %s by hand", kept, keep)
		}
		if errReal == nil {
			t, err := os.Readlink(real)
			if err != nil || t != copyOf(staging, n) {
				fail("refusing: both %s and the copy kept aside, %s, exist; put one back by hand", real, kept)
			}
			if err := unix.Unlink(real); err != nil {
				failErrno(real, err)
			}
		}
		if err := unix.Rename(kept, real); err != nil {
			failErrno(real, err)
		}
		if err := unix.Unlink(pathFile); err != nil {
			failErrno(pathFile, err)
		}
		restored++
	}
	unix.Rmdir(keep)
	return restored
}

// removeStaging removes the staging directory, but never a keep/ that holds an entry, whose
// directory belongs in the tree: the rest goes, and where it waits is said.
func removeStaging(staging string) {
	if len(keepEntries(staging)) == 0 {
		if err := os.RemoveAll(staging); err != nil {
			failErrno(staging, err)
		}
		return
	}
	names, _ := dirNames(staging)
	for _, n := range names {
		if n != "keep" {
			os.RemoveAll(pathJoin(staging, n))
		}
	}
	fmt.Fprintf(os.Stderr, "exclave: the tree's directories set aside wait in %s; exclave caches puts them back\n",
		keepDir(staging))
}

// refuseSetAside refuses a command on an exclave whose tree has directories set aside by a run of
// exclave caches that did not end, so that nothing records the tree as it stands then.
func refuseSetAside(ex, cmd string) {
	if keep := keepDir(pathJoin(ex, ".exclave/caches")); len(keepEntries(pathJoin(ex, ".exclave/caches"))) > 0 {
		fail("refusing to %s: a run of exclave caches that did not end set directories of the tree aside in %s; "+
			"exclave caches %s puts them back", cmd, keep, ex)
	}
}

// made is every regular file and link under the copies, as the files and links the tree's
// directories get; a link keeps its text, which updmap-sys writes relative. A link to the copy,
// by either spelling of the staging directory, is refused: the tree cannot hold it.
func (p *inPlace) made(what string) cache {
	m := cache{what: what}
	spellings := []string{p.staging + "/"}
	if r, err := filepath.EvalSymlinks(p.staging); err == nil && r != p.staging {
		spellings = append(spellings, r+"/")
	}
	for i, cp := range p.copies {
		err := filepath.WalkDir(cp, func(f string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			v := inPlaceDirs[p.dirs[i]] + strings.TrimPrefix(f, cp)
			switch {
			case d.Type().IsRegular():
				m.files = append(m.files, [2]string{f, v})
			case d.Type()&os.ModeSymlink != 0:
				t, err := os.Readlink(f)
				if err != nil {
					return err
				}
				for _, s := range spellings {
					if strings.HasPrefix(t+"/", s) {
						fail("%s: the generators made %s a link to the copy, %s, which the tree cannot hold",
							what, v, t)
					}
				}
				m.links = append(m.links, [2]string{t, v})
			}
			return nil
		})
		if err != nil {
			fail("%s: %s", cp, errnoText(err))
		}
	}
	return m
}

// texLive makes TeX Live's configuration, file indexes, font maps and formats as tex-common's
// postinst makes them on Debian, by its own steps in its order: update-texmf writes
// /etc/texmf/web2c/texmf.cnf; update-updmap, update-fmtutil and update-language the
// configuration and hyphenation files under /var/lib/texmf, which the packages' links name
// (texmf-dist's web2c/fmtutil.cnf is /var/lib/texmf/fmtutil.cnf-TEXLIVEDIST); mktexlsr the ls-R
// indexes, the distribution's trees' through their links into /var/lib/texmf; updmap-sys the font
// maps; and fmtutil every format. Without them pdflatex finds no format and kpathsea, which
// searches the distribution's trees only through their ls-R, no file. Both directories are
// written in place (inPlace). fmtutil adds each format to the ls-R of the tree it names the
// format in, and names it by the copy's real path, in no tree, so a last mktexlsr indexes
// /var/lib/texmf with the formats. What the steps say is printed only when one fails, since
// fmtutil's runs are long.
func texLive(c *cacheRun, root string) []cache {
	for _, t := range []string{"/usr/sbin/update-texmf", "/usr/sbin/update-updmap", "/usr/sbin/update-fmtutil",
		"/usr/sbin/update-language", "/usr/bin/mktexlsr", "/usr/bin/updmap-sys", "/usr/bin/fmtutil"} {
		if findTool(root, t) == "" {
			return nil
		}
	}
	for _, d := range inPlaceDirs {
		if v := treeDir(root, d); v == "" {
			return nil
		} else if v != d {
			fmt.Fprintf(out, "TeX Live: %s is a link in the tree, to %s, which is not written in place; "+
				"none made\n", d, v)
			return nil
		}
	}
	p := &inPlace{root: root, staging: c.staging, dirs: []int{0, 1}}
	p.open()
	// the postinst's locale; the date fixed, so that a pdfTeX format is the same on every run
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "SOURCE_DATE_EPOCH=0",
		"FORCE_SOURCE_DATE=1"}
	for _, argv := range [][]string{
		{"/usr/sbin/update-texmf"},
		{"/usr/sbin/update-updmap", "--quiet"},
		{"/usr/sbin/update-fmtutil", "--quiet"},
		{"/usr/sbin/update-language", "--quiet"},
		{"/usr/bin/mktexlsr", "/var/lib/texmf", "/usr/share/texmf", "/usr/share/texlive/texmf-dist"},
		{"/usr/bin/updmap-sys", "--nohash"},
		{"/usr/bin/fmtutil", "--sys", "--strict", "--no-error-if-no-engine=luajittex,mfluajit,luajithbtex", "--all"},
		{"/usr/bin/mktexlsr", "/var/lib/texmf"},
	} {
		if rc, text := c.run(env, argv...); rc != 0 {
			fail("%s exited %d: %s", strings.Join(argv, " "), rc, lastLines(text, 20))
		}
	}
	p.close()
	return []cache{p.made("TeX Live's configuration, indexes and formats")}
}

// lockExclave holds an exclusive lock on the exclave's .exclave/ for the rest of the process, so
// that two runs of exclave caches never share a staging directory; a second is refused.
func lockExclave(ex string) {
	d := pathJoin(ex, ".exclave")
	fd, err := unix.Open(d, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		failErrno(d, err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		fail("refusing: another exclave caches runs on %s (%s is locked)", ex, d)
	}
}

// inPlaceBegun makes SIGINT, SIGTERM and SIGHUP end the command as a refusal does, from the
// moment a generator first sets a directory of the tree aside, so that it is put back (exit1):
// the signal ends the generator running, whose process group is its own, and the command fails
// as its run returns, or at the next one, on its own goroutine, which alone runs exit1.
func inPlaceBegun() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, unix.SIGINT, unix.SIGTERM, unix.SIGHUP)
	go func() {
		sig := <-ch
		interruptMu.Lock()
		interrupted = sig
		if runningPgid > 0 {
			unix.Kill(-runningPgid, unix.SIGKILL)
		}
		interruptMu.Unlock()
	}()
}

// lastLines is the last n lines of text.
func lastLines(text string, n int) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

// notOlder gives the directory holding the file real the file's modification time where its own
// is later.
func notOlder(real string) {
	f, err := stat(real)
	if err != nil {
		failErrno(real, err)
	}
	dir := dirnameOf(real)
	d, err := stat(dir)
	if err != nil {
		failErrno(dir, err)
	}
	if d.Mtim.Nano() > f.Mtim.Nano() {
		ts := []unix.Timespec{{Nsec: unix.UTIME_OMIT}, f.Mtim}
		if err := unix.UtimesNanoAt(unix.AT_FDCWD, dir, ts, 0); err != nil {
			failErrno(dir, err)
		}
	}
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
	staging := pathJoin(ex, ".exclave/caches")
	lockExclave(ex)
	// a run killed while generators wrote in place left their directories aside: put them back first
	if n := restoreInPlace(root, staging); n > 0 {
		fmt.Fprintf(out, "%s: %s a killed run left aside put back\n", ex, plural(n, "directory"))
	}
	if rec := find(loadHashes(pathJoin(ex, ".exclave/hashes")), "tree"); treeHash(root) != rec.f[0].v {
		fail("refusing: %s's tree differs from the hash its hashes file records; exclave check reports it, and "+
			"exclave wrap records the tree as it is", ex)
	}
	sh := findTool(root, "/bin/sh")
	if sh == "" {
		fail("refusing: %s has no /bin/sh to run its generators by", ex)
	}
	removeStaging(staging)
	atFail(func() { removeStaging(staging) })
	makeDirs(staging)
	// a panic in a generator's run still puts the tree's directories back (exit1)
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "exclave: panic: %v\n%s", r, debug.Stack())
			exit1()
		}
	}()
	c := &cacheRun{sh: treeReal(root, sh), staging: staging}
	var made []cache
	for _, g := range []func(*cacheRun, string) []cache{pythonBytecode, gsettingsSchemas, mimeDatabase, gioModules,
		pixbufLoaders, iconCaches, desktopDatabase, fontCaches, graphvizPlugins, texLive} {
		made = append(made, g(c, root)...)
	}
	if len(made) == 0 {
		removeStaging(staging)
		fmt.Fprintf(out, "%s: no generator applies: the tree holds none of the programs exclave caches runs\n", ex)
		return 0
	}
	// a generator that exits 0 and writes nothing fails here, before the tree changes
	for _, m := range made {
		for _, f := range m.files {
			if st, err := os.Lstat(f[0]); err != nil || !st.Mode().IsRegular() {
				fail("%s: the generator made no %s", m.what, f[1])
			}
		}
	}
	checkInterrupted()
	// every generator has succeeded: now the tree changes
	for _, m := range made {
		changed := 0
		for _, f := range m.files {
			dest := treeDest(root, f[1])
			if placeFile(dest, readFile(f[0])) {
				changed++
			}
			if m.dirTimes {
				notOlder(dest)
			}
		}
		for _, l := range m.links {
			if placeLink(treeDest(root, l[1]), l[0]) {
				changed++
			}
		}
		n := plural(len(m.files), "file")
		if len(m.links) > 0 {
			n += " and " + plural(len(m.links), "link")
		}
		fmt.Fprintf(out, "%s: %s, %d new or changed\n", m.what, n, changed)
	}
	removeStaging(staging)
	writeHashes(ex, "", false, true)
	fmt.Fprintf(out, "%s: the tree hash recorded\n", ex)
	return 0
}
