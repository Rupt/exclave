// The caches only a tree's own programs can make, made by them inside the exclave (DESIGN.md
// 10.1, 13 item 48): Python's bytecode, GLib's compiled GSettings schemas, the MIME database,
// GIO's module cache, gdk-pixbuf's loader cache, icon caches, the desktop database,
// fontconfig's caches and graphviz's plugin configuration.
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
	"path/filepath"
	"regexp"
	"slices"
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

func (c *cacheRun) exec(env []string, stdout, stderr io.Writer, argv []string) int {
	cmd := &exec.Cmd{Path: c.sh, Args: append([]string{"sh", "-c", `exec "$0" "$@"`}, argv...)}
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + c.staging, "TMPDIR=" + c.staging}, env...)
	cmd.Dir = c.staging
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
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
// the tree it becomes; with dirTimes, the directory it lands in is made no newer than it.
type cache struct {
	what     string
	files    [][2]string
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

// iconCaches writes icon-theme.cache for each theme under /usr/share/icons with an index.theme,
// which an icon lookup reads in place of walking the theme's directories; the generator runs on
// a mirror of the theme, since it writes into it. GTK takes a cache older than its theme's
// directory for stale, so the directory gets the cache's time where its own is later, as the
// generator gives it. A theme whose index names no directory of icons, as the cursor theme
// /usr/share/icons/default does, gets no cache from the generator, which then writes none, and
// none is made, as the maintainer script makes none.
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
		if theme == "" || slices.Contains(seen, theme) || treeResolve(root, theme+"/index.theme", true, nil) == "" {
			continue
		}
		seen = append(seen, theme)
		at := pathJoin(c.staging, "icons/"+strconv.Itoa(len(seen)))
		mirror(root, theme, at, func(n string) bool { return n != "icon-theme.cache" })
		rc, text := c.run(nil, tool, "-q", "-t", "-f", at)
		ran(tool, rc, text)
		if !lexists(pathJoin(at, "icon-theme.cache")) {
			continue
		}
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
	for _, g := range []func(*cacheRun, string) []cache{pythonBytecode, gsettingsSchemas, mimeDatabase, gioModules,
		pixbufLoaders, iconCaches, desktopDatabase, fontCaches, graphvizPlugins} {
		made = append(made, g(c, root)...)
	}
	if len(made) == 0 {
		os.RemoveAll(staging)
		fmt.Fprintf(out, "%s: no generator applies: the tree holds none of the programs exclave caches runs\n", ex)
		return 0
	}
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
		fmt.Fprintf(out, "%s: %s, %d new or changed\n", m.what, plural(len(m.files), "file"), changed)
	}
	if err := os.RemoveAll(staging); err != nil {
		failErrno(staging, err)
	}
	writeHashes(ex, "", false, true)
	fmt.Fprintf(out, "%s: the tree hash recorded\n", ex)
	return 0
}
