package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

// TestTreeHash states 6.4 and holds treeHash to it: one entry per file, directory and link,
// kind and content or target, a wrapper standing for its original, sorted by bytes and hashed.
func TestTreeHash(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tree")
	write(t, filepath.Join(root, "a"), []byte("A"))
	write(t, filepath.Join(root, "d", "new\nline"), []byte("N"))
	write(t, filepath.Join(root, "usr", "bin", "w"), []byte("launcher"))
	if err := os.Chmod(filepath.Join(root, "usr", "bin", "w"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "usr", "bin", ".real", "w"), []byte("W"))
	write(t, filepath.Join(root, "usr", "bin", ".real", "stray"), []byte("S"))
	if err := os.Symlink("\xfe/x", filepath.Join(root, "l")); err != nil {
		t.Fatal(err)
	}
	hex := func(s string) string { d := blake2b.Sum256([]byte(s)); return fmt.Sprintf("%x", d[:]) }
	lines := []string{
		"a\x00f\x00" + hex("A") + "\x00",
		"d\x00d\x00\x00",
		"d/new\nline\x00f\x00" + hex("N") + "\x00",
		"usr\x00d\x00\x00",
		"usr/bin\x00d\x00\x00",
		"usr/bin/w\x00x\x00" + hex("W") + "\x00",
		"usr/bin/.real/stray\x00f\x00" + hex("S") + "\x00",
		"l\x00l\x00\xfe/x\x00",
	}
	sort.Slice(lines, func(i, j int) bool { return bytes.Compare([]byte(lines[i]), []byte(lines[j])) < 0 })
	h, _ := blake2b.New256(nil)
	for _, l := range lines {
		h.Write([]byte(l))
	}
	want := "b2:" + fmt.Sprintf("%x", h.Sum(nil))
	if got := treeHash(root); got != want {
		t.Errorf("treeHash: %s, stated %s", got, want)
	}
}

func TestResolve(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tree")
	write(t, filepath.Join(root, "usr", "lib", "libc.so.6"), []byte("c"))
	for link, target := range map[string]string{"lib": "usr/lib", "usr/lib/libx.so": "libc.so.6", "loop": "loop2",
		"loop2": "loop", "abs": "/usr/lib/../lib/libx.so", "gone": "nowhere"} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		v      string
		follow bool
		want   string
		links  int
	}{
		{"/lib/libx.so", true, "/usr/lib/libc.so.6", 2},
		{"/lib/libx.so", false, "/usr/lib/libx.so", 1},
		{"/lib/../lib/./libc.so.6", true, "/usr/lib/libc.so.6", 1},
		{"//usr//lib/", true, "/usr/lib", 0},
		{"/", true, "/", 0},
		{"/loop", true, "", 0},
		{"/abs", true, "/usr/lib/libc.so.6", 2},
		{"/gone", true, "", 0},
		{"/gone", false, "/gone", 0},
		{"/usr/missing/..", true, "", 0},
	} {
		var links []string
		got := treeResolve(root, c.v, c.follow, &links)
		if got != c.want || (got != "" && len(links) != c.links) {
			t.Errorf("%s follow=%v: %q through %v", c.v, c.follow, got, links)
		}
	}
}

func TestPathSpelling(t *testing.T) {
	for _, c := range [][2]string{{"", "."}, {"/", "/"}, {"//a", "//a"}, {"///a", "/a"}, {"a//b/./c/..", "a/b"},
		{"/..", "/"}, {"..", ".."}, {"../../x", "../../x"}, {"a/../..", ".."}, {"/a/b/", "/a/b"}} {
		if got := normpath(c[0]); got != c[1] {
			t.Errorf("normpath(%q) = %q, wanted %q", c[0], got, c[1])
		}
	}
	for _, c := range [][2]string{{"/a/b", "/a"}, {"/a", "/"}, {"a", ""}, {"//a", "//"}, {"/a/b/", "/a/b"},
		{"a/b", "a"}} {
		if got := dirnameOf(c[0]); got != c[1] {
			t.Errorf("dirnameOf(%q) = %q, wanted %q", c[0], got, c[1])
		}
	}
	for _, c := range [][3]string{{"/a/b/c", "/a", "b/c"}, {"/a", "/a/b", ".."}, {"/x", "/a/b", "../../x"},
		{"/a", "/a", "."}} {
		if got := relpath(c[0], c[1]); got != c[2] {
			t.Errorf("relpath(%q, %q) = %q, wanted %q", c[0], c[1], got, c[2])
		}
	}
	for _, c := range []struct {
		v, prefix string
		want      bool
	}{{"/usr/lib", "/usr", true}, {"/usr", "/usr/", false}, {"/usr/", "/usr", true}, {"/usrx", "/usr", false},
		{"/a", "/", true}, {"/", "/", true}} {
		if got := under(c.v, c.prefix); got != c.want {
			t.Errorf("under(%q, %q) = %v", c.v, c.prefix, got)
		}
	}
}

// TestListing holds the listing to the disk's answers: every walk the same, in the same order,
// every original found where payloadPath finds it, and the ELF magic the tree hash notes as the
// files' own first bytes; on a tree with originals, a stray, a .real/ that is a link and a
// directory that cannot be read.
func TestListing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tree")
	write(t, filepath.Join(root, "usr", "bin", "w"), []byte("launcher"))
	write(t, filepath.Join(root, "usr", "bin", ".real", "w"), []byte("\x7fELF and the rest"))
	write(t, filepath.Join(root, "usr", "bin", ".real", "stray"), []byte("S"))
	write(t, filepath.Join(root, "usr", "share", "short"), []byte("\x7fEL"))
	write(t, filepath.Join(root, "usr", "share", "deep", "x", "y"), []byte("Y"))
	write(t, filepath.Join(root, "elsewhere", "o"), []byte("O"))
	write(t, filepath.Join(root, "opt", "o"), []byte("link's"))
	write(t, filepath.Join(root, "shut", "z"), []byte("Z"))
	if err := os.Symlink("../elsewhere", filepath.Join(root, "opt", ".real")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "shut"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(root, "shut"), 0o755) })
	l := listTree(root)
	walk := func(l *listing) []string {
		var seen []string
		l.walkFiles(root, func(real, v string, st *unix.Stat_t) {
			seen = append(seen, fmt.Sprintf("%s %s %o %s", real, v, st.Mode, l.payload(real)))
		})
		l.walkDirsAt(root, "", false, func(dir, rel string, e []entryInfo) { seen = append(seen, "dir "+dir) })
		return append(seen, l.strays(root)...)
	}
	disk, listed := walk(nil), walk(l)
	if fmt.Sprint(disk) != fmt.Sprint(listed) {
		t.Errorf("the listing's walks differ from the disk's:\n disk   %q\n listed %q", disk, listed)
	}
	for _, p := range []string{"usr/bin/w", "usr/share/short", "opt/o", "usr/bin/.real/stray"} {
		real := filepath.Join(root, p)
		if got, want := l.payload(real), payloadPath(real); got != want {
			t.Errorf("payload(%s) = %s, payloadPath %s", p, got, want)
		}
	}
	if err := os.Chmod(filepath.Join(root, "shut"), 0o755); err != nil { // the tree hash refuses it
		t.Fatal(err)
	}
	l = listTree(root)
	if got, want := l.treeHash(root), treeHash(root); got != want {
		t.Errorf("the listing's tree hash %s, the disk's %s", got, want)
	}
	for v, want := range map[string]bool{"/usr/bin/w": true, "/usr/share/short": false, "/usr/share/deep/x/y": false} {
		if got, ok := l.isELF(v); !ok || got != want {
			t.Errorf("isELF(%s) = %v, %v; the file says %v", v, got, ok, want)
		}
	}
	if _, ok := (*listing)(nil).isELF("/usr/bin/w"); ok {
		t.Errorf("a nil listing knows a file's magic")
	}
}
