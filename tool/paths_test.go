package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTreeRealDir holds treeRealDir to the launcher's tree_real_of (src/vis.c, 8.4): a directory
// as the tree resolves it, a missing component taken as a directory to be made, and no place for
// a file on the way, a loop or a directory under a volatile one.
func TestTreeRealDir(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tree")
	if err := os.MkdirAll(filepath.Join(root, "etc", "c"), 0o755); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"etc/a":   "b",
		"etc/b":   "c",
		"etc/r":   "../usr/share/real",
		"etc/abs": "/opt/pki",
		"etc/l1":  "l2",
		"etc/l2":  "l1",
		"etc/d":   "/srv/new/deeper",
		"etc/run": "/run/x",
	}
	for name, text := range links {
		if err := os.Symlink(text, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(root, "etc", "file"), []byte("F"))
	for _, c := range []struct {
		dir, want string
		placed    bool
	}{
		{"/etc/a/x", "/etc/c/x", true},              // a chain of several hops
		{"/etc/r/sub", "/usr/share/real/sub", true}, // relative text with ..
		{"/etc/abs/tls", "/opt/pki/tls", true},      // absolute text, its target made
		{"/etc/d", "/srv/new/deeper", true},         // a dangling link, its target made
		{"/etc/l1/x", "", false},                    // a loop
		{"/etc/file/x", "", false},                  // a file on the way
		{"/etc/run", "", false},                     // under a volatile directory, the host's
		{"/etc/c/../c", "/etc/c", true},             // .. in the path itself
	} {
		got, why := treeRealDir(root, c.dir)
		if (why == "") != c.placed || got != c.want {
			t.Errorf("treeRealDir(%q) = %q, %q; want %q, placed %v", c.dir, got, why, c.want, c.placed)
		}
	}
}
