package root

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tree makes a tree beside a sentinel directory, which no operation may touch, and returns both.
func tree(t *testing.T) (*Root, string) {
	t.Helper()
	d := t.TempDir()
	host := filepath.Join(d, "host")
	if err := os.MkdirAll(host, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(host, "secret"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(d, "tree"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := Open(filepath.Join(d, "tree"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r, host
}

func hostUnchanged(t *testing.T, host string) {
	t.Helper()
	entries, err := os.ReadDir(host)
	if err != nil || len(entries) != 1 || entries[0].Name() != "secret" {
		t.Fatalf("the host directory changed: %v %v", entries, err)
	}
	if data, _ := os.ReadFile(filepath.Join(host, "secret")); string(data) != "s" {
		t.Fatal("the host's file changed")
	}
}

// TestEscapesStayInside: an absolute link starts at the tree's root, `..` stops there, and every
// write through them lands inside, whatever the packages ship.
func TestEscapesStayInside(t *testing.T) {
	r, host := tree(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(r.Makedirs("usr/share"))
	must(r.Symlink("../../../../host", "usr/share/doc"))
	must(r.Symlink(host, "opt"))
	must(r.Symlink("/", "slash"))
	must(r.WriteBytes("usr/share/doc/x", []byte("x"), 0o644))
	must(r.WriteBytes("opt/y", []byte("y"), 0o644))
	must(r.Makedirs("slash/etc/deep"))
	must(r.WriteBytes("a", []byte("a"), 0o644))
	must(r.Link("opt/y", "usr/z"))
	// an absolute link starts at the tree's root: the host's whole path is made inside the tree
	for _, p := range []string{"host/x", host + "/y", "etc/deep", "usr/z"} {
		if !r.Lexists(p) {
			t.Errorf("%s did not land in the tree", p)
		}
	}
	must(r.Makedirs("x"))
	if err := r.Link("opt/secret", "copy"); err == nil || !strings.Contains(err.Error(), "does not hold") {
		t.Errorf("a hard link through an absolute link to the host: %v", err)
	}
	must(r.Remove("opt/y"))
	must(r.Rmtree("host"))
	if err := r.Rmtree("x/.."); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("x/.. names the root and must be refused: %v", err)
	}
	hostUnchanged(t, host)
}

func TestLoopsAndDepth(t *testing.T) {
	r, host := tree(t)
	if err := r.Symlink("b", "a"); err != nil {
		t.Fatal(err)
	}
	if err := r.Symlink("a", "b"); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteBytes("a/x", []byte("x"), 0o644); err == nil || !strings.Contains(err.Error(), "ELOOP") {
		t.Errorf("a loop of links: %v", err)
	}
	// a chain of exactly 40 links resolves; 41 do not
	for i := 0; i < 41; i++ {
		target := "end"
		if i > 0 {
			target = "l" + string(rune('0'+i-1)) + "x"
		}
		_ = target
	}
	if err := r.WriteBytes("end", []byte("e"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := "end"
	for i := 0; i < 41; i++ {
		name := strings.Repeat("c", i+1)
		if err := r.Symlink(prev, name); err != nil {
			t.Fatal(err)
		}
		prev = name
	}
	if !r.Exists(strings.Repeat("c", 40)) {
		t.Error("40 links must resolve")
	}
	if r.Exists(strings.Repeat("c", 41)) {
		t.Error("41 links must not resolve")
	}
	// a path deeper than the descriptors kept, then a hard link across the eviction
	deep := strings.TrimSuffix(strings.Repeat("d/", 70), "/")
	if err := r.WriteBytes(deep+"/f", []byte("f"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.Link(deep+"/f", "top"); err != nil {
		t.Fatal(err)
	}
	if !r.IsFile("top") || !r.IsFile(deep+"/f") {
		t.Error("the deep file and its link")
	}
	var pe *os.PathError
	if err := r.Remove("missing/x"); !errors.As(err, &pe) || !errors.Is(err, ErrMissing) || !strings.Contains(err.Error(), "missing/x") {
		t.Errorf("a missing path names itself: %v", err)
	}
	hostUnchanged(t, host)
}

func TestDecode(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain", "plain"},
		{"\xe2\x82a", "�a"},     // a truncated three-byte sequence: one replacement
		{"\xf0\x9f\x98", "�"},   // a truncated four-byte sequence
		{"\xff\xff", "��"},      // two bytes that lead nothing
		{"\xe0\x80\x80", "���"}, // an overlong lead: no continuation is valid for E0 80
		{"a\xc3", "a�"},
	} {
		if got := decode([]byte(c.in)); got != c.want {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
}
