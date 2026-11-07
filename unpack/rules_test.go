package unpack

import (
	"slices"
	"strings"
	"testing"
)

func TestUnrollLoops(t *testing.T) {
	got, ok := unrollLoops("for p in a b; do\n  echo $p ${p}x\ndone\n")
	if !ok || strings.Count(got, "echo") != 2 || !strings.Contains(got, "echo a ax") ||
		!strings.Contains(got, "echo b bx") {
		t.Fatalf("a literal loop: %q %v", got, ok)
	}
	if got, ok := unrollLoops("for p in $X; do echo $p; done"); !ok || !strings.Contains(got, "for p in $X") {
		t.Fatalf("a loop over a variable is left: %q %v", got, ok)
	}
	// eight nested loops of ten words would make about a hundred million copies: refused, not built
	var b strings.Builder
	for i := range 8 {
		b.WriteString("for v" + string(rune('a'+i)) + " in 0 1 2 3 4 5 6 7 8 9; do\n")
	}
	b.WriteString("echo $va$vb$vc$vd$ve$vf$vg$vh\n")
	b.WriteString(strings.Repeat("done\n", 8))
	if _, ok := unrollLoops(b.String()); ok {
		t.Fatal("nested loops past the bound are unrolled")
	}
	// one loop with a long word in place of many references
	long := "for w in " + strings.Repeat("x", 4096) + "; do " + strings.Repeat("$w", 1000) + "; done"
	if _, ok := unrollLoops(long); ok {
		t.Fatal("a word in place of many references past the bound is unrolled")
	}
	many := strings.Repeat("for w in a; do echo $w; done\n", unrollsMax+1)
	if _, ok := unrollLoops(many); ok {
		t.Fatal("more loops than the bound are unrolled")
	}
}

func TestLiteralDiversion(t *testing.T) {
	for _, c := range []struct {
		line, key, to string
		ok            bool
	}{
		{"dpkg-divert --package pg --rename --divert /usr/bin/x.o --add /usr/bin/x", "usr/bin/x", "usr/bin/x.o",
			true},
		{"dpkg-divert --package=pg --divert=/lib/y.o /lib/y", "usr/lib/y", "lib/y.o", true},
		{"dpkg-divert --package other --rename --divert /usr/bin/x.o /usr/bin/x", "", "", false},
		{"dpkg-divert --local --rename --divert /usr/bin/x.o /usr/bin/x", "", "", false},
		{`dpkg-divert --package pg --divert "$1.o" "$1"`, "", "", false},
		{"dpkg-divert --package pg --divert /a/../../b /c", "", "", false},
	} {
		key, to, ok := literalDiversion(c.line, "pg")
		if key != c.key || to != c.to || ok != c.ok {
			t.Errorf("%q: %q %q %v, want %q %q %v", c.line, key, to, ok, c.key, c.to, c.ok)
		}
	}
}

func FuzzUnrollLoops(f *testing.F) {
	f.Add("for p in a b; do echo $p; done")
	f.Add("for a in 1 2; do for b in x y; do echo $a$b; done; done")
	f.Fuzz(func(t *testing.T, text string) {
		if got, ok := unrollLoops(text); ok && len(got) > unrolledMax+len(text) {
			t.Fatalf("unrolled to %d bytes", len(got))
		}
	})
}

func FuzzLiteralDiversion(f *testing.F) {
	f.Add("dpkg-divert --package pg --rename --divert /usr/bin/x.o --add /usr/bin/x")
	f.Add("dpkg-divert --package=pg --divert=/lib/y.o /lib/y")
	f.Fuzz(func(t *testing.T, line string) {
		if !strings.Contains(line, "dpkg-divert") {
			return
		}
		key, to, ok := literalDiversion(line, "pg")
		parts := strings.Split(key+"/"+to, "/")
		if ok && (key == "" || to == "" || strings.HasPrefix(key, "/") || slices.Contains(parts, "..")) {
			t.Fatalf("%q: %q %q", line, key, to)
		}
	})
}
