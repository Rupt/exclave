package deb

import (
	"testing"

	"exclave/unpack/reader"
)

func TestVercmp(t *testing.T) {
	// dpkg's order (Debian policy 5.6.12): each pair sorts a before b
	for _, c := range [][2]string{
		{"1.0", "1.1"}, {"1.0-1", "1.0-2"}, {"2.0", "1:1.0"}, {"1.0~rc1", "1.0"}, {"1.0", "1.0a"},
		{"1.0-1~", "1.0-1"}, {"2.0", "2.0.1"}, {"1.0", "1.0+dfsg"}, {"1.0-0ubuntu1", "1.0-1"},
		{"13.3.0-6ubuntu2~24.04", "13.3.0-6ubuntu2~24.04.1"}, {"1.9", "1.10"}, {"0:1.0", "1:0.1"},
	} {
		if Vercmp(c[0], c[1]) >= 0 || Vercmp(c[1], c[0]) <= 0 {
			t.Errorf("%s should sort before %s", c[0], c[1])
		}
	}
	if Vercmp("1.0", "0:1.0") != 0 || Vercmp("1.0-1", "1.0-1") != 0 {
		t.Error("equal versions compare unequal")
	}
	if !Satisfies("1.0", "", "") || !Satisfies("1.0", ">=", "1.0") || Satisfies("1.0", ">>", "1.0") || !Satisfies("1.0", "<<", "1.1") {
		t.Error("a constraint is misjudged")
	}
}

func TestParseDeps(t *testing.T) {
	got, err := ParseDeps("a (>= 1) | b, c:any, d (< 2) [amd64] <!nocheck>")
	if err != nil {
		t.Fatal(err)
	}
	d := func(name, op, version string) reader.Dep { return reader.Dep{Name: name, Op: op, Version: version} }
	want := [][]reader.Dep{{d("a", ">=", "1"), d("b", "", "")}, {d("c", "", "")}, {d("d", "<<", "2")}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if len(got[i]) != len(want[i]) {
			t.Fatalf("group %d: got %v", i, got[i])
		}
		for j := range want[i] {
			if got[i][j] != want[i][j] {
				t.Errorf("got %v, want %v", got[i][j], want[i][j])
			}
		}
	}
	if _, err := ParseDeps("a b"); err == nil {
		t.Error("`a b` is not a dependency")
	}
	if got, _ := ParseDeps(""); len(got) != 0 {
		t.Error("an empty field has no dependencies")
	}
}

func TestParseStanzas(t *testing.T) {
	got := ParseStanzas("Package: a\nDescription: one\n two\n\n\nPackage: b\nVersion: 1\n")
	if len(got) != 2 || got[0]["Package"] != "a" || got[0]["Description"] != "one\ntwo" || got[1]["Version"] != "1" {
		t.Errorf("got %v", got)
	}
}
