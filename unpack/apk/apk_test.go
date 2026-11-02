package apk

import "testing"

func TestVercmp(t *testing.T) {
	// apk-tools' order: each pair sorts a before b
	for _, c := range [][2]string{
		{"1.0", "1.0-r1"}, {"1.0_rc1", "1.0"}, {"1.0", "1.0_p1"}, {"1.0", "1.0a"}, {"1.9", "1.10"},
		{"1.0_alpha", "1.0_beta"}, {"1.0_rc1", "1.0_rc2"}, {"1.0-r1", "1.0-r2"}, {"3.21.0", "3.21.0.1"},
		{"14.2.0-r4", "14.2.0-r5"}, {"1.0_alpha1", "1.0_alpha2"},
	} {
		if Vercmp(c[0], c[1]) >= 0 || Vercmp(c[1], c[0]) <= 0 {
			t.Errorf("%s should sort before %s", c[0], c[1])
		}
	}
	if Vercmp("1.0", "1.0") != 0 || Vercmp("1.0-r0", "1.0") != 0 {
		t.Error("equal versions compare unequal")
	}
	for _, c := range []struct {
		v, op, want string
		ok          bool
	}{
		{"1.2.3", "~", "1.2", true}, {"1.2.3", "~", "1.2.3", true}, {"1.20", "~", "1.2", false},
		{"1.2", ">=", "1.2", true}, {"1.2", ">", "1.2", false}, {"1.2", "", "", true}, {"1.2", "><", "9", true},
	} {
		if Satisfies(c.v, c.op, c.want) != c.ok {
			t.Errorf("%s %s %s should be %v", c.v, c.op, c.want, c.ok)
		}
	}
}

func TestParseDeps(t *testing.T) {
	got, err := ParseDeps("so:libc.musl-x86_64.so.1 zlib>=1.2 !conflict /bin/sh cmd:[ pc:zlib=1.3")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 || got[0][0].Name != "so:libc.musl-x86_64.so.1" || got[1][0].Op != ">=" ||
		got[1][0].Version != "1.2" || got[2][0].Name != "/bin/sh" || got[3][0].Name != "cmd:[" ||
		got[4][0].Version != "1.3" {
		t.Errorf("got %v", got)
	}
	if _, err := ParseDeps(">x"); err == nil {
		t.Error("`>x` is not a dependency")
	}
}
