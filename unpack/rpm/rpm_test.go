package rpm

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestVercmp(t *testing.T) {
	// rpmvercmp's order: each pair sorts a before b
	for _, c := range [][2]string{
		{"1.0", "1.0.1"}, {"1.0~rc1", "1.0"}, {"1.0", "1.0^post"}, {"1.0a", "1.0.1"}, {"2.0", "1:1.0"},
		{"2.17-55", "2.17-326"}, {"1.9", "1.10"}, {"1.0", "1.0a"}, {"2.17-55.el7", "2.17-55.el7_9"},
		{"1.0.1", "1.0.1a"}, {"0.9", "1"},
	} {
		if Vercmp(c[0], c[1]) >= 0 || Vercmp(c[1], c[0]) <= 0 {
			t.Errorf("%s should sort before %s", c[0], c[1])
		}
	}
	// a constraint without a release matches any release
	if Vercmp("1.0-1.el7", "1.0") != 0 || Vercmp("0:1.0", "1.0") != 0 || Vercmp("1.0.a", "1.0a") != 0 {
		t.Error("equal versions compare unequal")
	}
	if !Satisfies("2.17-326.el7", ">=", "2.17") || Satisfies("2.16", ">=", "2.17") || !Satisfies("1", "", "") {
		t.Error("a constraint is misjudged")
	}
}

func TestParseDeps(t *testing.T) {
	got, err := ParseDeps("glibc>=2.17 libc.so.6(GLIBC_2.2.5)(64bit) /bin/sh rtld(GNU_HASH)")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[0][0].Name != "glibc" || got[0][0].Op != ">=" || got[0][0].Version != "2.17" ||
		got[1][0].Name != "libc.so.6(GLIBC_2.2.5)(64bit)" || got[2][0].Name != "/bin/sh" {
		t.Errorf("got %v", got)
	}
	if _, err := ParseDeps("a>=<b"); err == nil {
		t.Error("`a>=<b` is not a dependency")
	}
}

func TestHeaderBudget(t *testing.T) {
	// entries that together decode to more than the data holds are refused
	var index, data []byte
	data = make([]byte, 64)
	for tag := uint32(1000); tag < 1000+64; tag++ {
		e := make([]byte, 16)
		binary.BigEndian.PutUint32(e[0:], tag)
		binary.BigEndian.PutUint32(e[4:], 4)
		binary.BigEndian.PutUint32(e[12:], 16)
		index = append(index, e...)
	}
	raw := append([]byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}, make([]byte, 8)...)
	binary.BigEndian.PutUint32(raw[8:], 64)
	binary.BigEndian.PutUint32(raw[12:], uint32(len(data)))
	raw = append(append(raw, index...), data...)
	if _, _, err := readHeader(bytes.NewReader(raw)); err == nil {
		t.Error("64 entries of 64 bytes over 64 bytes of data were accepted")
	}
	one := append([]byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}, make([]byte, 8)...)
	binary.BigEndian.PutUint32(one[8:], 1)
	binary.BigEndian.PutUint32(one[12:], uint32(len(data)))
	one = append(append(one, index[:16]...), data...)
	if _, _, err := readHeader(bytes.NewReader(one)); err != nil {
		t.Errorf("one entry within the data was refused: %s", err)
	}
}

func TestDeps(t *testing.T) {
	h := Header{
		TagRequireName:    {Strs: []string{"a", "b", "rpmlib(X)", "(c or d)", "e"}},
		TagRequireVersion: {Strs: []string{"1", "", "1", "", "2"}},
		TagRequireFlags:   {Ints: []int64{senseGreater | senseEqual, 0, senseRpmlib | senseEqual, 0, senseLess}},
	}
	got := deps(h, TagRequireName, TagRequireVersion, TagRequireFlags)
	if len(got) != 3 || got[0] != "a>=1" || got[1] != "b" || got[2] != "e<2" {
		t.Errorf("got %v", got)
	}
}
