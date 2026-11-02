package ldcache

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"exclave/unpack/root"
)

func TestFnmatch(t *testing.T) {
	for _, c := range []struct {
		pattern, name string
		want          bool
	}{
		{"*.conf", "a.conf", true}, {"*.conf", "a.confx", false}, {"é*", "éa", true}, {"[!x]a", "ya", true},
		{"[!x]a", "xa", false}, {"[]]", "]", true}, {"[[:digit:]]", "[", false}, {"a?c", "a/c", true},
		{"/usr/share/fonts*", "/usr/share/fonts/truetype", true}, {"[", "[", true},
	} {
		if got := Fnmatch(c.pattern, c.name); got != c.want {
			t.Errorf("Fnmatch(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

// elf64 makes a shared object: one PT_LOAD at offset 0, a PT_DYNAMIC naming a string table and
// the soname given, for the machine given.
func elf64(machine uint16, soname string) []byte {
	const phoff, phnum, dynOff, strOff = 64, 2, 64 + 2*56, 64 + 2*56 + 3*16
	strtab := append([]byte{0}, append([]byte(soname), 0)...)
	data := make([]byte, strOff+len(strtab))
	copy(data, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(data[16:], 3) // ET_DYN
	binary.LittleEndian.PutUint16(data[18:], machine)
	binary.LittleEndian.PutUint64(data[32:], phoff)
	binary.LittleEndian.PutUint16(data[54:], 56)
	binary.LittleEndian.PutUint16(data[56:], phnum)
	ph := data[phoff:]
	binary.LittleEndian.PutUint32(ph[0:], 1) // PT_LOAD, offset 0, vaddr 0x1000, filesz the file
	binary.LittleEndian.PutUint64(ph[16:], 0x1000)
	binary.LittleEndian.PutUint64(ph[32:], uint64(len(data)))
	binary.LittleEndian.PutUint32(ph[56:], 2) // PT_DYNAMIC
	binary.LittleEndian.PutUint64(ph[56+8:], dynOff)
	binary.LittleEndian.PutUint64(ph[56+16:], 0x1000+dynOff)
	binary.LittleEndian.PutUint64(ph[56+32:], 3*16)
	dyn := data[dynOff:]
	binary.LittleEndian.PutUint64(dyn[0:], 5) // DT_STRTAB
	binary.LittleEndian.PutUint64(dyn[8:], 0x1000+strOff)
	binary.LittleEndian.PutUint64(dyn[16:], 14) // DT_SONAME
	binary.LittleEndian.PutUint64(dyn[24:], 1)
	copy(data[strOff:], strtab)
	return data
}

func TestSharedObject(t *testing.T) {
	obj, ok := SharedObject(elf64(EMX8664, "libx.so.1"), EMX8664)
	if !ok || obj.Soname != "libx.so.1" || !obj.HasSoname || obj.Flags != flagElfLibc6|flagX8664Lib64 {
		t.Errorf("got %+v %v", obj, ok)
	}
	obj, ok = SharedObject(elf64(EMAarch64, "libm.so.6"), EMAarch64)
	if !ok || obj.Flags != flagElfLibc6|flagAarch64Lib64 {
		t.Errorf("aarch64: got %+v %v", obj, ok)
	}
	if _, ok := SharedObject(elf64(EMAarch64, "x"), EMX8664); ok {
		t.Error("an aarch64 object is not x86-64's")
	}
	// cut before its string table, an object is skipped as ldconfig's check_ptr skips it; cut
	// inside the table, its soname is what is there, as ldconfig reads it
	data := elf64(EMX8664, "libx.so.1")
	for cut := 1; cut < len(data)-len("libx.so.1")-2; cut += 7 {
		if _, ok := SharedObject(data[:cut], EMX8664); ok {
			t.Errorf("an object cut at %d was read", cut)
		}
	}
	SharedObject([]byte{}, EMX8664)
}

func TestIncludesNest(t *testing.T) {
	d := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	conf := []byte("include /etc/ld.so.conf\n/opt\n")
	if err := os.WriteFile(filepath.Join(d, "etc", "ld.so.conf"), conf, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := root.Open(d)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	l := &Ldconfig{r: r, log: func(string) {}}
	if err := l.parseConf("/etc/ld.so.conf", 0); err == nil || !strings.Contains(err.Error(), "nest deeper") {
		t.Errorf("a file that includes itself: %v", err)
	}
}

func TestStringTable(t *testing.T) {
	strs := map[string]bool{"libc.so.6": true, "c.so.6": true, "/lib/libc.so.6": true, "x": true}
	table := newStringTable(strs)
	for s, off := range table.offset {
		if got := string(table.data[off : off+len(s)]); got != s || table.data[off+len(s)] != 0 {
			t.Errorf("%q at %d reads %q", s, off, got)
		}
	}
	if len(table.data) != len("/lib/libc.so.6")+1+len("x")+1 {
		t.Errorf("the tails were not merged: %q", table.data)
	}
}
