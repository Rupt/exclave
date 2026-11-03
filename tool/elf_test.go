package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// An elfOpts describes a 64-bit little-endian ET_DYN for this machine, as its arguments break it:
// one PT_LOAD mapping the whole file from address 0, then PT_INTERP and PT_DYNAMIC. strtabAt and
// strsz override DT_STRTAB and DT_STRSZ, neededAt every DT_NEEDED's offset; interpCut puts the
// interpreter last in the file without its NUL, its PT_INTERP running past the end.
type elfOpts struct {
	interp           *string
	needed           []string
	soname           string
	phoff, phentsize uint64
	phnum            *uint64
	strtabAt, strsz  *uint64
	neededAt         *uint64
	interpCut        bool
}

func makeELF(o elfOpts) []byte {
	le := binary.LittleEndian
	strtab, offsets := []byte{0}, []uint64{}
	for _, n := range o.needed {
		offsets = append(offsets, uint64(len(strtab)))
		strtab = append(strtab, n...)
		strtab = append(strtab, 0)
	}
	soAt := uint64(len(strtab))
	strtab = append(strtab, o.soname...)
	strtab = append(strtab, 0)
	nph := 2
	if o.interp != nil {
		nph = 3
	}
	start := uint64(64 + 56*nph)
	body := append([]byte(nil), strtab...)
	for len(body)%8 != 0 {
		body = append(body, 0)
	}
	dynOff := start + uint64(len(body))
	type tag struct{ t, v uint64 }
	var tags []tag
	for _, off := range offsets {
		if o.neededAt != nil {
			off = *o.neededAt
		}
		tags = append(tags, tag{dtNeeded, off})
	}
	if o.soname != "" {
		tags = append(tags, tag{dtSoname, soAt})
	}
	strOff, strSz := start, uint64(len(strtab))
	if o.strtabAt != nil {
		strOff = *o.strtabAt
	}
	if o.strsz != nil {
		strSz = *o.strsz
	}
	tags = append(tags, tag{dtStrtab, strOff}, tag{dtStrsz, strSz}, tag{dtNull, 0})
	var dyn []byte
	for _, tg := range tags {
		dyn = le.AppendUint64(dyn, tg.t)
		dyn = le.AppendUint64(dyn, tg.v)
	}
	body = append(body, dyn...)
	interpOff := start + uint64(len(body))
	if o.interp != nil {
		body = append(body, *o.interp...)
		if !o.interpCut {
			body = append(body, 0)
		}
	}
	size := start + uint64(len(body))
	ph := func(typ, flags uint32, off, filesz, align uint64) []byte {
		b := le.AppendUint32(nil, typ)
		b = le.AppendUint32(b, flags)
		for _, v := range []uint64{off, off, 0, filesz, filesz, align} {
			b = le.AppendUint64(b, v)
		}
		return b
	}
	phs := ph(ptLoad, 5, 0, size, 0x1000)
	if o.interp != nil {
		n := uint64(len(*o.interp)) + 1
		if o.interpCut {
			n = uint64(len(*o.interp)) + 16
		}
		phs = append(phs, ph(ptInterp, 4, interpOff, n, 1)...)
	}
	phs = append(phs, ph(ptDynamic, 6, dynOff, uint64(len(dyn)), 8)...)
	phoff, phentsize, phnum := uint64(64), uint64(56), uint64(nph)
	if o.phoff != 0 {
		phoff = o.phoff
	}
	if o.phentsize != 0 {
		phentsize = o.phentsize
	}
	if o.phnum != nil {
		phnum = *o.phnum
	}
	h := append([]byte("\x7fELF\x02\x01\x01"), make([]byte, 9)...)
	h = le.AppendUint16(h, etDyn)
	h = le.AppendUint16(h, uint16(ownMachine().eMachine))
	h = le.AppendUint32(h, 1)
	h = le.AppendUint64(h, 0)
	h = le.AppendUint64(h, phoff)
	h = le.AppendUint64(h, 0)
	h = le.AppendUint32(h, 0)
	h = le.AppendUint16(h, 64)
	h = le.AppendUint16(h, uint16(phentsize))
	h = le.AppendUint16(h, uint16(phnum))
	h = le.AppendUint16(h, 64)
	h = le.AppendUint16(h, 0)
	h = le.AppendUint16(h, 0)
	return append(append(h, phs...), body...)
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestElfRead(t *testing.T) {
	dir := t.TempDir()
	read := func(name string, data []byte) (*elfFile, int, string) {
		p := filepath.Join(dir, name)
		write(t, p, data)
		e, rc, why, err := elfRead(p)
		if err != nil {
			t.Fatal(err)
		}
		return e, rc, why
	}
	e, rc, why := read("good",
		makeELF(elfOpts{interp: new("/lib/ld.so"), needed: []string{"libfoo.so.1", "libc.so.6"}, soname: "x"}))
	if rc != elfOK || e.interp == nil || *e.interp != "/lib/ld.so" || len(e.needed) != 2 ||
		e.needed[1] != "libc.so.6" || e.soname == nil || *e.soname != "x" || e.rpath != nil || e.typ != etDyn ||
		e.machine != ownMachine().eMachine {
		t.Errorf("a good file: %d %q %+v", rc, why, e)
	}
	// 10.3: an ELF file whose headers lie is an error by name
	past := "truncated or malformed ELF: its program headers run past the end of the file"
	for _, c := range []struct {
		name string
		data []byte
		rc   int
		why  string
	}{
		{"short", makeELF(elfOpts{})[:40], elfBad, "truncated ELF header"},
		{"notelf", []byte("hello"), elfBad, "not ELF64 LE"},
		{"elf32", append([]byte("\x7fELF\x01\x01"), make([]byte, 60)...), elfForeign,
			"ELF32 or big-endian: a foreign object, not checked (13)"},
		{"phoff", makeELF(elfOpts{phoff: 4096})[:64], elfBad, past},
		{"phentsize", makeELF(elfOpts{phentsize: 1, phnum: new(uint64(1))}), elfBad, past},
		{"strtab", makeELF(elfOpts{strtabAt: new(uint64(1 << 20)), needed: []string{"libfoo.so.1"}}), elfBad,
			"address not in a loaded segment"},
	} {
		_, rc, why := read(c.name, c.data)
		if rc != c.rc || why != c.why {
			t.Errorf("%s: %d %q", c.name, rc, why)
		}
	}
	// a DT_NEEDED past DT_STRSZ is the empty name; a PT_INTERP cut by the end of the file is the bytes there are
	e, rc, _ = read("needed",
		makeELF(elfOpts{needed: []string{"libfoo.so.1"}, strsz: new(uint64(4)), neededAt: new(uint64(100))}))
	if rc != elfOK || len(e.needed) != 1 || e.needed[0] != "" {
		t.Errorf("a DT_NEEDED past DT_STRSZ: %d %+v", rc, e)
	}
	e, rc, _ = read("cut", makeELF(elfOpts{interp: new("/lib/ld.so"), interpCut: true}))
	if rc != elfOK || e.interp == nil || *e.interp != "/lib/ld.so" {
		t.Errorf("a PT_INTERP cut by the end: %d %+v", rc, e)
	}
	// a separate debug file's empty PT_INTERP marks it as no program
	e, rc, _ = read("debug", makeELF(elfOpts{interp: new("")}))
	if rc != elfOK || !e.debugOnly {
		t.Errorf("an empty PT_INTERP: %d %+v", rc, e)
	}
	if _, rc, _, err := elfRead(filepath.Join(dir, "missing")); rc != elfOS || err == nil {
		t.Errorf("a missing file: %d %v", rc, err)
	}
}

// makeCache is an ld.so.cache in glibc's glibc-ld.so.cache1.1 format, offsets from its header;
// nlibs overrides the count of entries; past moves every key's offset a megabyte past the end.
func makeCache(entries [][2]string, nlibs *uint32, past bool) []byte {
	le := binary.LittleEndian
	first := uint32(48 + 24*len(entries))
	var strs, rows []byte
	for _, e := range entries {
		k := first + uint32(len(strs))
		strs = append(append(strs, e[0]...), 0)
		v := first + uint32(len(strs))
		strs = append(append(strs, e[1]...), 0)
		if past {
			k += 1 << 20
		}
		rows = le.AppendUint32(rows, 0x0303)
		rows = le.AppendUint32(rows, k)
		rows = le.AppendUint32(rows, v)
		rows = le.AppendUint32(rows, 0)
		rows = le.AppendUint64(rows, 0)
	}
	count := uint32(len(entries))
	if nlibs != nil {
		count = *nlibs
	}
	head := []byte("glibc-ld.so.cache1.1")
	head = le.AppendUint32(head, count)
	head = le.AppendUint32(head, uint32(len(strs)))
	head = append(head, make([]byte, 20)...)
	return append(append(head, rows...), strs...)
}

func TestReadCache(t *testing.T) {
	entries := [][2]string{{"libfoo.so.1", "/opt/lib/libfoo.so.1"}, {"libbar.so.2", "/lib/libbar.so.2"}}
	huge := uint32(0xFFFFFFFF)
	for _, c := range []struct {
		name string
		data []byte
		n    int
	}{
		{"good", makeCache(entries, nil, false), 2},
		{"nlibs", makeCache(entries, &huge, false), 0},
		{"past", makeCache(entries, nil, true), 0},
		{"short", makeCache(entries, nil, false)[:60], 0},
		{"nomagic", []byte("nothing here"), 0},
	} {
		root := filepath.Join(t.TempDir(), "tree")
		write(t, filepath.Join(root, "etc", "ld.so.cache"), c.data)
		got, has := readCache(root)
		if !has || len(got) != c.n {
			t.Errorf("%s: %v %+v", c.name, has, got)
		}
		if c.n == 2 && (got[0].soname != "libfoo.so.1" || got[1].path != "/lib/libbar.so.2") {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	if _, has := readCache(t.TempDir()); has {
		t.Error("a tree without a cache has one")
	}
}

func TestReadLog(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	write(t, p, []byte("launcher 0 cwd /\nopen 3 /srv/liba.so\x00junk\nopen 3 /srv/libb\\\\c.so\n"+
		"open 99999999999999999999 /srv/libbig.so\nopen -2 /srv/libgone.so\nbad line\nopen x /y\n"+
		"open 3 /srv/libz.so\\"))
	lines := readLog(p)
	want := []logLine{{"launcher", "cwd /", 0}, {"open", "/srv/liba.so", 3}, {"open", "/srv/libb\\c.so", 3},
		{"open", "/srv/libbig.so", 1<<63 - 1}, {"open", "/srv/libgone.so", -2}, {"open", "/srv/libz.so\\", 3}}
	if len(lines) != len(want) {
		t.Fatalf("%+v", lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d: %+v, wanted %+v", i, lines[i], want[i])
		}
	}
}

func FuzzElf(f *testing.F) {
	f.Add(makeELF(elfOpts{interp: new("/lib/ld.so"), needed: []string{"libc.so.6"}, soname: "x"}))
	f.Add(makeELF(elfOpts{strtabAt: new(uint64(1 << 20)), needed: []string{"libfoo.so.1"}}))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		elfRead(p)
		dirsTable(data)
	})
}

func FuzzCache(f *testing.F) {
	f.Add(makeCache([][2]string{{"libfoo.so.1", "/opt/lib/libfoo.so.1"}}, nil, false))
	f.Fuzz(func(t *testing.T, data []byte) {
		root := filepath.Join(t.TempDir(), "tree")
		if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "etc", "ld.so.cache"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		readCache(root)
	})
}

func FuzzLog(f *testing.F) {
	f.Add([]byte("open 3 /srv/liba.so\nlauncher 0 cwd given to the host /x\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "log")
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		for _, l := range readLog(p) {
			_ = libraryName(l.path)
		}
	})
}
