// The parts of an ELF file and of glibc's ld.so.cache that the checks read (DESIGN.md 10.3).

package main

import (
	"bytes"
	"io"
	"math"
	"os"

	"exclave/tool/format"
)

const (
	ptLoad    = 1
	ptDynamic = 2
	ptInterp  = 3
	etDyn     = 3
)

const (
	dtNull    = 0
	dtNeeded  = 1
	dtStrtab  = 5
	dtStrsz   = 10
	dtSoname  = 14
	dtRpath   = 15
	dtRunpath = 29
)

type elfLoad struct {
	vaddr, off, filesz uint64
}

// An elfFile is what the checks read of an ELF file. A string the file lacks is nil; one it has,
// empty or not, is set. debugOnly marks a separate debug file, whose PT_INTERP is empty.
type elfFile struct {
	typ, machine                   int
	debugOnly                      bool
	loads                          []elfLoad
	interp, rpath, runpath, soname *string
	needed                         []string
}

// elfRead's answers: elfOK; elfBad or elfForeign with the reason; elfOS with the error of
// opening the file.
const (
	elfOK = iota
	elfBad
	elfForeign
	elfOS
)

// le is a little-endian field of n bytes.
func le(p []byte, n int) uint64 {
	var v uint64
	for i := n - 1; i >= 0; i-- {
		v = v<<8 | uint64(p[i])
	}
	return v
}

// readAt is up to n bytes of the file from off, as many as there are.
func readAt(f io.ReaderAt, off, n uint64) []byte {
	var b []byte
	chunk := make([]byte, 1<<16)
	for n > 0 && off <= math.MaxInt64 {
		k, err := f.ReadAt(chunk[:min(n, uint64(len(chunk)))], int64(off))
		if k > 0 {
			b = append(b, chunk[:k]...)
			off += uint64(k)
			n -= uint64(k)
		}
		if err != nil || k == 0 {
			break
		}
	}
	return b
}

// cString is the bytes up to the first NUL, as C reads them.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// elfRead reads the file's type, machine, loads, interpreter and dynamic strings.
func elfRead(path string) (e *elfFile, rc int, why string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, elfOS, "", err
	}
	defer f.Close()
	e, rc, why = elfParse(f)
	return e, rc, why, nil
}

// elfParse is elfRead of the bytes f holds: any bytes, answered with a verdict.
func elfParse(f io.ReaderAt) (e *elfFile, rc int, why string) {
	h := readAt(f, 0, 64)
	switch {
	case len(h) < 16 || string(h[:4]) != "\x7fELF":
		return nil, elfBad, "not ELF64 LE"
	case h[4] != 2 || h[5] != 1:
		return nil, elfForeign, "ELF32 or big-endian: a foreign object, not checked (13)"
	case len(h) < 64:
		return nil, elfBad, "truncated ELF header"
	}
	e = &elfFile{typ: int(le(h[16:], 2)), machine: int(le(h[18:], 2))}
	phoff, phentsize, phnum := le(h[32:], 8), le(h[54:], 2), le(h[56:], 2)
	ph := readAt(f, phoff, phentsize*phnum)
	var dynoff, dynsz uint64
	hasDyn := false
	for i := range phnum {
		if i*phentsize+56 > uint64(len(ph)) {
			return nil, elfBad, "truncated or malformed ELF: its program headers run past the end of the file"
		}
		p := ph[i*phentsize:]
		typ, off, vaddr, filesz := le(p, 4), le(p[8:], 8), le(p[16:], 8), le(p[32:], 8)
		switch {
		case typ == ptLoad:
			e.loads = append(e.loads, elfLoad{vaddr, off, filesz})
		case typ == ptInterp && filesz < 2:
			// a separate debug file (objcopy --only-keep-debug, /usr/lib/debug) keeps a program's headers but
			// not the bytes they map; its PT_INTERP is empty in the file, which the kernel refuses (ENOEXEC),
			// so it is no program
			e.debugOnly = true
		case typ == ptInterp:
			e.interp = new(cString(bytes.TrimRight(readAt(f, off, filesz), "\x00")))
		case typ == ptDynamic:
			hasDyn, dynoff, dynsz = true, off, filesz
		}
	}
	if !hasDyn {
		return e, elfOK, ""
	}
	d := readAt(f, dynoff, dynsz)
	ntags, strtab, strsz, hasStrtab := 0, uint64(0), uint64(1<<20), false
	for i := 0; i+16 <= len(d); i += 16 {
		tag, val := le(d[i:], 8), le(d[i+8:], 8)
		if tag == dtNull {
			break
		}
		ntags++
		if tag == dtStrtab {
			hasStrtab, strtab = true, val
		}
		if tag == dtStrsz {
			strsz = val
		}
	}
	if !hasStrtab {
		return e, elfOK, ""
	}
	var off uint64
	found := false
	for _, l := range e.loads {
		if l.vaddr <= strtab && strtab < l.vaddr+l.filesz {
			off, found = l.off+strtab-l.vaddr, true
			break
		}
	}
	if !found {
		return nil, elfBad, "address not in a loaded segment"
	}
	table := readAt(f, off, strsz)
	for i := range ntags {
		tag, val := le(d[16*i:], 8), le(d[16*i+8:], 8)
		if tag != dtNeeded && tag != dtRpath && tag != dtRunpath && tag != dtSoname {
			continue
		}
		s := cString(table[min(val, uint64(len(table))):])
		switch tag {
		case dtNeeded:
			e.needed = append(e.needed, s)
		case dtRpath:
			e.rpath = new(s)
		case dtRunpath:
			e.runpath = new(s)
		default:
			e.soname = new(s)
		}
	}
	return e, elfOK, ""
}

// ---------------------------------------------------------------- ld.so.cache

type cacheEntry struct {
	soname, path string
}

// cacheStr is the NUL-terminated string at data[at], strict UTF-8.
func cacheStr(data []byte, at uint64) (string, bool) {
	if at >= uint64(len(data)) {
		return "", false
	}
	end := bytes.IndexByte(data[at:], 0)
	if end < 0 || !format.UTF8Valid(data[at:at+uint64(end)]) {
		return "", false
	}
	return string(data[at : at+uint64(end)]), true
}

// readCache reads the tree's /etc/ld.so.cache in the glibc-ld.so.cache1.1 format: each soname's
// paths in the cache's order, entries for a hardware capability left out. Returns false when the
// tree has no regular file there, true otherwise: a cache cut inside its header or its table has
// no entries, and one whose entries cannot all be read under either base keeps those the second
// base read before the first that failed.
func readCache(root string) ([]cacheEntry, bool) {
	r := treeResolve(root, "/etc/ld.so.cache", true, nil)
	if r == "" {
		return nil, false
	}
	real := treeReal(root, r)
	if st, err := os.Stat(real); err != nil || !st.Mode().IsRegular() {
		return nil, false
	}
	return parseCache(readFile(real)), true
}

// parseCache is the entries of an ld.so.cache's bytes, as readCache gives them.
func parseCache(data []byte) []cacheEntry {
	n := uint64(len(data))
	m := bytes.Index(data, []byte("glibc-ld.so.cache1.1"))
	if m < 0 || uint64(m)+48 > n {
		return nil
	}
	off := uint64(m)
	entries := off + 48
	nlibs := le(data[off+20:], 4)
	if entries+24*nlibs > n {
		return nil
	}
	// offsets are from the header; failing that, from the string table
	var c []cacheEntry
	for _, base := range [2]uint64{off, entries + 24*nlibs} {
		c = nil
		ok := true
		for i := range nlibs {
			en := data[entries+24*i:]
			k, kok := cacheStr(data, base+le(en[4:], 4))
			v, vok := "", false
			if kok {
				v, vok = cacheStr(data, base+le(en[8:], 4))
			}
			if !kok || !vok || v == "" || v[0] != '/' {
				ok = false
				break
			}
			if le(en[16:], 8) == 0 {
				c = append(c, cacheEntry{k, v})
			}
		}
		if ok {
			break
		}
	}
	return c
}
