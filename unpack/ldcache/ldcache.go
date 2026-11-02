// Package ldcache writes glibc's ld.so.cache as the tree's own ldconfig writes it, from the
// tree's files alone (DESIGN.md 10.1).
//
// Written from glibc's elf/ldconfig.c, elf/cache.c, elf/stringtable.c and elf/readelflib.c,
// which 2.39 and 2.41 share, so that a tree of any architecture gets the cache its own ldconfig
// would have written, byte for byte, without running it:
//
//   - The directories: those /etc/ld.so.conf and its includes name, in order, then the built-in
//     ones. The built-in directories are the loader's trusted directories, read from the loader's
//     own table (the same table the loader prints with --list-diagnostics); glibc's ldconfig
//     takes the first two of them, the slibdir and the libdir, and reads a `lib64` among them as
//     `lib`, `lib64` and `libx32` (`libilp32` on aarch64), while Debian's ldconfig takes every
//     one as the table spells it, from a copy of the table of its own, which is how it is told
//     apart: its binary carries the table twice, once in that copy and once in the static C
//     library it is linked with, where glibc's carries it once. A directory named twice, by
//     inode, counts once, and each has its glibc-hwcaps subdirectories after it.
//   - The files: in each directory, the names that look like a shared object (`lib*.so*`,
//     `ld-*.so*`, `ld.so.*`, `ld64.so.*`), regular files and symlinks, each read as the
//     readelflib of ldconfig's own machine reads it: its class, machine, type and DT_SONAME, and
//     on x86 the ISA level its GNU property note needs. A dangling symlink whose name has `.so.`
//     is removed, as ldconfig removes it.
//   - One entry per soname per directory, a file preferred to a link and the later name by
//     ldconfig's own version comparison to the earlier; the soname link is made beside a file
//     whose name is not its soname, where ldconfig would make it.
//   - The entries in ldconfig's order, the string table tail-merged in its order, the generator
//     string the ldconfig binary carries.
//
// Every path is a virtual path resolved by the Root, so nothing outside the tree is read or
// changed. Paths and names are byte strings throughout, as the kernel has them.
package ldcache

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"exclave/unpack/root"
)

// Log is where the writer says what it made.
type Log func(line string)

// The machines ldconfig's readelflib tells apart.
const (
	EM386     = 3
	EMX8664   = 62
	EMAarch64 = 183
)

// ldconfig's flags (sysdeps/generic/ldconfig.h), ELF's constants, and the cache's own
// (sysdeps/generic/dl-cache.h)
const (
	flagElfLibc6     = 0x0003
	flagX8664Lib64   = 0x0300
	flagX8664Libx32  = 0x0800
	flagArmLibhf     = 0x0900
	flagAarch64Lib64 = 0x0A00
	flagArmLibsf     = 0x0B00

	efArmAbiFloatSoft        = 0x200
	efArmAbiFloatHard        = 0x400
	ptLoad                   = 1
	ptDynamic                = 2
	ptGnuProperty            = 0x6474E553
	dtStrtab                 = 5
	dtSoname                 = 14
	ntGnuPropertyType0       = 5
	gnuPropertyX86Isa1Needed = 0xC0008002

	magic          = "glibc-ld.so.cache1.1"
	endianLittle   = 2
	extensionMagic = 0xEAA42174
	tagGenerator   = 0
	tagGlibcHwcaps = 1
	hwcapExtension = uint64(1) << 62
)

// the loaders Debian's ldconfig leaves the soname link of alone (its local-ldconfig-ignore-ld.so)
var ldSonames = map[string]bool{
	"ld-kfreebsd-x86-64.so.1":  true,
	"ld-linux-aarch64.so.1":    true,
	"ld-linux-aarch64_be.so.1": true,
	"ld-linux-armhf.so.3":      true,
	"ld-linux-ia64.so.2":       true,
	"ld-linux-mipsn8.so.1":     true,
	// two literals, no comma between
	"ld-linux-riscv64-lp64.so.1ld-linux-riscv64-lp64d.so.1": true,
	"ld-linux-x32.so.2":    true,
	"ld-linux-x86-64.so.2": true,
	"ld-linux.so.2":        true,
	"ld-linux.so.3":        true,
	"ld.so.1":              true,
	"ld64.so.1":            true,
	"ld64.so.2":            true,
}

// the names the distributions give a static ldconfig
var ldconfigNames = []string{
	"/usr/sbin/ldconfig.real", "/sbin/ldconfig.real", "/usr/sbin/ldconfig", "/sbin/ldconfig", "/usr/bin/ldconfig",
}

// truncated is a read past a file's end: ldconfig's check_ptr, which skips the file.
type truncated struct{}

// u reads a little-endian integer of size bytes at at, or panics with truncated.
func u(data []byte, at, size uint64) uint64 {
	if at > uint64(len(data)) || at+size > uint64(len(data)) || at+size < at {
		panic(truncated{})
	}
	var v uint64
	for i := size; i > 0; i-- {
		v = v<<8 | uint64(data[at+i-1])
	}
	return v
}

// catch turns a truncated panic into ok false.
func catch(ok *bool) {
	if e := recover(); e != nil {
		if _, is := e.(truncated); !is {
			panic(e)
		}
		*ok = false
	}
}

// VersionCmp orders two names as ldconfig's version comparison has it: byte by byte, except that
// a run of digits counts as one number, and a digit outranks every other byte; a name that ends
// first comes first (glibc's _dl_cache_libcmp).
func VersionCmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		da, db := isDigit(a[i]), isDigit(b[j])
		if da != db {
			if da {
				return 1
			}
			return -1
		}
		if !da {
			if a[i] != b[j] {
				if a[i] < b[j] {
					return -1
				}
				return 1
			}
			i++
			j++
			continue
		}
		ie, je := i, j
		for ie < len(a) && isDigit(a[ie]) {
			ie++
		}
		for je < len(b) && isDigit(b[je]) {
			je++
		}
		if c := cmpNum(a[i:ie], b[j:je]); c != 0 {
			return c
		}
		i, j = ie, je
	}
	switch {
	case i < len(a):
		return 1
	case j < len(b):
		return -1
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func cmpNum(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// IsDSO says whether a name looks like a shared object to ldconfig: lib*.so*, ld-*.so*, ld.so.*.
func IsDSO(name string) bool {
	return ((strings.HasPrefix(name, "lib") || strings.HasPrefix(name, "ld-")) && strings.Contains(name, ".so")) ||
		strings.HasPrefix(name, "ld.so.") || strings.HasPrefix(name, "ld64.so.")
}

// skippedName says whether ldconfig skips the name: prelink's, rpm's and dpkg's temporary files.
func skippedName(name string) bool {
	return (len(name) >= len(".#prelink#.XXXXXX") && name[len(name)-17:len(name)-6] == ".#prelink#.") ||
		strings.Contains(name, ";") ||
		strings.HasSuffix(name, ".#prelink#") || strings.HasSuffix(name, ".dpkg-new") || strings.HasSuffix(name, ".dpkg-tmp")
}

// isaLevel is the ISA level a PT_GNU_PROPERTY segment needs, as x86's read_gnu_property reads it.
func isaLevel(data []byte, offset, size, addr uint64) int {
	note, end, level := offset, offset+size, 0
	for note+12-offset < size {
		namesz, descsz, kind := u(data, note, 4), u(data, note+4, 4), u(data, note+8, 4)
		gnu := note+16 <= uint64(len(data)) && string(data[note+12:note+16]) == "GNU\x00"
		if namesz == 4 && kind == ntGnuPropertyType0 && gnu {
			if descsz < 8 || descsz%addr != 0 {
				return level
			}
			ptr, pend, last := note+16, note+16+descsz, uint64(0)
			for {
				ptype, datasz := u(data, ptr, 4), u(data, ptr+4, 4)
				if ptype < last {
					return level
				}
				ptr += 8
				if ptr+datasz > pend {
					return level
				}
				last = ptype
				if ptype > gnuPropertyX86Isa1Needed {
					return level
				}
				if ptype == gnuPropertyX86Isa1Needed && datasz == 4 {
					if needed := u(data, ptr, 4); needed != 0 {
						level = bits.Len64(needed) - 1
					}
				}
				ptr += (datasz + addr - 1) / addr * addr
				if pend < ptr || pend-ptr < 8 {
					return level
				}
			}
		}
		note += 12 + (namesz+addr-1)/addr*addr + (descsz+addr-1)/addr*addr
		if note > end {
			return level
		}
	}
	return level
}

// Object is what ldconfig makes of a shared object: its flags, the ISA level it needs, and its
// DT_SONAME, where it has one.
type Object struct {
	Flags     int
	ISALevel  int
	Soname    string
	HasSoname bool
}

// SharedObject reads a file as ldconfig for the machine family does; ok is false where it would
// skip the file: not an ELF shared object of a class and machine its readelflib takes, or one
// whose dynamic section it cannot read.
func SharedObject(data []byte, family int) (obj Object, ok bool) {
	ok = true
	defer catch(&ok)
	obj, ok = sharedObject(data, family)
	return obj, ok
}

func sharedObject(data []byte, family int) (Object, bool) {
	var o Object
	if len(data) < 64 || string(data[:4]) != "\x7fELF" || data[5] != 1 {
		return o, false
	}
	cls := data[4]
	if (cls != 1 && cls != 2) || u(data, 16, 2) != 3 { // ET_DYN alone
		return o, false
	}
	machine := int(u(data, 18, 2))
	var phoff, phnum, flags, psize, addr uint64
	if cls == 1 {
		phoff, phnum, flags, psize, addr = u(data, 28, 4), u(data, 44, 2), u(data, 36, 4), 32, 4
	} else {
		phoff, phnum, flags, psize, addr = u(data, 32, 8), u(data, 56, 2), u(data, 48, 4), 56, 8
	}
	switch {
	case family == EMX8664:
		switch {
		case machine == EMX8664 && cls == 2:
			o.Flags = flagElfLibc6 | flagX8664Lib64
		case machine == EMX8664:
			o.Flags = flagElfLibc6 | flagX8664Libx32
		case machine == EM386 && cls == 1:
			o.Flags = flagElfLibc6
		default:
			return o, false
		}
	case cls == 2: // the arm readelflib: a 64-bit object is aarch64's, whatever its machine
		o.Flags = flagElfLibc6 | flagAarch64Lib64
	case flags&efArmAbiFloatHard != 0:
		o.Flags = flagElfLibc6 | flagArmLibhf
	case flags&efArmAbiFloatSoft != 0:
		o.Flags = flagElfLibc6 | flagArmLibsf
	default:
		o.Flags = flagElfLibc6
	}
	if phoff > uint64(len(data)) {
		return o, false
	}
	type load struct{ off, vaddr, filesz uint64 }
	var loads []load
	var dynOff, dynSize uint64
	for i := uint64(0); i < phnum; i++ {
		at := phoff + i*psize
		if at > uint64(len(data)) {
			return o, false
		}
		kind := u(data, at, 4)
		var off, vaddr, filesz, align uint64
		if cls == 1 {
			off, vaddr, filesz, align = u(data, at+4, 4), u(data, at+8, 4), u(data, at+16, 4), u(data, at+28, 4)
		} else {
			off, vaddr, filesz, align = u(data, at+8, 8), u(data, at+16, 8), u(data, at+32, 8), u(data, at+48, 8)
		}
		switch kind {
		case ptLoad:
			loads = append(loads, load{off, vaddr, filesz})
		case ptDynamic:
			dynOff, dynSize = off, filesz
		case ptGnuProperty:
			if family == EMX8664 && align == addr {
				o.ISALevel = isaLevel(data, off, filesz, addr)
			}
		}
	}
	if dynSize == 0 || dynOff > uint64(len(data)) {
		return o, false
	}
	dsize := uint64(16)
	if cls == 1 {
		dsize = 8
	}
	var strtab uint64
	found := false
	for d := dynOff; ; d += dsize {
		tag := u(data, d, dsize/2)
		if tag == 0 {
			break
		}
		if tag == dtStrtab {
			val := u(data, d+dsize/2, dsize/2)
			var loadoff uint64
			for _, l := range loads {
				if l.vaddr <= val && val < l.vaddr+l.filesz {
					loadoff = l.vaddr - l.off
					break
				}
			}
			strtab = val - loadoff
			if strtab > uint64(len(data)) {
				return o, false
			}
			found = true
			break
		}
	}
	if !found {
		return o, false
	}
	for d := dynOff; ; d += dsize {
		tag := u(data, d, dsize/2)
		if tag == 0 {
			break
		}
		if tag == dtSoname {
			at := strtab + u(data, d+dsize/2, dsize/2)
			if at > uint64(len(data)) || at < strtab {
				return o, false
			}
			name := data[at:]
			if end := bytes.IndexByte(name, 0); end >= 0 {
				name = name[:end]
			}
			o.Soname, o.HasSoname = string(name), true
			return o, true
		}
	}
	return o, true
}

// TrustedDirs returns the loader's trusted directories, from its own table of them: the first
// run of two or more consecutive strings spelt `/.../`, each ending in a slash as glibc's build
// writes them, in the loader's read-only data: its sections that are allocated, not code and not
// writable, in file order, each split at its NULs, so that a string is one the section holds and
// not the tail of the code before it; a loader without section headers is read whole.
func TrustedDirs(loader []byte) []string {
	for _, data := range rodata(loader) {
		var run []string
		for _, chunk := range bytes.Split(data, []byte{0}) {
			if len(chunk) >= 2 && chunk[0] == '/' && chunk[len(chunk)-1] == '/' {
				run = append(run, string(chunk))
			} else if len(run) >= 2 {
				return run
			} else {
				run = nil
			}
		}
		if len(run) >= 2 {
			return run
		}
	}
	return nil
}

// rodata returns an ELF file's read-only data sections in file order, or the whole file without
// headers.
func rodata(elf []byte) (out [][]byte) {
	whole := [][]byte{elf}
	if len(elf) < 5 || string(elf[:4]) != "\x7fELF" || (elf[4] != 1 && elf[4] != 2) {
		return whole
	}
	defer func() {
		if e := recover(); e != nil {
			if _, is := e.(truncated); !is {
				panic(e)
			}
			out = whole
		}
	}()
	cls := elf[4]
	var shoff, shentsize, shnum uint64
	if cls == 1 {
		shoff, shentsize, shnum = u(elf, 32, 4), u(elf, 46, 2), u(elf, 48, 2)
	} else {
		shoff, shentsize, shnum = u(elf, 40, 8), u(elf, 58, 2), u(elf, 60, 2)
	}
	type section struct {
		off  uint64
		data []byte
	}
	var sections []section
	for i := uint64(0); i < shnum; i++ {
		at := shoff + i*shentsize
		kind := u(elf, at+4, 4)
		var flags, off, size uint64
		if cls == 1 {
			flags, off, size = u(elf, at+8, 4), u(elf, at+16, 4), u(elf, at+20, 4)
		} else {
			flags, off, size = u(elf, at+8, 8), u(elf, at+24, 8), u(elf, at+32, 8)
		}
		// SHT_PROGBITS, SHF_ALLOC, neither SHF_EXECINSTR nor SHF_WRITE
		if kind == 1 && flags&2 != 0 && flags&5 == 0 && off+size <= uint64(len(elf)) && off+size >= off {
			sections = append(sections, section{off, elf[off : off+size]})
		}
	}
	if len(sections) == 0 {
		return whole
	}
	sort.SliceStable(sections, func(i, j int) bool { return sections[i].off < sections[j].off })
	for _, s := range sections {
		out = append(out, s.data)
	}
	return out
}

var generatorRe = regexp.MustCompile(`ldconfig \([^)]*\) [a-z]+ release version [0-9][0-9.]*`)

// Generator returns the generator string an ldconfig writes, which it carries as a literal.
func Generator(ldconfig []byte) string {
	return string(generatorRe.Find(ldconfig))
}

type dir struct {
	path   string
	hwcaps string // the glibc-hwcaps subdirectory's name, or ""
	isHw   bool
}

type entry struct {
	lib      string
	path     string
	flags    int
	isaLevel int
	hwcaps   string
	isHw     bool
}

type inode struct{ dev, ino uint64 }

// Ldconfig is one run of ldconfig over a tree, as its own binary would make it.
type Ldconfig struct {
	r         *root.Root
	log       Log
	family    int
	generator string
	dirs      []dir
	keys      []inode
	entries   []entry
	Loader    string // the tree's glibc loader, or "" without one
	table     []string
	debian    bool
}

// New reads the ldconfig binary at ldconfig in the tree and finds the loader whose table it
// takes its built-in directories from.
func New(r *root.Root, ldconfig string, log Log) (*Ldconfig, error) {
	binary, err := r.ReadBytes(ldconfig)
	if err != nil {
		return nil, err
	}
	l := &Ldconfig{r: r, log: log, generator: Generator(binary)}
	if len(binary) >= 20 {
		l.family = int(u(binary, 18, 2))
	}
	l.Loader = l.findLoader()
	if l.Loader != "" {
		if data, err := r.ReadBytes(l.Loader); err == nil {
			l.table = TrustedDirs(data)
		}
	}
	// Debian's ldconfig carries a copy of the loader's table beside its static C library's and
	// adds its entries as spelt; glibc's takes slibdir and libdir and expands a lib64
	run := []byte(strings.Join(l.table, "\x00") + "\x00")
	l.debian = len(l.table) > 0 && bytes.Count(binary, run) >= 2
	return l, nil
}

// ---------------------------------------------------------------- the directories

// findLoader finds the tree's glibc loader: the first ld-*.so* in a library directory, by name.
func (l *Ldconfig) findLoader() string {
	tops := map[string]bool{}
	for _, top := range []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64"} {
		tops[top] = true
		for _, n := range l.r.Listdir(top) {
			if strings.Contains(n, "linux") {
				tops[top+"/"+n] = true
			}
		}
	}
	sorted := make([]string, 0, len(tops))
	for t := range tops {
		sorted = append(sorted, t)
	}
	sort.Strings(sorted)
	for _, d := range sorted {
		for _, name := range l.r.Listdir(d) {
			if !(strings.HasPrefix(name, "ld-") && strings.Contains(name, ".so")) &&
				!strings.HasPrefix(name, "ld.so.") && !strings.HasPrefix(name, "ld64.so.") {
				continue
			}
			if !l.r.IsFile(d + "/" + name) {
				continue
			}
			data, err := l.r.ReadBytes(d + "/" + name)
			if err != nil {
				continue
			}
			if len(data) > 64 && string(data[:4]) == "\x7fELF" && int(u(data, 18, 2)) == l.family && len(TrustedDirs(data)) > 0 {
				return d + "/" + name
			}
		}
	}
	return ""
}

func key(st *unix.Stat_t) inode { return inode{uint64(st.Dev), uint64(st.Ino)} }

func (l *Ldconfig) known(k inode) bool {
	for _, have := range l.keys {
		if have == k {
			return true
		}
	}
	return false
}

// addDir adds a directory as ldconfig's add_dir_1 does: trailing blanks and slashes off, once.
func (l *Ldconfig) addDir(line string) {
	path := strings.TrimRight(strings.TrimRight(line, " \t\n\v\f\r"), "/")
	if path == "" {
		return
	}
	st, ok := l.r.Stat(path, true)
	if !ok {
		return
	}
	if l.known(key(st)) {
		return
	}
	l.keys = append(l.keys, key(st))
	l.dirs = append(l.dirs, dir{path: path})
	for _, name := range l.r.Listdir(path + "/glibc-hwcaps") {
		if strings.HasPrefix(name, ".") || strings.Contains(name, ":") {
			continue
		}
		sub := path + "/glibc-hwcaps/" + name
		lst, ok := l.r.Stat(sub, false)
		if !ok || lst.Mode&unix.S_IFMT == unix.S_IFREG {
			continue
		}
		st, ok := l.r.Stat(sub, true)
		if !ok || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			continue
		}
		if l.known(key(st)) {
			continue
		}
		l.keys = append(l.keys, key(st))
		l.dirs = append(l.dirs, dir{path: sub, hwcaps: name, isHw: true})
	}
}

// addSystemDir adds a built-in directory as glibc's add_system_dir does: lib64 is lib, lib64,
// libx32.
func (l *Ldconfig) addSystemDir(d string) {
	other := "ilp32"
	if l.family == EMX8664 {
		other = "x32"
	}
	if strings.HasSuffix(d, "/lib64") {
		d = d[:len(d)-2]
	} else if strings.HasSuffix(d, "/lib"+other) {
		d = d[:len(d)-len(other)]
	}
	l.addDir(d)
	if strings.HasSuffix(d, "/lib") {
		l.addDir(d + "64")
		l.addDir(d + other)
	}
}

func (l *Ldconfig) parseConf(filename string) {
	text, err := l.r.ReadBytes(filename)
	if err != nil {
		return
	}
	for _, raw := range bytes.Split(text, []byte("\n")) {
		line, _, _ := bytes.Cut(raw, []byte("#"))
		s := strings.TrimLeft(string(line), " \t\n\v\f\r")
		if s == "" {
			continue
		}
		switch {
		case strings.HasPrefix(s, "include") && len(s) > 7 && (s[7] == ' ' || s[7] == '\t'):
			for _, pattern := range strings.FieldsFunc(s[8:], func(r rune) bool { return r == ' ' || r == '\t' }) {
				l.include(filename, pattern)
			}
		case len(s) > 5 && strings.ToLower(s[:5]) == "hwcap" && (s[5] == ' ' || s[5] == '\t'):
			continue
		default:
			l.addDir(s)
		}
	}
}

func (l *Ldconfig) include(configFile, pattern string) {
	if !strings.HasPrefix(pattern, "/") && strings.Contains(configFile, "/") {
		pattern = configFile[:strings.LastIndex(configFile, "/")] + "/" + pattern
	}
	for _, path := range l.glob(pattern) {
		l.parseConf(path)
	}
}

// glob returns the tree's paths matching the pattern, in byte order, as glob64 finds them.
func (l *Ldconfig) glob(pattern string) []string {
	paths := []string{""} // the tree's root, which no virtual path names
	for _, comp := range strings.Split(pattern, "/") {
		if comp == "" {
			continue
		}
		var next []string
		if strings.ContainsAny(comp, "*?[") {
			for _, p := range paths {
				for _, n := range l.r.Listdir(p) {
					if !strings.HasPrefix(n, ".") && Fnmatch(comp, n) {
						next = append(next, p+"/"+n)
					}
				}
			}
		} else {
			for _, p := range paths {
				if l.r.Lexists(p + "/" + comp) {
					next = append(next, p+"/"+comp)
				}
			}
		}
		paths = next
	}
	return paths
}

// Fnmatch matches name against a shell pattern as Python's fnmatchcase does: `*` and `?` match
// any character, `/` included, and `[...]` a class.
func Fnmatch(pattern, name string) bool {
	var re strings.Builder
	re.WriteString("(?s)^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			re.WriteString(".*")
		case '?':
			re.WriteString(".")
		case '[':
			j := i + 1
			if j < len(pattern) && pattern[j] == '!' {
				j++
			}
			if j < len(pattern) && pattern[j] == ']' {
				j++
			}
			for j < len(pattern) && pattern[j] != ']' {
				j++
			}
			if j >= len(pattern) {
				re.WriteString(`\[`)
				continue
			}
			class := pattern[i+1 : j]
			i = j
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			} else if strings.HasPrefix(class, "^") {
				class = `\` + class
			}
			re.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
		default:
			re.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	re.WriteString("$")
	compiled, err := regexp.Compile(re.String())
	return err == nil && compiled.MatchString(name)
}

func (l *Ldconfig) builtinDirs() {
	if l.debian {
		for _, d := range l.table {
			l.addDir(d)
		}
	} else {
		for i, d := range l.table {
			if i >= 2 {
				break
			}
			l.addSystemDir(strings.TrimRight(d, "/"))
		}
	}
}

// ---------------------------------------------------------------- the files

type dlib struct {
	name   string
	flag   int
	isLink bool
	level  int
}

// searchDir reads a directory as ldconfig's search_dir does: one library per soname, and its
// link.
func (l *Ldconfig) searchDir(e dir) error {
	r := l.r
	dlibs := map[string]*dlib{}
	var order []string
	for _, name := range r.Listdir(e.path) {
		full := e.path + "/" + name
		lst, ok := r.Stat(full, false)
		if !ok {
			continue
		}
		kind := lst.Mode & unix.S_IFMT
		if kind != unix.S_IFLNK && kind != unix.S_IFREG && kind != unix.S_IFDIR {
			continue
		}
		if !IsDSO(name) && (kind == unix.S_IFREG || !e.isHw) {
			continue
		}
		if skippedName(name) {
			continue
		}
		isLink := kind == unix.S_IFLNK
		if isLink {
			if _, ok := r.Stat(full, true); !ok {
				if strings.Contains(name, ".so.") { // a stale symlink, which ldconfig removes
					if err := r.Remove(full); err != nil {
						return err
					}
					l.log("removed the dangling link " + full + ", as ldconfig does")
				}
				continue
			}
		} else if kind != unix.S_IFREG {
			continue
		}
		data, err := r.ReadBytes(full)
		if err != nil {
			continue
		}
		obj, ok := SharedObject(data, l.family)
		if !ok {
			continue
		}
		soname := name
		if obj.HasSoname {
			soname = obj.Soname
		}
		if isLink {
			// a link named by the soname, or the .so link a soname extends, stays a link
			if name != soname && !(strings.HasSuffix(name, ".so") && strings.HasPrefix(soname, name)) {
				isLink = false
			}
			if isLink {
				soname = name
			}
		}
		if have, ok := dlibs[soname]; ok {
			if (!isLink && have.isLink) || (isLink == have.isLink && VersionCmp(have.name, name) < 0) {
				have.name, have.isLink, have.level = name, isLink, obj.ISALevel
			}
			continue
		}
		dlibs[soname] = &dlib{name, obj.Flags, isLink, obj.ISALevel}
		order = append(order, soname)
	}
	for i := len(order) - 1; i >= 0; i-- { // the list ldconfig builds at its head
		soname := order[i]
		d := dlibs[soname]
		filename := d.name
		if !e.isHw {
			if !d.isLink {
				if err := l.createLinks(e.path, d.name, soname); err != nil {
					return err
				}
			}
			filename = soname
		}
		l.entries = append(l.entries, entry{soname, e.path + "/" + filename, d.flag, d.level, e.hwcaps, e.isHw})
	}
	return nil
}

// createLinks makes the soname link to the library as ldconfig's create_links does, where
// missing.
func (l *Ldconfig) createLinks(path, libname, soname string) error {
	r := l.r
	fullSo, fullLib := path+"/"+soname, path+"/"+libname
	doLink, doRemove := true, true
	if stSo, ok := r.Stat(fullSo, true); ok {
		stLib, ok := r.Stat(fullLib, true)
		if !ok {
			return nil
		}
		if l.debian && ldSonames[soname] {
			doLink = false
		}
		if key(stLib) == key(stSo) {
			doLink = false
		} else if lst, ok := r.Stat(fullSo, false); ok && lst.Mode&unix.S_IFMT != unix.S_IFLNK {
			doLink, doRemove = false, false
		}
	} else if lst, ok := r.Stat(fullSo, false); !ok || lst.Mode&unix.S_IFMT != unix.S_IFLNK {
		doRemove = false
	}
	if doLink {
		if doRemove {
			if err := r.Remove(fullSo); err != nil {
				return err
			}
		}
		if err := r.Symlink(libname, fullSo); err != nil {
			return err
		}
		l.log("synthesised " + fullSo + " -> " + libname + ", as ldconfig does")
	}
	return nil
}

// ---------------------------------------------------------------- the cache

// Run reads the directories and the files and returns the cache, as `ldconfig` with no option
// makes them.
func (l *Ldconfig) Run() ([]byte, error) {
	l.parseConf("/etc/ld.so.conf")
	l.builtinDirs()
	for _, e := range l.dirs {
		if err := l.searchDir(e); err != nil {
			return nil, err
		}
	}
	return l.cache(), nil
}

func (l *Ldconfig) cache() []byte {
	// the entries in cache.c's order: by soname, the later version first, then the higher flags
	// first, then the glibc-hwcaps entries before the plain one, in their names' order; stable
	// sorts, the last key first
	entries := append([]entry(nil), l.entries...)
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.isHw != b.isHw {
			return a.isHw // hwcaps entries (false < true in Python's key) first
		}
		return a.hwcaps < b.hwcaps
	})
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].flags > entries[j].flags })
	sort.SliceStable(entries, func(i, j int) bool { return VersionCmp(entries[i].lib, entries[j].lib) > 0 })
	hwset := map[string]bool{}
	for _, e := range entries {
		if e.isHw {
			hwset[e.hwcaps] = true
		}
	}
	hwcaps := make([]string, 0, len(hwset))
	for h := range hwset {
		hwcaps = append(hwcaps, h)
	}
	sort.Strings(hwcaps)
	index := map[string]int{}
	for i, h := range hwcaps {
		index[h] = i
	}
	all := map[string]bool{}
	for _, e := range entries {
		all[e.lib], all[e.path] = true, true
	}
	for _, h := range hwcaps {
		all[h] = true
	}
	strs := newStringTable(all)
	strOffset := 48 + 24*len(entries)
	var body []byte
	le := binary.LittleEndian
	for _, e := range entries {
		var hwcap uint64
		if e.isHw {
			hwcap = hwcapExtension | uint64(e.isaLevel)<<32 | uint64(index[e.hwcaps])
		}
		body = le.AppendUint32(body, uint32(e.flags))
		body = le.AppendUint32(body, uint32(strOffset+strs.offset[e.lib]))
		body = le.AppendUint32(body, uint32(strOffset+strs.offset[e.path]))
		body = append(body, 0, 0, 0, 0)
		body = le.AppendUint64(body, hwcap)
	}
	extOffset := (strOffset + len(strs.data) + 3) &^ 3
	header := []byte(magic)
	header = le.AppendUint32(header, uint32(len(entries)))
	header = le.AppendUint32(header, uint32(len(strs.data)))
	header = append(header, endianLittle, 0, 0, 0)
	header = le.AppendUint32(header, uint32(extOffset))
	header = append(header, make([]byte, 12)...)
	gen := []byte(l.generator)
	// the extension directory is sized for both tags; without hwcaps the generator moves up
	hwcapsOffset := extOffset + 8 + 2*16
	hwcapsSize := 4 * len(hwcaps)
	genOffset := hwcapsOffset - 16
	if len(hwcaps) > 0 {
		genOffset = hwcapsOffset + hwcapsSize
	}
	sections := [][4]uint32{{tagGenerator, 0, uint32(genOffset), uint32(len(gen))}}
	if len(hwcaps) > 0 {
		sections = append(sections, [4]uint32{tagGlibcHwcaps, 0, uint32(hwcapsOffset), uint32(hwcapsSize)})
	}
	ext := le.AppendUint32(nil, extensionMagic)
	ext = le.AppendUint32(ext, uint32(len(sections)))
	for _, sec := range sections {
		for _, x := range sec {
			ext = le.AppendUint32(ext, x)
		}
	}
	for _, n := range hwcaps {
		ext = le.AppendUint32(ext, uint32(strOffset+strs.offset[n]))
	}
	out := append(append(header, body...), strs.data...)
	out = append(out, make([]byte, extOffset-len(out))...)
	return append(append(out, ext...), gen...)
}

// stringTable is the cache's string table: every string once, tail-merged in stringtable.c's
// order. The strings sorted by their tails, the greater byte first and, of a string and its own
// tail, the longer first, so that each tail follows the string that holds it.
type stringTable struct {
	data   []byte
	offset map[string]int
}

func reversed(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func newStringTable(strs map[string]bool) *stringTable {
	order := make([]string, 0, len(strs))
	for s := range strs {
		order = append(order, s)
	}
	sort.Slice(order, func(i, j int) bool { return reversed(order[i]) > reversed(order[j]) })
	t := &stringTable{offset: map[string]int{}}
	previous, has := "", false
	for _, s := range order {
		if has && strings.HasSuffix(previous, s) {
			t.offset[s] = t.offset[previous] + len(previous) - len(s)
		} else {
			t.offset[s] = len(t.data)
			t.data = append(append(t.data, s...), 0)
		}
		previous, has = s, true
	}
	return t
}

// FindLdconfig returns the tree's static ldconfig, by the names the distributions give it, or "".
func FindLdconfig(r *root.Root) string {
	for _, cand := range ldconfigNames {
		if r.IsFile(cand) {
			if head, err := r.ReadBytesN(cand, 4); err == nil && string(head) == "\x7fELF" {
				return cand
			}
		}
	}
	return ""
}

// Write writes /etc/ld.so.cache as the tree's ldconfig would, mode 0644; false when it could not.
func Write(r *root.Root, ldconfig string, log Log) (bool, error) {
	if !r.IsDir("/etc") {
		log("no /etc: ldconfig would write no cache")
		return false, nil
	}
	run, err := New(r, ldconfig, log)
	if err != nil {
		return false, err
	}
	if run.Loader == "" {
		log("no glibc loader in the tree: no built-in directories for ld.so.cache")
	}
	data, err := run.Run()
	if err != nil {
		return false, err
	}
	if r.Lexists("/etc/ld.so.cache") {
		if err := r.Remove("/etc/ld.so.cache"); err != nil {
			return false, err
		}
	}
	if err := r.WriteBytes("/etc/ld.so.cache", data, 0o644); err != nil {
		return false, err
	}
	if err := r.Chmod("/etc/ld.so.cache", 0o644); err != nil {
		return false, err
	}
	return true, nil
}
