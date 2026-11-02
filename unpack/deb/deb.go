// Package deb reads Debian packages (DESIGN.md 10.1), and the index format the fetchers read.
//
// A .deb is an `ar` archive holding `control.tar.*` and `data.tar.*`. Both are read here, xz,
// gzip, bzip2 and zstd through the streams of package reader. Versions are ordered as dpkg orders
// them.
package deb

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"exclave/unpack/reader"
)

// Format is the reader of .deb files.
type Format struct{}

// Reader is the format as unpack and the fetchers use it.
var Reader reader.Reader = Format{}

// MergedUsr is true: Debian and Ubuntu merge /bin, /sbin and /lib into /usr.
func (Format) MergedUsr() bool { return true }

// ---------------------------------------------------------------- ar

// ArMember is one member of a GNU ar archive: its name, and where its bytes lie in the file.
type ArMember struct {
	Name   string
	Offset int64
	Size   int64
}

// ArMembers lists the members of the ar archive at path.
func ArMembers(p string) ([]ArMember, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var magic [8]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil || string(magic[:]) != "!<arch>\n" {
		return nil, reader.Errorf("%s: not an ar archive", p)
	}
	var out []ArMember
	pos := int64(8)
	for {
		var h [60]byte
		n, err := io.ReadFull(f, h[:])
		if err != nil && n < 60 {
			break
		}
		pos += 60
		name := strings.TrimRight(strings.TrimSpace(string(bytes.Map(ascii, h[:16]))), "/")
		sizeField := strings.TrimSpace(string(h[48:58]))
		if sizeField == "" {
			sizeField = "0"
		}
		size, perr := strconv.ParseInt(sizeField, 10, 64)
		if string(h[58:60]) != "`\n" || perr != nil || size < 0 {
			return nil, reader.Errorf("%s: bad ar header", p)
		}
		out = append(out, ArMember{Name: name, Offset: pos, Size: size})
		pos += size + size&1
		if _, err := f.Seek(pos, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ascii replaces a byte outside ASCII, as a decode with "replace" would.
func ascii(r rune) rune {
	if r > 127 {
		return '�'
	}
	return r
}

func findMember(p, member string) (ArMember, error) {
	members, err := ArMembers(p)
	if err != nil {
		return ArMember{}, err
	}
	for _, m := range members {
		if m.Name == member || strings.HasPrefix(m.Name, member+".") {
			return m, nil
		}
	}
	return ArMember{}, reader.Errorf("%s: no member %s", p, member)
}

// ArRead returns the full name and the contents of the member named member or member.<suffix>.
func ArRead(p, member string) (string, []byte, error) {
	m, err := findMember(p, member)
	if err != nil {
		return "", nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	data := make([]byte, m.Size)
	if _, err := f.ReadAt(data, m.Offset); err != nil {
		return "", nil, reader.Errorf("%s: %s is cut short", p, m.Name)
	}
	return m.Name, data, nil
}

// Decompress decompresses data by the compression its file name's suffix names: an unknown suffix
// or corrupt data is an error.
func Decompress(name string, data []byte) ([]byte, error) {
	suffix := path.Ext(name)
	comp, ok := reader.Suffixes[suffix]
	if !ok {
		return nil, reader.Errorf("unknown compression: %s", name)
	}
	corrupt := func(err error) error {
		return reader.Errorf("%s: corrupt %s data: %s", name, suffix, err)
	}
	s, err := reader.Decompress(comp, bytes.NewReader(data))
	if err != nil {
		return nil, corrupt(err)
	}
	defer s.Close()
	out, err := io.ReadAll(s)
	if err != nil {
		return nil, corrupt(err)
	}
	return out, nil
}

// memberStream is the bytes of one ar member, read from the package file, closed with the file.
type memberStream struct {
	*io.SectionReader
	f *os.File
}

func (m *memberStream) Close() error { return m.f.Close() }

// openTar opens the .deb's control.tar.* or data.tar.* member as a tar archive read as it
// decompresses.
func openTar(p, member string, keep func(*reader.Member) bool) (*reader.Tar, error) {
	m, err := findMember(p, member)
	if err != nil {
		return nil, err
	}
	comp, ok := reader.Suffixes[path.Ext(m.Name)]
	if !ok {
		return nil, reader.Errorf("%s: unknown compression: %s", p, m.Name)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	label := fmt.Sprintf("%s: corrupt %s", p, m.Name)
	stream, err := reader.Decompress(comp, &memberStream{io.NewSectionReader(f, m.Offset, m.Size), f})
	if err != nil {
		f.Close()
		return nil, reader.Errorf("%s: %s", label, err)
	}
	return reader.NewTar(&closeBoth{stream, f}, label, keep), nil
}

type closeBoth struct {
	io.ReadCloser
	f *os.File
}

func (c *closeBoth) Close() error {
	err := c.ReadCloser.Close()
	c.f.Close()
	return err
}

// OpenData returns the package's payload, data.tar.*.
func (Format) OpenData(p string) (reader.Archive, error) {
	return openTar(p, "data.tar", nil)
}

// the maintainer scripts and files a control archive carries that unpack reads
var scriptNames = map[string]bool{
	"preinst": true, "postinst": true, "prerm": true, "postrm": true, "config": true, "triggers": true,
}

// Control returns the package's control fields and its maintainer scripts by name.
func (Format) Control(p string) (map[string]string, map[string]string, error) {
	fields, scripts := map[string]string{}, map[string]string{}
	t, err := openTar(p, "control.tar", nil)
	if err != nil {
		return nil, nil, err
	}
	defer t.Close()
	for {
		m, err := t.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		n := strings.TrimPrefix(m.Name, "./")
		if m.Kind != reader.File {
			continue
		}
		data, err := io.ReadAll(t.Open())
		if err != nil {
			return nil, nil, err
		}
		if n == "control" {
			if stanzas := ParseStanzas(string(data)); len(stanzas) > 0 {
				fields = stanzas[0]
			}
		} else if scriptNames[n] {
			scripts[n] = string(data)
		}
	}
	return fields, scripts, nil
}

// Interests returns the package's trigger interests: the `interest` lines of its control file
// `triggers`.
func (f Format) Interests(p string) ([]string, error) {
	_, scripts, err := f.Control(p)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(scripts["triggers"], "\n") {
		words := strings.Fields(line)
		if len(words) == 2 && (words[0] == "interest" || words[0] == "interest-await" || words[0] == "interest-noawait") {
			out = append(out, words[1])
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- indexes

// ParseStanzas parses the RFC 822-style stanzas of a control or Packages file. A field's
// continuation lines are joined to it with newlines.
func ParseStanzas(text string) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	key := ""
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			if len(cur) > 0 {
				out = append(out, cur)
			}
			cur, key = map[string]string{}, ""
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && key != "" {
			cur[key] += "\n" + strings.TrimSpace(line)
			continue
		}
		k, v, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(k)
		cur[key] = strings.TrimSpace(v)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

var depRe = regexp.MustCompile(
	`^\s*([A-Za-z0-9][A-Za-z0-9+.\-]*)(?::([A-Za-z0-9\-]+))?` +
		`\s*(?:\(\s*(<<|<=|=|>=|>>|<|>)\s*([^)]+?)\s*\))?` +
		`\s*(?:\[[^\]]*\])?\s*(?:<[^>]*>\s*)*$`)

// ParseDeps parses a Depends-style field into groups of alternatives. For example,
// `a (>= 1) | b, c:any` gives [[{a >= 1} {b}] [{c}]]. The architecture qualifier, architecture
// lists and build profiles are dropped; an item that is not a dependency is an error.
func ParseDeps(field string) ([][]reader.Dep, error) {
	var out [][]reader.Dep
	if field == "" {
		return out, nil
	}
	for _, group := range strings.Split(strings.ReplaceAll(field, "\n", " "), ",") {
		if strings.TrimSpace(group) == "" {
			continue
		}
		var alts []reader.Dep
		for _, alt := range strings.Split(group, "|") {
			m := depRe.FindStringSubmatch(alt)
			if m == nil {
				return nil, reader.Errorf("cannot parse dependency %q", alt)
			}
			op := m[3]
			switch op {
			case "<":
				op = "<<"
			case ">":
				op = ">>"
			}
			alts = append(alts, reader.Dep{Name: m[1], Op: op, Version: m[4]})
		}
		out = append(out, alts)
	}
	return out, nil
}

// ParseDeps is the format's.
func (Format) ParseDeps(field string) ([][]reader.Dep, error) { return ParseDeps(field) }

// ---------------------------------------------------------------- versions (Debian policy 5.6.12)

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func order(c byte) int {
	switch {
	case c == '~':
		return -1
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	}
	return int(c) + 256
}

// verrevcmp compares two upstream versions or two revisions as dpkg's verrevcmp does.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := 0, 0
			if i < len(a) {
				ac = order(a[i])
			}
			if j < len(b) {
				bc = order(b[j])
			}
			if ac != bc {
				return ac - bc
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}
	return 0
}

// split splits a version into epoch, upstream version and Debian revision.
func split(v string) (int64, string, string) {
	epoch, rest := "0", v
	if e, r, found := strings.Cut(v, ":"); found {
		epoch, rest = e, r
	}
	up, rev := rest, ""
	if i := strings.LastIndex(rest, "-"); i >= 0 {
		up, rev = rest[:i], rest[i+1:]
	}
	n, _ := strconv.ParseInt(epoch, 10, 64)
	return n, up, rev
}

// Vercmp returns a negative number, zero or a positive number as a sorts before, with or after b,
// in dpkg's order (Debian policy 5.6.12).
func Vercmp(a, b string) int {
	ea, ua, ra := split(a)
	eb, ub, rb := split(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if r := verrevcmp(ua, ub); r != 0 {
		return r
	}
	return verrevcmp(ra, rb)
}

// Satisfies says whether version meets the constraint `op want`; no operator is always met.
func Satisfies(version, op, want string) bool {
	if op == "" {
		return true
	}
	c := Vercmp(version, want)
	switch op {
	case "<<":
		return c < 0
	case "<=":
		return c <= 0
	case "=":
		return c == 0
	case ">=":
		return c >= 0
	case ">>":
		return c > 0
	}
	return false
}

// Satisfies is the format's.
func (Format) Satisfies(version, op, want string) bool { return Satisfies(version, op, want) }
