// Package rpm reads RPM packages (DESIGN.md 10.1).
//
// An .rpm is a 96-byte lead, a signature header, a header and a compressed cpio payload. The
// header is an index of tagged entries, from which the reader takes the name, version,
// architecture, dependencies, install scripts and the payload's compressor. The payload is cpio
// in the "newc" or "crc" form, compressed with gzip, xz, bzip2 or zstd. `Obsoletes` is presented
// as `Replaces`.
//
// The synthesis rules are Debian's, read in rpm's spelling (DESIGN.md 10.1). These are the places
// an rpm set needs more:
//
//   - cpio records hard links as entries of one inode with the content on the last; the reader
//     gives the content to the first and links the rest, as tar would.
//   - Versions are ordered as rpmvercmp orders them: epoch first, then version and release
//     segment by segment.
//   - Dependencies come as rpm spells them: package names, the provides a library's package
//     declares (`libc.so.6(GLIBC_2.2.5)(64bit)`, `rtld(GNU_HASH)`), and file names. `rpmlib(...)`
//     features and rich dependencies (`(a or b)`) are rpm's own and are skipped.
//   - `alternatives --install` lines in %post are read in either spelling, the tree's own ldconfig
//     runs where it is static, and the identity files are the placeholders wrap adds. `setup`
//     ships /etc/passwd, so nothing is made for it.
//   - An `alternatives --install` line replaces a file or link already standing at the link path,
//     as both implementations do. Fedora's binutils needs this: it ships gold at /usr/bin/ld and
//     removes it in %post before installing ld.bfd as the alternative.
//   - Fedora, RHEL and CentOS 7 have merged /usr, so the merged-/usr links are made. A symlink
//     that one package ships at a path under which other packages ship files is made before
//     anything is extracted, whatever the order of the packages, so those files land where the
//     link points.
//   - Fedora 42's `filesystem` package merges sbin into bin in its %posttrans, written in Lua:
//     when every entry of /usr/sbin is a link `../bin/<name>`, the directory becomes a link to
//     bin. Unpack does the same when that script is present.
//   - Red Hat's ld.so.conf says `include ld.so.conf.d/*.conf`, relative to /etc, which ldconfig
//     refuses under -r. Unpack runs ldconfig on a temporary copy in the tree with the pattern
//     spelt from /etc, and removes the copy afterwards.
//   - Files shipped unreadable, such as Fedora's /etc/gshadow at mode 0, are made readable by
//     their owner, since a tree its owner cannot read can be neither hashed nor copied. A tree
//     that comes from outside with such a file is refused by `wrap`, naming the file (10.3).
//   - Fedora's ca-certificates ships a p11-kit trust source and links every consumer path to the
//     bundle that update-ca-trust extracts in %post. Unpack extracts it the same way, one PEM for
//     each anchor marked trusted and not distrusted, so that the Red Hat identity file of
//     DESIGN.md 8.4 has a copy to fall back to.
package rpm

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"exclave/unpack/reader"
)

// Format is the reader of .rpm files.
type Format struct{}

// Reader is the format as unpack and the fetchers use it.
var Reader reader.Reader = Format{}

// MergedUsr is true: Fedora and RHEL 7 and later merge /bin, /sbin and /lib into /usr; their
// filesystem package ships /bin -> usr/bin and /lib64 -> usr/lib64.
func (Format) MergedUsr() bool { return true }

const lead = 96

var headerMagic = []byte{0x8e, 0xad, 0xe8, 0x01}

// The tags the reader uses, from rpm's rpmtag.h.
const (
	TagName              = 1000
	TagVersion           = 1001
	TagRelease           = 1002
	TagEpoch             = 1003
	TagArch              = 1022
	TagPrein             = 1023
	TagPostin            = 1024
	TagProvideName       = 1047
	TagRequireFlags      = 1048
	TagRequireName       = 1049
	TagRequireVersion    = 1050
	TagObsoleteName      = 1090
	TagProvideFlags      = 1112
	TagProvideVersion    = 1113
	TagObsoleteFlags     = 1114
	TagObsoleteVersion   = 1115
	TagPayloadCompressor = 1125
	TagPosttrans         = 1152
)

// RPMSENSE_LESS, GREATER and EQUAL, in the order their spelling joins them; RPMSENSE_RPMLIB
const (
	senseLess    = 2
	senseGreater = 4
	senseEqual   = 8
	senseRpmlib  = 1 << 24
)

// Value is one tagged entry of a header: integers, strings or bytes, by the entry's type.
type Value struct {
	Ints []int64
	Strs []string
	Bin  []byte
}

// Header is a header section's entries by tag.
type Header map[uint32]Value

// Str returns the tag's first string, or "".
func (h Header) Str(tag uint32) string {
	if v, ok := h[tag]; ok && len(v.Strs) > 0 {
		return v.Strs[0]
	}
	return ""
}

// Int returns the tag's first integer, and whether it has one.
func (h Header) Int(tag uint32) (int64, bool) {
	if v, ok := h[tag]; ok && len(v.Ints) > 0 {
		return v.Ints[0], true
	}
	return 0, false
}

// readHeader reads one header section at r's position.
func readHeader(r io.Reader) (Header, []byte, error) {
	var head [16]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, nil, fmt.Errorf("bad header magic")
	}
	if !bytes.Equal(head[:4], headerMagic) {
		return nil, nil, fmt.Errorf("bad header magic")
	}
	nindex, hsize := binary.BigEndian.Uint32(head[8:12]), binary.BigEndian.Uint32(head[12:16])
	if nindex > 1<<20 || hsize > 1<<28 {
		return nil, nil, fmt.Errorf("corrupt header: %d entries, %d bytes", nindex, hsize)
	}
	raw := make([]byte, 16+16*int(nindex)+int(hsize))
	copy(raw, head[:])
	if _, err := io.ReadFull(r, raw[16:]); err != nil {
		return nil, nil, fmt.Errorf("corrupt header: cut short")
	}
	index, data := raw[16:16+16*int(nindex)], raw[16+16*int(nindex):]
	out := Header{}
	for i := 0; i < int(nindex); i++ {
		e := index[16*i : 16*i+16]
		tag, typ := binary.BigEndian.Uint32(e[0:4]), binary.BigEndian.Uint32(e[4:8])
		off, count := int(binary.BigEndian.Uint32(e[8:12])), int(binary.BigEndian.Uint32(e[12:16]))
		if off < 0 || off > len(data) || count < 0 {
			return nil, nil, fmt.Errorf("corrupt header: entry %d out of range", tag)
		}
		var v Value
		switch typ {
		case 3, 4, 5: // int16, int32, int64
			size := map[uint32]int{3: 2, 4: 4, 5: 8}[typ]
			if count > (len(data)-off)/size {
				return nil, nil, fmt.Errorf("corrupt header: entry %d out of range", tag)
			}
			for k := 0; k < count; k++ {
				b := data[off+k*size:]
				switch typ {
				case 3:
					v.Ints = append(v.Ints, int64(int16(binary.BigEndian.Uint16(b))))
				case 4:
					v.Ints = append(v.Ints, int64(int32(binary.BigEndian.Uint32(b))))
				default:
					v.Ints = append(v.Ints, int64(binary.BigEndian.Uint64(b)))
				}
			}
		case 6: // one string
			e := bytes.IndexByte(data[off:], 0)
			if e < 0 {
				return nil, nil, fmt.Errorf("corrupt header: entry %d has no end", tag)
			}
			v.Strs = []string{string(data[off : off+e])}
		case 8, 9: // string array, i18n string array
			p := off
			for k := 0; k < count; k++ {
				e := bytes.IndexByte(data[p:], 0)
				if e < 0 {
					return nil, nil, fmt.Errorf("corrupt header: entry %d has no end", tag)
				}
				v.Strs = append(v.Strs, string(data[p:p+e]))
				p += e + 1
			}
		case 7, 1: // binary, char
			if count > len(data)-off {
				return nil, nil, fmt.Errorf("corrupt header: entry %d out of range", tag)
			}
			v.Bin = data[off : off+count]
		default:
			continue
		}
		out[tag] = v
	}
	return out, raw, nil
}

// Sections is an rpm file's parts as its signatures cover them (DESIGN.md 10).
type Sections struct {
	Signature   Header // the signature header: the header's signatures and digests
	Header      Header
	HeaderBytes []byte // the header section whole, from its magic, which a header signature covers
	Payload     int64  // where the payload begins
}

// ReadSections reads an rpm file's signature header and header.
func ReadSections(p string) (*Sections, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var l [lead]byte
	if _, err := io.ReadFull(f, l[:]); err != nil || !bytes.Equal(l[:4], []byte{0xed, 0xab, 0xee, 0xdb}) {
		return nil, reader.Errorf("%s: not an rpm", p)
	}
	r := &reader.Counting{R: bufio.NewReader(f), Pos: lead}
	sig, _, err := readHeader(r)
	if err != nil {
		return nil, reader.Errorf("%s: corrupt header: %s", p, err)
	}
	// the signature header, then padding to 8 bytes
	if pad := (8 - r.Pos%8) % 8; pad > 0 {
		if _, err := io.CopyN(io.Discard, r, pad); err != nil {
			return nil, reader.Errorf("%s: corrupt header: cut short", p)
		}
	}
	h, raw, err := readHeader(r)
	if err != nil {
		return nil, reader.Errorf("%s: corrupt header: %s", p, err)
	}
	return &Sections{Signature: sig, Header: h, HeaderBytes: raw, Payload: r.Pos}, nil
}

// sections returns an rpm file's header, the offset of its payload, and the payload's compressor.
func sections(p string) (Header, int64, string, error) {
	s, err := ReadSections(p)
	if err != nil {
		return nil, 0, "", err
	}
	comp := "gzip"
	if c, ok := s.Header[TagPayloadCompressor]; ok && len(c.Strs) > 0 {
		comp = c.Strs[0]
	}
	return s.Header, s.Payload, comp, nil
}

// the payload compressors, by the name the header gives
var compressors = map[string]string{
	"gzip": reader.Gzip, "xz": reader.Xz, "lzma": reader.Lzma, "bzip2": reader.Bzip2, "zstd": reader.Zstd,
}

// payload is the cpio archive, its entries handed out as they decompress, in its order.
//
// The archive ends at its trailer, which must be there, every entry whole before it and nothing
// but NUL padding after it (10.1). cpio records a hard link as several entries of one inode, the
// content on the last of them; the entry with the content is handed out as the file, and the
// others, held back until it comes, as links to it, as tar would have them.
type payload struct {
	label   string
	stream  io.Closer
	f       *os.File
	r       *reader.Counting
	pending []*reader.Member           // members read ahead: hard links of a file just handed out
	held    map[inode][]*reader.Member // links waiting for their content, by inode, in order
	heldAt  []inode
	files   map[inode]*reader.Member // the entry each inode's links name
	cur     *contents                // the current entry's data, while it is a regular file
	end     int64                    // where the current entry's data ends
	done    bool
}

type inode struct{ devmaj, devmin, ino int64 }

// contents is the current entry's data in the payload's stream, which must hold all of it.
type contents struct {
	p    *payload
	left int64
	name string
}

func (c *contents) Read(b []byte) (int, error) {
	if c.left == 0 {
		return 0, io.EOF
	}
	if int64(len(b)) > c.left {
		b = b[:c.left]
	}
	n, err := c.p.r.Read(b)
	c.left -= int64(n)
	if err == io.EOF || (err == nil && n == 0) {
		if c.left > 0 {
			return n, reader.Errorf("%s: cpio entry %q runs past the end of the payload", c.p.label, c.name)
		}
		return n, io.EOF
	}
	return n, err
}

func openPayload(p string) (*payload, error) {
	_, at, comp, err := sections(p)
	if err != nil {
		return nil, err
	}
	kind, ok := compressors[comp]
	if !ok {
		return nil, reader.Errorf("%s: unknown payload compressor %q", p, comp)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(at, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	label := fmt.Sprintf("%s: corrupt %s payload", p, comp)
	stream, err := reader.Decompress(kind, bufio.NewReader(f))
	if err != nil {
		f.Close()
		return nil, reader.Errorf("%s: %s", label, err)
	}
	return &payload{
		label:  label,
		stream: stream,
		f:      f,
		r:      &reader.Counting{R: &reader.Labelled{R: stream, Label: label}},
		held:   map[inode][]*reader.Member{},
		files:  map[inode]*reader.Member{},
	}, nil
}

func (p *payload) Close() error {
	err := p.stream.Close()
	p.f.Close()
	return err
}

// exact reads n bytes, or fails with what their absence means.
func (p *payload) exact(n int64, what string) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(p.r, buf); err != nil {
		if e, ok := err.(*reader.Error); ok {
			return nil, e
		}
		return nil, reader.Errorf("%s: %s", p.label, what)
	}
	return buf, nil
}

func (p *payload) skip(n int64, what string) error {
	if n <= 0 {
		return nil
	}
	_, err := p.exact(n, what)
	return err
}

func (p *payload) Open() io.Reader {
	return p.cur
}

func (p *payload) Next() (*reader.Member, error) {
	if len(p.pending) > 0 {
		m := p.pending[0]
		p.pending = p.pending[1:]
		return m, nil
	}
	if p.done {
		return nil, io.EOF
	}
	if p.cur != nil {
		// past what the caller left unread of the data, and its padding to four bytes
		name := p.cur.name
		p.cur = nil
		if p.r.Pos > p.end {
			return nil, reader.Errorf("%s: cpio entry %q is shorter than its data", p.label, name)
		}
		past := fmt.Sprintf("cpio entry %q runs past the end of the payload", name)
		if err := p.skip(p.end-p.r.Pos, past); err != nil {
			return nil, err
		}
		if err := p.skip((4-p.end%4)%4, past); err != nil {
			return nil, err
		}
	}
	for {
		start := p.r.Pos
		header, err := p.exact(110, "the cpio payload has no trailer: it is cut short")
		if err != nil {
			return nil, err
		}
		if magic := string(header[:6]); magic != "070701" && magic != "070702" {
			return nil, reader.Errorf("%s: bad cpio header at %d", p.label, start)
		}
		var fields [13]int64
		for k := range fields {
			v, err := strconv.ParseInt(string(header[6+8*k:14+8*k]), 16, 64)
			if err != nil {
				return nil, reader.Errorf("%s: bad cpio header at %d", p.label, start)
			}
			fields[k] = v
		}
		ino, mode, nlink, mtime, size := fields[0], fields[1], fields[4], fields[5], fields[6]
		devmaj, devmin, nsize := fields[7], fields[8], fields[11]
		if nsize < 1 {
			return nil, reader.Errorf("%s: bad cpio header at %d", p.label, start)
		}
		raw, err := p.exact(nsize, "the cpio payload ends inside a name")
		if err != nil {
			return nil, err
		}
		name := string(raw[:nsize-1])
		if err := p.skip((4-p.r.Pos%4)%4, "the cpio payload ends inside a name"); err != nil {
			return nil, err
		}
		dataAt := p.r.Pos
		past := fmt.Sprintf("cpio entry %q runs past the end of the payload", name)
		if name == "TRAILER!!!" {
			if err := p.skip(size, past); err != nil {
				return nil, err
			}
			p.done = true
			for _, ino := range p.heldAt { // hard links whose inode carried no content: empty
				group := p.held[ino]
				if group == nil {
					continue
				}
				first := group[0]
				first.Kind = reader.File
				p.pending = append(p.pending, first)
				for _, m := range group[1:] {
					p.pending = append(p.pending, &reader.Member{Name: m.Name, Mode: m.Mode, Mtime: m.Mtime, Kind: reader.Hardlink, Linkname: first.Name})
				}
				delete(p.held, ino)
			}
			if why := reader.AfterEnd(p.r, p.r.Pos); why != nil {
				return nil, reader.Errorf("%s: %s", p.label, why)
			}
			if len(p.pending) > 0 {
				p.cur = &contents{p: p, left: 0, name: p.pending[0].Name}
				return p.Next()
			}
			return nil, io.EOF
		}
		name = strings.TrimPrefix(name, "./")
		perm, format, in := mode&0o7777, mode&0o170000, inode{devmaj, devmin, ino}
		p.end = dataAt + size
		m := &reader.Member{Name: name, Mode: perm, Mtime: mtime}
		switch {
		case format == 0o040000:
			m.Kind = reader.Dir
		case format == 0o120000:
			link, err := p.exact(size, past)
			if err != nil {
				return nil, err
			}
			m.Kind, m.Linkname = reader.Symlink, string(link)
		case format == 0o100000 && nlink > 1 && p.files[in] != nil:
			m.Kind, m.Linkname = reader.Hardlink, p.files[in].Name
		case format == 0o100000 && nlink > 1 && size == 0:
			if p.held[in] == nil {
				p.heldAt = append(p.heldAt, in)
			}
			p.held[in] = append(p.held[in], m)
			if err := p.skip((4-p.end%4)%4, past); err != nil {
				return nil, err
			}
			continue
		case format == 0o100000:
			m.Kind, m.Size = reader.File, size
			p.cur = &contents{p: p, left: size, name: name}
			if nlink > 1 {
				p.files[in] = m
				for _, h := range p.held[in] {
					p.pending = append(p.pending, &reader.Member{Name: h.Name, Mode: h.Mode, Mtime: h.Mtime, Kind: reader.Hardlink, Linkname: name})
				}
				delete(p.held, in)
			}
			return m, nil
		default:
			m.Kind = reader.Special
		}
		// no data to hand out: past the entry's data and its padding
		if err := p.skip(p.end-p.r.Pos, past); err != nil {
			return nil, err
		}
		if err := p.skip((4-p.end%4)%4, past); err != nil {
			return nil, err
		}
		return m, nil
	}
}

// OpenData returns the package's payload, the files it installs.
func (Format) OpenData(p string) (reader.Archive, error) {
	return openPayload(p)
}

// deps spells the header's dependencies of one kind as ParseDeps reads them, rpm's own skipped.
func deps(h Header, names, versions, flags uint32) []string {
	var out []string
	ns, vs, fs := h[names].Strs, h[versions].Strs, h[flags].Ints
	for i, n := range ns {
		v, fl := "", int64(0)
		if i < len(vs) {
			v = vs[i]
		}
		if i < len(fs) {
			fl = fs[i]
		}
		// rpm's own features; rich dependencies
		if fl&senseRpmlib != 0 || strings.HasPrefix(n, "rpmlib(") || strings.HasPrefix(n, "(") {
			continue
		}
		if v == "" {
			out = append(out, n)
			continue
		}
		op := ""
		if fl&senseLess != 0 {
			op += "<"
		}
		if fl&senseGreater != 0 {
			op += ">"
		}
		if fl&senseEqual != 0 {
			op += "="
		}
		out = append(out, n+op+v)
	}
	return out
}

// Control returns the package's control fields and its install scripts by name.
//
// The header's tags are given Debian's field names: NAME is Package, REQUIRENAME is Depends, and
// so on; noarch is spelt all, and the version is epoch:version-release.
func (Format) Control(p string) (map[string]string, map[string]string, error) {
	h, _, _, err := sections(p)
	if err != nil {
		return nil, nil, err
	}
	fields := map[string]string{
		"Package":      h.Str(TagName),
		"Version":      h.Str(TagVersion) + "-" + h.Str(TagRelease),
		"Architecture": h.Str(TagArch),
	}
	if fields["Architecture"] == "noarch" {
		fields["Architecture"] = "all"
	}
	if e, ok := h.Int(TagEpoch); ok {
		fields["Version"] = fmt.Sprintf("%d:%s", e, fields["Version"])
	}
	if fields["Package"] == "" {
		return nil, nil, reader.Errorf("%s: no NAME in its header", p)
	}
	fields["Depends"] = strings.Join(deps(h, TagRequireName, TagRequireVersion, TagRequireFlags), " ")
	fields["Provides"] = strings.Join(deps(h, TagProvideName, TagProvideVersion, TagProvideFlags), " ")
	fields["Replaces"] = strings.Join(deps(h, TagObsoleteName, TagObsoleteVersion, TagObsoleteFlags), " ")
	scripts := map[string]string{}
	for _, kt := range []struct {
		key string
		tag uint32
	}{{"postinst", TagPostin}, {"preinst", TagPrein}, {"posttrans", TagPosttrans}} {
		if v, ok := h[kt.tag]; ok && len(v.Strs) > 0 && strings.Join(v.Strs, "") != "" {
			scripts[kt.key] = strings.Join(v.Strs, "\n")
		}
	}
	return fields, scripts, nil
}

// Interests returns none: rpm's file triggers are in other packages' headers, which this reader
// does not read.
func (Format) Interests(string) ([]string, error) {
	return nil, nil
}

var tokenRe = regexp.MustCompile(`^([^\s<>=]+)(?:(<=|>=|<|>|=)([^\s<>=]+))?$`)

// ParseDeps parses a dependency field, as Control spells it, into groups of one alternative each.
// For example, `glibc>=2.17 libc.so.6(GLIBC_2.2.5)(64bit) /bin/sh` gives [[{glibc >= 2.17}]
// [{libc.so.6(GLIBC_2.2.5)(64bit)}] [{/bin/sh}]]. A file item names a file some package must
// ship. An item that is not a dependency is an error.
func ParseDeps(field string) ([][]reader.Dep, error) {
	var out [][]reader.Dep
	for _, tok := range strings.Fields(field) {
		m := tokenRe.FindStringSubmatch(tok)
		if m == nil {
			return nil, reader.Errorf("cannot parse dependency %q", tok)
		}
		out = append(out, []reader.Dep{{Name: m[1], Op: m[2], Version: m[3]}})
	}
	return out, nil
}

// ParseDeps is the format's.
func (Format) ParseDeps(field string) ([][]reader.Dep, error) { return ParseDeps(field) }

// -------------------------------------------------------------- versions, as rpmvercmp orders them

var segmentRe = regexp.MustCompile(`[0-9]+|[a-zA-Z]+|~|\^`)

func isDigits(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }

// cmpNum compares two strings of decimal digits by value, whatever their length.
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

// rpmvercmp compares two version or release strings as rpmvercmp does: segment by segment,
// alphabetic and numeric segments alternating. A numeric segment sorts after an alphabetic one,
// and `~` before anything.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	ta, tb := segmentRe.FindAllString(a, -1), segmentRe.FindAllString(b, -1)
	for i := 0; i < len(ta) && i < len(tb); i++ {
		x, y := ta[i], tb[i]
		if x == "~" || y == "~" {
			if x != y {
				if x == "~" {
					return -1
				}
				return 1
			}
			continue
		}
		if x == "^" || y == "^" {
			if x != y {
				if x == "^" {
					return -1
				}
				return 1
			}
			continue
		}
		var c int
		switch {
		case isDigits(x) && isDigits(y):
			c = cmpNum(x, y)
		case isDigits(x) || isDigits(y):
			if isDigits(x) {
				return 1
			}
			return -1
		default:
			c = strings.Compare(x, y)
		}
		if c != 0 {
			return c
		}
	}
	if len(ta) != len(tb) {
		rest, longer := []string(nil), len(ta) > len(tb)
		if longer {
			rest = ta[len(tb):]
		} else {
			rest = tb[len(ta):]
		}
		if rest[0] == "~" {
			if longer {
				return -1
			}
			return 1
		}
		if longer {
			return 1
		}
		return -1
	}
	return 0
}

// evr splits a version into epoch, version and release.
func evr(v string) (int64, string, string) {
	epoch, rest := "0", v
	if e, r, found := strings.Cut(v, ":"); found {
		epoch, rest = e, r
	}
	ver, rel, _ := strings.Cut(rest, "-")
	n, err := strconv.ParseInt(epoch, 10, 64)
	if err != nil || !isDigits(epoch) {
		n = 0
	}
	return n, ver, rel
}

// Vercmp returns -1, 0 or 1 as a sorts before, with or after b, in rpm's order.
func Vercmp(a, b string) int {
	ea, va, ra := evr(a)
	eb, vb, rb := evr(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	c := rpmvercmp(va, vb)
	if c != 0 || ra == "" || rb == "" { // a constraint without a release matches any release
		return c
	}
	return rpmvercmp(ra, rb)
}

// Satisfies says whether version meets the constraint `op want`; no operator is always met.
func Satisfies(version, op, want string) bool {
	if op == "" {
		return true
	}
	c := Vercmp(version, want)
	switch op {
	case "=":
		return c == 0
	case "<":
		return c < 0
	case ">":
		return c > 0
	case "<=":
		return c <= 0
	case ">=":
		return c >= 0
	}
	return true
}

// Satisfies is the format's.
func (Format) Satisfies(version, op, want string) bool { return Satisfies(version, op, want) }
