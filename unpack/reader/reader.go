// Package reader is the interface every package reader provides, and the streams they read
// (DESIGN.md 10.1).
//
// Packages deb, apk and rpm each satisfy Reader, and unpack picks one by the package file's
// name. A reader presents its format in Debian's terms: control fields named as dpkg names them,
// and the payload as members handed out in the archive's order as it is decompressed, so that a
// payload is never held whole in memory.
package reader

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// Dep is one alternative of a dependency: a name, and an operator with a version when it is
// versioned, both "" when it is not.
type Dep struct {
	Name, Op, Version string
}

// Error is a package file that cannot be read: truncated, corrupt, or not of its format.
type Error struct {
	Msg string
}

func (e *Error) Error() string { return e.Msg }

// Errorf makes an Error from a format and its arguments.
func Errorf(format string, a ...any) error {
	return &Error{Msg: fmt.Sprintf(format, a...)}
}

// Kind is what a member of a payload is.
type Kind int

// The kinds of member: a directory, a regular file, a symbolic link, a hard link to an earlier
// member, and anything else (a device, a FIFO, a socket), which unpack skips.
const (
	Dir Kind = iota
	File
	Symlink
	Hardlink
	Special
)

// Member is one entry of a package's payload, as tar presents it.
type Member struct {
	Name     string
	Linkname string // a symbolic link's target, or the member a hard link names
	Mode     int64  // the permission bits, with setuid, setgid and sticky when the archive has them
	Mtime    int64  // seconds since the epoch
	MtimeNS  int64  // and the nanoseconds within the second, where the archive records them
	Size     int64  // a regular file's bytes
	Kind     Kind
}

// Archive is a package's payload, iterated once in its order with Next and closed afterwards.
// A regular member's contents are read with Open while it is the current member.
type Archive interface {
	// Next returns the next member, or io.EOF after the last, once what follows the archive's end
	// has been checked (10.1).
	Next() (*Member, error)
	// Open returns the current member's contents, which is a regular file.
	Open() io.Reader
	Close() error
}

// Reader is a package format: the package that reads it.
type Reader interface {
	// MergedUsr says whether the format's distributions merge /bin, /sbin and /lib into /usr.
	MergedUsr() bool
	// Control returns the package's control fields and its maintainer scripts by name.
	Control(path string) (fields, scripts map[string]string, err error)
	// Interests returns the paths, or named triggers, the package's maintainer scripts are run
	// for: where a package keeps a cache or an index other packages' files feed, which unpack does
	// not build (10.1); a format without them returns none.
	Interests(path string) ([]string, error)
	// OpenData returns the package's payload, the files it installs.
	OpenData(path string) (Archive, error)
	// ParseDeps parses a dependency field into groups of alternatives.
	ParseDeps(field string) ([][]Dep, error)
	// Satisfies says whether version meets the constraint `op want`; no operator is always met.
	Satisfies(version, op, want string) bool
}

// Compressions, by the name rpm gives a payload compressor; a file suffix maps onto them.
const (
	None  = "none"
	Gzip  = "gzip"
	Xz    = "xz"
	Lzma  = "lzma"
	Bzip2 = "bzip2"
	Zstd  = "zstd"
)

// dictCap is the largest LZMA dictionary a stream may ask for: xz -9 uses 64 MiB.
const dictCap = 128 << 20

// Suffixes maps a file name's suffix onto its compression.
var Suffixes = map[string]string{
	".xz": Xz, ".lzma": Lzma, ".gz": Gzip, ".bz2": Bzip2, ".zst": Zstd, ".tar": None,
}

type zstdCloser struct {
	*zstd.Decoder
}

func (z zstdCloser) Close() error {
	z.Decoder.Close()
	return nil
}

// Decompress returns r decompressed by the compression named, read forward; an unknown name is an
// error. The stream's own error on data it cannot decode comes back from Read as it is.
func Decompress(compression string, r io.Reader) (io.ReadCloser, error) {
	switch compression {
	case None:
		return io.NopCloser(r), nil
	case Gzip:
		g, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		return g, nil
	case Xz:
		// the dictionary a stream's header asks for is capped, since a few bytes could ask for 4 GiB
		x, err := xz.ReaderConfig{DictCap: dictCap}.NewReader(r)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(x), nil
	case Lzma:
		l, err := lzma.ReaderConfig{DictCap: dictCap}.NewReader(r)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(l), nil
	case Bzip2:
		return io.NopCloser(bzip2.NewReader(r)), nil
	case Zstd:
		// a stream without a frame is no stream: zstd's decoder would read it as nothing
		b := bufio.NewReader(r)
		if _, err := b.Peek(1); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		z, err := zstd.NewReader(b, zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, err
		}
		return zstdCloser{z}, nil
	}
	return nil, fmt.Errorf("unknown compression %q", compression)
}

// SmallLimit bounds a control file or script read whole: no package's is near it.
const SmallLimit = 16 << 20

// ReadSmall reads r whole, refusing more than SmallLimit bytes, naming what in the refusal.
func ReadSmall(r io.Reader, what string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, SmallLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > SmallLimit {
		return nil, Errorf("%s: larger than %d MiB", what, SmallLimit>>20)
	}
	return data, nil
}

// Labelled wraps a stream so that every error but io.EOF comes back as an Error naming label,
// for a decompressor's error on data it cannot decode or that ends early.
type Labelled struct {
	R     io.Reader
	Label string
}

func (l *Labelled) Read(p []byte) (int, error) {
	n, err := l.R.Read(p)
	if err != nil && err != io.EOF && !IsError(err) {
		err = &Error{Msg: l.Label + ": " + err.Error()}
	}
	return n, err
}

// Counting counts the bytes read through it: a reader's position in a stream read forward.
type Counting struct {
	R   io.Reader
	Pos int64
}

func (c *Counting) Read(p []byte) (int, error) {
	n, err := c.R.Read(p)
	c.Pos += int64(n)
	return n, err
}

// AfterEnd names what follows an archive's end at offset end in r, which stands there, unless it
// is nothing but NUL padding: what lies past a tar archive's last header or a cpio trailer could
// hold members another reader would extract, so it is refused (10.1).
func AfterEnd(r io.Reader, end int64) error {
	buf := make([]byte, 1<<16)
	for {
		n, err := r.Read(buf)
		for _, b := range buf[:n] {
			if b != 0 {
				return fmt.Errorf("data after the archive's end at byte %d, not padding", end)
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// CmpNum compares two strings of decimal digits by value, whatever their length.
func CmpNum(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// IsError says whether err is a package file that cannot be read, however wrapped.
func IsError(err error) bool {
	var e *Error
	return errors.As(err, &e)
}

// Pyrepr spells s as Python's repr does, for a message that names a path or a field that way.
func Pyrepr(s string) string {
	q := "'"
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		q = `"`
	}
	var b strings.Builder
	b.WriteString(q)
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case string(r) == q:
			b.WriteString(`\` + q)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 32 || r == 127:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteString(q)
	return b.String()
}
