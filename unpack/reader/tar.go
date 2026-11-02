package reader

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"strings"
)

// Tar is a tar archive read as its stream decompresses, its members handed out in the archive's
// order. keep chooses the members a caller sees; every header is read, and when the last has
// been, anything but NUL padding after the archive's end is refused. A header that cannot be
// read ends the archive where it stands, as tar's own readers stop there, and what it holds is
// then data after the end.
type Tar struct {
	label  string
	keep   func(*Member) bool
	closer io.Closer
	count  *Counting // the decompressed stream, counted
	held   *holding  // the bytes the last header read took, for the end check
	tr     *tar.Reader
	done   bool
}

// holding keeps what is read through it while on, for a header that turns out to end the archive.
type holding struct {
	r   io.Reader
	on  bool
	buf bytes.Buffer
}

func (h *holding) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	if h.on {
		h.buf.Write(p[:n])
	}
	return n, err
}

// NewTar opens stream, decompressed, as a tar archive; a decompressor's error names label.
func NewTar(stream io.ReadCloser, label string, keep func(*Member) bool) *Tar {
	count := &Counting{R: &Labelled{R: stream, Label: label}}
	held := &holding{r: count}
	return &Tar{label: label, keep: keep, closer: stream, count: count, held: held, tr: tar.NewReader(held)}
}

func (t *Tar) Next() (*Member, error) {
	for {
		if t.done {
			return nil, io.EOF
		}
		// the previous member's unread data first, so that the header's offset is known
		if _, err := io.Copy(io.Discard, t.tr); err != nil {
			return nil, t.wrap(err)
		}
		start := (t.count.Pos + 511) &^ 511
		t.held.buf.Reset()
		t.held.on = true
		hdr, err := t.tr.Next()
		t.held.on = false
		if err == io.EOF || errors.Is(err, tar.ErrHeader) || err == io.ErrUnexpectedEOF {
			t.done = true
			// the archive ended at start: what the header read took and the rest must be padding
			rest := io.MultiReader(bytes.NewReader(t.held.buf.Bytes()), t.count)
			if why := AfterEnd(rest, start); why != nil {
				return nil, t.wrap(why)
			}
			return nil, io.EOF
		}
		if err != nil {
			return nil, t.wrap(err)
		}
		m := fromHeader(hdr)
		if t.keep == nil || t.keep(m) {
			return m, nil
		}
	}
}

func (t *Tar) wrap(err error) error {
	if _, ok := err.(*Error); ok {
		return err
	}
	return &Error{Msg: t.label + ": " + err.Error()}
}

// Open returns the current member's contents; a stream that ends inside them is an error.
func (t *Tar) Open() io.Reader {
	return &Labelled{R: t.tr, Label: t.label}
}

func (t *Tar) Close() error {
	return t.closer.Close()
}

func fromHeader(h *tar.Header) *Member {
	m := &Member{
		Name:     h.Name,
		Linkname: h.Linkname,
		Mode:     h.Mode,
		Mtime:    h.ModTime.Unix(),
		MtimeNS:  int64(h.ModTime.Nanosecond()),
		Size:     h.Size,
	}
	switch h.Typeflag {
	case tar.TypeDir:
		m.Kind = Dir
	case tar.TypeReg, tar.TypeRegA, tar.TypeCont, tar.TypeGNUSparse:
		m.Kind = File
		if strings.HasSuffix(h.Name, "/") {
			m.Kind = Dir
		}
	case tar.TypeSymlink:
		m.Kind = Symlink
	case tar.TypeLink:
		m.Kind = Hardlink
	default:
		m.Kind = Special
	}
	if m.Kind == Dir { // as tar's readers name a directory, without its trailing slashes
		m.Name = strings.TrimRight(m.Name, "/")
	}
	return m
}
