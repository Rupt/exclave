package reader

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Tar is a tar archive read as its stream decompresses, its members handed out in the archive's
// order. keep chooses the members a caller sees; every header is read, and when the last has
// been, anything but NUL padding after the archive's end is refused. A header that cannot be
// read ends the archive where it stands, as tar's own readers stop there, and what it holds is
// then data after the end. A sparse member is refused, since its bytes in the stream are not its
// size, and dpkg refuses it too.
type Tar struct {
	label  string
	keep   func(*Member) bool
	closer io.Closer
	file   io.Closer // the file under the stream, or nil
	count  *Counting // the decompressed stream, counted
	held   *holding  // whether the last header read took a byte that was not NUL
	tr     *tar.Reader
	done   bool
}

// holding notes, while on, whether any byte read through it was not NUL: what a header read
// took, for a header that turns out to end the archive.
type holding struct {
	r     io.Reader
	on    bool
	dirty bool
}

func (h *holding) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	if h.on && !h.dirty {
		for _, b := range p[:n] {
			if b != 0 {
				h.dirty = true
				break
			}
		}
	}
	return n, err
}

// NewTar opens stream, decompressed, as a tar archive; a decompressor's error names label. file,
// which may be nil, is closed after the stream.
func NewTar(stream io.ReadCloser, file io.Closer, label string, keep func(*Member) bool) *Tar {
	count := &Counting{R: &Labelled{R: stream, Label: label}}
	held := &holding{r: count}
	return &Tar{label: label, keep: keep, closer: stream, file: file, count: count, held: held, tr: tar.NewReader(held)}
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
		t.held.dirty = false
		t.held.on = true
		hdr, err := t.tr.Next()
		t.held.on = false
		if err == io.EOF && start == 0 && t.count.Pos == 0 {
			t.done = true
			return nil, t.wrap(errors.New("empty archive"))
		}
		if err != nil && err != io.EOF && start == 0 {
			// no archive at all: tar's own word for its first header
			t.done = true
			return nil, t.wrap(err)
		}
		if err == io.EOF || errors.Is(err, tar.ErrHeader) || err == io.ErrUnexpectedEOF {
			t.done = true
			// the archive ended at start: what the header read took and the rest must be padding
			if t.held.dirty {
				return nil, t.wrap(fmt.Errorf("data after the archive's end at byte %d, not padding", start))
			}
			if why := AfterEnd(t.count, start); why != nil {
				return nil, t.wrap(why)
			}
			return nil, io.EOF
		}
		if err != nil {
			return nil, t.wrap(err)
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue // a pax global header, which tar's readers consume
		}
		if sparse(hdr) {
			return nil, t.wrap(fmt.Errorf("%s is a sparse member, which no package format uses", Pyrepr(hdr.Name)))
		}
		m := fromHeader(hdr)
		if t.keep == nil || t.keep(m) {
			return m, nil
		}
	}
}

// sparse says whether a header describes a GNU or pax sparse member, whose size is not its
// bytes in the stream.
func sparse(h *tar.Header) bool {
	if h.Typeflag == tar.TypeGNUSparse {
		return true
	}
	for k := range h.PAXRecords {
		if strings.HasPrefix(k, "GNU.sparse.") {
			return true
		}
	}
	return false
}

func (t *Tar) wrap(err error) error {
	if IsError(err) {
		return err
	}
	return &Error{Msg: t.label + ": " + err.Error()}
}

// Open returns the current member's contents; a stream that ends inside them is an error.
func (t *Tar) Open() io.Reader {
	return &Labelled{R: t.tr, Label: t.label}
}

// Close closes the stream, then the file under it.
func (t *Tar) Close() error {
	err := t.closer.Close()
	if t.file != nil {
		t.file.Close()
	}
	return err
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
	case tar.TypeReg, tar.TypeCont:
		m.Kind = File
	case tar.TypeRegA: // the old form, which spelt a directory by a trailing slash
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
