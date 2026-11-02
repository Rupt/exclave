package reader

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"
)

// tarBytes makes a tar archive of the entries given, for the seeds.
func tarBytes(entries ...*tar.Header) []byte {
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, h := range entries {
		w.WriteHeader(h)
		if h.Typeflag == tar.TypeReg {
			w.Write(bytes.Repeat([]byte("x"), int(h.Size)))
		}
	}
	w.Close()
	return b.Bytes()
}

// FuzzTar reads any bytes as a tar stream: every input is answered, by members or a refusal.
func FuzzTar(f *testing.F) {
	f.Add([]byte{})
	f.Add(tarBytes(&tar.Header{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755},
		&tar.Header{Name: "usr/x", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5},
		&tar.Header{Name: "usr/l", Typeflag: tar.TypeSymlink, Linkname: "x"}))
	f.Add(append(tarBytes(&tar.Header{Name: "a", Typeflag: tar.TypeReg, Size: 1}), []byte("junk")...))
	f.Fuzz(func(t *testing.T, data []byte) {
		tr := NewTar(io.NopCloser(bytes.NewReader(data)), "fuzz", nil)
		defer tr.Close()
		for {
			m, err := tr.Next()
			if err != nil {
				break
			}
			if m.Kind == File {
				io.Copy(io.Discard, tr.Open())
			}
		}
	})
}
