package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"

	"exclave/unpack/reader"
)

func gz(data []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(data)
	w.Close()
	return b.Bytes()
}

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

// FuzzApk reads any bytes as an .apk: every input is answered, by its contents or a refusal.
func FuzzApk(f *testing.F) {
	control := tarBytes(&tar.Header{Name: ".PKGINFO", Typeflag: tar.TypeReg, Size: 20})
	data := tarBytes(&tar.Header{Name: "usr/x", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2})
	f.Add([]byte{})
	f.Add(append(gz(control[:len(control)-1024]), gz(data)...))
	f.Add(gz([]byte("not a tar")))
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, raw []byte) {
		p := filepath.Join(dir, "f.apk")
		if err := os.WriteFile(p, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		fields, scripts, _ := Reader.Control(p)
		Reader.Interests(fields, scripts)
		ControlChecksum(p)
		a, err := Reader.OpenData(p)
		if err != nil {
			return
		}
		defer a.Close()
		for {
			m, err := a.Next()
			if err != nil {
				return
			}
			if m.Kind == reader.File {
				io.Copy(io.Discard, a.Open())
			}
		}
	})
}

// FuzzParseDeps parses any field: an answer or an error, never a panic.
func FuzzParseDeps(f *testing.F) {
	f.Add("so:libc.musl-x86_64.so.1 zlib>=1.2 !conflict /bin/sh")
	f.Fuzz(func(t *testing.T, field string) {
		ParseDeps(field)
	})
}

// FuzzVercmp holds the order to its laws: a version equals itself, and the order reverses with
// its arguments.
func FuzzVercmp(f *testing.F) {
	f.Add("1.0_rc1-r2", "1.0a_p1")
	f.Fuzz(func(t *testing.T, a, b string) {
		if Vercmp(a, a) != 0 {
			t.Errorf("%q differs from itself", a)
		}
		if x, y := Vercmp(a, b), Vercmp(b, a); x != -y {
			t.Errorf("%q against %q: %d and %d", a, b, x, y)
		}
		Satisfies(a, "~", b)
	})
}
