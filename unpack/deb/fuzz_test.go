package deb

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"exclave/unpack/reader"
)

// arBytes makes an ar archive of the members given, for the seeds.
func arBytes(members ...[2][]byte) []byte {
	out := []byte("!<arch>\n")
	for _, m := range members {
		header := fmt.Sprintf("%-16s%-12s%-6s%-6s%-8s%-10d`\n", m[0], "0", "0", "0", "100644", len(m[1]))
		out = append(out, header...)
		out = append(out, m[1]...)
		if len(m[1])%2 == 1 {
			out = append(out, '\n')
		}
	}
	return out
}

func readAll(rd reader.Reader, path string) {
	fields, scripts, _ := rd.Control(path)
	rd.Interests(fields, scripts)
	a, err := rd.OpenData(path)
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

// FuzzDeb reads any bytes as a .deb: every input is answered, by its contents or a refusal.
func FuzzDeb(f *testing.F) {
	control := tarBytes(&tar.Header{Name: "./control", Typeflag: tar.TypeReg, Size: 3})
	data := tarBytes(&tar.Header{Name: "./usr/", Typeflag: tar.TypeDir, Mode: 0o755},
		&tar.Header{Name: "./usr/x", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2})
	f.Add([]byte{})
	f.Add(arBytes([2][]byte{[]byte("debian-binary"), []byte("2.0\n")}, [2][]byte{[]byte("control.tar"), control},
		[2][]byte{[]byte("data.tar"), data}))
	f.Add(arBytes([2][]byte{[]byte("data.tar.gz"), []byte("not gzip")}))
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, raw []byte) {
		p := filepath.Join(dir, "f.deb")
		if err := os.WriteFile(p, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		ArMembers(p)
		readAll(Reader, p)
		ParseDeps(string(raw))
	})
}

// FuzzParseDeps parses any field: an answer or an error, never a panic.
func FuzzParseDeps(f *testing.F) {
	f.Add("a (>= 1) | b, c:any [amd64] <!nocheck>")
	f.Add("")
	f.Fuzz(func(t *testing.T, field string) {
		ParseDeps(field)
		ParseStanzas(field)
		Decompress("x.gz", []byte(field))
	})
}

// FuzzVercmp holds the order to its laws: a version equals itself, and the order reverses with
// its arguments.
func FuzzVercmp(f *testing.F) {
	f.Add("1:1.0-1", "1.0~rc1")
	f.Fuzz(func(t *testing.T, a, b string) {
		if Vercmp(a, a) != 0 {
			t.Errorf("%q differs from itself", a)
		}
		if x, y := Vercmp(a, b), Vercmp(b, a); (x < 0) != (y > 0) || (x == 0) != (y == 0) {
			t.Errorf("%q against %q: %d and %d", a, b, x, y)
		}
	})
}
