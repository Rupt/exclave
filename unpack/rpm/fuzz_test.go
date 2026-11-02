package rpm

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"exclave/unpack/reader"
)

// header makes a header section of string entries, for the seeds.
func header(entries map[uint32]string) []byte {
	var index, data []byte
	for tag, s := range entries {
		e := make([]byte, 16)
		binary.BigEndian.PutUint32(e[0:], tag)
		binary.BigEndian.PutUint32(e[4:], 6)
		binary.BigEndian.PutUint32(e[8:], uint32(len(data)))
		binary.BigEndian.PutUint32(e[12:], 1)
		index = append(index, e...)
		data = append(append(data, s...), 0)
	}
	out := append([]byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}, make([]byte, 8)...)
	binary.BigEndian.PutUint32(out[8:], uint32(len(entries)))
	binary.BigEndian.PutUint32(out[12:], uint32(len(data)))
	return append(append(out, index...), data...)
}

// cpioEntry makes one newc entry, for the seeds.
func cpioEntry(name string, mode, size int) []byte {
	h := fmt.Sprintf("070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		1, mode, 0, 0, 1, 0, size, 0, 0, 0, 0, len(name)+1, 0)
	out := append([]byte(h), name...)
	out = append(out, 0)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	out = append(out, bytes.Repeat([]byte("x"), size)...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}

// rpmBytes makes a minimal rpm: lead, an empty signature header, a header and a gzip cpio payload.
func rpmBytes(payload []byte) []byte {
	out := append([]byte{0xed, 0xab, 0xee, 0xdb}, make([]byte, lead-4)...)
	out = append(out, header(map[uint32]string{})...)
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	out = append(out, header(map[uint32]string{TagName: "x", TagVersion: "1", TagRelease: "1", TagArch: "noarch"})...)
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(payload)
	w.Close()
	return append(out, b.Bytes()...)
}

// FuzzRpm reads any bytes as an .rpm: every input is answered, by its contents or a refusal.
func FuzzRpm(f *testing.F) {
	payload := append(cpioEntry("usr", 0o040755, 0), cpioEntry("usr/x", 0o100644, 3)...)
	payload = append(payload, cpioEntry("TRAILER!!!", 0, 0)...)
	f.Add([]byte{})
	f.Add(rpmBytes(payload))
	f.Add(rpmBytes(payload[:len(payload)-20]))
	f.Add(rpmBytes([]byte("not cpio")))
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, raw []byte) {
		p := filepath.Join(dir, "f.rpm")
		if err := os.WriteFile(p, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		ReadSections(p)
		Reader.Control(p)
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

// FuzzCpio reads any bytes as a cpio payload: every input is answered, by entries or a refusal.
func FuzzCpio(f *testing.F) {
	f.Add([]byte{})
	whole := append(cpioEntry("usr", 0o040755, 0), cpioEntry("usr/x", 0o100644, 3)...)
	f.Add(append(whole, cpioEntry("TRAILER!!!", 0, 0)...))
	f.Add(append(cpioEntry("l", 0o120777, 3), cpioEntry("TRAILER!!!", 0, 0)...))
	f.Add([]byte("070701" + "00000001" + "000081a4" + "00000000" + "00000000" + "00000002" + "00000000" + "-0000001" +
		"00000000" + "00000000" + "00000000" + "00000000" + "00000002" + "00000000" + "x\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		a := newPayload(io.NopCloser(bytes.NewReader(raw)), "fuzz")
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
	f.Add("glibc>=2.17 libc.so.6(GLIBC_2.2.5)(64bit) /bin/sh")
	f.Fuzz(func(t *testing.T, field string) {
		ParseDeps(field)
	})
}

// FuzzVercmp holds the order to its laws: a version equals itself, and the order reverses with
// its arguments.
func FuzzVercmp(f *testing.F) {
	f.Add("1:2.17-55.el7_9", "2.17^post1")
	f.Fuzz(func(t *testing.T, a, b string) {
		if Vercmp(a, a) != 0 {
			t.Errorf("%q differs from itself", a)
		}
		if x, y := Vercmp(a, b), Vercmp(b, a); x != -y {
			t.Errorf("%q against %q: %d and %d", a, b, x, y)
		}
	})
}
