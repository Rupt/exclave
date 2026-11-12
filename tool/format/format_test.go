package format

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// records gives n records of key, each a path of its own.
func records(key string, n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "%s \"/c%03d\"\n", key, i)
	}
	return b.String()
}

// TestPositions holds the parser to the line and column of an error at a known place (6.2), as
// test/grammar_test.py holds the command and the launcher's parser together.
func TestPositions(t *testing.T) {
	for _, c := range []struct {
		text, want string
	}{
		{"exclave 1\n\ncpu \"x86-64\"\n\nown \"/x\"\nbogus 1\n", "line 6 col 1"},
		{"exclave 1\n\nown \"/x\"\nown \"x\"\n", "line 4 col 1"},
		{"exclave 1\n\nown \"/x\"\r\n", "line 3 col 1"},
		{"exclave 1\n\nown \"/\xff\"\n", "line 3 col 1"},
		{"exclave 1\n\nown \"/x\" \n", "line 3 col 10"},
		{"exclave 1\n\nown \"/x\"\n# after\n", "line 5 col 1"},
		{"exclave 1\n\n" + records("own", 257), "line 259 col 1"},
		{"exclave 1\n\n" + records("host", 33), "line 35 col 1"},
		{"exclave 1\n\n" + records("data", 33), "line 35 col 1"},
		{"exclave 1\n\nown \"/éé\\q\"\n", "line 3 col 9"},
		{"exclave 1\n\nown \"/" + strings.Repeat("a", 9000) + "\"\n", "line 3 col 4101"},
		{"exclave 1\n\nown \"/" + strings.Repeat("é", 3000) + "\"\n", "line 3 col 2054"},
		{"exclave 1\n\ncpu " + strings.Repeat("1", 5000) + "\n", "line 3 col 4100"},
		{"exclave 1\n\n" + strings.Repeat("a", 32) + " \"/x\"\n", "line 3 col 32"},
		{"exclave 1\n\nown" + strings.Repeat(" \"/a\"", 9) + "\n", "line 3 col 45"},
		{"", "line 1 col 1"},
		{"\n", "line 2 col 1"},
		{"hashes 1\n", "line 1 col 1"},
	} {
		_, err := Parse([]byte(c.text), Manifest)
		if err == nil || !strings.HasPrefix(err.Error(), c.want+": ") {
			t.Errorf("%q: %v, wanted %s", c.text[:min(len(c.text), 40)], err, c.want)
		}
	}
}

// TestCanonical: a value spelt in canonical form is canonical, a value spelt with every byte
// escaped is rewritten to that form, and the launcher's limits are the grammar's.
func TestCanonical(t *testing.T) {
	for _, v := range []string{"/x", "/a b", "/é", "/\xff\xfe", "/\"\\\n\t\x01\x7f", "/\xc2\x80",
		"/" + strings.Repeat("z", 4094)} {
		canon := "exclave 1\n\nown " + Quote(v) + "\n"
		rs, err := Parse([]byte(canon), Manifest)
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if rs[1].F[0].V != v {
			t.Errorf("%q decoded as %q", v, rs[1].F[0].V)
		}
		if out := Dump(rs, Manifest); string(out) != canon {
			t.Errorf("%q: dumped as %q", canon, out)
		}
		var every strings.Builder
		for i := 0; i < len(v); i++ {
			fmt.Fprintf(&every, "\\x%02x", v[i])
		}
		rs, err = Parse([]byte("exclave 1\n\nown \""+every.String()+"\"\n"), Manifest)
		if err != nil {
			t.Fatalf("%q every byte escaped: %v", v, err)
		}
		if out := Dump(rs, Manifest); string(out) != canon {
			t.Errorf("%q every byte escaped: dumped as %q", v, out)
		}
	}
	// the hashes file's order: keys in the schema's order, then the fields' bytes, a blank line between keys
	text := "hashes 1\n\ntool \"v\"\n\npkg \"b\" \"1\" \"amd64\" \"b3:x\"\npkg \"a\" \"2\" \"amd64\" \"b3:y\"\n"
	rs, err := Parse([]byte(text), Hashes)
	if err != nil {
		t.Fatal(err)
	}
	want := "hashes 1\n\ntool \"v\"\n\npkg \"a\" \"2\" \"amd64\" \"b3:y\"\npkg \"b\" \"1\" \"amd64\" \"b3:x\"\n"
	if out := Dump(rs, Hashes); string(out) != want {
		t.Errorf("sorted as %q", out)
	}
	if _, err := Parse([]byte("exclave 1\n\n"+records("own", 256)), Manifest); err != nil {
		t.Errorf("256 own records: %v", err)
	}
}

// FuzzGrammar: every input is refused or parsed, and what parses dumps to a canonical form that
// parses again to the same bytes.
func FuzzGrammar(f *testing.F) {
	f.Add([]byte("exclave 1\n\ncpu \"x86-64-v3\"\n\ndata \"/opt/d\"\n\nhost \"/etc/x\"\n\n# why\nown \"/usr\"\n"))
	f.Add([]byte("hashes 1\n\ntool \"0.1.0\"\n\nlauncher \"b3:00\"\n\npkg \"a\" \"1\" \"all\" \"b3:01\"\n\n" +
		"manifest \"b3:02\"\n\ntree \"b3:03\"\n"))
	f.Add([]byte("exclave 1\n\nown \"/\\x00\\n\\t\\\"\\\\é\"\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, k := range []Kind{Manifest, Hashes} {
			rs, err := Parse(data, k)
			if err != nil {
				continue
			}
			canon := Dump(rs, k)
			again, err := Parse(canon, k)
			if err != nil {
				t.Fatalf("the canonical form %q is refused: %v", canon, err)
			}
			if !bytes.Equal(Dump(again, k), canon) {
				t.Fatalf("the canonical form %q is not idempotent", canon)
			}
		}
	})
}
