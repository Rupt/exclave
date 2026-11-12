// Package format is the exclave format as the command and unpack both write it (DESIGN.md 6):
// the strict grammar of the manifest and the hashes file (6.2, 6.4), a hash's text, and the
// volatile directories no tree ships (8.1).
//
// Both files are lines of records: a lowercase key, then fields separated by single spaces, each
// a bare token or a double-quoted string. Parse accepts exactly one spelling of each file and
// Dump produces it, so a file that Parse accepts and Dump reproduces byte for byte is canonical.
// The launcher's own parser (src/manifest.c) reads the manifest into its tables;
// test/grammar_test.py holds the two to the same answers.
package format

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"lukechampine.com/blake3"
)

// VolatileDirs are the host's volatile directories (8.1): always the host's at run time, never
// shipped. test/tables_test.py holds them to the launcher's.
var VolatileDirs = []string{"/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run"}

// HashPrefix names the hash of every digest the hashes file records (6.4): BLAKE3-256.
const HashPrefix = "b3:"

// DigestText is a digest as the hashes file writes it: the prefix and lowercase hex.
func DigestText(sum []byte) string { return HashPrefix + hex.EncodeToString(sum) }

// HashText is the hash of data as the hashes file writes it.
func HashText(data []byte) string {
	d := blake3.Sum256(data)
	return DigestText(d[:])
}

// Kind is the file a record belongs to.
type Kind int

const (
	Manifest Kind = iota
	Hashes
)

func (k Kind) name() string {
	if k == Hashes {
		return "hashes"
	}
	return "exclave"
}

// A Field is a string (s), whose value may hold any byte, or a bare token (t).
type Field struct {
	Typ byte
	V   string
}

// S and T are a string field and a token field, and Rec a record of them.
func S(v string) Field                  { return Field{'s', v} }
func T(v string) Field                  { return Field{'t', v} }
func Rec(key string, f ...Field) Record { return Record{Key: key, F: f} }

// A Record is one line of either file: its key and fields, its line, and the comments above it.
type Record struct {
	Key      string
	F        []Field
	Line     int
	Comments []string // the comment lines above it, without their #
}

// schema: each key, the file it belongs to, its place in that file's order, its fields (s a
// string, t a token), and whether it may appear once only.
var schema = []struct {
	Key    string
	Kind   Kind
	order  int
	fields string
	once   bool
}{
	{"exclave", Manifest, 0, "t", true},
	{"cpu", Manifest, 1, "s", true},
	{"data", Manifest, 2, "s", false},
	{"host", Manifest, 3, "s", false},
	{"own", Manifest, 4, "s", false},
	{"hashes", Hashes, 0, "t", true},
	{"tool", Hashes, 1, "s", true},
	{"launcher", Hashes, 2, "s", true},
	{"pkg", Hashes, 3, "ssss", false},
	{"manifest", Hashes, 4, "s", true},
	{"tree", Hashes, 5, "s", true},
}

// limits: the launcher's tables (8.1), the most records of each key a manifest may carry.
var limits = []struct {
	Key  string
	most int
}{{"own", 256}, {"host", 32}, {"data", 32}}

// fieldMax is the most bytes a field holds, a string's decoded: a path the launcher's buffers
// hold, which a longer one would not fit in the kernel's either (6.2).
const fieldMax = 4095

// keyMax and fieldsMax are the most characters of a key and the most fields of a record the
// launcher's parser takes (MANIFEST_KEY_MAX, MANIFEST_FIELDS): past either, the error is named
// by the character that takes the record past the bound, as the launcher names it.
const (
	keyMax    = 31
	fieldsMax = 8
)

func schemaOf(key string, k Kind) int {
	for i, s := range schema {
		if s.Kind == k && s.Key == key {
			return i
		}
	}
	return -1
}

// utf8Len is the length of the well-formed UTF-8 sequence at b[i], or 0 if it is malformed: no
// overlong forms, no surrogates, nothing above U+10FFFF (Unicode's table 3-7).
func utf8Len(b []byte, i int) int {
	c, left := b[i], len(b)-i
	cont := func(x byte) bool { return x >= 0x80 && x <= 0xBF }
	switch {
	case c < 0x80:
		return 1
	case c < 0xC2:
		return 0
	case c < 0xE0:
		if left >= 2 && cont(b[i+1]) {
			return 2
		}
		return 0
	case c < 0xF0:
		if left < 3 || !cont(b[i+2]) {
			return 0
		}
		lo, hi := byte(0x80), byte(0xBF)
		if c == 0xE0 {
			lo = 0xA0
		}
		if c == 0xED {
			hi = 0x9F
		}
		if b[i+1] >= lo && b[i+1] <= hi {
			return 3
		}
		return 0
	case c < 0xF5:
		if left < 4 || !cont(b[i+2]) || !cont(b[i+3]) {
			return 0
		}
		lo, hi := byte(0x80), byte(0xBF)
		if c == 0xF0 {
			lo = 0x90
		}
		if c == 0xF4 {
			hi = 0x8F
		}
		if b[i+1] >= lo && b[i+1] <= hi {
			return 4
		}
		return 0
	}
	return 0
}

// UTF8Valid reports whether s is well-formed UTF-8 throughout, by utf8Len's rule.
func UTF8Valid(s []byte) bool {
	for i := 0; i < len(s); {
		k := utf8Len(s, i)
		if k == 0 {
			return false
		}
		i += k
	}
	return true
}

// codePoint is the code point of the well-formed sequence of length k at p.
func codePoint(p []byte, k int) uint32 {
	if k == 1 {
		return uint32(p[0])
	}
	v := uint32(p[0]) & (0x7F >> k)
	for j := 1; j < k; j++ {
		v = v<<6 | uint32(p[j])&0x3F
	}
	return v
}

// An Error names where in the file the grammar is broken: "line L col C: why".
type Error struct {
	Line, Col int
	Why       string
}

func (e *Error) Error() string { return fmt.Sprintf("line %d col %d: %s", e.Line, e.Col, e.Why) }

// column is the column of raw[i], counted in characters from 1 as the launcher counts it (6.2);
// the line is well-formed UTF-8, so every byte that is not a continuation byte starts a character.
func column(raw []byte, i int) int {
	c := 1
	for j := range i {
		if raw[j]&0xC0 != 0x80 {
			c++
		}
	}
	return c
}

func isTokenChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' ||
		c == '+' || c == '-'
}

// parseString reads the quoted string at raw[col], its opening quote; returns its value and the
// column past its closing quote.
func parseString(raw []byte, col, line int) (string, int, error) {
	var v []byte
	c := col + 1
	for {
		if c >= len(raw) {
			return "", 0, &Error{line, column(raw, c), "unterminated string"}
		}
		ch := raw[c]
		if ch == '"' {
			break
		}
		if ch == '\\' {
			var e, b byte
			if c+1 < len(raw) {
				e = raw[c+1]
			}
			step := 2
			switch {
			case e == '\\' || e == '"':
				b = e
			case e == 'n':
				b = '\n'
			case e == 't':
				b = '\t'
			case e == 'x':
				const hex = "0123456789abcdef"
				h1, h2 := -1, -1
				if c+2 < len(raw) {
					h1 = strings.IndexByte(hex, raw[c+2])
				}
				if c+3 < len(raw) {
					h2 = strings.IndexByte(hex, raw[c+3])
				}
				if h1 < 0 || h2 < 0 {
					return "", 0, &Error{line, column(raw, c), "\\x needs two lowercase hex digits"}
				}
				b = byte(h1*16 + h2)
				step = 4
			default:
				return "", 0, &Error{line, column(raw, c), "unknown escape"}
			}
			if len(v)+1 > fieldMax {
				return "", 0, &Error{line, column(raw, c), "string too long"}
			}
			v = append(v, b)
			c += step
			continue
		}
		k := utf8Len(raw, c)
		if k == 0 { // the file was checked whole, so a line holds no malformed sequence
			k = 1
		}
		o := codePoint(raw[c:], k)
		if o < 0x20 || (o >= 0x7F && o <= 0x9F) {
			return "", 0, &Error{line, column(raw, c), "control character must be escaped"}
		}
		if len(v)+k > fieldMax {
			return "", 0, &Error{line, column(raw, c), "string too long"}
		}
		v = append(v, raw[c:c+k]...)
		c += k
	}
	return string(v), c + 1, nil
}

// normalisedAbs reports whether v is an absolute path with no empty, . or .. component and no
// trailing slash, and no NUL.
func normalisedAbs(v string) bool {
	if v == "" || v[0] != '/' || strings.IndexByte(v, 0) >= 0 {
		return false
	}
	if v == "/" {
		return true
	}
	if v[len(v)-1] == '/' {
		return false
	}
	for part := range strings.SplitSeq(v[1:], "/") { // every component after the first slash
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func checkRecord(r *Record, k Kind) error {
	s := schemaOf(r.Key, k)
	if s < 0 {
		return &Error{r.Line, 1, "unknown key " + r.Key}
	}
	want := schema[s].fields
	ok := len(r.F) == len(want)
	for i := 0; ok && i < len(r.F); i++ {
		ok = r.F[i].Typ == want[i]
	}
	if !ok {
		return &Error{r.Line, 1, "wrong Field count or type for " + r.Key}
	}
	// every key has a field, which the schema has just checked
	if (r.Key == "own" || r.Key == "host" || r.Key == "data") && !normalisedAbs(r.F[0].V) {
		return &Error{r.Line, 1, r.Key + " must be a normalised absolute path"}
	}
	if r.Key == "cpu" && strings.IndexByte(r.F[0].V, 0) >= 0 {
		return &Error{r.Line, 1, "cpu must not contain NUL"}
	}
	return nil
}

// Parse reads a manifest or a hashes file into its records, or says where it is refused.
func Parse(data []byte, k Kind) ([]Record, error) {
	n := len(data)
	if n == 0 || data[n-1] != '\n' {
		return nil, &Error{1, 1, "file must end with LF"}
	}
	if n >= 3 && string(data[:3]) == "\xef\xbb\xbf" {
		return nil, &Error{1, 1, "byte order mark"}
	}
	line := 1
	for i := 0; i < n; {
		if data[i] == '\r' {
			return nil, &Error{line, 1, "CR not allowed"}
		}
		k := utf8Len(data, i)
		if k == 0 {
			return nil, &Error{line, 1, "malformed UTF-8"}
		}
		if data[i] == '\n' {
			line++
		}
		i += k
	}
	var out []Record
	var comments []string
	counts := make([]int, len(limits))
	line = 1
	for pos := 0; pos < n; line++ {
		raw := data[pos:]
		raw = raw[:bytes.IndexByte(raw, '\n')]
		pos += len(raw) + 1
		if len(raw) == 0 {
			continue
		}
		if raw[0] == '#' { // kept with the record below it; a comment may hold any character
			comments = append(comments, string(raw[1:]))
			continue
		}
		r := Record{Line: line, Comments: comments}
		comments = nil
		col := 0
		for col < len(raw) {
			c := raw[col]
			if col == 0 {
				if !(c >= 'a' && c <= 'z') {
					break
				}
			} else if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				break
			}
			if col == keyMax {
				return nil, &Error{line, column(raw, col), "key too long"}
			}
			col++
		}
		if col == 0 {
			return nil, &Error{line, 1, "Record must start with a lowercase key"}
		}
		r.Key = string(raw[:col])
		for col < len(raw) {
			if raw[col] != ' ' {
				why := "expected a single space between fields"
				if raw[col] == '\t' {
					why = "tab outside a string"
				}
				return nil, &Error{line, column(raw, col), why}
			}
			col++
			if col >= len(raw) {
				return nil, &Error{line, column(raw, col), "trailing space"}
			}
			if raw[col] == ' ' {
				return nil, &Error{line, column(raw, col), "multiple spaces"}
			}
			if len(r.F) == fieldsMax {
				return nil, &Error{line, column(raw, col), "too many fields"}
			}
			if raw[col] == '"' {
				v, next, err := parseString(raw, col, line)
				if err != nil {
					return nil, err
				}
				r.F = append(r.F, Field{'s', v})
				col = next
			} else {
				start := col
				for col < len(raw) && isTokenChar(raw[col]) {
					if col-start == fieldMax {
						return nil, &Error{line, column(raw, col), "token too long"}
					}
					col++
				}
				if col == start {
					return nil, &Error{line, column(raw, col), "expected a string or token"}
				}
				r.F = append(r.F, Field{'t', string(raw[start:col])})
			}
		}
		if err := checkRecord(&r, k); err != nil {
			return nil, err
		}
		out = append(out, r)
		// each record's errors in the file's order, as the launcher meets them, so the two name the same line
		if len(out) == 1 && (r.Key != k.name() || len(r.F) < 1 || r.F[0].V != "1") {
			return nil, &Error{line, 1, "first Record must be " + k.name() + " 1"}
		}
		if schema[schemaOf(r.Key, k)].once {
			for _, p := range out[:len(out)-1] {
				if p.Key == r.Key {
					return nil, &Error{line, 1, "duplicate " + r.Key}
				}
			}
		}
		// refused here where the launcher's tables would refuse it (8.1)
		for l, lim := range limits {
			if k == Manifest && r.Key == lim.Key {
				counts[l]++
				if counts[l] > lim.most {
					return nil, &Error{line, 1, fmt.Sprintf("more than %d %s records", lim.most, r.Key)}
				}
			}
		}
	}
	if len(comments) > 0 {
		return nil, &Error{line, 1, "comment after the last Record"}
	}
	if len(out) == 0 {
		return nil, &Error{line, 1, "empty file"}
	}
	return out, nil
}

// Quote is the canonical string literal for v: printable UTF-8 as itself; backslash,
// double quote, newline and tab by their one-letter escapes; every other control character, C1
// controls byte by byte, and every malformed byte as \xHH.
func Quote(v string) string {
	b := []byte(v)
	var out strings.Builder
	out.WriteByte('"')
	for i := 0; i < len(b); {
		k := utf8Len(b, i)
		var o uint32
		if k > 0 {
			o = codePoint(b[i:], k)
		}
		switch {
		case b[i] == '\\':
			out.WriteString("\\\\")
		case b[i] == '"':
			out.WriteString("\\\"")
		case b[i] == '\n':
			out.WriteString("\\n")
		case b[i] == '\t':
			out.WriteString("\\t")
		case k == 0 || o < 0x20 || o == 0x7F || (o >= 0x80 && o <= 0x9F):
			for j := 0; j < max(k, 1); j++ {
				fmt.Fprintf(&out, "\\x%02x", b[i+j])
			}
		default:
			out.Write(b[i : i+k])
		}
		i += max(k, 1)
	}
	out.WriteByte('"')
	return out.String()
}

// fieldOrder orders two records by their fields' bytes, a shorter list first.
func fieldOrder(a, b *Record) int {
	for i := 0; i < len(a.F) && i < len(b.F); i++ {
		if c := strings.Compare(a.F[i].V, b.F[i].V); c != 0 {
			return c
		}
	}
	switch {
	case len(a.F) < len(b.F):
		return -1
	case len(a.F) > len(b.F):
		return 1
	}
	return 0
}

// Dump writes the records in canonical form: by key in the file's order, then by their
// fields' bytes, keeping file order between equals, a blank line between keys.
func Dump(rs []Record, k Kind) []byte {
	o := make([]*Record, len(rs))
	for i := range rs {
		o[i] = &rs[i]
	}
	sort.SliceStable(o, func(i, j int) bool {
		ko := schema[schemaOf(o[i].Key, k)].order - schema[schemaOf(o[j].Key, k)].order
		return ko < 0 || (ko == 0 && fieldOrder(o[i], o[j]) < 0)
	})
	var out strings.Builder
	for i, r := range o {
		if i > 0 && o[i-1].Key != r.Key {
			out.WriteByte('\n')
		}
		for _, c := range r.Comments {
			out.WriteString("#" + c + "\n")
		}
		out.WriteString(r.Key)
		for _, f := range r.F {
			out.WriteByte(' ')
			if f.Typ == 't' {
				out.WriteString(f.V)
			} else {
				out.WriteString(Quote(f.V))
			}
		}
		out.WriteByte('\n')
	}
	return []byte(out.String())
}
