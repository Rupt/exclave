// Package apk reads Alpine packages (DESIGN.md 10.1).
//
// An .apk is three gzip members back to back, each a tar stream: the signature, the control files
// (.PKGINFO and the install scripts, dot-files at the top level), and the data. Decompressed as
// one stream they read as one tar archive, since the first two streams carry no end-of-archive
// blocks.
//
// Alpine's formats differ from Debian's in ways the rest of unpack sees through this reader:
//
//   - `depend` and `provides` name packages, shared objects (`so:libc.musl-x86_64.so.1`), commands
//     (`cmd:gcc`) and pkg-config modules (`pc:zlib`). There are no alternatives. A file dependency,
//     such as `/bin/sh`, names something some package must ship.
//   - Versions are ordered as apk-tools orders them: `_rc` before the release, `-r` revisions after.
//   - Alpine's /bin, /sbin and /lib are directories of their own, not links into /usr.
//   - busybox's post-install makes its applet links with `busybox --install`. Unpack makes them
//     instead from the paths busybox lists in /etc/busybox-paths.d, each a relative link to
//     /bin/busybox, so that tree/bin/sh run from outside the exclave reaches the wrapper in the
//     tree (DESIGN.md 13 item 37).
//   - musl's loader reads no ld.so.cache, so the tool's static check asks for none.
//   - A package's licence text comes only in its `-doc` package.
package apk

import (
	"io"
	"os"
	"regexp"
	"strings"

	"exclave/unpack/reader"
)

// Format is the reader of .apk files.
type Format struct{}

// Reader is the format as unpack and the fetchers use it.
var Reader reader.Reader = Format{}

// MergedUsr is false: Alpine's /bin, /sbin and /lib are directories of their own.
func (Format) MergedUsr() bool { return false }

var scripts = map[string]bool{
	".pre-install": true, ".post-install": true, ".pre-upgrade": true, ".post-upgrade": true,
	".pre-deinstall": true, ".post-deinstall": true, ".trigger": true,
}

// norm returns a member name without its leading ./ or /, so control files start with a dot.
func norm(name string) string {
	for strings.HasPrefix(name, "./") {
		name = name[2:]
	}
	return strings.TrimLeft(name, "/")
}

// open opens the .apk as one tar archive read as it decompresses: its data members, or every
// member. The gzip members decompress as one stream, so the signature's and the control files'
// streams, which carry no end-of-archive blocks, run on into the data's.
func open(p string, data bool) (*reader.Tar, error) {
	label := p + ": not an apk"
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	stream, err := reader.Decompress(reader.Gzip, f)
	if err != nil {
		f.Close()
		return nil, reader.Errorf("%s: %s", label, err)
	}
	var keep func(*reader.Member) bool
	if data {
		keep = func(m *reader.Member) bool { return !strings.HasPrefix(norm(m.Name), ".") }
	}
	return reader.NewTar(stream, f, label, keep), nil
}

// OpenData returns the package's payload, the files it installs: the archive without its dot-files.
func (Format) OpenData(p string) (reader.Archive, error) {
	return open(p, true)
}

// Control returns the package's control fields and its install scripts by name.
//
// .PKGINFO's keys are given Debian's field names: pkgname is Package, depend is Depends, and so
// on; noarch is spelt all. The control files are those before the first data member, as apk-tools
// reads them; the data is read, and checked, by OpenData.
func (Format) Control(p string) (map[string]string, map[string]string, error) {
	fields, found := map[string]string{}, map[string]string{}
	raw := map[string][]string{}
	t, err := open(p, false)
	if err != nil {
		return nil, nil, err
	}
	defer t.Close()
	for {
		m, err := t.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		n := norm(m.Name)
		if !strings.HasPrefix(n, ".") {
			break
		}
		if m.Kind != reader.File || (n != ".PKGINFO" && !scripts[n]) {
			continue
		}
		data, err := reader.ReadSmall(t.Open(), p+": "+n)
		if err != nil {
			return nil, nil, err
		}
		if n == ".PKGINFO" {
			for line := range strings.SplitSeq(string(data), "\n") {
				if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, " = ") {
					continue
				}
				k, v, _ := strings.Cut(line, " = ")
				k = strings.TrimSpace(k)
				raw[k] = append(raw[k], strings.TrimSpace(v))
			}
		} else if scripts[n] {
			found[n] = string(data)
		}
	}
	if raw["pkgname"] == nil || raw["pkgver"] == nil {
		return nil, nil, reader.Errorf("%s: no pkgname or pkgver in .PKGINFO", p)
	}
	fields["Package"] = raw["pkgname"][0]
	fields["Version"] = raw["pkgver"][0]
	fields["Architecture"] = "noarch"
	if a := raw["arch"]; a != nil {
		fields["Architecture"] = a[0]
	}
	if fields["Architecture"] == "noarch" {
		fields["Architecture"] = "all"
	}
	for _, kv := range [][2]string{
		{"depend", "Depends"}, {"provides", "Provides"}, {"replaces", "Replaces"}, {"install_if", "Install-If"},
	} {
		if v, ok := raw[kv[0]]; ok {
			fields[kv[1]] = strings.Join(v, " ")
		}
	}
	if v, ok := raw["triggers"]; ok {
		fields["Triggers"] = strings.Join(v, " ")
	}
	return fields, found, nil
}

// Interests returns the package's trigger interests: the directories .PKGINFO's `triggers` names.
func (f Format) Interests(p string) ([]string, error) {
	fields, _, err := f.Control(p)
	if err != nil {
		return nil, err
	}
	return strings.Fields(fields["Triggers"]), nil
}

// a name is anything up to an operator: cmd:[ and so:libstdc++.so.6 are names
var tokenRe = regexp.MustCompile(`^(!?)([^\s<>=~!][^\s<>=~]*?)(?:(<=|>=|><|<|>|=|~)(.+))?$`)

// ParseDeps parses a depend or provides field into groups of one alternative each. For example,
// `so:libc.musl-x86_64.so.1 zlib>=1.2 !conflict /bin/sh` gives [[{so:libc.musl-x86_64.so.1}]
// [{zlib >= 1.2}] [{/bin/sh}]]: a `!` item is a conflict, not a dependency, and is dropped. An
// item that is not a dependency is an error.
func ParseDeps(field string) ([][]reader.Dep, error) {
	var out [][]reader.Dep
	for tok := range strings.FieldsSeq(field) {
		m := tokenRe.FindStringSubmatch(tok)
		if m == nil {
			return nil, reader.Errorf("cannot parse dependency %s", reader.Pyrepr(tok))
		}
		if m[1] != "" {
			continue
		}
		out = append(out, []reader.Dep{{Name: m[2], Op: m[3], Version: m[4]}})
	}
	return out, nil
}

// ParseDeps is the format's.
func (Format) ParseDeps(field string) ([][]reader.Dep, error) { return ParseDeps(field) }

// ------------------------------------------------------------ versions, as apk-tools orders them

// A version is digit{.digit}...{letter}{_suffix{number}}...{~hash}{-r number}, read into tokens
// as apk-tools' version.c reads it (its 3.0), and two versions compare token by token.
type tokenKind int

const (
	tokInitialDigit tokenKind = iota
	tokDigit
	tokLetter
	tokSuffix
	tokSuffixNo
	tokCommitHash
	tokRevisionNo
	tokEnd
	tokInvalid
)

// the suffixes in apk-tools' order; those before "" are pre-releases
var suffixes = []string{"", "alpha", "beta", "pre", "rc", "", "cvs", "svn", "git", "hg", "p"}

const (
	suffixInvalid = 0
	suffixNone    = 5
)

type token struct {
	kind   tokenKind
	value  string // the digits, the letter, the suffix's word or the hash
	suffix int    // a suffix's place in suffixes
}

// tokens reads a version into its tokens, ending with tokEnd, or tokInvalid where apk-tools
// would stop.
type tokens struct {
	rest string
	cur  token
}

func (t *tokens) digits() {
	i := 0
	for i < len(t.rest) && t.rest[i] >= '0' && t.rest[i] <= '9' {
		i++
	}
	if i == 0 {
		t.cur.kind = tokInvalid
		return
	}
	t.cur.value, t.rest = t.rest[:i], t.rest[i:]
}

func (t *tokens) first() {
	t.cur = token{kind: tokInitialDigit}
	t.digits()
}

func (t *tokens) next() {
	prev := t.cur.kind
	if t.rest == "" {
		t.cur = token{kind: tokEnd}
		return
	}
	c := t.rest[0]
	switch {
	case c >= 'a' && c <= 'z':
		if prev > tokDigit {
			break
		}
		t.cur = token{kind: tokLetter, value: t.rest[:1]}
		t.rest = t.rest[1:]
		return
	case c == '.' || (c >= '0' && c <= '9'):
		if c == '.' {
			if prev > tokDigit {
				break
			}
			t.rest = t.rest[1:]
		}
		switch prev {
		case tokInitialDigit, tokDigit:
			t.cur = token{kind: tokDigit}
		case tokSuffix:
			if c == '.' {
				t.cur = token{kind: tokInvalid}
				return
			}
			t.cur = token{kind: tokSuffixNo}
		default:
			t.cur = token{kind: tokInvalid}
			return
		}
		t.digits()
		return
	case c == '_':
		if prev > tokSuffixNo {
			break
		}
		i := 1
		for i < len(t.rest) && t.rest[i] >= 'a' && t.rest[i] <= 'z' {
			i++
		}
		word := t.rest[1:i]
		t.rest = t.rest[i:]
		s := suffixInvalid
		for k, w := range suffixes {
			if k != suffixInvalid && w != "" && w == word {
				s = k
			}
		}
		if s == suffixInvalid {
			t.cur = token{kind: tokInvalid}
			return
		}
		t.cur = token{kind: tokSuffix, value: word, suffix: s}
		return
	case c == '~':
		if prev >= tokCommitHash {
			break
		}
		i := 1
		for i < len(t.rest) && ((t.rest[i] >= '0' && t.rest[i] <= '9') || (t.rest[i] >= 'a' && t.rest[i] <= 'f')) {
			i++
		}
		if i == 1 {
			t.cur = token{kind: tokInvalid}
			return
		}
		t.cur = token{kind: tokCommitHash, value: t.rest[1:i]}
		t.rest = t.rest[i:]
		return
	case c == '-':
		if prev >= tokRevisionNo || !strings.HasPrefix(t.rest, "-r") {
			break
		}
		t.rest = t.rest[2:]
		t.cur = token{kind: tokRevisionNo}
		t.digits()
		return
	}
	t.cur = token{kind: tokInvalid}
}

// cmp compares two tokens of one kind as apk-tools' token_cmp does.
func (a token) cmp(b token) int {
	switch a.kind {
	case tokDigit:
		// a component with a leading zero compares as a string, as Gentoo's rule has it
		if a.value[0] == '0' || b.value[0] == '0' {
			return strings.Compare(a.value, b.value)
		}
		return reader.CmpNum(a.value, b.value)
	case tokInitialDigit, tokSuffixNo, tokRevisionNo:
		return reader.CmpNum(a.value, b.value)
	case tokLetter:
		return strings.Compare(a.value, b.value)
	case tokSuffix:
		if a.suffix != b.suffix {
			if a.suffix < b.suffix {
				return -1
			}
			return 1
		}
		return 0
	}
	return strings.Compare(a.value, b.value)
}

// compare returns -1, 0 or 1 as a sorts before, with or after b, in apk-tools' order; with fuzzy,
// b that is a prefix of a, token for token, counts as equal.
func compare(a, b string, fuzzy bool) int {
	var ta, tb tokens
	ta.rest, tb.rest = a, b
	ta.first()
	tb.first()
	for ta.cur.kind == tb.cur.kind && ta.cur.kind < tokEnd {
		if r := ta.cur.cmp(tb.cur); r != 0 {
			return r
		}
		ta.next()
		tb.next()
	}
	if ta.cur.kind == tb.cur.kind {
		return 0
	}
	if tb.cur.kind == tokEnd && fuzzy {
		return 0
	}
	// the leading components agree: the longer version is the later unless its suffix says
	// pre-release
	if ta.cur.kind == tokSuffix && ta.cur.suffix < suffixNone {
		return -1
	}
	if tb.cur.kind == tokSuffix && tb.cur.suffix < suffixNone {
		return 1
	}
	if ta.cur.kind > tb.cur.kind {
		return -1
	}
	if tb.cur.kind > ta.cur.kind {
		return 1
	}
	return 0
}

// Vercmp returns -1, 0 or 1 as a sorts before, with or after b, in apk-tools' order.
func Vercmp(a, b string) int {
	return compare(a, b, false)
}

// Satisfies says whether version meets the constraint `op want`; no operator is always met.
// `~` is apk's fuzzy match: want is a prefix of version, token for token.
func Satisfies(version, op, want string) bool {
	if op == "" {
		return true
	}
	if op == "~" {
		return compare(version, want, true) == 0
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
