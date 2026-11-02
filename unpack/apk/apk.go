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
	return reader.NewTar(&closeBoth{stream, f}, label, keep), nil
}

type closeBoth struct {
	io.ReadCloser
	f *os.File
}

func (c *closeBoth) Close() error {
	err := c.ReadCloser.Close()
	c.f.Close()
	return err
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
		if m.Kind != reader.File {
			continue
		}
		data, err := io.ReadAll(t.Open())
		if err != nil {
			return nil, nil, err
		}
		if n == ".PKGINFO" {
			for _, line := range strings.Split(string(data), "\n") {
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
	for _, tok := range strings.Fields(field) {
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

var suffixOrder = map[string]int{
	"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5,
}

var verRe = regexp.MustCompile(
	`^(\d+(?:\.\d+)*)([a-z])?((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:-r(\d+))?$`)

type suffix struct {
	order int
	num   string
}

// key is a version split into the parts apk-tools compares: numbers, letter, suffixes, revision.
type key struct {
	nums   []string
	letter string
	sufs   []suffix
	rev    string
}

func parse(v string) key {
	m := verRe.FindStringSubmatch(v)
	if m == nil {
		return key{nums: []string{"0"}, rev: "0"} // a version apk would not accept: compared as 0
	}
	k := key{nums: strings.Split(m[1], "."), letter: m[2], rev: m[4]}
	if k.rev == "" {
		k.rev = "0"
	}
	for _, s := range strings.Split(m[3], "_") {
		if s == "" {
			continue
		}
		word := strings.TrimRight(s, "0123456789")
		k.sufs = append(k.sufs, suffix{suffixOrder[word], s[len(word):]})
	}
	return k
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

// Vercmp returns -1, 0 or 1 as a sorts before, with or after b, in apk-tools' order.
func Vercmp(a, b string) int {
	ka, kb := parse(a), parse(b)
	for i := 0; i < len(ka.nums) && i < len(kb.nums); i++ {
		if c := CmpNum(ka.nums[i], kb.nums[i]); c != 0 {
			return c
		}
	}
	if len(ka.nums) != len(kb.nums) {
		if len(ka.nums) < len(kb.nums) {
			return -1
		}
		return 1
	}
	if ka.letter != kb.letter {
		return strings.Compare(ka.letter, kb.letter)
	}
	sa, sb := ka.sufs, kb.sufs
	if len(sa) == 0 {
		sa = []suffix{{0, "0"}}
	}
	if len(sb) == 0 {
		sb = []suffix{{0, "0"}}
	}
	for i := 0; i < len(sa) && i < len(sb); i++ {
		if sa[i].order != sb[i].order {
			if sa[i].order < sb[i].order {
				return -1
			}
			return 1
		}
		if c := CmpNum(sa[i].num, sb[i].num); c != 0 {
			return c
		}
	}
	if len(sa) != len(sb) {
		if len(sa) < len(sb) {
			return -1
		}
		return 1
	}
	return CmpNum(ka.rev, kb.rev)
}

// Satisfies says whether version meets the constraint `op want`; no operator is always met.
// `~` is a fuzzy match: the version is want, or starts with want and a separator.
func Satisfies(version, op, want string) bool {
	if op == "" {
		return true
	}
	if op == "~" {
		return version == want || strings.HasPrefix(version, want+".") || strings.HasPrefix(version, want+"-")
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
