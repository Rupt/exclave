// The steps that make a tree from package files (DESIGN.md 10.1): extraction, synthesis of what
// maintainer scripts would have made, the volatile directories stripped, the dependency report,
// and the hashes file's pkg records.
package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"

	"exclave/unpack/reader"
	"exclave/unpack/root"
)

// mergedUsr are the directories Debian's and Fedora's merged /usr links into usr/.
var mergedUsr = []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32"}

// volatile are the host's volatile directories (8.1): always the host's at run time, never
// shipped.
var volatile = []string{"/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run"}

var aliasRe = regexp.MustCompile(`^(bin|sbin|lib|lib32|lib64|libx32)(/|$)`)

// refusing turns a tree that cannot hold what the packages ask into unpack's refusal.
func refusing(err error) error {
	var re *root.Error
	if errors.As(err, &re) {
		return &UnpackError{Msg: re.Msg}
	}
	return err
}

// extract extracts every package's payload into the tree at rootPath, after making the
// merged-/usr links (10.1).
//
// Paths resolve with the tree as their root (package root), so a symlink a package ships leads
// nowhere outside it. A regular file shipped by two packages is an error unless one declares
// Replaces on the other; the /lib and /usr/lib spellings of a path count as one. Renaming
// diversions are refused, and so is a file that would leave the output's filesystem short of
// room. log gets one line per special file skipped.
func extract(rootPath string, packages []*Package, log Log) error {
	if err := os.MkdirAll(rootPath, 0o777); err != nil {
		return err
	}
	r, err := root.Open(rootPath)
	if err != nil {
		return err
	}
	defer r.Close()
	return refusing(extractInto(r, packages, log))
}

var divertRe = regexp.MustCompile(`--(remove|list|listpackage|truename)\b`)

// extractInto extracts into the open tree; owner, the package that owns each extracted path by
// its /usr-merged spelling, is how a file shipped twice is told from one replaced.
func extractInto(r *root.Root, packages []*Package, log Log) error {
	if err := r.Makedirs("usr"); err != nil {
		return err
	}
	// A symlink one package ships at a path other packages ship files under, Fedora 42's
	// usr/sbin -> bin, is made before anything is extracted, as the merged-usr links are, so that
	// those files land where the link points whatever the order of the packages; a package's own
	// files under its own link count too.
	links := map[string]string{}
	parents := map[string]bool{}
	// the files' declared sizes: a set that cannot fit is refused before it is written, the free
	// space asked once per package and whenever the total has grown by 64 MiB since it was asked
	var total, asked int64
	for _, pkg := range packages {
		t, err := readerFor(pkg.Path).OpenData(pkg.Path)
		if err != nil {
			return err
		}
		for {
			m, err := t.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Close()
				return err
			}
			rel, err := safeRel(m.Name)
			if err != nil {
				t.Close()
				return err
			}
			if rel == "" {
				continue
			}
			if m.Kind == reader.File {
				total += m.Size
				if total-asked >= 64<<20 {
					if err := r.Room(total, fmt.Sprintf("the files up to /%s in %s declare", rel, pkg.Name)); err != nil {
						t.Close()
						return err
					}
					asked = total
				}
			}
			if m.Kind == reader.Symlink {
				links[rel] = m.Linkname
			} else if m.Kind != reader.Dir {
				parts := strings.Split(rel, "/")
				for i := 1; i < len(parts); i++ {
					parents[strings.Join(parts[:i], "/")] = true
				}
			}
		}
		t.Close()
		if err := r.Room(total, fmt.Sprintf("the files of the packages up to %s declare", pkg.Name)); err != nil {
			return err
		}
		asked = total
	}
	merged := map[string]bool{}
	for _, d := range mergedUsr {
		merged["usr/"+d] = true
	}
	// Debian's and Fedora's merged /usr; Alpine's directories are its own
	allMerged := true
	for _, p := range packages {
		if !readerFor(p.Path).MergedUsr() {
			allMerged = false
		}
	}
	if allMerged {
		for _, d := range mergedUsr {
			// unless a package ships usr/<d> itself as a link (Fedora 42's usr/sbin -> bin)
			if _, ok := links["usr/"+d]; !ok {
				if err := r.Makedirs("usr/" + d); err != nil {
					return err
				}
			}
			if !r.Lexists(d) {
				if err := r.Symlink("usr/"+d, d); err != nil {
					return err
				}
			}
		}
	}
	linkPaths := make([]string, 0, len(links))
	for rel := range links {
		linkPaths = append(linkPaths, rel)
	}
	sort.Strings(linkPaths)
	for _, rel := range linkPaths {
		target := links[rel]
		if (parents[rel] || merged[rel]) && !strings.HasPrefix(target, "/") &&
			!hasPart(target, "..") && !r.Lexists(rel) {
			if err := r.Symlink(target, rel); err != nil {
				return err
			}
		}
	}
	owner := map[string]string{}
	replaces := map[string]map[string]bool{}
	var hardlinks []pending
	for _, pkg := range packages {
		name, rd := pkg.Name, readerFor(pkg.Path)
		_, scripts, err := rd.Control(pkg.Path)
		if err != nil {
			return err
		}
		// 10.1 step 2: a diversion that renames a file changes where the tree must hold it, and
		// dpkg's database is not reproduced here; those are refused. Diversions with --no-rename,
		// and the merged-usr and zutils transitions every noble closure carries, leave a fresh
		// tree unchanged.
		for _, sname := range []string{"preinst", "postinst"} {
			for _, line := range strings.Split(strings.ReplaceAll(scripts[sname], "\\\n", " "), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "#") || !strings.Contains(line, "dpkg-divert") {
					continue
				}
				if divertRe.MatchString(line) || strings.Contains(line, "--no-rename") || strings.Contains(line, ".usr-is-merged") {
					continue
				}
				return refuse("%s adds a renaming diversion in its %s (%s); diversions are refused (10.1)",
					name, sname, cut(strings.TrimSpace(line), 100))
			}
		}
		groups, err := rd.ParseDeps(pkg.Fields["Replaces"])
		if err != nil {
			return err
		}
		replaces[name] = map[string]bool{}
		for _, alts := range groups {
			for _, a := range alts {
				replaces[name][a.Name] = true
			}
		}
		t, err := rd.OpenData(pkg.Path)
		if err != nil {
			return err
		}
		if err := extractPackage(r, t, name, replaces, owner, &hardlinks, log); err != nil {
			t.Close()
			return err
		}
		t.Close()
	}
	for _, h := range hardlinks {
		if r.Lexists(h.dst) {
			if err := r.Remove(h.dst); err != nil {
				return err
			}
		}
		// the member the archive names, never what a shipped symlink there points at
		if err := r.Link(h.src, h.dst); err != nil {
			return err
		}
	}
	return nil
}

// pending is a hard link to make once every member is extracted: the entry it names, and its path.
type pending struct{ src, dst string }

func extractPackage(r *root.Root, t reader.Archive, name string, replaces map[string]map[string]bool,
	owner map[string]string, hardlinks *[]pending, log Log) error {
	for {
		m, err := t.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		rel, err := safeRel(m.Name)
		if err != nil {
			return err
		}
		if rel == "" {
			continue
		}
		key := aliasRe.ReplaceAllString(rel, "usr/$1$2") // /lib/x and /usr/lib/x are one file
		if m.Kind == reader.Dir {
			if r.IsLink(rel) && r.IsDir(rel) {
				continue
			}
			if r.Lexists(rel) && !r.IsDir(rel) {
				return refuse("%s ships the directory /%s where a file stands", name, rel)
			}
			if err := r.Makedirs(rel); err != nil {
				return err
			}
			// the tar's mode; a tree must stay traversable by its owner
			if err := r.ChmodDir(rel, uint32(m.Mode&0o777)|0o700); err != nil {
				return err
			}
			continue
		}
		if r.Lexists(rel) && (r.IsLink(rel) || !r.IsDir(rel)) {
			prev := owner[key]
			if m.Kind == reader.Symlink && r.IsLink(rel) {
				if target, err := r.Readlink(rel); err == nil && target == m.Linkname {
					// identical symlink from two packages, or a merged-usr link: normal
					continue
				}
			}
			if r.IsLink(rel) && r.IsDir(rel) && m.Kind != reader.Symlink {
				return refuse("%s ships /%s over a directory symlink", name, rel)
			}
			switch {
			case prev != "" && replaces[name][prev]:
				if err := r.Remove(rel); err != nil { // this package replaces the previous owner's file
					return err
				}
			case prev != "" && replaces[prev][name]:
				continue // the previous owner replaces ours: keep theirs
			case prev != "":
				return refuse("%s and %s both ship /%s and neither declares Replaces", prev, name, rel)
			default:
				if err := r.Remove(rel); err != nil {
					return err
				}
			}
		}
		switch m.Kind {
		case reader.Symlink:
			if err := r.Symlink(m.Linkname, rel); err != nil {
				return err
			}
		case reader.Hardlink:
			src, err := safeRel(m.Linkname)
			if err != nil {
				return err
			}
			*hardlinks = append(*hardlinks, pending{src, rel})
		case reader.File:
			f, err := r.Create(rel, m.Size)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, t.Open()); err != nil {
				f.Close()
				return err
			}
			// setuid and setgid are meaningless under no_new_privs; a tree stays readable by its
			// owner (Fedora ships /etc/gshadow as 0000)
			if err := f.Chmod(os.FileMode(m.Mode&0o777) | 0o400); err != nil {
				f.Close()
				return err
			}
			if err := futimens(int(f.Fd()), unix.Timespec{Sec: m.Mtime, Nsec: m.MtimeNS}); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		default:
			log(fmt.Sprintf("skipping special file /%s from %s", rel, name))
			continue
		}
		owner[key] = name
	}
}

// futimens sets the access and modification times of the open file fd to t: utimensat on the
// descriptor with no path, as glibc's futimens is.
func futimens(fd int, t unix.Timespec) error {
	ts := [2]unix.Timespec{t, t}
	if _, _, e := unix.Syscall6(unix.SYS_UTIMENSAT, uintptr(fd), 0, uintptr(unsafe.Pointer(&ts)), 0, 0, 0); e != 0 {
		return e
	}
	return nil
}

func hasPart(path, part string) bool {
	for _, p := range strings.Split(path, "/") {
		if p == part {
			return true
		}
	}
	return false
}

// cut returns the first n characters of s, as Python's s[:n] does.
func cut(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		return string(runes[:n])
	}
	return s
}

// ---------------------------------------------------------------- the volatile directories (step 4)

// stripVolatile removes what the packages shipped in the volatile directories, which are the
// host's (8.1). A link standing at one is left as the package made it, and the path resolves with
// the tree as its root, so nothing outside it is removed. The empty directories, and the identity
// files, are the placeholders `exclave wrap` adds where the tree lacks them.
func stripVolatile(rootPath string) error {
	r, err := root.Open(rootPath)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, d := range volatile {
		if r.Lexists(d) && !r.IsLink(d) {
			if err := r.Rmtree(d); err != nil {
				return refusing(err)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- the dependency report (10.1)

// dependencyReport returns a line for every Depends or Pre-Depends that the set of packages does
// not satisfy. Provides and version constraints are honoured. A dependency spelt as a path, such
// as rpm's and apk's `/bin/sh`, is satisfied when it resolves in the tree under rootPath,
// extracted and synthesised, or always when rootPath is "". This is a report, not a refusal: the
// set is the user's.
func dependencyReport(packages []*Package, rd reader.Reader, rootPath string) ([]string, error) {
	var r *root.Root
	if rootPath != "" {
		var err error
		if r, err = root.Open(rootPath); err != nil {
			return nil, err
		}
		defer r.Close()
	}
	have := map[string]string{}
	for _, p := range packages {
		have[p.Name] = p.Version()
	}
	provides := map[string][]string{} // each provided name's versions, "" for an unversioned one
	for _, p := range packages {
		groups, err := rd.ParseDeps(p.Fields["Provides"])
		if err != nil {
			return nil, err
		}
		for _, alts := range groups {
			for _, d := range alts {
				v := ""
				if d.Op == "=" {
					v = d.Version
				}
				provides[d.Name] = append(provides[d.Name], v)
			}
		}
	}
	sorted := append([]*Package(nil), packages...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var out []string
	for _, p := range sorted {
		for _, field := range []string{"Pre-Depends", "Depends"} {
			groups, err := rd.ParseDeps(p.Fields[field])
			if err != nil {
				return nil, err
			}
			for _, alts := range groups {
				ok := false
				for _, d := range alts {
					if strings.HasPrefix(d.Name, "/") && (r == nil || r.Exists(d.Name)) {
						ok = true
					}
				}
				for _, d := range alts {
					if v, had := have[d.Name]; had && rd.Satisfies(v, d.Op, d.Version) {
						ok = true
					}
					if pvs, had := provides[d.Name]; had {
						for _, pv := range pvs {
							if d.Op == "" || (pv != "" && rd.Satisfies(pv, d.Op, d.Version)) {
								ok = true
							}
						}
					}
				}
				if !ok {
					var want []string
					for _, d := range alts {
						w := d.Name
						if d.Op != "" {
							w += fmt.Sprintf(" (%s %s)", d.Op, d.Version)
						}
						want = append(want, w)
					}
					out = append(out, fmt.Sprintf("%s needs %s, not in the set", p.Name, strings.Join(want, " | ")))
				}
			}
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- the inputs (step 5, 6.4)

// writeRecords writes OUT/.exclave/hashes with one pkg record per package file, in canonical
// form (6.4): the name, version and architecture from the file's control data and the file's
// BLAKE2b-256. `exclave wrap` keeps the records and adds its own. A field that is not printable
// ASCII, which no package format allows, is refused.
func writeRecords(out string, packages []*Package) error {
	var rows [][4]string
	for _, p := range packages {
		f, err := os.Open(p.Path)
		if err != nil {
			return err
		}
		h, _ := blake2b.New256(nil)
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return err
		}
		row := [4]string{p.Name, p.Version(), p.Arch(), "b2:" + hex.EncodeToString(h.Sum(nil))}
		for _, v := range row {
			for _, c := range v {
				if c < ' ' || c > '~' {
					return refuse("%s: control field %s is not printable ASCII", p.Path, reader.Pyrepr(v))
				}
			}
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		for k := range rows[i] {
			if rows[i][k] != rows[j][k] {
				return rows[i][k] < rows[j][k]
			}
		}
		return false
	})
	var b strings.Builder
	b.WriteString("hashes 1\n\n")
	for _, row := range rows {
		b.WriteString("pkg")
		for _, v := range row {
			b.WriteString(` "` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"`)
		}
		b.WriteString("\n")
	}
	return os.WriteFile(filepath.Join(out, ".exclave", "hashes"), []byte(b.String()), 0o666)
}
