package unpack

import (
	"fmt"
	"path"
	"strings"

	"exclave/unpack/apk"
	"exclave/unpack/deb"
	"exclave/unpack/reader"
	"exclave/unpack/rpm"
)

// Package is a package file to unpack, with the control fields its reader gave.
type Package struct {
	Name   string
	Path   string
	Fields map[string]string
}

// Version is the package's version, as its control fields spell it.
func (p *Package) Version() string { return p.Fields["Version"] }

// Arch is the package's architecture, as its control fields spell it.
func (p *Package) Arch() string { return p.Fields["Architecture"] }

// logger is where every step writes its lines.
type logger func(line string)

// refusal is a refusal: package files unpack will not make a tree from, or a step that
// cannot be done.
type refusal struct {
	Msg string
}

func (e *refusal) Error() string { return e.Msg }

func refuse(format string, a ...any) error {
	return &refusal{Msg: fmt.Sprintf(format, a...)}
}

// safeRel returns a member's path relative to the tree, refusing `..` and the reserved `.real`.
func safeRel(name string) (string, error) {
	var parts []string
	for p := range strings.SplitSeq(name, "/") {
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			return "", refuse("path escapes the tree: %s", name)
		}
		if p == ".real" {
			return "", refuse("the reserved name .real is shipped at %s", name)
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "/"), nil
}

// readers are the formats, by name.
var readers = map[string]reader.Reader{"deb": deb.Reader, "apk": apk.Reader, "rpm": rpm.Reader}

// packageFormat returns a package file's format, by its name: "apk", "rpm", or else "deb".
func packageFormat(p string) string {
	switch path.Ext(p) {
	case ".apk":
		return "apk"
	case ".rpm":
		return "rpm"
	}
	return "deb"
}

// readerFor returns the reader for a package file, chosen by its name (10.1).
func readerFor(p string) reader.Reader {
	return readers[packageFormat(p)]
}
