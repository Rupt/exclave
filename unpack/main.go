// The unpack command line (DESIGN.md 10.1):
//
//	unpack OUT PKG...    Make the unwrapped exclave OUT from package files: extract, synthesise
//	                     what maintainer scripts would have done, strip the volatile directories,
//	                     record every input in OUT/.exclave/hashes, report dependencies the set
//	                     does not satisfy.
//
// `exclave wrap OUT` then makes it an exclave. Between the two OUT is a directory, and anything
// may be done to it. Unpack never opens a network connection: the files it is given are its
// inputs, whoever fetched them.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"exclave/unpack/reader"
)

// unpack makes the unwrapped exclave out from package files (10.1).
//
// The packages are extracted, what their maintainer scripts would have made is synthesised, the
// volatile directories are stripped, each package file's hash is recorded, and unmet
// dependencies are logged. On any failure, out is removed. It refuses when out exists, or the
// packages mix formats, architectures or versions of one package.
func unpack(out string, paths []string, log Log) error {
	if _, err := os.Lstat(out); err == nil {
		return refuse("refusing: %s exists", out)
	}
	if len(paths) == 0 {
		return refuse("unpack needs at least one package file")
	}
	formats := map[string]bool{}
	for _, p := range paths {
		formats[packageFormat(p)] = true
	}
	if len(formats) > 1 {
		return refuse("the package files mix formats %s: one format per exclave", pylist(keys(formats)))
	}
	rd := readerFor(paths[0])
	var packages []*Package
	seen := map[string]string{}
	for _, p := range paths {
		fields, _, err := rd.Control(p)
		if err != nil {
			return err
		}
		name := fields["Package"]
		if name == "" || fields["Version"] == "" {
			return refuse("%s: no Package or Version in its control file", p)
		}
		if prev, ok := seen[name]; ok {
			return refuse("%s and %s both carry package %s: one version of a package per exclave", prev, p, name)
		}
		seen[name] = p
		packages = append(packages, &Package{Name: name, Path: p, Fields: fields})
	}
	arches := map[string]bool{}
	for _, p := range packages {
		if a := p.Arch(); a != "" && a != "all" {
			arches[a] = true
		}
	}
	if len(arches) > 1 {
		return refuse("the packages mix architectures %s", pylist(keys(arches)))
	}
	if err := os.MkdirAll(filepath.Join(out, ".exclave"), 0o777); err != nil {
		return err
	}
	rootPath := filepath.Join(out, "tree")
	err := func() error {
		if _, err := extract(rootPath, packages, log); err != nil {
			return err
		}
		if err := synthesise(rootPath, packages, log); err != nil {
			return err
		}
		lines, err := notes(packages)
		if err != nil {
			return err
		}
		for _, line := range lines {
			log(line)
		}
		if err := stripVolatile(rootPath); err != nil {
			return err
		}
		// after synthesis, so that a file dependency is asked of the finished tree
		report, err := dependencyReport(packages, rd, rootPath)
		if err != nil {
			return err
		}
		for _, line := range report {
			log("depends: " + line)
		}
		return writeRecords(out, packages)
	}()
	if err != nil {
		os.RemoveAll(out)
		return err
	}
	log(fmt.Sprintf("unpacked %d packages into %s; exclave wrap %s makes it an exclave", len(packages), out, out))
	return nil
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pylist spells strings as Python prints a list of them.
func pylist(items []string) string {
	var quoted []string
	for _, s := range items {
		quoted = append(quoted, reader.Pyrepr(s))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Println("usage: unpack OUT PACKAGE [PACKAGE ...]\n\nMake the unwrapped exclave OUT from package files; " +
			"exclave wrap OUT then makes it an exclave. PACKAGE: .deb, .apk or .rpm files")
		return
	}
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: unpack OUT PACKAGE [PACKAGE ...]\nunpack: error: OUT and at least one PACKAGE are required")
		os.Exit(2)
	}
	if err := unpack(args[0], args[1:], func(line string) { fmt.Println(line) }); err != nil {
		fmt.Fprintf(os.Stderr, "unpack: %s\n", err)
		os.Exit(1)
	}
}
