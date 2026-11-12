// exclave-fetch, the program: a package closure resolved from a distribution's repository, every
// file checked against the repository's signatures, and downloaded (DESIGN.md 10.1):
//
//	exclave-fetch debs ...    a Debian or Ubuntu closure, from an archive's Packages indexes
//	exclave-fetch apks ...    an Alpine closure, from a branch's APKINDEX files
//	exclave-fetch rpms ...    an rpm closure, from yum or dnf repositories' primary indexes
//	exclave-fetch version     the build, as exclave version prints the command's
//
// Each takes the arguments its --help lists, which are part of what a release keeps (6.7). It is
// the one program of exclave that opens a network connection: `exclave unpack OUT DIR/*` takes
// whatever directory of package files this program, a package manager, a mirror or a person has
// made. A refusal is one line, "exclave-fetch KIND: " and the reason.
package fetch

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// version is the build's, which Main is given; it names the command to the servers it asks.
var version = "dev"

func userAgent() string { return "exclave-fetch/" + version }

// log writes one line to stderr, the parts joined by spaces as print does.
func log(parts ...any) {
	fmt.Fprintln(os.Stderr, parts...)
}

// multi is a flag given several times.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

// parseArgs parses the flags of fs from args, in any order with the positional arguments,
// which it returns; an argument the flags cannot take is a usage error.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if err == flag.ErrHelp {
				return nil, err
			}
			return nil, &usageError{err.Error()}
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

// splitChoices reads --choose VIRTUAL=PKG arguments.
func splitChoices(choose []string) (map[string]string, error) {
	out := map[string]string{}
	for _, c := range choose {
		k, v, found := strings.Cut(c, "=")
		if !found || k == "" || v == "" {
			return nil, &usageError{"--choose takes VIRTUAL=PKG, not " + c}
		}
		out[k] = v
	}
	return out, nil
}

// Main runs exclave-fetch with the build's version and the arguments after its name; returns its
// exit status.
func Main(v string, args []string) int {
	version = v
	usage := "usage: exclave-fetch debs|apks|rpms [ARGS...] | version; " +
		"exclave-fetch debs --help and the others say which"
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	kind, args := args[0], args[1:]
	var err error
	switch kind {
	case "debs", "apks", "rpms":
		end := watchSignals()
		err = map[string]func([]string) error{"debs": fetchDebs, "apks": fetchApks, "rpms": fetchRpms}[kind](args)
		end()
	case "version":
		if len(args) != 0 {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		fmt.Println("exclave-fetch " + version)
		return 0
	case "-h", "--help":
		fmt.Println(usage)
		return 0
	default:
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	if err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		if _, usageErr := err.(*usageError); usageErr {
			fmt.Fprintf(os.Stderr, "exclave-fetch %s: error: %s\n", kind, err)
			return 2
		}
		fmt.Fprintf(os.Stderr, "exclave-fetch %s: %s\n", kind, err)
		return 1
	}
	return 0
}

// usageError is an argument the command cannot take.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }
