// The exclave command (DESIGN.md 10): one static file per architecture that carries its launcher
// and the README every exclave gets, and makes, checks, prunes and relinks exclaves; the step before
// it, unpack, is its subcommand. It opens no network connection and holds no code that could:
// fetching package files is exclave-fetch's (fetch/exclave-fetch).
//
// Its commands are the table commands below, which `exclave` alone lists: each one's arguments,
// as its usage line spells them, and what it does in a line; DESIGN.md 10 says the rest.
//
// Paths are bytes, as the kernel has them, and every list the command prints or hashes is sorted
// by its bytes. A refusal prints one line, "exclave: " and the reason (unpack's its own prefix,
// "unpack: "), and exits 1; a usage error exits 2.
package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"exclave/tool/format"
	"exclave/unpack"
)

// toolVersion is the project's version, the file VERSION's, which scripts/check holds it to.
const toolVersion = "0.0.1"

// version is the build's (7, 10): the project's version and the commit, which scripts/build
// sets; what `version` prints and the hashes file's tool record says (6.4).
var version = toolVersion

// readmeBlob is the README every exclave gets (6.1); the launcher this command carries is
// launcherBlob, embedded by the file for its architecture.
//
//go:embed README.txt
var readmeBlob []byte

// ---------------------------------------------------------------- failures

// out is standard output, buffered as stdio buffers it on a pipe: what a command printed before a
// refusal comes out after the refusal's line, and the end of main flushes it and reports a failure.
var out = bufio.NewWriter(os.Stdout)

// failing are what a refusal undoes before it exits, last registered first: a command's
// temporary files.
var failing []func()

// atFail registers f to run when the command refuses.
func atFail(f func()) { failing = append(failing, f) }

// exit1 runs what atFail registered, last first, each taken off the list before it runs, so that
// one that refuses in turn reaches the rest and not itself again; then flushes the output and
// exits 1.
func exit1() {
	for len(failing) > 0 {
		f := failing[len(failing)-1]
		failing = failing[:len(failing)-1]
		f()
	}
	out.Flush()
	os.Exit(1)
}

// fail prints "exclave: " and the reason and exits 1.
func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "exclave: "+format+"\n", a...)
	exit1()
}

// errnoText is the reason of an OS error as strerror spells it, capitalised.
func errnoText(err error) string {
	if errno, ok := errors.AsType[syscall.Errno](err); ok {
		s := errno.Error()
		return strings.ToUpper(s[:1]) + s[1:]
	}
	return err.Error()
}

// failErrno fails naming path and the OS's reason.
func failErrno(path string, err error) { fail("%s: %s", path, errnoText(err)) }

// failGrammar fails on a manifest or hashes file the grammar refuses: "grammar: " and where.
func failGrammar(err error) {
	fmt.Fprintf(os.Stderr, "grammar: %s\n", err)
	exit1()
}

// usage prints the command's usage line and exits 2.
// A command is one of exclave's: its name, its arguments as a usage line spells them, what it does
// in a line, and what runs it.
type command struct {
	name, args, does string
	run              func(args []string) int
}

// commands lists the commands in the order of their names. It is made when asked for and not
// kept, since each command's function names its own usage through the table.
func commands() []command {
	return []command{
		{"caches", "EXCLAVE", "run the tree's own generators of caches inside and add what they make", cmdCaches},
		{"check", "EXCLAVE [LOG...]", "check the wrappers, the tree hash and every ELF; with logs, what a run opened",
			cmdCheck},
		{"format", "[--check] FILE...", "put a manifest or hashes file in canonical form, or only report", cmdFormat},
		{"hash", "EXCLAVE|FILE", "print the tree hash of an exclave, or a file's hash", cmdHash},
		{"prune", "EXCLAVE LOG...", "drop every file no logged run touched", cmdPrune},
		{"relink", "EXCLAVE [LAUNCHER]", "replace the launcher and relink the wrappers to it", cmdRelink},
		{"unpack", "OUT PKG...", "make the unwrapped exclave OUT from package files",
			func(args []string) int { return unpack.Main(version, args) }},
		{"unwrap", "EXCLAVE", "move every original back over its wrapper", cmdUnwrap},
		{"version", "", "print the build this command is from", cmdVersion},
		{"wrap", "EXCLAVE [LAUNCHER]", "check an exclave, wrap every executable and record its hashes", cmdWrap},
	}
}

// running is the name of the command that runs, for its usage line.
var running string

// usage ends the command that runs with its usage line, or, before one runs, with every
// command's; either way the status is 2.
func usage() {
	for _, c := range commands() {
		if running == "" {
			fmt.Fprintf(os.Stderr, "usage: exclave %-27s %s\n", strings.TrimSpace(c.name+" "+c.args), c.does)
		} else if c.name == running {
			fmt.Fprintf(os.Stderr, "usage: exclave %s\n", strings.TrimSpace(c.name+" "+c.args))
		}
	}
	out.Flush()
	os.Exit(2)
}

// isErrno reports whether err is the errno given.
func isErrno(err error, want syscall.Errno) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == want
}

// ---------------------------------------------------------------- files

// pathJoin is a, then a slash unless a ends in one, then b: os.path.join's spelling, which the
// messages use.
func pathJoin(a, b string) string {
	if a != "" && !strings.HasSuffix(a, "/") {
		return a + "/" + b
	}
	return a + b
}

// readFile is the whole of a file, or a failure naming it.
func readFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		failErrno(path, err)
	}
	return data
}

// writeFile writes data as the whole of path, created with mode, the kernel's bits, or truncated
// with its own.
func writeFile(path string, data []byte, mode uint32) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC, mode)
	if err != nil {
		failErrno(path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	if _, err := f.Write(data); err != nil {
		failErrno(path, err)
	}
	if err := f.Close(); err != nil {
		failErrno(path, err)
	}
}

// lexists reports whether anything is at path, a dangling link included.
func lexists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// isDir reports whether path is a directory, through a link.
func isDir(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

// ---------------------------------------------------------------- the commands

func cmdVersion(args []string) int {
	if len(args) != 0 {
		usage()
	}
	fmt.Fprintf(out, "exclave %s\n", version)
	return 0
}

// cmdHash prints the tree hash of an exclave, or the hash of a file as the hashes file writes it,
// so that a machine with the command needs no other tool to check one (6.4).
func cmdHash(args []string) int {
	if len(args) != 1 {
		usage()
	}
	if st, err := os.Stat(args[0]); err == nil && st.Mode().IsRegular() {
		j := hashJob{path: args[0]}
		hashFile(&j, make([]byte, 1<<20))
		if j.err != nil {
			failErrno(args[0], j.err)
		}
		fmt.Fprintln(out, format.HashPrefix+j.hex)
		return 0
	}
	requireExclave(args[0], "hash")
	fmt.Fprintln(out, treeHash(pathJoin(args[0], "tree")))
	return 0
}

// cmdFormat rewrites each file in canonical form, or with --check only reports. Each file is a
// manifest or a hashes file by its first record, not its name (6.5).
func cmdFormat(args []string) int {
	check, options := false, true
	var files []string
	for _, a := range args {
		switch {
		case options && a == "--":
			options = false
		case options && a == "--check":
			check = true
		case options && len(a) > 1 && a[0] == '-':
			usage()
		default:
			files = append(files, a)
		}
	}
	if len(files) == 0 {
		usage()
	}
	rc := 0
	for _, path := range files {
		data := readFile(path)
		first := data // the first line that is neither empty nor a comment
		for len(first) > 0 && (first[0] == '\n' || first[0] == '#') {
			lf := bytes.IndexByte(first, '\n')
			if lf < 0 {
				first = nil
				break
			}
			first = first[lf+1:]
		}
		k := format.Manifest
		if bytes.HasPrefix(first, []byte("hashes ")) {
			k = format.Hashes
		}
		rs, err := format.Parse(data, k)
		if err != nil {
			fmt.Fprintf(out, "%s: %s\n", path, err)
			rc = 1
			continue
		}
		canon := format.Dump(rs, k)
		if !bytes.Equal(canon, data) {
			if check {
				fmt.Fprintf(out, "%s: not canonical\n", path)
				rc = 1
			} else {
				writeFile(path, canon, 0o666)
				fmt.Fprintf(out, "%s: rewritten\n", path)
			}
		}
	}
	return rc
}

func main() {
	// Go runs on eight threads at most, BLAKE3's own goroutines too, since the machine may be in
	// use beside the command (10.5)
	runtime.GOMAXPROCS(threads())
	if len(os.Args) < 2 {
		usage()
	}
	var run func([]string) int
	for _, c := range commands() {
		if c.name == os.Args[1] {
			running, run = c.name, c.run
		}
	}
	if run == nil {
		fmt.Fprintf(os.Stderr, "exclave: unknown command %s\n", os.Args[1])
		usage()
	}
	rc := run(os.Args[2:])
	if err := out.Flush(); err != nil {
		fail("standard output: %s", errnoText(err))
	}
	os.Exit(rc)
}
