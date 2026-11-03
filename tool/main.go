// The exclave command (DESIGN.md 10): one static file per architecture that carries its launcher
// and the README every exclave gets, and makes, checks, prunes and relinks exclaves; the step before
// it, unpack, is its subcommand. It opens no network connection and holds no code that could:
// fetching package files is exclave-fetch's (fetch/exclave-fetch).
//
//	exclave check EXCLAVE [LOG...]      Wrappers, originals, the tree against its recorded hash and the static
//	                                    check; with EXCLAVE_LOG files, the dynamic check of what a workload opened.
//	exclave format [--check] FILE...    Parse with the strict grammar and rewrite in canonical form; --check
//	                                    only reports.
//	exclave hash EXCLAVE                The tree hash of 6.4.
//	exclave prune EXCLAVE LOG...        Drop every file no logged workload touched (10.4).
//	exclave relink EXCLAVE [LAUNCHER]   Replace the launcher and relink every wrapper.
//	exclave unwrap EXCLAVE              Move every original back over its wrapper.
//	exclave wrap EXCLAVE [LAUNCHER]     Wrap an exclave: add the launcher, the one given or this command's own, and
//	                                    the placeholders where missing, check the manifest, the wrappers and every
//	                                    ELF as the launcher's machine, then wrap every executable and write the
//	                                    launcher, manifest and tree hashes to .exclave/hashes.
//	exclave version                     The build this command is from.
//	exclave unpack OUT PKG...           The unwrapped exclave OUT from package files (10.1, unpack/).
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
	"lukechampine.com/blake3"

	"exclave/unpack"
)

// toolVersion is the project's version, the file VERSION's, which scripts/check holds it to.
const toolVersion = "0.1.0"

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

// fail prints "exclave: " and the reason and exits 1.
func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "exclave: "+format+"\n", a...)
	out.Flush()
	os.Exit(1)
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
	out.Flush()
	os.Exit(1)
}

// usage prints the command's usage line and exits 2.
func usage(line string) {
	fmt.Fprintf(os.Stderr, "usage: exclave %s\n", line)
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

// hashText is "b3:" and the lowercase hex of the BLAKE3-256 of data, as the hashes file writes
// it (6.4).
func hashText(data []byte) string {
	d := blake3.Sum256(data)
	return "b3:" + fmt.Sprintf("%x", d[:])
}

// ---------------------------------------------------------------- the commands

func cmdVersion(args []string) int {
	if len(args) != 0 {
		usage("version")
	}
	fmt.Fprintf(out, "exclave %s\n", version)
	return 0
}

// cmdHash prints the tree hash of an exclave, or the hash of a file as the hashes file writes it,
// so that a machine with the command needs no other tool to check one (6.4).
func cmdHash(args []string) int {
	if len(args) != 1 {
		usage("hash EXCLAVE|FILE")
	}
	if st, err := os.Stat(args[0]); err == nil && st.Mode().IsRegular() {
		j := hashJob{path: args[0]}
		hashFile(&j, make([]byte, 1<<20))
		if j.err != nil {
			failErrno(args[0], j.err)
		}
		fmt.Fprintln(out, "b3:"+j.hex)
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
		case options && len(a) > 2 && strings.HasPrefix("--check", a): // any prefix, as argparse takes one
			check = true
		case options && len(a) > 1 && a[0] == '-':
			usage("format [--check] FILE...")
		default:
			files = append(files, a)
		}
	}
	if len(files) == 0 {
		usage("format [--check] FILE...")
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
		k := kindManifest
		if bytes.HasPrefix(first, []byte("hashes ")) {
			k = kindHashes
		}
		rs, err := grammarParse(data, k)
		if err != nil {
			fmt.Fprintf(out, "%s: %s\n", path, err)
			rc = 1
			continue
		}
		canon := grammarDump(rs, k)
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
	commands := map[string]func([]string) int{
		"check": cmdCheck, "format": cmdFormat, "hash": cmdHash, "prune": cmdPrune,
		"relink": cmdRelink, "unwrap": cmdUnwrap, "version": cmdVersion, "wrap": cmdWrap,
		"unpack": func(args []string) int { return unpack.Main(version, args) },
	}
	if len(os.Args) < 2 {
		usage("COMMAND ARGS...")
	}
	run, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "exclave: unknown command %s\n", os.Args[1])
		os.Exit(2)
	}
	rc := run(os.Args[2:])
	if err := out.Flush(); err != nil {
		fail("standard output: %s", errnoText(err))
	}
	os.Exit(rc)
}
