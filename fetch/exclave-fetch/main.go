// exclave-fetch: a package closure resolved from a distribution's repository, every file checked
// against the repository's signatures, and downloaded (DESIGN.md 10.1). It is a program of its own,
// apart from the exclave command, so that the command, which makes, checks and ships exclaves,
// holds no network code at all; the package fetch is its work.
package main

import (
	"os"

	"exclave/fetch"
)

// version is the build's, which scripts/build sets: the project's version and the commit.
var version = "dev"

func main() { os.Exit(fetch.Main(version, os.Args[1:])) }
