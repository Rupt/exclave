// The fetch command: a package closure downloaded and verified (DESIGN.md 10.1), the port of
// fetch/debs.py, apks.py and rpms.py beside it, which scripts/fetch-* run until the port is complete.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "fetch: not yet ported; scripts/fetch-debs, fetch-apks and fetch-rpms run the Python")
	os.Exit(2)
}
