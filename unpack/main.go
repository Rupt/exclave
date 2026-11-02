// The unpack command: package files -> an unwrapped exclave (DESIGN.md 10.1), the port of the
// Python package beside it, which scripts/unpack runs until the port is complete.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "unpack: not yet ported; scripts/unpack runs the Python")
	os.Exit(2)
}
