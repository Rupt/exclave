package main

import _ "embed"

// launcherBlob is this architecture's launcher (10.5), which wrap installs and relink puts behind
// every wrapper unless given another; scripts/build copies it here from build/ before building.
//
//go:embed launcher-aarch64
var launcherBlob []byte
