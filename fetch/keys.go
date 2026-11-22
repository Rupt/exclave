// The archive keys exclave-fetch carries (DESIGN.md 10.1), so that a fetch from a distribution's own archive needs no
// key from the machine it runs on: Ubuntu's and Debian's archive keyrings, the files their ubuntu-keyring and
// debian-archive-keyring packages ship, and Alpine's signing keys for x86-64 and aarch64, from its alpine-keys
// package under the names apk gives them. A --keyring or --key given takes their place whole, so that the keys named
// are the whole statement of trust, as they must be for a repository that is not the distribution's. No rpm key is
// carried: one signs a single release of a single distribution, and an rpm repository is the caller's to name.
package fetch

import (
	"embed"
	"strings"
)

//go:embed keys
var carried embed.FS

// carriedKeyring is the archive keyring carried for distro, ubuntu or debian.
func carriedKeyring(distro string) (*keyring, error) {
	name := distro + "-archive-keyring.gpg"
	data, err := carried.ReadFile("keys/" + name)
	if err != nil {
		return nil, verifyErrorf("no archive keyring is carried for %s: give one with --keyring", distro)
	}
	k := &keyring{}
	if err := k.add("the carried "+name, data); err != nil {
		return nil, err
	}
	return k, nil
}

// carriedApkKeys are Alpine's public keys, PEM, by the names its indexes' signatures give.
func carriedApkKeys() map[string][]byte {
	keys := map[string][]byte{}
	entries, err := carried.ReadDir("keys")
	if err != nil {
		panic(err) // the directory is this file's own
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".rsa.pub") {
			data, err := carried.ReadFile("keys/" + e.Name())
			if err != nil {
				panic(err)
			}
			keys[e.Name()] = data
		}
	}
	return keys
}
