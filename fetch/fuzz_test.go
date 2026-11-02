package main

import (
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// FuzzSignatures reads any bytes as OpenPGP packets, armoured or not, against an empty keyring:
// a verdict, never a panic.
func FuzzSignatures(f *testing.F) {
	f.Add([]byte{}, []byte("signed"))
	f.Add([]byte("-----BEGIN PGP SIGNATURE-----\n\naGVsbG8=\n=abcd\n-----END PGP SIGNATURE-----\n"), []byte("x"))
	f.Add([]byte{0x89, 0x00, 0x14, 3, 5, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 1, 8, 0, 0, 0, 8, 0xff}, []byte("x"))
	f.Add([]byte{0xc2, 0x02, 4, 0}, []byte("x"))
	k := &keyring{keys: openpgp.EntityList{entity(f, "fuzz")}}
	f.Add(v3(f, k.keys[0], []byte("x"), 8, 0), []byte("x"))
	f.Add(detach(f, k.keys[0], []byte("x")), []byte("x"))
	f.Fuzz(func(t *testing.T, sig, signed []byte) {
		splitPackets(sig)
		dearmor(sig)
		k.detached(signed, sig)
		k.clearsigned(sig)
		gzipMembers(sig)
	})
}
