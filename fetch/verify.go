// The signatures the fetchers check (DESIGN.md 10, 13 item 32).
//
// A Debian or Ubuntu archive signs its `InRelease` file, an rpm repository its `repomd.xml` and
// each rpm's header, and an Alpine repository its `APKINDEX.tar.gz`: OpenPGP for the first three,
// checked against the keyrings the caller names, and an RSA signature over the index's bytes for
// Alpine, checked against the public key the signature names, as apk does. OpenPGP's packets,
// hashes and public-key arithmetic are go-crypto's, but for the version 3 signatures CentOS 7
// made, which it does not read: their hash is computed here and checked with the standard
// library's RSA; the rule is apt's: one good signature by a
// key of the keyring, and no bad one. A key's expiry and revocation are not consulted, as gpgv
// does not consult them: the keyring is the whole statement of trust. Nothing here opens a
// network connection: the keys come from the caller, pinned by hash in scripts/inputs or taken
// from the machine's own keyrings.
package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// verifyError is a signature that does not verify, or a key that cannot be read.
type verifyError struct{ msg string }

func (e *verifyError) Error() string { return e.msg }

func verifyErrorf(format string, a ...any) error {
	return &verifyError{fmt.Sprintf(format, a...)}
}

// dearmor returns the OpenPGP packets of an ASCII-armoured file, its blocks concatenated: an
// RPM-GPG-KEY file or a Debian `.asc` keyring, each block's headers ending at a blank line, its
// base64 body at the CRC24 line or the END line.
func dearmor(data []byte) ([]byte, error) {
	var out []byte
	lines := bytes.Split(data, []byte("\n"))
	for i := 0; i < len(lines); {
		if !bytes.HasPrefix(lines[i], []byte("-----BEGIN PGP ")) {
			i++
			continue
		}
		i++
		for i < len(lines) && len(bytes.TrimSpace(lines[i])) > 0 { // the armour headers
			i++
		}
		var body []byte
		for i < len(lines) && !bytes.HasPrefix(lines[i], []byte("=")) && !bytes.HasPrefix(lines[i], []byte("-----END")) {
			body = append(body, bytes.TrimSpace(lines[i])...)
			i++
		}
		decoded, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil {
			return nil, verifyErrorf("not an ASCII-armoured OpenPGP file: %s", err)
		}
		out = append(out, decoded...)
	}
	if len(out) == 0 {
		return nil, verifyErrorf("no PGP block in the armoured file")
	}
	return out, nil
}

// keyring is the keys the signatures are checked against: every key of the files given.
type keyring struct {
	keys openpgp.EntityList
}

// readKeyrings reads the keyring files given, binary or in ASCII armour.
func readKeyrings(paths []string) (*keyring, error) {
	if len(paths) == 0 {
		return nil, verifyErrorf("no keyring given")
	}
	k := &keyring{}
	for _, given := range paths {
		data, err := os.ReadFile(given)
		if err != nil {
			return nil, err
		}
		if bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("-----BEGIN PGP ")) {
			if data, err = dearmor(data); err != nil {
				return nil, err
			}
		}
		keys, err := openpgp.ReadKeyRing(bytes.NewReader(data))
		if err != nil {
			return nil, verifyErrorf("%s: cannot read the keyring: %s", given, err)
		}
		k.keys = append(k.keys, keys...)
	}
	return k, nil
}

// pgpPacket is one packet of an OpenPGP message: its tag, its body, and the whole as framed.
type pgpPacket struct {
	tag  int
	body []byte
	raw  []byte
}

// splitPackets frames an OpenPGP packet sequence (RFC 4880 4.2), old and new formats, so that
// each packet can be read by what understands it.
func splitPackets(data []byte) ([]pgpPacket, error) {
	var out []pgpPacket
	for len(data) > 0 {
		ctb := data[0]
		if ctb&0x80 == 0 {
			return nil, fmt.Errorf("not an OpenPGP packet")
		}
		var tag, headerLen int
		var length uint64
		if ctb&0x40 != 0 { // the new format
			tag = int(ctb & 0x3f)
			if len(data) < 2 {
				return nil, io.ErrUnexpectedEOF
			}
			switch b := uint64(data[1]); {
			case b < 192:
				length, headerLen = b, 2
			case b < 224:
				if len(data) < 3 {
					return nil, io.ErrUnexpectedEOF
				}
				length, headerLen = (b-192)<<8+uint64(data[2])+192, 3
			case b == 255:
				if len(data) < 6 {
					return nil, io.ErrUnexpectedEOF
				}
				length, headerLen = uint64(data[2])<<24|uint64(data[3])<<16|uint64(data[4])<<8|uint64(data[5]), 6
			default:
				return nil, fmt.Errorf("a packet of partial body lengths")
			}
		} else { // the old format
			tag = int(ctb>>2) & 0xf
			switch ctb & 3 {
			case 0:
				if len(data) < 2 {
					return nil, io.ErrUnexpectedEOF
				}
				length, headerLen = uint64(data[1]), 2
			case 1:
				if len(data) < 3 {
					return nil, io.ErrUnexpectedEOF
				}
				length, headerLen = uint64(data[1])<<8|uint64(data[2]), 3
			case 2:
				if len(data) < 5 {
					return nil, io.ErrUnexpectedEOF
				}
				length, headerLen = uint64(data[1])<<24|uint64(data[2])<<16|uint64(data[3])<<8|uint64(data[4]), 5
			default:
				length, headerLen = uint64(len(data)-1), 1
			}
		}
		if length > uint64(len(data)-headerLen) {
			return nil, io.ErrUnexpectedEOF
		}
		end := headerLen + int(length)
		out = append(out, pgpPacket{tag, data[headerLen:end], data[:end]})
		data = data[end:]
	}
	return out, nil
}

// OpenPGP's hash algorithms by number (RFC 4880 9.4).
var pgpHashes = map[byte]crypto.Hash{
	1: crypto.MD5, 2: crypto.SHA1, 8: crypto.SHA256, 9: crypto.SHA384, 10: crypto.SHA512, 11: crypto.SHA224,
}

// verifyV3 checks a version 3 signature packet (RFC 4880 5.2.2), which go-crypto does not read
// and CentOS 7 made, by the keys of the keyring with its issuer's ID: the hash is over the data,
// the signature type and the creation time, and the signature RSA's. Returns whether a key of
// the keyring issued it, and the verdict when one did.
func (k *keyring) verifyV3(signed, body []byte) (known bool, err error) {
	if len(body) < 19 || body[1] != 5 {
		return false, verifyErrorf("a version 3 signature packet of the wrong shape")
	}
	sigType, creation, keyID := body[2], body[3:7], binary.BigEndian.Uint64(body[7:15])
	pubAlgo, hashAlgo := body[15], body[16]
	keys := k.keys.KeysById(keyID)
	if len(keys) == 0 {
		return false, nil
	}
	h, ok := pgpHashes[hashAlgo]
	if !ok || !h.Available() {
		return true, verifyErrorf("BAD signature by key %016X: hash algorithm %d is not supported", keyID, hashAlgo)
	}
	if pubAlgo != 1 && pubAlgo != 3 { // RSA, or RSA sign-only
		return true, verifyErrorf("BAD signature by key %016X: a version 3 signature by algorithm %d is not supported", keyID, pubAlgo)
	}
	var w hash.Hash = h.New()
	if sigType == 1 {
		w = openpgp.NewCanonicalTextHash(w)
	}
	w.Write(signed)
	w.Write([]byte{sigType})
	w.Write(creation)
	digest := w.Sum(nil)
	// the signature: one MPI, its bit length then its bytes
	mpi := body[19:]
	if len(mpi) < 2 {
		return true, verifyErrorf("BAD signature by key %016X: no signature value", keyID)
	}
	bits := int(binary.BigEndian.Uint16(mpi[:2]))
	sig := mpi[2:]
	if len(sig) < (bits+7)/8 {
		return true, verifyErrorf("BAD signature by key %016X: a short signature value", keyID)
	}
	sig = sig[:(bits+7)/8]
	for _, key := range keys {
		pub, ok := key.PublicKey.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		padded := make([]byte, pub.Size())
		if len(sig) <= len(padded) {
			copy(padded[len(padded)-len(sig):], sig)
			if rsa.VerifyPKCS1v15(pub, h, digest, padded) == nil {
				return true, nil
			}
		}
	}
	return true, verifyErrorf("BAD signature by key %016X", keyID)
}

// check applies apt's rule to the signature packets over signed: one good signature by a key of
// the keyring, and no bad one. A signature by a key the keyring lacks is passed over beside a
// good one; a signature by a key of the keyring that does not verify refuses the file whatever
// else it carries.
func (k *keyring) check(signed, signatures []byte) error {
	packets, err := splitPackets(signatures)
	if err != nil {
		return verifyErrorf("no good signature by a key in the keyring: cannot read the signature: %s", err)
	}
	good, seen := false, 0
	for _, pkt := range packets {
		if pkt.tag != 2 {
			return verifyErrorf("no good signature by a key in the keyring: not a signature packet")
		}
		seen++
		if len(pkt.body) > 0 && pkt.body[0] == 3 {
			known, err := k.verifyV3(signed, pkt.body)
			if err != nil {
				return err
			}
			if known {
				good = true
			}
			continue
		}
		p, err := packet.Read(bytes.NewReader(pkt.raw))
		if err != nil {
			return verifyErrorf("no good signature by a key in the keyring: cannot read the signature: %s", err)
		}
		sig, ok := p.(*packet.Signature)
		if !ok {
			return verifyErrorf("no good signature by a key in the keyring: not a signature packet")
		}
		if sig.IssuerKeyId == nil {
			continue
		}
		keys := k.keys.KeysById(*sig.IssuerKeyId)
		if len(keys) == 0 {
			continue
		}
		h, err := sig.PrepareVerify()
		if err != nil {
			return verifyErrorf("no good signature by a key in the keyring: %s", err)
		}
		var w hash.Hash = h
		if sig.SigType == packet.SigTypeText {
			w = openpgp.NewCanonicalTextHash(h)
		}
		w.Write(signed)
		verified := false
		for _, key := range keys {
			if key.PublicKey.VerifySignature(h, sig) == nil {
				verified = true
				break
			}
		}
		if !verified {
			return verifyErrorf("BAD signature by key %016X", *sig.IssuerKeyId)
		}
		good = true
	}
	if !good {
		why := "no signature by a key in the keyring"
		if seen == 0 {
			why = "no signature"
		}
		return verifyErrorf("no good signature by a key in the keyring: %s", why)
	}
	return nil
}

// clearsigned returns the text a clearsigned file carries, once its signature verifies. The
// signatures are the packets of the armour block the text ends with and of any armour block
// after it, as gpg leaves them when it signs a file twice.
func (k *keyring) clearsigned(data []byte) ([]byte, error) {
	block, rest := clearsign.Decode(data)
	if block == nil {
		return nil, verifyErrorf("no good signature by a key in the keyring: not a clearsigned file")
	}
	sigs, err := io.ReadAll(block.ArmoredSignature.Body)
	if err != nil {
		return nil, verifyErrorf("no good signature by a key in the keyring: %s", err)
	}
	if bytes.Contains(rest, []byte("-----BEGIN PGP SIGNATURE-----")) {
		more, err := dearmor(rest)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, more...)
	}
	if err := k.check(block.Bytes, sigs); err != nil {
		return nil, err
	}
	return block.Plaintext, nil
}

// detached checks a detached signature, armoured or binary, over data.
func (k *keyring) detached(data, signature []byte) error {
	if bytes.HasPrefix(bytes.TrimLeft(signature, " \t\r\n"), []byte("-----BEGIN PGP ")) {
		raw, err := dearmor(signature)
		if err != nil {
			return err
		}
		signature = raw
	}
	return k.check(data, signature)
}

// the digest each of apk's signature kinds uses, by the name's prefix (apk-tools' .SIGN.RSA*.)
var apkDigests = map[string]crypto.Hash{"RSA": crypto.SHA1, "RSA256": crypto.SHA256, "RSA512": crypto.SHA512}

// checkRSA checks an RSA signature over data against the PEM public key file.
func checkRSA(data, signature []byte, keyFile string, digest crypto.Hash) error {
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return verifyErrorf("the RSA signature does not verify against %s: not a PEM public key", keyFile)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return verifyErrorf("the RSA signature does not verify against %s: %s", keyFile, err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return verifyErrorf("the RSA signature does not verify against %s: not an RSA key", keyFile)
	}
	var sum []byte
	switch digest {
	case crypto.SHA1:
		s := sha1.Sum(data) // apk's index signatures are SHA-1, which the design records
		sum = s[:]
	case crypto.SHA256:
		s := sha256.Sum256(data)
		sum = s[:]
	default:
		s := sha512.Sum512(data)
		sum = s[:]
	}
	if err := rsa.VerifyPKCS1v15(pub, digest, sum, signature); err != nil {
		return verifyErrorf("the RSA signature does not verify against %s", keyFile)
	}
	return nil
}

func isVerifyError(err error) bool {
	var ve *verifyError
	return errors.As(err, &ve)
}
