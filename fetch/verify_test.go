package fetch

import (
	"archive/tar"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func entity(t testing.TB, name string) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity(name, "", name+"@test", &packet.Config{Algorithm: packet.PubKeyAlgoRSA, RSABits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func detach(t testing.TB, e *openpgp.Entity, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := openpgp.DetachSign(&b, e, bytes.NewReader(data), nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// v3 makes a version 3 RSA signature packet over data, as CentOS 7's are, with the hash and
// type given.
func v3(t testing.TB, e *openpgp.Entity, data []byte, hashAlgo byte, sigType byte) []byte {
	t.Helper()
	h := pgpHashes[hashAlgo]
	if hashAlgo == 1 {
		h = crypto.MD5
	}
	creation := []byte{0x5f, 0xad, 0x60, 0xb9}
	w := h.New()
	if sigType == 1 {
		w = openpgp.NewCanonicalTextHash(w)
	}
	w.Write(data)
	w.Write([]byte{sigType})
	w.Write(creation)
	digest := w.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, e.PrivateKey.PrivateKey.(*rsa.PrivateKey), h, digest)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte{3, 5, sigType}
	body = append(body, creation...)
	body = binary.BigEndian.AppendUint64(body, e.PrimaryKey.KeyId)
	body = append(body, 1, hashAlgo, digest[0], digest[1])
	body = binary.BigEndian.AppendUint16(body, uint16(len(sig)*8))
	body = append(body, sig...)
	pkt := []byte{0x89, byte(len(body) >> 8), byte(len(body))}
	return append(pkt, body...)
}

func TestSignatures(t *testing.T) {
	right, wrong := entity(t, "right"), entity(t, "wrong")
	k := &keyring{keys: openpgp.EntityList{right}}
	data := []byte("Suite: noble\nCodename: noble\n")
	good := detach(t, right, data)
	if err := k.detached(data, good); err != nil {
		t.Errorf("a good signature: %v", err)
	}
	if err := k.detached(append(data, 'x'), good); err == nil || !strings.Contains(err.Error(), "BAD") {
		t.Errorf("altered data: %v", err)
	}
	other := detach(t, wrong, data)
	if err := k.detached(data, other); err == nil || !strings.Contains(err.Error(), "no good signature") {
		t.Errorf("an unknown key alone: %v", err)
	}
	if err := k.detached(data, append(other, good...)); err != nil {
		t.Errorf("an unknown key beside a good one: %v", err)
	}
	bad := detach(t, right, []byte("something else"))
	if err := k.detached(data, append(good, bad...)); err == nil || !strings.Contains(err.Error(), "BAD") {
		t.Errorf("a bad signature by a known key beside a good one: %v", err)
	}
	// a key of the same ID that is not the signer, first in the keyring: the signer still verifies
	twin := entity(t, "twin")
	twin.PrimaryKey.KeyId = right.PrimaryKey.KeyId
	both := &keyring{keys: openpgp.EntityList{twin, right}}
	if err := both.detached(data, good); err != nil {
		t.Errorf("the signer behind a key of the same ID: %v", err)
	}
	// version 3, as CentOS 7 signs
	if err := k.detached(data, v3(t, right, data, 8, 0)); err != nil {
		t.Errorf("a version 3 signature: %v", err)
	}
	if err := k.detached(data, v3(t, right, data, 2, 1)); err != nil {
		t.Errorf("a version 3 text signature over SHA-1: %v", err)
	}
	flipped := v3(t, right, data, 8, 0)
	flipped[len(flipped)-1] ^= 1
	if err := k.detached(data, flipped); err == nil || !strings.Contains(err.Error(), "BAD") {
		t.Errorf("a flipped version 3 signature: %v", err)
	}
	for _, c := range []struct {
		name string
		sig  []byte
		why  string
	}{
		{"MD5", v3(t, right, data, 1, 0), "hash algorithm 1"},
		{"a certification", v3(t, right, data, 8, 0x13), "not a signature over data"},
		{"an unknown key's version 3 signature", v3(t, wrong, data, 8, 0), "no good signature"},
	} {
		if err := k.detached(data, c.sig); err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s must be refused: %v", c.name, err)
		}
	}
	// clearsigned, as an InRelease file is, and signed twice
	var armoured bytes.Buffer
	w, err := clearsign.Encode(&armoured, right.PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(data)
	w.Close()
	text, err := k.clearsigned(armoured.Bytes())
	if err != nil || !bytes.Equal(bytes.TrimSpace(text), bytes.TrimSpace(data)) {
		t.Errorf("clearsigned: %v %q", err, text)
	}
	var second bytes.Buffer
	w, _ = clearsign.Encode(&second, wrong.PrivateKey, nil)
	w.Write(data)
	w.Close()
	tail := second.Bytes()[bytes.Index(second.Bytes(), []byte("-----BEGIN PGP SIGNATURE-----")):]
	twice := append(append([]byte(nil), armoured.Bytes()...), tail...)
	if _, err := k.clearsigned(twice); err != nil {
		t.Errorf("clearsigned twice, the keyring holding the first key: %v", err)
	}
	if _, err := (&keyring{keys: openpgp.EntityList{wrong}}).clearsigned(twice); err != nil {
		t.Errorf("clearsigned twice, the keyring holding the second key: %v", err)
	}
	if _, err := (&keyring{}).clearsigned(twice); err == nil {
		t.Error("clearsigned twice, the keyring holding neither key")
	}
}

func TestRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	keyFile := filepath.Join(t.TempDir(), "k.rsa.pub")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	data := []byte("APKINDEX")
	for kind, h := range apkDigests {
		w := h.New()
		w.Write(data)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, h, w.Sum(nil))
		if err != nil {
			t.Fatal(err)
		}
		if err := checkRSA(data, sig, keyFile, h); err != nil {
			t.Errorf("%s: %v", kind, err)
		}
		if err := checkRSA(append(data, 'x'), sig, keyFile, h); err == nil {
			t.Errorf("%s: altered data verified", kind)
		}
	}
}

func TestSignaturesOnly(t *testing.T) {
	sig := tarOf(t, ".SIGN.RSA.key", tar.TypeReg)
	if !signaturesOnly(sig) {
		t.Error("a signature section")
	}
	planted := map[string]byte{"usr/bin/gcc": tar.TypeReg, ".SIGN.RSA.key/x": tar.TypeReg, ".SIGN.dir": tar.TypeDir}
	for name, kind := range planted {
		if signaturesOnly(tarOf(t, name, kind)) {
			t.Errorf("%s passed as a signature section", name)
		}
	}
}

// tarOf makes a one-member tar stream without end blocks, as an apk's sections are.
func tarOf(t *testing.T, name string, kind byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	h := &tar.Header{Name: name, Typeflag: kind, Mode: 0o644}
	if kind == tar.TypeReg {
		h.Size = 1
	}
	if err := w.WriteHeader(h); err != nil {
		t.Fatal(err)
	}
	if kind == tar.TypeReg {
		w.Write([]byte("x"))
	}
	w.Close()
	return b.Bytes()[:b.Len()-1024]
}
