"""The signatures the fetchers check, through gpgv and openssl (DESIGN.md 10, 13 item 32).

A Debian or Ubuntu archive signs its `InRelease` file, an rpm repository its `repomd.xml` and each
rpm's header, and an Alpine repository its `APKINDEX.tar.gz`: OpenPGP for the first three, checked
by gpgv against the keyrings the caller names, and an RSA signature over the index's bytes for
Alpine, checked by openssl against the public key the signature names, as apk does. A keyring
given in ASCII armour is decoded here, since gpgv reads binary keyrings only. Nothing here opens a
network connection: the keys come from the caller, pinned by hash in scripts/inputs or taken from
the machine's own keyrings.
"""

import base64
import binascii
import os
import subprocess
import tempfile
lazy from collections.abc import Sequence


class VerifyError(Exception):
    """A signature that does not verify, a key that cannot be read, or a tool that is missing."""


def dearmor(data: bytes) -> bytes:
    """Return the OpenPGP packets of an ASCII-armoured file, its blocks concatenated.

    An RPM-GPG-KEY file or a Debian `.asc` keyring: each block's headers end at a blank line, its
    base64 body at the CRC24 line or the END line.
    """
    out = b""
    lines = data.split(b"\n")
    i = 0
    while i < len(lines):
        if not lines[i].startswith(b"-----BEGIN PGP "):
            i += 1
            continue
        i += 1
        while i < len(lines) and lines[i].strip():  # the armour headers
            i += 1
        body = b""
        while i < len(lines) and not lines[i].startswith((b"=", b"-----END")):
            body += lines[i].strip()
            i += 1
        try:
            out += base64.b64decode(body, validate=True)
        except binascii.Error as e:
            msg = f"not an ASCII-armoured OpenPGP file: {e}"
            raise VerifyError(msg) from e
    if not out:
        msg = "no PGP block in the armoured file"
        raise VerifyError(msg)
    return out


class Keyrings:
    """The keyrings gpgv checks against: the files given, an armoured one decoded to a temporary."""

    def __init__(self, paths: Sequence[str]) -> None:
        self.paths: list[str] = []
        self._temps: list[tempfile._TemporaryFileWrapper[bytes]] = []
        for given in paths:
            with open(given, "rb") as f:
                data = f.read()
            path = given
            if data.lstrip().startswith(b"-----BEGIN PGP "):
                tmp = tempfile.NamedTemporaryFile(suffix=".gpg")  # noqa: SIM115 -- gpgv reads it by name while the keyrings live
                tmp.write(dearmor(data))
                tmp.flush()
                self._temps.append(tmp)
                path = tmp.name
            self.paths.append(path)
        if not self.paths:
            msg = "no keyring given"
            raise VerifyError(msg)

    def _gpgv(self, args: Sequence[str]) -> None:
        """Run gpgv on args and apply apt's rule to what it reports: one good signature, no bad one.

        A Release file is signed by several keys, and a keyring need hold only one of them, so
        gpgv's exit status, which fails on any signature it cannot check, is not the verdict; its
        status lines are. A signature by a key the keyring lacks (ERRSIG) is ignored beside a good
        one; a signature that does not verify (BADSIG) refuses the file whatever else it carries;
        and a signature gpgv reports as other than good, by an expired or revoked key where it
        knows one to be, does not count as good.
        """
        cmd = ["gpgv", "--quiet", "--status-fd", "1"]
        for path in self.paths:
            cmd += ["--keyring", path]
        try:
            p = subprocess.run(  # noqa: S603 -- an argument vector, no shell
                [*cmd, *args], capture_output=True, check=False
            )
        except FileNotFoundError as e:
            msg = "gpgv is not installed, so no signature can be checked"
            raise VerifyError(msg) from e
        status = [
            ln.split()[1:]
            for ln in p.stdout.decode("utf-8", "replace").splitlines()
            if ln.startswith("[GNUPG:] ") and len(ln.split()) > 1
        ]
        kinds = [s[0] for s in status]
        if "BADSIG" in kinds:
            bad = next(s for s in status if s[0] == "BADSIG")
            msg = f"BAD signature by key {bad[1]}" if len(bad) > 1 else "BAD signature"
            raise VerifyError(msg)
        if "GOODSIG" not in kinds:
            lines = [ln for ln in p.stderr.decode("utf-8", "replace").splitlines() if ln.strip()]
            why = (lines[-1] if lines else "gpgv reported no signature").removeprefix("gpgv: ")
            msg = f"no good signature by a key in the keyring: {why}"
            raise VerifyError(msg)

    def clearsigned(self, data: bytes) -> bytes:
        """Return the text a clearsigned file carries, once its signature verifies."""
        with tempfile.TemporaryDirectory(prefix="verify-") as d:
            signed, out = os.path.join(d, "signed"), os.path.join(d, "out")
            with open(signed, "wb") as f:
                f.write(data)
            self._gpgv(["--output", out, "--", signed])
            try:
                with open(out, "rb") as f:
                    return f.read()
            except FileNotFoundError as e:
                msg = "gpgv verified the file but wrote no output"
                raise VerifyError(msg) from e

    def detached(self, data: bytes, signature: bytes) -> None:
        """Check a detached signature, armoured or binary, over data."""
        with tempfile.TemporaryDirectory(prefix="verify-") as d:
            signed, sig = os.path.join(d, "signed"), os.path.join(d, "sig")
            with open(signed, "wb") as f:
                f.write(data)
            with open(sig, "wb") as f:
                f.write(signature)
            self._gpgv(["--", sig, signed])


# the digest each of apk's signature kinds uses, by the name's prefix (apk-tools' .SIGN.RSA*.)
APK_DIGESTS = {"RSA": "sha1", "RSA256": "sha256", "RSA512": "sha512"}


def rsa(data: bytes, signature: bytes, key: str, digest: str) -> None:
    """Check an RSA signature over data against the PEM public key, through openssl."""
    with tempfile.TemporaryDirectory(prefix="verify-") as d:
        signed, sig = os.path.join(d, "signed"), os.path.join(d, "sig")
        with open(signed, "wb") as f:
            f.write(data)
        with open(sig, "wb") as f:
            f.write(signature)
        cmd = ["openssl", "dgst", f"-{digest}", "-verify", key, "-signature", sig, signed]
        try:
            p = subprocess.run(cmd, capture_output=True, check=False)  # noqa: S603 -- an argument vector, no shell
        except FileNotFoundError as e:
            msg = "openssl is not installed, so no signature can be checked"
            raise VerifyError(msg) from e
    if p.returncode or p.stdout.strip() != b"Verified OK":
        err = p.stderr.decode("utf-8", "replace").strip().splitlines()
        msg = f"the RSA signature does not verify against {key}" + (f": {err[-1]}" if err else "")
        raise VerifyError(msg)
