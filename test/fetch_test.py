"""The fetchers' signature checks, against signed repositories made here (DESIGN.md 10, 17).

    test/fetch_test.py [--work DIR] [-k NAME|SUBSTRING]

Each test makes a repository of one package under its work directory, signed with keys made here
(an OpenPGP key from gpg, an RSA key from openssl), and runs build/exclave-fetch on it through a file://
URL, as scripts/fetch-debs, fetch-rpms and fetch-apks run it. The signed repository must yield its
package; the same repository signed by another key, with its signed text altered, with the
package altered, or without its signature, must be refused in one line with nothing fetched, and
so must one whose signed text is intact but a digest below it, of an index or of a package, does
not match.
Needs gpg and openssl to make the keys and signatures, and says so and exits 0 without them. Prints
one line per test; the exit status is the number of failures, at most 255.
"""

import argparse
import base64
import gzip
import hashlib
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import zlib
from typing import Protocol
lazy from collections.abc import Callable, Sequence

from packages import DEB_ARCH, MACHINE, make_apk, make_deb, make_rpm, tar_bytes

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
FETCH = (os.path.join(REPO, "build", "exclave-fetch"),)  # exclave-fetch, as scripts/build built it


class Test(Protocol):
    """A test: given its work directory, it raises AssertionError when a rule does not hold."""

    __name__: str

    def __call__(self, work: str, /) -> None: ...


TESTS: list[Test] = []


def test(f: Test) -> Test:
    """Register a test."""
    TESTS.append(f)
    return f


def expect(cond: object, msg: str) -> None:
    """Fail the test with msg unless cond holds."""
    if not cond:
        raise AssertionError(msg)


def run(cmd: Sequence[str], inp: bytes = b"", env: dict[str, str] | None = None) -> bytes:
    p = subprocess.run(cmd, input=inp, capture_output=True, check=False, env=env, timeout=120)
    if p.returncode:
        msg = f"{cmd[0]} failed: {p.stderr.decode(errors='replace')[-400:]}"
        raise AssertionError(msg)
    return p.stdout


# ---------------------------------------------------------------- keys
class PgpKey:
    """An OpenPGP signing key of its own, in a GNUPGHOME under d."""

    def __init__(self, d: str, name: str) -> None:
        self.home = os.path.join(d, f"gnupg-{name}")
        os.makedirs(self.home, mode=0o700)
        self.env = dict(os.environ, GNUPGHOME=self.home)
        run(
            [
                "gpg",
                "--batch",
                "--quiet",
                "--passphrase",
                "",
                "--quick-gen-key",
                f"exclave test {name} <{name}@test>",
                "ed25519",
                "sign",
                "0",
            ],
            env=self.env,
        )

    def _gpg(self, *args: str, inp: bytes = b"") -> bytes:
        return run(["gpg", "--batch", "--quiet", *args], inp=inp, env=self.env)

    def export(self, d: str, name: str, *, armor: bool = False) -> str:
        """Write the public key as a binary keyring, or in ASCII armour, and return its path."""
        path = os.path.join(d, name)
        with open(path, "wb") as f:
            f.write(self._gpg("--export", *(["--armor"] if armor else [])))
        return path

    def clearsign(self, data: bytes) -> bytes:
        return self._gpg("--clearsign", inp=data)

    def detach(self, data: bytes, *, armor: bool = False) -> bytes:
        return self._gpg("--detach-sign", *(["--armor"] if armor else []), inp=data)


class RsaKey:
    """An RSA key pair of its own, made by openssl, its public key named as apk names keys."""

    def __init__(self, d: str, name: str) -> None:
        self.private = os.path.join(d, f"{name}.pem")
        self.public = os.path.join(d, name)
        run(["openssl", "genrsa", "-out", self.private, "2048"])
        run(["openssl", "rsa", "-in", self.private, "-pubout", "-out", self.public])

    def sign(self, data: bytes, digest: str = "sha1") -> bytes:
        return run(["openssl", "dgst", f"-{digest}", "-sign", self.private], inp=data)


# ---------------------------------------------------------------- repositories
def write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def deb_mirror(d: str, sign: Callable[[bytes], bytes] | None, *, tamper: str = "") -> str:
    """A Debian-style archive of one package, its InRelease signed by sign, or unsigned.

    tamper: what is altered after the digest that covers it was written: "signed" the InRelease
    text, "index" the Packages.gz the Release file lists, "deb" a byte of the package the index
    lists; "size" gives the index a size one byte off, signed with the rest.
    """
    pkg = os.path.join(d, "pool", f"x_1_{DEB_ARCH}.deb")
    os.makedirs(os.path.dirname(pkg), exist_ok=True)
    make_deb(pkg, "x", [("./usr", "dir", None, 0o755), ("./usr/x", "file", b"x\n", 0o644)])
    with open(pkg, "rb") as f:
        deb = f.read()
    stanza = (
        f"Package: x\nVersion: 1\nArchitecture: {DEB_ARCH}\nFilename: pool/x_1_{DEB_ARCH}.deb\n"
        f"Size: {len(deb) + (tamper == 'size')}\nSHA256: {hashlib.sha256(deb).hexdigest()}\n\n"
    )
    packages = gzip.compress(stanza.encode(), mtime=0)
    index = os.path.join(d, "dists", "noble", "main", f"binary-{DEB_ARCH}", "Packages.gz")
    write(index, gzip.compress(stanza.encode(), mtime=1) if tamper == "index" else packages)
    if tamper == "deb":
        write(pkg, deb[:-10] + bytes([deb[-10] ^ 1]) + deb[-9:])
    release = (
        "Suite: noble\nCodename: noble\nAcquire-By-Hash: no\nSHA256:\n"
        f" {hashlib.sha256(packages).hexdigest()} {len(packages)}"
        f" main/binary-{DEB_ARCH}/Packages.gz\n"
    ).encode()
    if sign is None:
        write(os.path.join(d, "dists", "noble", "Release"), release)
        return d
    signed = sign(release)
    if tamper == "signed":
        signed = signed.replace(b"Codename: noble", b"Codename: nobel")
    write(os.path.join(d, "dists", "noble", "InRelease"), signed)
    return d


def fetch_debs(
    work: str, mirror: str, keyring: str, name: str, *, cache: bool = True
) -> tuple[int, str, list[str]]:
    """Run the deb fetcher on the mirror; return its status, stderr and what it fetched.

    It has a home directory of its own, and a cache of its own unless cache is false.
    """
    out = os.path.join(work, f"out-{name}")
    home = os.path.join(work, f"home-{name}")
    os.makedirs(home, exist_ok=True)
    p = subprocess.run(
        [
            *FETCH,
            "debs",
            "--out",
            out,
            "--keyring",
            keyring,
            "--mirror",
            "file://" + mirror,
            "--arch",
            DEB_ARCH,  # the mirror's index is this machine's; the fetcher's default is amd64
            "--suite",
            "noble",
            "--components",
            "main",
            "--no-essential",
            *(["--cache", os.path.join(work, f"cache-{name}")] if cache else []),
            "x",
        ],
        capture_output=True,
        check=False,
        timeout=120,
        env={**os.environ, "HOME": home, "XDG_CACHE_HOME": os.path.join(home, ".cache")},
    )
    got = sorted(os.listdir(out)) if os.path.isdir(out) else []
    return p.returncode, p.stderr.decode("utf-8", "replace"), got


def rpm_mirror(
    d: str,
    sign: Callable[[bytes], bytes] | None,
    *,
    sign_payload: bool = False,
    flip: bool = False,
    repomd_sign: Callable[[bytes], bytes] | None = None,
    tamper: str = "",
) -> str:
    """A yum-style repository of one package, signed as rpm signs, its repomd.xml signed or not.

    flip alters a byte of the package before the index is written, so that only its signature can
    tell; tamper alters "rpm" a byte of it after, or "primary" the index after repomd.xml lists it.
    """
    pkg = os.path.join(d, "Packages", f"x-1.0-1.{MACHINE}.rpm")
    os.makedirs(os.path.dirname(pkg), exist_ok=True)
    make_rpm(
        pkg,
        "x",
        [("usr", "dir", None, 0o755), ("usr/x", "file", b"x" * 4000, 0o644)],
        sign=sign,
        sign_payload=sign_payload,
    )
    if flip:
        with open(pkg, "r+b") as f:
            f.seek(-100, os.SEEK_END)
            byte = f.read(1)
            f.seek(-100, os.SEEK_END)
            f.write(bytes([byte[0] ^ 1]))
    with open(pkg, "rb") as f:
        rpm = f.read()
    primary = gzip.compress(
        (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<metadata xmlns="http://linux.duke.edu/metadata/common" '
            'xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="1">\n'
            f'<package type="rpm"><name>x</name><arch>{MACHINE}</arch>'
            '<version epoch="0" ver="1.0" rel="1"/>'
            f'<checksum type="sha256" pkgid="YES">{hashlib.sha256(rpm).hexdigest()}</checksum>'
            f'<size package="{len(rpm)}" installed="4000" archive="4096"/>'
            f'<location href="Packages/x-1.0-1.{MACHINE}.rpm"/>'
            '<format><rpm:provides><rpm:entry name="x"/></rpm:provides></format>'
            "</package>\n</metadata>\n"
        ).encode(),
        mtime=0,
    )
    if tamper == "rpm":
        write(pkg, rpm[:-100] + bytes([rpm[-100] ^ 1]) + rpm[-99:])
    write(os.path.join(d, "repodata", "primary.xml.gz"), primary)
    repomd = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<repomd xmlns="http://linux.duke.edu/metadata/repo">\n'
        f'<data type="primary"><checksum type="sha256">{hashlib.sha256(primary).hexdigest()}'
        '</checksum><location href="repodata/primary.xml.gz"/></data>\n</repomd>\n'
    ).encode()
    write(os.path.join(d, "repodata", "repomd.xml"), repomd)
    if tamper == "primary":
        write(os.path.join(d, "repodata", "primary.xml.gz"), gzip.decompress(primary))
    if repomd_sign is not None:
        write(os.path.join(d, "repodata", "repomd.xml.asc"), repomd_sign(repomd))
    return d


def fetch_rpms(work: str, repo: str, keyring: str, name: str) -> tuple[int, str, list[str]]:
    out = os.path.join(work, f"out-{name}")
    p = subprocess.run(
        [
            *FETCH,
            "rpms",
            "--out",
            out,
            "--keyring",
            keyring,
            "--repo",
            "file://" + repo,
            "--arch",
            MACHINE,
            "--no-base",
            "--cache",
            os.path.join(work, f"cache-{name}"),
            "x",
        ],
        capture_output=True,
        check=False,
        timeout=120,
    )
    got = sorted(os.listdir(out)) if os.path.isdir(out) else []
    return p.returncode, p.stderr.decode("utf-8", "replace"), got


def first_gzip_member(data: bytes) -> bytes:
    """The bytes of the first gzip member of a concatenated stream."""
    stream = zlib.decompressobj(31)
    stream.decompress(data)
    return data[: len(data) - len(stream.unused_data)]


def apk_mirror(d: str, key: RsaKey, signer: str, *, kind: str = "RSA", tamper: str = "") -> str:
    """An Alpine repository of one package, its index signed by key under the name signer.

    tamper: "signed" alters the index after signing; "control" gives the index the checksum of
    another package's control section, "data" gives .PKGINFO the datahash of other data, and
    "planted" puts a file beside the signature in the package's signature section, which no
    digest covers, with the index's size and checksum true of the package as planted.
    """
    rel = os.path.join("v3.21", "main", MACHINE)
    pkg = os.path.join(d, rel, "x-1.0-r0.apk")
    os.makedirs(os.path.dirname(pkg), exist_ok=True)
    members = [("usr", "dir", None, 0o755), ("usr/x", "file", b"x\n", 0o644)]
    data = gzip.compress(tar_bytes(members), mtime=0)
    hashed = gzip.compress(tar_bytes(members), mtime=1) if tamper == "data" else data
    make_apk(pkg, "x", members, f"datahash = {hashlib.sha256(hashed).hexdigest()}\n", data=data)
    with open(pkg, "rb") as f:
        apk = f.read()
    if tamper == "planted":
        section = [(".SIGN.RSA.x", "file", b"", 0o644), ("usr/planted", "file", b"p\n", 0o644)]
        planted = gzip.compress(tar_bytes(section, trailer=False), mtime=0)
        write(pkg, planted + apk)
        with open(pkg, "rb") as f:
            apk = f.read()
    if tamper == "control":
        make_apk(pkg + ".other", "x", members, "pkgdesc = another\n", data=data)
        with open(pkg + ".other", "rb") as f:
            listed = f.read()
        os.remove(pkg + ".other")
    else:
        listed = apk
    control = first_gzip_member(listed)
    if tamper == "planted":  # the control section is the second member, after the planted one
        control = first_gzip_member(listed[len(first_gzip_member(listed)) :])
    control_sha1 = hashlib.sha1(control).digest()  # noqa: S324 -- apk's checksum
    index = (
        f"C:Q1{base64.b64encode(control_sha1).decode()}\nP:x\nV:1.0-r0\nA:{MACHINE}\n"
        f"S:{len(apk)}\nI:4096\nT:x\nU:x\nL:MIT\nD:\n\n"
    ).encode()
    rest = gzip.compress(
        tar_bytes(
            [("DESCRIPTION", "file", b"main 1\n", 0o644), ("APKINDEX", "file", index, 0o644)]
        ),
        mtime=0,
    )
    digest = {"RSA": "sha1", "RSA256": "sha256", "RSA512": "sha512"}[kind]
    signature = key.sign(rest, digest)
    if tamper == "signed":
        rest = bytearray(rest)
        rest[len(rest) // 2] ^= 1
        rest = bytes(rest)
    sig_tar = tar_bytes([(f".SIGN.{kind}.{signer}", "file", signature, 0o644)], trailer=False)
    write(os.path.join(d, rel, "APKINDEX.tar.gz"), gzip.compress(sig_tar, mtime=0) + rest)
    return d


def fetch_apks(work: str, mirror: str, key: str, name: str) -> tuple[int, str, list[str]]:
    out = os.path.join(work, f"out-{name}")
    p = subprocess.run(
        [
            *FETCH,
            "apks",
            "--out",
            out,
            "--key",
            key,
            "--mirror",
            "file://" + mirror,
            "--branch",
            "v3.21",
            "--repos",
            "main",
            "--arch",
            MACHINE,
            "--no-base",
            "--cache",
            os.path.join(work, f"cache-{name}"),
            "x",
        ],
        capture_output=True,
        check=False,
        timeout=120,
    )
    got = sorted(os.listdir(out)) if os.path.isdir(out) else []
    return p.returncode, p.stderr.decode("utf-8", "replace"), got


def refused(name: str, result: tuple[int, str, list[str]], why: str) -> None:
    rc, err, got = result
    last = err.strip().splitlines()[-1] if err.strip() else ""
    expect(
        rc == 1 and why in err and "Traceback" not in err and last.startswith("fetch-"),
        f"{name}: wanted a one-line refusal naming {why!r}: rc={rc} {err[-500:]!r}",
    )
    expect(not got, f"{name}: fetched {got} although refused")


def accepted(name: str, result: tuple[int, str, list[str]], file: str, note: str) -> None:
    rc, err, got = result
    expect(rc == 0 and got == [file], f"{name}: rc={rc} fetched {got}: {err[-500:]!r}")
    expect(note in err, f"{name}: the log does not say {note!r}: {err[-500:]!r}")


# ---------------------------------------------------------------- the tests
@test
def debs_check_inrelease(work: str) -> None:
    """10: fetch-debs takes a suite only from an InRelease the keyring signed.

    Signed: fetched, with a binary keyring or one in ASCII armour, and when the file carries two
    signatures, as the archives' do, with a keyring holding either key. Signed by another key,
    altered after signing, or with a Release file alone: refused, nothing fetched.
    Below the signature, an index the Release file does not list, a package its index does not
    list, by its SHA256 or its size: refused.
    """
    right, wrong, second = PgpKey(work, "right"), PgpKey(work, "wrong"), PgpKey(work, "second")
    keyring = right.export(work, "right.gpg")
    armoured = right.export(work, "right.asc", armor=True)
    deb = f"x_1_{DEB_ARCH}.deb"
    good = deb_mirror(os.path.join(work, "good"), right.clearsign)
    accepted("signed", fetch_debs(work, good, keyring, "signed"), deb, "signature verified")
    accepted("armoured", fetch_debs(work, good, armoured, "armoured"), deb, "signature verified")

    def twice(data: bytes) -> bytes:
        """Clearsigned by right and by second: the two signatures one after the other."""
        one, two = right.clearsign(data), second.clearsign(data)
        return one + two[two.index(b"-----BEGIN PGP SIGNATURE-----") :]

    both = deb_mirror(os.path.join(work, "both"), twice)
    accepted("two keys, first", fetch_debs(work, both, keyring, "both1"), deb, "verified")
    second_ring = second.export(work, "second.gpg")
    accepted("two keys, second", fetch_debs(work, both, second_ring, "both2"), deb, "verified")
    wrong_ring = wrong.export(work, "wrong.gpg")
    refused("two keys, neither", fetch_debs(work, both, wrong_ring, "both3"), "no good signature")
    other = deb_mirror(os.path.join(work, "other"), wrong.clearsign)
    refused("other key", fetch_debs(work, other, keyring, "other"), "signature does not verify")
    altered = deb_mirror(os.path.join(work, "altered"), right.clearsign, tamper="signed")
    refused("altered", fetch_debs(work, altered, keyring, "altered"), "signature does not verify")
    for tamper, why in (
        ("index", "the index does not match the Release file"),
        ("deb", f"x_1_{DEB_ARCH}.deb: SHA256 does not match the index"),
        ("size", f"x_1_{DEB_ARCH}.deb: size does not match the index"),
    ):
        mirror = deb_mirror(os.path.join(work, tamper), right.clearsign, tamper=tamper)
        refused(f"{tamper} altered", fetch_debs(work, mirror, keyring, tamper), why)
    unsigned = deb_mirror(os.path.join(work, "unsigned"), None)
    refused("unsigned", fetch_debs(work, unsigned, keyring, "unsigned"), "InRelease")


@test
def debs_cache_by_digest(work: str) -> None:
    """10: the cache keeps a file the signed index names under its digest, whatever its URL.

    The same archive at another URL is a hit for the index and the package, and the InRelease
    file alone is fetched; a package damaged in the cache is fetched again, not refused.
    """
    right = PgpKey(work, "right")
    keyring = right.export(work, "right.gpg")
    deb = f"x_1_{DEB_ARCH}.deb"
    first = deb_mirror(os.path.join(work, "first"), right.clearsign)
    second = os.path.join(work, "second")
    shutil.copytree(first, second)

    def fetched(err: str) -> list[str]:
        lines = err.splitlines()
        return [line.removeprefix("fetch ") for line in lines if line.startswith("fetch ")]

    accepted("first mirror", fetch_debs(work, first, keyring, "cache"), deb, "verified")
    result = fetch_debs(work, second, keyring, "cache")
    accepted("second mirror", result, deb, "verified")
    urls = fetched(result[1])
    expect(
        len(urls) == 1 and urls[0].endswith("/InRelease"),
        f"the same files at another URL are fetched again: {urls}",
    )
    with open(os.path.join(first, "pool", deb), "rb") as f:
        cached = os.path.join(work, "cache-cache", "sha256", hashlib.sha256(f.read()).hexdigest())
    expect(os.path.isfile(cached), f"no package under its digest in the cache: {cached}")
    os.remove(cached)  # a damaged file in the cache, not one shared with the output by its link
    write(cached, b"damaged")
    result = fetch_debs(work, second, keyring, "cache")
    accepted("damaged in the cache", result, deb, "verified")
    expect(
        any(u.endswith("/" + deb) for u in fetched(result[1])),
        f"a damaged package is not fetched again: {result[1][-300:]!r}",
    )


@test
def debs_without_cache(work: str) -> None:
    """10.1: without --cache a fetch keeps nothing outside --out, and nothing in the home directory.

    The output holds the package alone, and a refused fetch leaves no file in it.
    """
    right = PgpKey(work, "right")
    keyring = right.export(work, "right.gpg")
    deb = f"x_1_{DEB_ARCH}.deb"
    mirror = deb_mirror(os.path.join(work, "mirror"), right.clearsign)
    accepted("fetched", fetch_debs(work, mirror, keyring, "nocache", cache=False), deb, "verified")
    expect(not os.path.exists(os.path.join(work, "cache-nocache")), "a cache was kept")
    home = os.path.join(work, "home-nocache")
    expect(not os.listdir(home), f"the fetch wrote into its home directory: {os.listdir(home)}")
    damaged = deb_mirror(os.path.join(work, "damaged"), right.clearsign, tamper="deb")
    refused("refused", fetch_debs(work, damaged, keyring, "refused", cache=False), "SHA256")
    expect(not os.path.exists(os.path.join(work, "out-refused")), "a refused fetch left its --out")


@test
def debs_interrupted(work: str) -> None:
    """10.1: a fetch without --cache that a signal ends leaves nothing behind, and ends by it.

    The mirror accepts the connection and never answers, so the fetch is waiting on InRelease when
    SIGTERM arrives.
    """
    right = PgpKey(work, "right")
    keyring = right.export(work, "right.gpg")
    with socket.create_server(("127.0.0.1", 0)) as server:
        out = os.path.join(work, "out-interrupted")
        p = subprocess.Popen(
            [
                *FETCH,
                "debs",
                "--out",
                out,
                "--keyring",
                keyring,
                "--mirror",
                f"http://127.0.0.1:{server.getsockname()[1]}",
                "--suite",
                "noble",
                "--no-essential",
                "x",
            ],
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not (
            os.path.isdir(out) and any(n.startswith(".exclave-fetch-") for n in os.listdir(out))
        ):
            time.sleep(0.01)
        p.send_signal(signal.SIGTERM)
        _, err = p.communicate(timeout=10)
    expect(p.returncode == -signal.SIGTERM, f"ended by {p.returncode}: {err[-300:]!r}")
    left = os.listdir(out) if os.path.isdir(out) else []
    expect(not os.path.exists(out), f"the interrupted fetch left its --out, holding {left}")


@test
def rpms_check_packages_and_repomd(work: str) -> None:
    """10: fetch-rpms takes a package only when its own signature verifies, and repomd.xml's too.

    A header signature with the payload's digest, or a signature over header and payload: fetched.
    Unsigned, signed by another key, or altered after signing: refused. repomd.xml.asc signed by
    another key: refused; absent: fetched, and the log says the index is the mirror's. Below the
    signatures, an index repomd.xml does not list, or a package its index does not: refused.
    """
    right, wrong = PgpKey(work, "right"), PgpKey(work, "wrong")
    keyring = right.export(work, "RPM-GPG-KEY-right", armor=True)
    rpm = f"x-1.0-1.{MACHINE}.rpm"

    def armoured(data: bytes) -> bytes:
        return right.detach(data, armor=True)

    good = rpm_mirror(os.path.join(work, "good"), right.detach, repomd_sign=armoured)
    accepted(
        "signed", fetch_rpms(work, good, keyring, "signed"), rpm, "repomd.xml signature verified"
    )
    whole = rpm_mirror(os.path.join(work, "whole"), right.detach, sign_payload=True)
    accepted(
        "whole", fetch_rpms(work, whole, keyring, "whole"), rpm, "not signed by this repository"
    )
    cases: list[tuple[str, Callable[[bytes], bytes] | None, bool, bool]] = [
        ("unsigned", None, False, False),
        ("other", wrong.detach, False, False),
        ("flipped", right.detach, False, True),
        ("whole-flipped", right.detach, True, True),
    ]
    for name, sign, sign_payload, flip in cases:
        mirror = rpm_mirror(os.path.join(work, name), sign, sign_payload=sign_payload, flip=flip)
        refused(name, fetch_rpms(work, mirror, keyring, name), rpm + ":")
    bad_md = rpm_mirror(
        os.path.join(work, "bad-md"),
        right.detach,
        repomd_sign=lambda d: wrong.detach(d, armor=True),
    )
    refused("bad repomd", fetch_rpms(work, bad_md, keyring, "bad-md"), "repomd.xml's signature")
    for tamper, why in (
        ("primary", "the index does not match repomd.xml"),
        ("rpm", f"{rpm}: SHA-256 does not match the index"),
    ):
        mirror = rpm_mirror(os.path.join(work, tamper), right.detach, tamper=tamper)
        refused(f"{tamper} altered", fetch_rpms(work, mirror, keyring, tamper), why)


@test
def apks_check_index(work: str) -> None:
    """10: fetch-apks takes an index only when the key its signature names verifies it.

    Signed by the key given, SHA-1 as Alpine signs or SHA-256: fetched. Signed under a name no
    --key has, by another key under the same name, or altered after signing: refused. Below the
    signature, a package whose control section the index's checksum does not name, whose data
    its .PKGINFO's datahash does not, or whose signature section holds a file beside the
    signature, which no digest covers: refused.
    """
    right, wrong = RsaKey(work, "right.rsa.pub"), RsaKey(work, "wrong.rsa.pub")
    apk = "x-1.0-r0.apk"
    good = apk_mirror(os.path.join(work, "good"), right, "right.rsa.pub")
    accepted("signed", fetch_apks(work, good, right.public, "signed"), apk, "signature verified")
    sha256 = apk_mirror(os.path.join(work, "sha256"), right, "right.rsa.pub", kind="RSA256")
    accepted("sha256", fetch_apks(work, sha256, right.public, "sha256"), apk, "signature verified")
    unknown = apk_mirror(os.path.join(work, "unknown"), right, "other.rsa.pub")
    refused("unknown", fetch_apks(work, unknown, right.public, "unknown"), "which no --key gives")
    other = apk_mirror(os.path.join(work, "other"), wrong, "right.rsa.pub")
    refused("other key", fetch_apks(work, other, right.public, "other"), "does not verify")
    altered = apk_mirror(os.path.join(work, "altered"), right, "right.rsa.pub", tamper="signed")
    refused("altered", fetch_apks(work, altered, right.public, "altered"), "does not verify")
    for tamper, why in (
        ("control", f"{apk}: checksum does not match the index"),
        ("data", f"{apk}: the data section does not match the datahash of .PKGINFO"),
        ("planted", f"{apk}: not an apk: the signature section holds more than signatures"),
    ):
        mirror = apk_mirror(os.path.join(work, tamper), right, "right.rsa.pub", tamper=tamper)
        refused(f"{tamper} altered", fetch_apks(work, mirror, right.public, tamper), why)


# ---------------------------------------------------------------- the runner
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--work", default=os.path.join(REPO, "build", "fetch-test"))
    ap.add_argument("-k", dest="select", default="")
    args = ap.parse_args()
    missing = [t for t in ("gpg", "openssl") if not shutil.which(t)]
    if missing:
        print(f"SKIP: {', '.join(missing)} not installed; the fetchers' checks cannot be tested")
        return 0
    work = os.path.abspath(args.work)
    shutil.rmtree(work, ignore_errors=True)
    failures = 0
    chosen = [t for t in TESTS if args.select in t.__name__]
    for t in chosen:
        d = os.path.join(work, t.__name__)
        os.makedirs(d)
        start = time.monotonic()
        try:
            t(d)
        except (AssertionError, OSError) as e:
            failures += 1
            print(f"FAIL {t.__name__:<34} {time.monotonic() - start:5.1f}s {str(e)[:700]}")
            continue
        print(f"PASS {t.__name__:<34} {time.monotonic() - start:5.1f}s")
    print(f"{len(chosen)} tests, {failures} failures")
    return min(failures, 255)


if __name__ == "__main__":
    sys.exit(main())
