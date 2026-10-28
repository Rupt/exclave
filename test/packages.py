"""Package files for the tests: minimal .deb, .apk and .rpm files made from lists of members.

A member is (path, kind, value, mode): kind "dir" (value None), "file" (its bytes), "sym" or "hard"
(the target), or "chr" and "fifo" (value None). Every member has the modification time MTIME. A
builder can carry payload bytes given whole instead, for a damaged package.
"""

import gzip
import hashlib
import io
import lzma
import platform
import struct
import tarfile
from compression import zstd
lazy from collections.abc import Callable, Sequence

MACHINE = platform.machine()
DEB_ARCH = {"x86_64": "amd64", "aarch64": "arm64"}.get(MACHINE, MACHINE)
MTIME = 1_700_000_000

# a package member: (path, kind, None for a directory, a link's target or a file's bytes, mode)
type Member = tuple[str, str, str | bytes | None, int]

TYPES = {
    "dir": tarfile.DIRTYPE,
    "sym": tarfile.SYMTYPE,
    "hard": tarfile.LNKTYPE,
    "chr": tarfile.CHRTYPE,
    "fifo": tarfile.FIFOTYPE,
}


def tar_bytes(
    members: Sequence[Member], *, fmt: int = tarfile.PAX_FORMAT, trailer: bool = True
) -> bytes:
    """A tar archive of the members; without trailer, no end-of-archive blocks, as apk's control."""
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:", format=fmt) as t:
        for n, kind, val, mode in members:
            ti = tarfile.TarInfo(n)
            ti.mtime, ti.mode = MTIME, mode
            if kind == "file":
                assert isinstance(val, bytes)
                ti.size = len(val)
                t.addfile(ti, io.BytesIO(val))
                continue
            ti.type = TYPES[kind]
            if kind in ("sym", "hard"):
                assert isinstance(val, str)
                ti.linkname = val
            t.addfile(ti)
    raw = bio.getvalue()
    if not trailer:
        raw = raw.rstrip(b"\0")
        raw += b"\0" * (-len(raw) % 512)
    return raw


def compress(data: bytes, suffix: str) -> bytes:
    """Return data compressed as a .deb member's suffix names it: .gz, .xz or .zst, checksummed."""
    if suffix == ".gz":
        return gzip.compress(data, mtime=0)
    if suffix == ".xz":
        return lzma.compress(data)
    params: dict[int, int] = {zstd.CompressionParameter.checksum_flag: 1}
    return zstd.ZstdCompressor(options=params).compress(data, zstd.ZstdCompressor.FLUSH_FRAME)


def make_deb(
    path: str,
    name: str,
    members: Sequence[Member],
    control_extra: str = "",
    *,
    suffix: str = ".gz",
    data: bytes | None = None,
) -> None:
    """A minimal .deb: ar(debian-binary, control.tar.gz, data.tar.SUFFIX).

    data: the data member's bytes as given, instead of the members compressed.
    """
    control = (
        f"Package: {name}\nVersion: 1\nArchitecture: {DEB_ARCH}\nMaintainer: t\n"
        f"Description: t\n{control_extra}"
    ).encode()
    parts = [
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", compress(tar_bytes([("./control", "file", control, 0o644)]), ".gz")),
        ("data.tar" + suffix, data if data is not None else compress(tar_bytes(members), suffix)),
    ]
    with open(path, "wb") as f:
        f.write(b"!<arch>\n")
        for n, part in parts:
            f.write((f"{n:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(part):<10}`\n").encode())
            f.write(part)
            if len(part) % 2:
                f.write(b"\n")


def make_apk(
    path: str,
    name: str,
    members: Sequence[Member],
    pkginfo_extra: str = "",
    *,
    data: bytes | None = None,
) -> None:
    """A minimal unsigned .apk.

    Two gzip members, the control stream (.PKGINFO) and the data stream, the way apk-tools lays them
    out; data: the data stream's bytes as given, instead of the members compressed.
    """
    info = (
        f"pkgname = {name}\npkgver = 1.0-r0\narch = {MACHINE}\nsize = 1\n{pkginfo_extra}"
    ).encode()
    control = tar_bytes([(".PKGINFO", "file", info, 0o644)], trailer=False)
    with open(path, "wb") as f:
        f.write(gzip.compress(control, mtime=0))
        f.write(data if data is not None else gzip.compress(tar_bytes(members), mtime=0))


def cpio(entries: Sequence[Member]) -> bytes:
    """A newc cpio archive of the members, its trailer and padding to 512 bytes."""
    out, ino = b"", 1
    for n, kind, val, mode in entries:
        body = b""
        if kind == "dir":
            m = 0o040000 | mode
        elif kind == "sym":
            assert isinstance(val, str)
            m, body = 0o120000 | mode, val.encode()
        else:
            assert isinstance(val, bytes)
            m, body = 0o100000 | mode, val
        nm = ("./" + n).encode() + b"\0"
        h = b"070701" + b"".join(
            b"%08x" % v for v in (ino, m, 0, 0, 1, MTIME, len(body), 0, 0, 0, 0, len(nm), 0)
        )
        rec = h + nm
        rec += b"\0" * (-len(rec) % 4) + body
        rec += b"\0" * (-len(rec) % 4)
        out += rec
        ino += 1
    nm = b"TRAILER!!!\0"
    h = b"070701" + b"".join(b"%08x" % v for v in (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(nm), 0))
    out += h + nm
    return out + b"\0" * (-len(out) % 512)


def make_rpm(
    path: str,
    name: str,
    members: Sequence[Member],
    *,
    requires: Sequence[tuple[str, int, str]] = (),
    provides: Sequence[tuple[str, int, str]] = (),
    postin: str = "",
    payload: bytes | None = None,
    sign: Callable[[bytes], bytes] | None = None,
    sign_payload: bool = False,
) -> None:
    """A minimal binary rpm.

    Lead, a signature header, a header with the tags the reader uses, a gzip newc cpio payload.
    members as for make_deb; requires and provides are (name, flags, version) triples; payload, the
    gzip bytes to carry instead, for a damaged package. With sign, an OpenPGP signature of the bytes
    given, the package is signed as rpm signs it: a header signature over the header section, with
    the payload's SHA-256 in the header (RPMTAG_PAYLOADDIGEST), or with sign_payload a signature
    over header and payload together, as rpm before 4.14 did, and no digest.
    """

    def header(entries: Sequence[tuple[int, int, Sequence[int | str] | bytes]]) -> bytes:
        """Pack (tag, type, values) entries: type 4 int32, 6 string, 7 binary, 8 string array."""
        index, data = b"", b""
        for tag, typ, vals in entries:
            if typ == 4:
                data += b"\0" * (-len(data) % 4)
                off = len(data)
                data += b"".join(struct.pack(">i", v) for v in vals)
                index += struct.pack(">IIII", tag, 4, off, len(vals))
            elif typ == 7:
                assert isinstance(vals, bytes)
                off = len(data)
                data += vals
                index += struct.pack(">IIII", tag, 7, off, len(vals))
            else:
                off = len(data)
                data += b"".join(str(v).encode() + b"\0" for v in vals)
                index += struct.pack(">IIII", tag, typ, off, len(vals))
        return (
            b"\x8e\xad\xe8\x01"
            + b"\0" * 4
            + struct.pack(">II", len(entries), len(data))
            + index
            + data
        )

    if payload is None:
        payload = gzip.compress(cpio(members), mtime=0)
    entries: list[tuple[int, int, Sequence[int | str] | bytes]] = [
        (1000, 6, [name]),
        (1001, 6, ["1.0"]),
        (1002, 6, ["1"]),
        (1022, 6, [MACHINE]),
        (1125, 6, ["gzip"]),
        (1124, 6, ["cpio"]),
    ]
    if requires:
        entries += [
            (1049, 8, [r[0] for r in requires]),
            (1048, 4, [r[1] for r in requires]),
            (1050, 8, [r[2] for r in requires]),
        ]
    if provides:
        entries += [
            (1047, 8, [p[0] for p in provides]),
            (1112, 4, [p[1] for p in provides]),
            (1113, 8, [p[2] for p in provides]),
        ]
    if postin:
        entries += [(1024, 6, [postin])]
    if sign and not sign_payload:
        entries += [(5092, 8, [hashlib.sha256(payload).hexdigest()]), (5093, 4, [8])]
    main = header(entries)
    signatures: list[tuple[int, int, Sequence[int | str] | bytes]] = [(1000, 4, [len(payload)])]
    if sign:
        signatures += [
            (1002 if sign_payload else 268, 7, sign(main + payload if sign_payload else main))
        ]
    sig = header(signatures)
    lead = (
        b"\xed\xab\xee\xdb"
        + bytes([3, 0])
        + struct.pack(">hh", 0, 1)
        + name.encode().ljust(66, b"\0")[:66]
        + struct.pack(">hh", 1, 5)
        + b"\0" * 16
    )
    with open(path, "wb") as f:
        f.write(lead + sig + b"\0" * (-len(sig) % 8) + main + payload)
