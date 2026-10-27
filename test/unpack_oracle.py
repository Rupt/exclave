"""Compare exclave unpack with scripts/unpack on .apk files: the unpack oracle (DESIGN.md 18).

    test/unpack_oracle.py [--apks DIR] [--work DIR] [--tool PATH]

Each set of package files goes to both, each into an output of its own. The exit status, the
standard output with the output's path replaced, and the directory each leaves behind must be the
same: every entry's kind, mode, link text, contents and hard-link group, and a file's modification
time when it came from the archive (one the run made is only said to be new). DIR, the apks
directory scripts/inputs fills, adds Alpine's own set; the generated sets cover the gzip and DEFLATE
forms zlib accepts and refuses, hand-built where zlib would not write them, the tar forms tarfile
reads, conflicts and Replaces, the synthesis an Alpine set reaches, and the refusals. A difference
that is right goes into EXPECTED with the rule that makes it so. Prints one line per difference and
a summary; exit status 1 when one is unexplained.
"""

import argparse
import gzip
import hashlib
import io
import os
import random
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import time
import zlib
lazy from collections.abc import Sequence

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PYTHON = (sys.executable, "-m", "unpack")
T0 = 1_700_000_000

type Result = tuple[int, bytes, bytes, bool, list[str]]

# A case whose answers differ by design: why, and the test that the pair is that case. exclave
# unpack refuses what it does not read or synthesise yet, where scripts/unpack goes on.
NOT_YET: dict[str, str] = {
    "gnu-longname": "GNU long names, which no .apk has",
    "pax-global": "a global PAX header, which no .apk has",
    "pax-twice": "two PAX headers in a row, which no .apk has",
    "ca-debian": "the ca-certificates bundle, not synthesised yet",
    "ca-p11kit": "the p11-kit bundle, not synthesised yet",
    "ldconfig-elf": "an ld.so.cache from an ELF ldconfig, not synthesised yet",
}


def c_refused_only(py: Result, c: Result) -> bool:
    return py[0] == 0 and c[0] == 1 and not c[3] and b"does not" in c[2]


# ---------------------------------------------------------------- package files
type Member = tuple[tarfile.TarInfo, bytes | None]


def mem(
    name: str,
    kind: str = "f",
    data: bytes = b"",
    *,
    mode: int = 0o644,
    mtime: float = T0,
    link: str = "",
    typeflag: bytes | None = None,
    pax: dict[str, str] | None = None,
) -> Member:
    """Return a member: a file (f), directory (d), symlink (l), hard link (h) or another type."""
    ti = tarfile.TarInfo(name)
    ti.mode, ti.mtime = mode, mtime
    ti.type = (
        typeflag
        or {"f": tarfile.REGTYPE, "d": tarfile.DIRTYPE, "l": tarfile.SYMTYPE, "h": tarfile.LNKTYPE}[
            kind
        ]
    )
    ti.linkname = link
    if pax:
        ti.pax_headers = pax
    if kind == "f" and ti.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.CONTTYPE):
        ti.size = len(data)
        return ti, data
    return ti, None


def tar_of(
    members: Sequence[Member],
    fmt: int = tarfile.PAX_FORMAT,
    *,
    trailer: bool = True,
    global_pax: dict[str, str] | None = None,
) -> bytes:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:", format=fmt, pax_headers=global_pax) as t:
        for ti, data in members:
            t.addfile(ti, io.BytesIO(data) if data is not None else None)
    raw = bio.getvalue()
    if not trailer:  # the control stream carries no end-of-archive blocks
        raw = raw.rstrip(b"\0")
        raw += b"\0" * (-len(raw) % 512)
    return raw


def pkginfo(name: str, *, version: str = "1.0-r0", arch: str = "x86_64", extra: str = "") -> bytes:
    return f"pkgname = {name}\npkgver = {version}\narch = {arch}\nsize = 1\n{extra}".encode()


def apk(
    path: str,
    info: bytes | None,
    members: Sequence[Member],
    *,
    fmt: int = tarfile.PAX_FORMAT,
    data: bytes | None = None,
    after: bytes = b"",
) -> str:
    """Write an .apk: the control stream with .PKGINFO, then the data stream; return its path.

    data replaces the data stream's gzip bytes; after is appended to the file.
    """
    control = [mem(".PKGINFO", data=info)] if info is not None else [mem(".SIGN.RSA.x", data=b"s")]
    with open(path, "wb") as f:
        f.write(gzip.compress(tar_of(control, trailer=False), mtime=0))
        f.write(data if data is not None else gzip.compress(tar_of(members, fmt), mtime=0))
        f.write(after)
    return path


def gz_member(raw_deflate: bytes, content: bytes, *, flags: int = 0, extra: bytes = b"") -> bytes:
    """Return a gzip member around a raw DEFLATE stream whose output is content."""
    head = bytearray(b"\x1f\x8b\x08" + bytes([flags]) + b"\0\0\0\0\0\x03")
    if flags & 4:
        head += struct.pack("<H", len(extra)) + extra
    if flags & 8:
        head += b"name.tar\0"
    if flags & 16:
        head += b"a comment\0"
    if flags & 2:
        head += struct.pack("<H", zlib.crc32(bytes(head)) & 0xFFFF)
    return bytes(head) + raw_deflate + struct.pack("<II", zlib.crc32(content), len(content))


def deflate_raw(
    data: bytes, *, level: int = 6, wbits: int = -15, strategy: int = zlib.Z_DEFAULT_STRATEGY
) -> bytes:
    c = zlib.compressobj(level, zlib.DEFLATED, wbits, 8, strategy)
    return c.compress(data) + c.flush()


# ---------------------------------------------------------------- DEFLATE blocks by hand (RFC 1951)
LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115]
LBASE += [131, 163, 195, 227, 258]
LEXTRA = [0] * 8 + [1] * 4 + [2] * 4 + [3] * 4 + [4] * 4 + [5] * 4 + [0]
DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025]
DBASE += [1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577]
DEXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12]
DEXTRA += [13, 13]
ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]


class Bits:
    def __init__(self) -> None:
        self.v, self.n = 0, 0

    def put(self, value: int, count: int) -> None:
        self.v |= value << self.n
        self.n += count

    def code(self, code: tuple[int, int]) -> None:
        c, n = code
        for i in range(n - 1, -1, -1):
            self.put((c >> i) & 1, 1)

    def done(self) -> bytes:
        return self.v.to_bytes((self.n + 7) // 8, "little")


def canonical(lengths: Sequence[int]) -> list[tuple[int, int]]:
    count = [0] * 16
    for n in lengths:
        if n:
            count[n] += 1
    nxt, code = [0] * 16, 0
    for bits in range(1, 16):
        code = (code + count[bits - 1]) << 1
        nxt[bits] = code
    out = []
    for n in lengths:
        out.append((nxt[n], n) if n else (0, 0))
        if n:
            nxt[n] += 1
    return out


type Sym = int | tuple[int, int]  # a literal byte or 256, or (length, distance)


def symbols(
    b: Bits, syms: Sequence[Sym], lit: list[tuple[int, int]], dist: list[tuple[int, int]]
) -> None:
    for s in syms:
        if isinstance(s, int):
            b.code(lit[s])
            continue
        length, d = s
        i = max(k for k in range(29) if LBASE[k] <= length)
        b.code(lit[257 + i])
        b.put(length - LBASE[i], LEXTRA[i])
        j = max(k for k in range(30) if DBASE[k] <= d)
        b.code(dist[j])
        b.put(d - DBASE[j], DEXTRA[j])


def dynamic(
    litlens: Sequence[int],
    distlens: Sequence[int],
    syms: Sequence[Sym],
    *,
    cl_syms: Sequence[tuple[int, int, int]] | None = None,
    nlen: int | None = None,
) -> bytes:
    """A final dynamic block, its code lengths one each or as cl_syms: (symbol, extra, bits)."""
    b = Bits()
    b.put(1, 1)
    b.put(2, 2)
    b.put((nlen or len(litlens)) - 257, 5)
    b.put(len(distlens) - 1, 5)
    b.put(15, 4)
    cl = [5] * 16 + [2, 3, 3]  # complete: 16/32 + 1/4 + 1/8 + 1/8
    for s in ORDER:
        b.put(cl[s], 3)
    clc = canonical(cl)
    if cl_syms is None:
        for n in [*litlens, *distlens]:
            b.code(clc[n])
    else:
        for s, extra, bits in cl_syms:
            b.code(clc[s])
            b.put(extra, bits)
    symbols(b, [*syms, 256], canonical(litlens), canonical(distlens))
    return b.done()


def fixed(syms: Sequence[Sym], *, raw_lit: int | None = None, raw_dist: int | None = None) -> bytes:
    """A final fixed-code block; raw_lit or raw_dist puts one code fixed coding has but forbids."""
    lens = [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8
    lit, dist = canonical(lens), canonical([5] * 32)
    b = Bits()
    b.put(1, 1)
    b.put(1, 2)
    symbols(b, syms, lit, dist)
    if raw_lit is not None:
        b.code(lit[raw_lit])
    if raw_dist is not None:
        b.code(lit[257])
        b.code(dist[raw_dist])
    b.code(lit[256])
    return b.done()


# lit/len: every byte 9 bits, end of block 2, lengths 3 to 6 four bits: complete
LIT = [9] * 256 + [2, 4, 4, 4, 4]


def tail_member(raw: bytes, out: bytes) -> bytes:
    """A gzip member decompressing to bytes after the archive's end, which tar never reads."""
    return gz_member(raw, out)


# ---------------------------------------------------------------- the sets
def base_members() -> list[Member]:
    return [
        mem("usr", "d", mode=0o755),
        mem("usr/bin", "d", mode=0o755),
        mem("usr/bin/tool", data=b"#!/bin/sh\necho tool\n", mode=0o755),
        mem("usr/share/doc/tool/README", data=b"read me\n" * 50),
    ]


def sets(d: str, rng: random.Random, *, non_utf8: bool) -> dict[str, list[str]]:
    """Return every generated set of package files, by name, writing them under d."""
    out: dict[str, list[str]] = {}

    def one(
        name: str,
        members: Sequence[Member],
        *,
        info: bytes | None = b"",
        fmt: int = tarfile.PAX_FORMAT,
        data: bytes | None = None,
        after: bytes = b"",
    ) -> None:
        """One package named for its set, or with the .PKGINFO given; None for none."""
        info = pkginfo("pkg-" + name) if info == b"" else info
        out[name] = [
            apk(os.path.join(d, name + ".apk"), info, members, fmt=fmt, data=data, after=after)
        ]

    # gzip and DEFLATE
    tar = tar_of(base_members())
    one("basic", base_members())
    one("stored", [], data=gz_member(deflate_raw(tar, level=0), tar))
    one("fixed", [], data=gz_member(deflate_raw(tar, strategy=zlib.Z_FIXED), tar))
    one("huffman-only", [], data=gz_member(deflate_raw(tar, strategy=zlib.Z_HUFFMAN_ONLY), tar))
    one("rle", [], data=gz_member(deflate_raw(tar, strategy=zlib.Z_RLE), tar))
    one("small-window", [], data=gz_member(deflate_raw(tar, wbits=-9, level=9), tar))
    for flags in (2, 4, 8, 16, 30):
        one(
            f"gzip-flags-{flags}",
            [],
            data=gz_member(deflate_raw(tar), tar, flags=flags, extra=b"ab"),
        )
    half = len(tar) // 2
    split = gz_member(deflate_raw(tar[:half]), tar[:half]) + b"\0" * 7
    one("two-members", [], data=split + gz_member(deflate_raw(tar[half:]), tar[half:]))
    one("trailing-nuls", base_members(), after=b"\0" * 100)
    one("trailing-junk", base_members(), after=b"junk")
    one("trailing-short", base_members(), after=b"\x1f")
    body = deflate_raw(tar)
    good = gz_member(body, tar)
    one("bad-crc", [], data=good[:-8] + struct.pack("<II", zlib.crc32(tar) ^ 1, len(tar)))
    one("bad-length", [], data=good[:-8] + struct.pack("<II", zlib.crc32(tar), len(tar) + 1))
    bad_hcrc = bytearray(gz_member(body, tar, flags=2))
    bad_hcrc[10] ^= 1
    one("bad-header-crc", [], data=bytes(bad_hcrc))
    for cut in (5, 12, len(good) // 2, len(good) - 9, len(good) - 4):
        one(f"truncated-{cut}", [], data=good[:cut])
    for k in range(6):
        flipped = bytearray(good)
        flipped[rng.randrange(10, len(good) - 8)] ^= 1 << rng.randrange(8)
        one(f"flipped-{k}", [], data=bytes(flipped))
    one("not-gzip", [], data=b"plain bytes, not gzip")
    out["empty-file"] = [os.path.join(d, "empty-file.apk")]
    open(out["empty-file"][0], "wb").close()
    # members after the archive's end: decoded and checked, never read as tar
    hello = [ord(c) for c in "hello"]
    for name, raw, ok_out in (
        ("dyn-complete", dynamic(LIT, [1, 1], [*hello, (3, 2)]), b"hellolol"),
        ("dyn-one-distance", dynamic(LIT, [1], [*hello, (4, 1)]), b"hellooooo"),
        ("dyn-only-end", dynamic([0] * 256 + [1], [0], []), b""),
        ("dyn-no-distances", dynamic(LIT, [0], hello), b"hello"),
        ("dyn-over-subscribed", dynamic(LIT, [1, 1, 1], hello), b""),
        ("dyn-incomplete-distances", dynamic(LIT, [2, 2, 2], hello), b""),
        ("dyn-incomplete-literals", dynamic([9] * 256 + [2, 4], [1, 1], hello), b""),
        ("dyn-no-end", dynamic([9] * 256 + [0, 2, 3, 3], [1, 1], []), b""),
        ("dyn-too-many", dynamic(LIT, [1, 1], hello, nlen=287), b""),
        ("dyn-repeat-first", dynamic(LIT, [1, 1], hello, cl_syms=[(16, 0, 2)]), b""),
        ("dyn-repeat-over", dynamic(LIT, [1, 1], hello, cl_syms=[(18, 127, 7)] * 3), b""),
        ("fixed-too-far", fixed([(3, 1)]), b""),
        ("fixed-lit-286", fixed(hello, raw_lit=286), b""),
        ("fixed-dist-30", fixed([*hello], raw_dist=30), b""),
        ("block-type-3", b"\x07", b""),
        ("stored-bad-nlen", b"\x01\x05\x00\x00\x00hello", b""),
        ("stored-empty-then-fixed", b"\x00\x00\x00\xff\xff" + fixed(hello), b"hello"),
    ):
        one("tail-" + name, base_members(), after=tail_member(raw, ok_out))
    # tar
    long = "usr/share/" + "/".join(["d" * 40] * 4) + "/file"
    one("ustar-prefix", [*base_members(), mem(long, data=b"long\n")], fmt=tarfile.USTAR_FORMAT)
    one("gnu-longname", [*base_members(), mem(long, data=b"long\n")], fmt=tarfile.GNU_FORMAT)
    one("gnu-base256", [mem("old", data=b"x", mtime=-1), mem("dir", "d")], fmt=tarfile.GNU_FORMAT)
    one(
        "pax-names",
        [
            mem(long, data=b"long\n"),
            mem("usr/l", "l", link="/" + long),
            mem("café", data=b"accent\n"),
            mem("usr/when", data=b"t", mtime=T0 + 0.25),
            mem("usr/when2", data=b"t", mtime=T0 + 0.123456789),
            mem("usr/sized", data=b"abc", pax={"size": "3", "comment": "c"}),
        ],
    )
    one(
        "pax-global",
        [],
        data=gzip.compress(tar_of(base_members(), global_pax={"comment": "g"}), mtime=0),
    )
    one(
        "old-dir",
        [
            mem("olddir/", data=b"", typeflag=tarfile.AREGTYPE),
            mem("olddir/f", data=b"in old dir\n"),
        ],
        fmt=tarfile.USTAR_FORMAT,
    )
    one(
        "types",
        [
            *base_members(),
            mem("usr/bin/hard", "h", link="usr/bin/tool"),
            mem("usr/bin/soft", "l", link="tool"),
            mem("usr/bin/hard-to-link", "h", link="usr/bin/soft"),
            mem("dev-null", "x", typeflag=tarfile.CHRTYPE),
            mem("fifo", "x", typeflag=tarfile.FIFOTYPE),
            mem("contiguous", data=b"c\n", typeflag=tarfile.CONTTYPE),
            mem("usr/suid", data=b"s", mode=0o4755),
            mem("usr/nomode", data=b"n", mode=0),
            mem("usr/locked", "d", mode=0o500),
            mem("usr/locked/f", data=b"f"),
            mem("./dotted/./name", data=b"d"),
            mem("/abs/name", data=b"a"),
            mem(".hidden-top", data=b"control-like"),
            mem("deep/er/than/before/f", data=b"made parents"),
        ],
    )
    unknown = bytearray(tar_of([*base_members(), mem("weird", data=b"zz")]))
    for off in range(0, len(unknown), 512):
        if unknown[off : off + 5] == b"weird":
            unknown[off + 156] = ord("Z")
            unknown[off + 148 : off + 156] = b"        "
            s = sum(unknown[off : off + 512])
            unknown[off + 148 : off + 156] = b"%06o\0 " % s
    one("unknown-type", [], data=gzip.compress(bytes(unknown), mtime=0))
    garbage = tar_of(base_members(), trailer=False) + b"x" * 512 + tar_of([mem("after", data=b"g")])
    one("garbage-header", [], data=gzip.compress(garbage, mtime=0))
    for cut in (1500, 1700, 2048):
        one(f"cut-tar-{cut}", [], data=gzip.compress(tar_of(base_members())[:cut], mtime=0))
    one("zero-blocks", [], data=gzip.compress(b"\0" * 2048, mtime=0))
    twice = bytearray(tar_of([mem("x", data=b"x", pax={"comment": "one"})]))
    one("pax-twice", [], data=gzip.compress(bytes(twice[:1024]) + bytes(twice), mtime=0))
    if non_utf8:
        one(
            "non-utf8", [mem(os.fsdecode(b"usr/\xff\xfe"), data=b"bytes\n")], fmt=tarfile.GNU_FORMAT
        )

    # conflicts and Replaces
    def pair(
        name: str, a: Sequence[Member], b: Sequence[Member], extra_b: str = "", extra_a: str = ""
    ) -> None:
        out[name] = [
            apk(os.path.join(d, name + "-a.apk"), pkginfo("a", extra=extra_a), a),
            apk(os.path.join(d, name + "-b.apk"), pkginfo("b", extra=extra_b), b),
        ]

    f1, f2 = [mem("usr/x", data=b"from a\n")], [mem("usr/x", data=b"from b\n")]
    pair("conflict", f1, f2)
    pair("replaces-later", f1, f2, extra_b="replaces = a\n")
    pair("replaces-earlier", f1, f2, extra_a="replaces = b>=1 !c\n")
    pair("same-symlink", [mem("usr/l", "l", link="x")], [mem("usr/l", "l", link="x")])
    pair("other-symlink", [mem("usr/l", "l", link="x")], [mem("usr/l", "l", link="y")])
    pair(
        "over-dir-link",
        [mem("usr/e", "d"), mem("usr/d", "l", link="e")],
        [mem("usr/d", data=b"file\n")],
    )
    pair(
        "early-link",
        [mem("usr/lib", "d"), mem("usr/lib64", "l", link="lib")],
        [mem("usr/lib64/libx.so", data=b"lib\n")],
    )
    pair("merged-link", [mem("usr/libx32", "l", link="lib")], [mem("usr/lib/y", data=b"y")])
    pair("bad-replaces", f1, f2, extra_b="replaces = a<\n")
    pair("alias-key", [mem("lib/x", data=b"1")], [mem("usr/lib/x", data=b"2")])
    # refusals
    one("dotdot", [mem("usr/../../escape", data=b"e")])
    one("real", [mem("usr/bin/.real/x", data=b"r")])
    one("hard-dotdot", [mem("f", data=b"f"), mem("h", "h", link="../f")])
    one("through-link", [mem("opt", "l", link="/tmp"), mem("opt/escaped-file", data=b"e")])
    one("hard-through-link", [mem("opt", "l", link="/etc"), mem("h", "h", link="opt/hostname")])
    one("no-pkginfo", base_members(), info=None)
    one("no-pkgname", base_members(), info=b"pkgver = 1\n")
    one("empty-pkgver", base_members(), info=b"pkgname = e\npkgver = \n")
    one("nonprintable", base_members(), info=pkginfo("np", version="1.0\x01"))
    one("noarch", base_members(), info=pkginfo("na", arch="noarch"))
    one(
        "pkginfo-oddities",
        base_members(),
        info=b"# c\npkgname = odd\npkgname = second\n  pkgver  =  2 \nx\n",
    )
    one("dir-over-file", [mem("usr/x", data=b"f"), mem("usr/x", "d")])
    one("file-over-dir", [mem("usr/x", "d"), mem("usr/x", data=b"f")])
    out["dup-name"] = [
        apk(os.path.join(d, "dup1.apk"), pkginfo("same"), base_members()),
        apk(os.path.join(d, "dup2.apk"), pkginfo("same", version="2"), base_members()),
    ]
    out["mixed-arch"] = [
        apk(os.path.join(d, "arch1.apk"), pkginfo("one", arch="x86_64"), base_members()),
        apk(os.path.join(d, "arch2.apk"), pkginfo("two", arch="aarch64"), base_members()),
        apk(os.path.join(d, "arch3.apk"), pkginfo("three", arch="noarch"), base_members()),
    ]
    deb = os.path.join(d, "mixed.deb")
    shutil.copyfile(out["basic"][0], deb)
    out["mixed-format"] = [out["basic"][0], deb]
    # synthesis
    bb = [
        mem("bin", "d"),
        mem("bin/busybox", data=b"#!/bin/true\n", mode=0o755),
        mem("etc/busybox-paths.d", "d"),
        mem(
            "etc/busybox-paths.d/busybox",
            data=b"bin/sh\r\n/usr/bin/wget\n  \nsbin/x\rbin/busybox\n",
        ),
        mem("etc/busybox-paths.d/another", data=b"usr/local/bin/y\n./a/./b"),
    ]
    one("busybox", bb, info=pkginfo("busybox"))
    one("busybox-escape", [*bb, mem("etc/busybox-paths.d/z", data=b"../../out\n")])
    one("busybox-real", [*bb, mem("etc/busybox-paths.d/z", data=b"usr/.real/x\n")])
    one("dash", [mem("usr/bin/dash", data=b"d", mode=0o755)], info=pkginfo("dash"))
    one("libssl", [mem("usr/lib/libssl.so.3", data=b"l")], info=pkginfo("libssl3"))
    one(
        "base-passwd",
        [
            mem("usr/share/base-passwd/passwd.master", data=b"root:x:0:0::/root:/bin/sh\n"),
            mem("usr/share/base-passwd/group.master", data=b"root:x:0:\n"),
            mem("etc/group", data=b"kept\n"),
        ],
        info=pkginfo("base-passwd"),
    )
    one("libc-bin", base_members(), info=pkginfo("libc-bin"))
    one(
        "volatile",
        [
            mem("tmp", "d", mode=0o1777),
            mem("tmp/f", data=b"t"),
            mem("var/tmp/deep/f", data=b"t"),
            mem("run", "l", link="var/run"),
            mem("dev/null-ish", data=b"n"),
        ],
    )
    one("volatile-file", [mem("var/tmp", data=b"a file where a directory goes")])
    one(
        "ca-debian",
        [mem("etc/ca-certificates.conf", data=b"mozilla/x.crt\n")],
        info=pkginfo("ca-certificates"),
    )
    one("ca-p11kit", [mem("usr/share/pki/ca-trust-source/x.p11-kit", data=b"p")])
    one("ldconfig-elf", [mem("sbin/ldconfig", data=b"\x7fELF not really", mode=0o755)])
    one("ldconfig-script", [mem("sbin/ldconfig", data=b"#!/bin/sh\n", mode=0o755)])
    return out


# ---------------------------------------------------------------- running and comparing
def snapshot(top: str, since: float) -> list[str]:
    """Every entry under top: path, kind, mode, and its link text, or contents, group and time."""
    out: list[str] = []
    btop = os.fsencode(top)
    files: list[tuple[bytes, os.stat_result]] = []
    for dirpath, dirnames, filenames in os.walk(btop):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            rel = os.path.relpath(p, btop)
            if stat.S_ISLNK(st.st_mode):
                out.append(f"{rel!r} link {os.readlink(p)!r}")
            elif stat.S_ISREG(st.st_mode):
                files.append((rel, st))
            else:
                kind = "dir" if stat.S_ISDIR(st.st_mode) else "other"
                out.append(f"{rel!r} {kind} {st.st_mode & 0o7777:o}")
    group: dict[tuple[int, int], bytes] = {}
    for rel, st in sorted(files):
        first = group.setdefault((st.st_dev, st.st_ino), rel)
        with open(os.path.join(btop, rel), "rb") as f:
            h = hashlib.blake2b(f.read(), digest_size=16).hexdigest()
        when = st.st_mtime_ns if st.st_mtime < since else "new"
        out.append(f"{rel!r} file {st.st_mode & 0o7777:o} {h} {first!r} {when}")
    return sorted(out)


def run(cmd: Sequence[str], out: str, pkgs: Sequence[str], since: float) -> Result:
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
    p = subprocess.run([*cmd, out, *pkgs], capture_output=True, check=False, timeout=900, env=env)
    stdout = p.stdout.replace(os.fsencode(out), b"OUT")
    left = os.path.lexists(out)
    return p.returncode, stdout, p.stderr, left, snapshot(out, since) if left else []


def differ(py: Result, c: Result) -> str:
    if py[0] != c[0]:
        return f"exit {py[0]} and {c[0]}: {py[2][-300:]!r} / {c[2][-300:]!r}"
    if py[1] != c[1]:
        return f"stdout {py[1][-300:]!r} / {c[1][-300:]!r}"
    if py[3] != c[3]:
        return f"output left {py[3]} and {c[3]}"
    if py[4] != c[4]:
        a, b = set(py[4]), set(c[4])
        return f"trees differ: python only {sorted(a - b)[:3]!r}, C only {sorted(b - a)[:3]!r}"
    return ""


def utf8_only(d: str) -> bool:
    """Whether the filesystem under d refuses a name that is not UTF-8 (ZFS's utf8only)."""
    p = os.path.join(os.fsencode(d), b"\xff")
    try:
        open(p, "wb").close()
    except OSError:
        return True
    os.remove(p)
    return False


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--apks")
    ap.add_argument("--work", default=os.path.join(REPO, "build", "unpack-oracle"))
    ap.add_argument("--tool", default=os.path.join(REPO, "build", "exclave-asan"))
    args = ap.parse_args()
    work = os.path.abspath(args.work)
    if os.path.exists(work):
        shutil.rmtree(work)  # every directory either makes is its owner's to write
    pkgdir = os.path.join(work, "pkgs")
    os.makedirs(pkgdir)
    non_utf8 = not utf8_only(work)
    if not non_utf8:
        print("this filesystem refuses names that are not UTF-8: none generated")
    all_sets = sets(pkgdir, random.Random(1), non_utf8=non_utf8)
    if args.apks:
        all_sets["alpine"] = sorted(
            os.path.join(args.apks, f) for f in os.listdir(args.apks) if f.endswith(".apk")
        )
    since = time.time() - 60
    exists_py = os.path.join(work, "exists-py")
    exists_c = os.path.join(work, "exists-c")
    os.makedirs(exists_py)
    os.makedirs(exists_c)
    diffs = expected = 0
    for name, pkgs in all_sets.items():
        py = run(PYTHON, os.path.join(work, "py", name), pkgs, since)
        c = run((args.tool, "unpack"), os.path.join(work, "c", name), pkgs, since)
        why = differ(py, c)
        if name in NOT_YET:
            if c_refused_only(py, c):
                expected += 1
                continue
            why = why or "the same answer, where exclave unpack should refuse"
            why = f"expected C to refuse ({NOT_YET[name]}) and Python to go on: {why}"
        if why:
            diffs += 1
            print(f"DIFF {name}: {why}")
    for cmd, at in ((PYTHON, exists_py), ((args.tool, "unpack"), exists_c)):
        r = run(cmd, at, all_sets["basic"], since)
        if r[0] != 1 or not os.path.isdir(at) or os.listdir(at):
            diffs += 1
            print(f"DIFF output-exists: {cmd[0]} answered {r[0]} and changed {at}")
    print(
        f"unpack oracle: {len(all_sets) + 1} cases, {diffs} unexplained differences, "
        f"{expected} expected"
    )
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main())
