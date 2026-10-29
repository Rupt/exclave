"""The Debian package reader (DESIGN.md 10.1), and the index format the fetchers read.

A .deb is an `ar` archive holding `control.tar.*` and `data.tar.*`. Both are read in Python, and
xz, gzip, bzip2 and zstd are decompressed with the standard library (`lzma`, `gzip`, `bz2`,
`compression.zstd`). Versions are ordered as dpkg orders them.
"""

import bz2
import gzip
import io
import lzma
import os
import re
import zlib
from compression import zstd
from typing import Any, BinaryIO
lazy from collections.abc import Callable

from unpack.reader import Dep, PackageError, Readable, StreamTar, Window

# Debian and Ubuntu merge /bin, /sbin and /lib into /usr.
MERGED_USR: bool = True


class DebError(PackageError):
    """A .deb, or a field in one, that cannot be read."""


# ---------------------------------------------------------------- ar
def ar_members(path: str) -> list[tuple[str, int, int]]:
    """Return (name, offset, size) for each member of a GNU ar archive."""
    out = []
    with open(path, "rb") as f:
        if f.read(8) != b"!<arch>\n":
            msg = f"{path}: not an ar archive"
            raise DebError(msg)
        while True:
            h = f.read(60)
            if len(h) < 60:
                break
            name = h[:16].decode("ascii", "replace").strip().rstrip("/")
            size_field = h[48:58].strip() or b"0"
            if h[58:60] != b"`\n" or not size_field.isdigit():
                msg = f"{path}: bad ar header"
                raise DebError(msg)
            size = int(size_field)
            out.append((name, f.tell(), size))
            f.seek(size + (size & 1), 1)
    return out


def ar_read(path: str, member: str) -> tuple[str, bytes]:
    """Return the full name and the contents of the member named member or member.<suffix>."""
    for name, off, size in ar_members(path):
        if name == member or name.startswith(member + "."):
            with open(path, "rb") as f:
                f.seek(off)
                return name, f.read(size)
    msg = f"{path}: no member {member}"
    raise DebError(msg)


def decompress(name: str, data: bytes) -> bytes:
    """Decompress data by the compression its file name's suffix names.

    Raises:
        DebError: When the suffix is unknown or the data is corrupt.
    """
    decompressors = {
        ".xz": lzma.decompress,
        ".lzma": lzma.decompress,
        ".gz": gzip.decompress,
        ".bz2": bz2.decompress,
        ".zst": zstd.decompress,
        ".tar": bytes,
    }
    suffix = os.path.splitext(name)[1]
    if suffix not in decompressors:
        raise DebError("unknown compression: " + name)
    try:
        return decompressors[suffix](data)
    except (lzma.LZMAError, zstd.ZstdError, OSError, EOFError, ValueError, zlib.error) as e:
        msg = f"{name}: corrupt {suffix} data: {e}"
        raise DebError(msg) from e


class _Slice(io.RawIOBase):
    """The bytes of one ar member, read from the package file."""

    def __init__(self, path: str, offset: int, size: int) -> None:
        super().__init__()
        self.f = open(path, "rb")  # noqa: SIM115 -- closed with the slice
        self.f.seek(offset)
        self.left = size

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:  # noqa: ANN401 -- io's own buffer type
        n = self.f.readinto(memoryview(b)[: min(len(b), self.left)]) or 0
        self.left -= n
        return n

    def close(self) -> None:
        self.f.close()
        super().close()


def open_tar(path: str, member: str) -> StreamTar:
    """Open the .deb's control.tar.* or data.tar.* member as a tar archive read as it decompresses.

    Raises:
        DebError: When the archive has no such member or its compression is unknown.
    """
    found = [m for m in ar_members(path) if m[0] == member or m[0].startswith(member + ".")]
    if not found:
        msg = f"{path}: no member {member}"
        raise DebError(msg)
    name, off, size = found[0]
    suffix = os.path.splitext(name)[1]
    raw: BinaryIO = io.BufferedReader(_Slice(path, off, size))
    streams: dict[str, Callable[[BinaryIO], Readable]] = {
        ".xz": lzma.LZMAFile,
        ".lzma": lzma.LZMAFile,
        ".gz": lambda f: gzip.GzipFile(fileobj=f),
        ".bz2": bz2.BZ2File,
        ".zst": zstd.ZstdFile,
        ".tar": lambda f: f,
    }
    if suffix not in streams:
        raw.close()
        msg = f"{path}: unknown compression: {name}"
        raise DebError(msg)
    return StreamTar(
        Window(streams[suffix](raw), f"{path}: corrupt {name}"), f"{path}: corrupt {name}"
    )


def open_data(path: str) -> StreamTar:
    """Return the package's payload, data.tar.*."""
    return open_tar(path, "data.tar")


def control(path: str) -> tuple[dict[str, str], dict[str, str]]:
    """Return the package's control fields and its maintainer scripts by name."""
    fields: dict[str, str] = {}
    scripts: dict[str, str] = {}
    with open_tar(path, "control.tar") as t:
        for m in t:
            n = m.name.removeprefix("./")
            if not m.isfile():
                continue
            f = t.extractfile(m)
            assert f is not None  # a regular file always has its content
            data = f.read()
            if n == "control":
                stanzas = parse_stanzas(data.decode("utf-8", "replace"))
                fields = stanzas[0] if stanzas else {}
            elif n in ("preinst", "postinst", "prerm", "postrm", "config", "triggers"):
                scripts[n] = data.decode("utf-8", "replace")
    return fields, scripts


def interests(path: str) -> list[str]:
    """The package's trigger interests: the `interest` lines of its control file `triggers`."""
    _fields, scripts = control(path)
    out: list[str] = []
    for line in scripts.get("triggers", "").split("\n"):
        words = line.split()
        if len(words) == 2 and words[0] in ("interest", "interest-await", "interest-noawait"):
            out.append(words[1])
    return out


# ---------------------------------------------------------------- indexes
def parse_stanzas(text: str) -> list[dict[str, str]]:
    """Parse the RFC 822-style stanzas of a control or Packages file.

    A field's continuation lines are joined to it with newlines.
    """
    out: list[dict[str, str]] = []
    cur: dict[str, str] = {}
    key: str | None = None
    for line in text.split("\n"):
        if not line.strip():
            if cur:
                out.append(cur)
            cur, key = {}, None
            continue
        if line[0] in " \t" and key:
            cur[key] += "\n" + line.strip()
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        cur[key] = val.strip()
    if cur:
        out.append(cur)
    return out


_DEP = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9+.\-]*)(?::([A-Za-z0-9\-]+))?"
    r"\s*(?:\(\s*(<<|<=|=|>=|>>|<|>)\s*([^)]+?)\s*\))?"
    r"\s*(?:\[[^\]]*\])?\s*(?:<[^>]*>\s*)*$"
)


def parse_deps(field: str | None) -> list[list[Dep]]:
    """Parse a Depends-style field into groups of alternatives.

    For example, `a (>= 1) | b, c:any` gives `[[("a", ">=", "1"), ("b", None, None)],
    [("c", None, None)]]`. The architecture qualifier, architecture lists and build profiles are
    dropped.

    Raises:
        DebError: For an item that is not a dependency.
    """
    out: list[list[Dep]] = []
    if not field:
        return out
    for group in field.replace("\n", " ").split(","):
        if not group.strip():
            continue
        alts: list[Dep] = []
        for alt in group.split("|"):
            m = _DEP.match(alt)
            if not m:
                msg = f"cannot parse dependency {alt!r}"
                raise DebError(msg)
            op = {"<": "<<", ">": ">>"}.get(m.group(3), m.group(3))
            alts.append((m.group(1), op, m.group(4)))
        out.append(alts)
    return out


# ---------------------------------------------------------------- versions (Debian policy 5.6.12)
def _order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    """Compare two upstream versions or two revisions as dpkg's verrevcmp does."""
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split(v: str) -> tuple[int, str, str]:
    """Split a version into epoch, upstream version and Debian revision."""
    epoch, rest = v.split(":", 1) if ":" in v else ("0", v)
    up, _, rev = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch), up, rev


def vercmp(a: str, b: str) -> int:
    """Return a negative number, zero or a positive number as a sorts before, with or after b.

    The order is dpkg's (Debian policy 5.6.12).
    """
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return ea - eb
    r = _verrevcmp(ua, ub)
    if r:
        return r
    return _verrevcmp(ra, rb)


def satisfies(version: str, op: str | None, want: str | None) -> bool:
    """Return whether version meets the constraint `op want`; no operator is always met."""
    if op is None:
        return True
    assert want is not None  # an operator always comes with its version
    c = vercmp(version, want)
    return {"<<": c < 0, "<=": c <= 0, "=": c == 0, ">=": c >= 0, ">>": c > 0}[op]
