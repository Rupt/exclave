"""deb.py — reading Debian binary packages and indexes (DESIGN.md 10.1).

`ar` and `tar` are read in Python; xz, gzip and bzip2 through the standard
library; zstd through the `zstd` tool, which the tool's own exclave ships.
"""

import bz2
import gzip
import io
import lzma
import re
import tarfile
from compression import zstd

type Dep = tuple[str, str | None, str | None]


class DebError(Exception):
    pass


# ---------------------------------------------------------------- ar
def ar_members(path: str) -> list[tuple[str, int, int]]:
    """[(name, offset, size)] of a GNU ar archive."""
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
            size = int(h[48:58].decode("ascii").strip() or "0")
            if h[58:60] != b"`\n":
                msg = f"{path}: bad ar header"
                raise DebError(msg)
            out.append((name, f.tell(), size))
            f.seek(size + (size & 1), 1)
    return out


def ar_read(path: str, member: str) -> tuple[str, bytes]:
    for name, off, size in ar_members(path):
        if name == member or name.startswith(member + "."):
            with open(path, "rb") as f:
                f.seek(off)
                return name, f.read(size)
    msg = f"{path}: no member {member}"
    raise DebError(msg)


def decompress(name: str, data: bytes) -> bytes:
    if name.endswith((".xz", ".lzma")):
        return lzma.decompress(data)
    if name.endswith(".gz"):
        return gzip.decompress(data)
    if name.endswith(".bz2"):
        return bz2.decompress(data)
    if name.endswith(".zst"):
        try:
            return zstd.decompress(data)
        except zstd.ZstdError as e:
            msg = f"zstd failed on {name}: {e}"
            raise DebError(msg) from e
    if name.endswith(".tar"):
        return data
    raise DebError("unknown compression: " + name)


def open_tar(path: str, member: str) -> tarfile.TarFile:
    """A tarfile for control.tar.* or data.tar.* of a .deb, fully in memory."""
    name, data = ar_read(path, member)
    return tarfile.open(fileobj=io.BytesIO(decompress(name, data)), mode="r:")


def control(path: str) -> tuple[dict[str, str], dict[str, str]]:
    """The control fields and the maintainer scripts of a .deb.

    Returns (fields dict, {script name: text}).
    """
    with open_tar(path, "control.tar") as t:
        fields, scripts = {}, {}
        for m in t.getmembers():
            n = m.name.lstrip("./")
            if not m.isfile():
                continue
            f = t.extractfile(m)
            assert f is not None  # a regular file always has its content
            data = f.read()
            if n == "control":
                fields = parse_stanzas(data.decode("utf-8", "replace"))[0]
            elif n in ("preinst", "postinst", "prerm", "postrm", "config"):
                scripts[n] = data.decode("utf-8", "replace")
    return fields, scripts


# ---------------------------------------------------------------- indexes
def parse_stanzas(text: str) -> list[dict[str, str]]:
    """RFC822-style stanzas of a Packages or control file: [dict].

    Continuation lines are joined with LF.
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
    """'a (>= 1) | b, c:any' -> [[(name, op, version)], [(name, op, version)]].

    op and version may be None.
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
    epoch, rest = v.split(":", 1) if ":" in v else ("0", v)
    up, _, rev = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch), up, rev


def vercmp(a: str, b: str) -> int:
    """<0, 0, >0 as dpkg --compare-versions."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return ea - eb
    r = _verrevcmp(ua, ub)
    if r:
        return r
    return _verrevcmp(ra, rb)


def satisfies(version: str, op: str | None, want: str | None) -> bool:
    if op is None:
        return True
    assert want is not None  # an operator always comes with its version
    c = vercmp(version, want)
    return {"<<": c < 0, "<=": c <= 0, "=": c == 0, ">=": c >= 0, ">>": c > 0}[op]
