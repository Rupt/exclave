"""The RPM package reader (DESIGN.md 10.1).

An .rpm is a 96-byte lead, a signature header, a header and a compressed cpio payload. The header
is an index of tagged entries, from which the reader takes the name, version, architecture,
dependencies, install scripts and the payload's compressor. The payload is cpio in the "newc" or
"crc" form, compressed with gzip, xz, bzip2 or zstd, and all of it is read with the standard
library. `Obsoletes` is presented as `Replaces`.

The synthesis rules are Debian's, read in rpm's spelling (DESIGN.md 10.1). These are the places an
rpm set needs more:

- cpio records hard links as entries of one inode with the content on the last; the reader gives the
  content to the first and links the rest, as tar would.
- Versions are ordered as rpmvercmp orders them: epoch first, then version and release segment by
  segment.
- Dependencies come as rpm spells them: package names, the provides a library's package declares
  (`libc.so.6(GLIBC_2.2.5)(64bit)`, `rtld(GNU_HASH)`), and file names. `rpmlib(...)` features and
  rich dependencies (`(a or b)`) are rpm's own and are skipped.
- `alternatives --install` lines in %post are read in either spelling, the tree's own ldconfig runs
  where it is static, and the identity files are the placeholders wrap adds. `setup` ships
  /etc/passwd, so nothing is made for it.
- An `alternatives --install` line replaces a file or link already standing at the link path, as
  both implementations do. Fedora's binutils needs this: it ships gold at /usr/bin/ld and removes it
  in %post before installing ld.bfd as the alternative.
- Fedora, RHEL and CentOS 7 have merged /usr, so the merged-/usr links are made. A symlink that one
  package ships at a path under which other packages ship files is made before anything is
  extracted, whatever the order of the packages, so those files land where the link points.
- Fedora 42's `filesystem` package merges sbin into bin in its %posttrans, written in Lua: when
  every entry of /usr/sbin is a link `../bin/<name>`, the directory becomes a link to bin. Unpack
  does the same when that script is present.
- Red Hat's ld.so.conf says `include ld.so.conf.d/*.conf`, relative to /etc, which ldconfig refuses
  under -r. Unpack runs ldconfig on a temporary copy in the tree with the pattern spelt from /etc,
  and removes the copy afterwards.
- Files shipped unreadable, such as Fedora's /etc/gshadow at mode 0, are made readable by their
  owner, since a tree its owner cannot read can be neither hashed nor copied. A tree that comes from
  outside with such a file is refused by `wrap`, naming the file (DESIGN.md 10.3).
- Fedora's ca-certificates ships a p11-kit trust source and links every consumer path to the bundle
  that update-ca-trust extracts in %post. Unpack extracts it the same way, one PEM for each anchor
  marked trusted and not distrusted, so that the Red Hat identity file of DESIGN.md 8.4 has a copy
  to fall back to.
"""

import bz2
import gzip
import io
import lzma
import re
import struct
from compression import zstd
from dataclasses import dataclass
from typing import IO, Any, BinaryIO, NamedTuple, Self
lazy from collections.abc import Callable, Iterator

from unpack.reader import Dep, PackageError, Readable, Window

# A header's values: bytes, int, str or a list of them. Each tag's type is fixed by rpm's tag table,
# which the reader follows and a static type cannot express.
type Header = dict[int, Any]


class RpmError(PackageError):
    """An .rpm, or a field in one, that cannot be read."""


# Fedora and RHEL 7 and later merge /bin, /sbin and /lib into /usr: their filesystem package ships
# /bin -> usr/bin and /lib64 -> usr/lib64.
MERGED_USR: bool = True
LEAD = 96
HEADER_MAGIC = b"\x8e\xad\xe8\x01"
# The tags the reader uses, from rpm's rpmtag.h.
RPMTAG = {
    "NAME": 1000,
    "VERSION": 1001,
    "RELEASE": 1002,
    "EPOCH": 1003,
    "ARCH": 1022,
    "POSTIN": 1024,
    "PREIN": 1023,
    "POSTTRANS": 1152,
    "REQUIREFLAGS": 1048,
    "REQUIRENAME": 1049,
    "REQUIREVERSION": 1050,
    "PROVIDEFLAGS": 1112,
    "PROVIDENAME": 1047,
    "PROVIDEVERSION": 1113,
    "OBSOLETENAME": 1090,
    "OBSOLETEVERSION": 1115,
    "OBSOLETEFLAGS": 1114,
    "PAYLOADCOMPRESSOR": 1125,
}
SENSE = {2: "<", 4: ">", 8: "="}  # RPMSENSE_LESS, GREATER, EQUAL bits
SENSE_RPMLIB = 1 << 24


def _header(f: BinaryIO) -> Header:
    """Read one header section at f's position into {tag: value}."""
    magic = f.read(8)
    if magic[:4] != HEADER_MAGIC:
        msg = "bad header magic"
        raise RpmError(msg)
    nindex, hsize = struct.unpack(">II", f.read(8))
    index = f.read(16 * nindex)
    data = f.read(hsize)
    out: Header = {}
    for i in range(nindex):
        tag, typ, off, count = struct.unpack(">IIII", index[16 * i : 16 * i + 16])
        if typ in (3, 4, 5):  # int16, int32, int64
            size = {3: 2, 4: 4, 5: 8}[typ]
            fmt = {3: ">h", 4: ">i", 5: ">q"}[typ]
            vals = [
                struct.unpack(fmt, data[off + k * size : off + (k + 1) * size])[0]
                for k in range(count)
            ]
            out[tag] = vals if count > 1 else vals[0]
        elif typ == 6:  # one string
            out[tag] = data[off : data.index(b"\0", off)].decode("utf-8", "replace")
        elif typ in (8, 9):  # string array, i18n string array
            vals, p = [], off
            for _ in range(count):
                e = data.index(b"\0", p)
                vals.append(data[p:e].decode("utf-8", "replace"))
                p = e + 1
            out[tag] = vals
        elif typ in {7, 1}:  # binary
            out[tag] = data[off : off + count]
    return out


class Sections(NamedTuple):
    """An rpm file's parts as its signatures cover them (DESIGN.md 10)."""

    signature: Header  # the signature header: the header's signatures and digests
    header: Header
    header_bytes: bytes  # the header section whole, from its magic, which a header signature covers
    payload: int  # where the payload begins


def sections(path: str) -> Sections:
    """Read an rpm file's signature header and header.

    Raises:
        RpmError: When the file is not an rpm or a header is truncated or corrupt.
    """
    with open(path, "rb") as f:
        lead = f.read(LEAD)
        if len(lead) < LEAD or lead[:4] != b"\xed\xab\xee\xdb":
            msg = f"{path}: not an rpm"
            raise RpmError(msg)
        try:
            sig = _header(f)  # the signature header, then padding to 8 bytes
            f.seek((f.tell() + 7) & ~7)
            start = f.tell()
            h = _header(f)
            payload = f.tell()
            f.seek(start)
            header_bytes = f.read(payload - start)
        except (struct.error, ValueError, IndexError) as e:
            msg = f"{path}: corrupt header: {e}"
            raise RpmError(msg) from e
    return Sections(sig, h, header_bytes, payload)


def _sections(path: str) -> tuple[Header, int, str]:
    """Return an rpm file's header, the offset of its payload, and the payload's compressor."""
    s = sections(path)
    return s.header, s.payload, s.header.get(RPMTAG["PAYLOADCOMPRESSOR"], "gzip")


# each payload compressor's stream
_STREAMS: dict[str, Callable[[BinaryIO], Readable]] = {
    "gzip": lambda f: gzip.GzipFile(fileobj=f),
    "xz": lzma.LZMAFile,
    "lzma": lzma.LZMAFile,
    "bzip2": bz2.BZ2File,
    "zstd": zstd.ZstdFile,
}


@dataclass(slots=True)
class _Member:
    """A payload entry with the parts of tarfile.TarInfo that the reader interface names."""

    name: str
    mode: int  # the permission bits alone
    mtime: int
    kind: str  # "dir", "sym", "lnk", "file" or "special"
    linkname: str = ""
    size: int = 0

    def isdir(self) -> bool:
        return self.kind == "dir"

    def issym(self) -> bool:
        return self.kind == "sym"

    def islnk(self) -> bool:
        return self.kind == "lnk"

    def isfile(self) -> bool:
        return self.kind == "file"


class _Contents(io.RawIOBase):
    """The current entry's data in the payload's stream, which must hold all of it."""

    def __init__(self, window: Window, size: int, name: str) -> None:
        super().__init__()
        self.window, self.left, self.name = window, size, name

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:  # noqa: ANN401 -- io's own buffer type
        if not self.left:
            return 0
        data = self.window.read(min(len(b), self.left))
        if not data:
            msg = f"cpio entry {self.name!r} runs past the end of the payload"
            raise RpmError(msg)
        b[: len(data)] = data
        self.left -= len(data)
        return len(data)


class _Payload:
    """The payload's cpio archive, its entries handed out as they decompress, in its order.

    The archive ends at its trailer, which must be there, every entry whole before it and nothing
    but NUL padding after it (10.1). cpio records a hard link as several entries of one inode, the
    content on the last of them; the entry with the content is handed out as the file, and the
    others, held back until it comes, as links to it, as tar would have them.
    """

    def __init__(self, path: str) -> None:
        _h, payload, comp = _sections(path)
        if comp not in _STREAMS:
            msg = f"{path}: unknown payload compressor {comp!r}"
            raise RpmError(msg)
        f = io.BufferedReader(io.FileIO(path))
        f.seek(payload)
        label = f"{path}: corrupt {comp} payload"
        self.window = Window(_STREAMS[comp](f), label)
        self.label = label
        self.current: _Contents | None = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.window.close()

    def _exact(self, n: int, what: str) -> bytes:
        data = self.window.read(n)
        if len(data) < n:
            msg = f"{self.label}: {what}"
            raise RpmError(msg)
        return data

    def __iter__(self) -> Iterator[_Member]:
        held: dict[tuple[int, int, int], list[_Member]] = {}  # links waiting for their content
        files: dict[tuple[int, int, int], _Member] = {}  # the entry each inode's links name
        w = self.window
        while True:
            start = w.tell()
            header = self._exact(110, "the cpio payload has no trailer: it is cut short")
            if header[:6] not in (b"070701", b"070702"):
                msg = f"{self.label}: bad cpio header at {start}"
                raise RpmError(msg)
            try:
                fields = [int(header[6 + 8 * k : 14 + 8 * k], 16) for k in range(13)]
            except ValueError as e:
                msg = f"{self.label}: bad cpio header at {start}"
                raise RpmError(msg) from e
            ino, mode, _uid, _gid, nlink, mtime, size, devmaj, devmin, _rmaj, _rmin, nsize, _c = (
                fields
            )
            raw = self._exact(nsize, "the cpio payload ends inside a name")
            name = raw[: nsize - 1].decode("utf-8", "surrogateescape")
            self._exact(-w.tell() % 4, "the cpio payload ends inside a name")
            data_at = w.tell()
            if name == "TRAILER!!!":
                self._exact(size, f"cpio entry {name!r} runs past the end of the payload")
                for group in held.values():  # hard links whose inode carried no content: empty
                    first, *rest = group
                    first.kind = "file"
                    self.current = _Contents(w, 0, first.name)
                    yield first
                    yield from (_Member(m.name, m.mode, m.mtime, "lnk", first.name) for m in rest)
                self.current = None
                if why := w.after_end(w.tell()):
                    msg = f"{self.label}: {why}"
                    raise RpmError(msg)
                return
            name = name.removeprefix("./")
            perm, fmt, inode = mode & 0o7777, mode & 0o170000, (devmaj, devmin, ino)
            if fmt == 0o040000:
                yield _Member(name, perm, mtime, "dir")
            elif fmt == 0o120000:
                link = self._exact(size, f"cpio entry {name!r} runs past the end of the payload")
                yield _Member(name, perm, mtime, "sym", link.decode("utf-8", "surrogateescape"))
            elif fmt == 0o100000 and nlink > 1 and inode in files:
                yield _Member(name, perm, mtime, "lnk", files[inode].name)
            elif fmt == 0o100000 and nlink > 1 and not size:
                held.setdefault(inode, []).append(_Member(name, perm, mtime, "held"))
            elif fmt == 0o100000:
                m = _Member(name, perm, mtime, "file", size=size)
                self.current = _Contents(w, size, name)
                yield m
                if nlink > 1:
                    files[inode] = m
                    for h in held.pop(inode, []):
                        yield _Member(h.name, h.mode, h.mtime, "lnk", name)
            else:
                yield _Member(name, perm, mtime, "special")
            # past what the caller left unread of the data, and its padding to four bytes
            end = data_at + size
            if w.tell() > end:
                msg = f"{self.label}: cpio entry {name!r} is shorter than its data"
                raise RpmError(msg)
            self._exact(end - w.tell(), f"cpio entry {name!r} runs past the end of the payload")
            self._exact(-end % 4, f"cpio entry {name!r} runs past the end of the payload")
            self.current = None

    def extractfile(self, m: _Member) -> IO[bytes]:
        assert self.current is not None  # the current member's contents, only
        assert m.kind == "file"
        return io.BufferedReader(self.current)


def open_data(path: str) -> _Payload:
    """Return the package's payload, the files it installs."""
    return _Payload(path)


def _deps(h: Header, names: int, versions: int, flags: int) -> list[str]:
    """Spell the header's dependencies of one kind as parse_deps reads them, rpm's own skipped."""
    out: list[str] = []
    ns, vs, fs = h.get(names, []), h.get(versions, []), h.get(flags, [])
    # a count of one is a scalar
    ns, vs, fs = (
        ([ns] if isinstance(ns, str) else ns),
        ([vs] if isinstance(vs, str) else vs),
        ([fs] if isinstance(fs, int) else fs),
    )
    for i, n in enumerate(ns):
        v = vs[i] if i < len(vs) else ""
        fl = fs[i] if i < len(fs) else 0
        # rpm's own features; rich dependencies
        if fl & SENSE_RPMLIB or n.startswith(("rpmlib(", "(")):
            continue
        op = "".join(s for bit, s in sorted(SENSE.items()) if fl & bit) if v else ""
        out.append(n + op + v if v else n)
    return out


def control(path: str) -> tuple[dict[str, str], dict[str, str]]:
    """Return the package's control fields and its install scripts by name.

    The header's tags are given Debian's field names: NAME is Package, REQUIRENAME is Depends, and
    so on; noarch is spelt all, and the version is epoch:version-release.
    """
    h, _, _ = _sections(path)
    fields = {
        "Package": h.get(RPMTAG["NAME"], ""),
        "Version": f"{h.get(RPMTAG['VERSION'], '')}-{h.get(RPMTAG['RELEASE'], '')}",
        "Architecture": h.get(RPMTAG["ARCH"], ""),
    }
    if fields["Architecture"] == "noarch":
        fields["Architecture"] = "all"
    if RPMTAG["EPOCH"] in h:
        fields["Version"] = f"{h[RPMTAG['EPOCH']]}:{fields['Version']}"
    if not fields["Package"]:
        msg = f"{path}: no NAME in its header"
        raise RpmError(msg)
    fields["Depends"] = " ".join(
        _deps(h, RPMTAG["REQUIRENAME"], RPMTAG["REQUIREVERSION"], RPMTAG["REQUIREFLAGS"])
    )
    fields["Provides"] = " ".join(
        _deps(h, RPMTAG["PROVIDENAME"], RPMTAG["PROVIDEVERSION"], RPMTAG["PROVIDEFLAGS"])
    )
    fields["Replaces"] = " ".join(
        _deps(h, RPMTAG["OBSOLETENAME"], RPMTAG["OBSOLETEVERSION"], RPMTAG["OBSOLETEFLAGS"])
    )
    scripts: dict[str, str] = {}
    for key, tag in (
        ("postinst", RPMTAG["POSTIN"]),
        ("preinst", RPMTAG["PREIN"]),
        ("posttrans", RPMTAG["POSTTRANS"]),
    ):
        if h.get(tag):
            scripts[key] = h[tag] if isinstance(h[tag], str) else "\n".join(h[tag])
    return fields, scripts


def interests(path: str) -> list[str]:  # noqa: ARG001 -- the interface's argument; nothing to read
    """None: rpm's file triggers are in other packages' headers, which this reader does not read."""
    return []


_TOKEN = re.compile(r"^([^\s<>=]+)(?:(<=|>=|<|>|=)([^\s<>=]+))?$")


def parse_deps(field: str | None) -> list[list[Dep]]:
    """Parse a dependency field, as control spells it, into groups of one alternative each.

    For example, `glibc>=2.17 libc.so.6(GLIBC_2.2.5)(64bit) /bin/sh` gives `[[("glibc", ">=",
    "2.17")], [("libc.so.6(GLIBC_2.2.5)(64bit)", None, None)], [("/bin/sh", None, None)]]`. A file
    item names a file some package must ship.

    Raises:
        RpmError: For an item that is not a dependency.
    """
    out: list[list[Dep]] = []
    for tok in (field or "").split():
        m = _TOKEN.match(tok)
        if not m:
            msg = f"cannot parse dependency {tok!r}"
            raise RpmError(msg)
        out.append([(m.group(1), m.group(2), m.group(3))])
    return out


# -------------------------------------------------------------- versions, as rpmvercmp orders them
def _rpmvercmp(a: str, b: str) -> int:
    """Compare two version or release strings as rpmvercmp does.

    The strings are compared segment by segment, alphabetic and numeric segments alternating. A
    numeric segment sorts after an alphabetic one, and `~` before anything.
    """
    if a == b:
        return 0
    ta, tb = re.findall(r"[0-9]+|[a-zA-Z]+|~|\^", a), re.findall(r"[0-9]+|[a-zA-Z]+|~|\^", b)
    for x, y in zip(ta, tb, strict=False):
        if x == "~" or y == "~":
            if x != y:
                return -1 if x == "~" else 1
            continue
        if x == "^" or y == "^":
            if x != y:
                return -1 if x == "^" else 1
            continue
        if x.isdigit() and y.isdigit():
            c = (int(x) > int(y)) - (int(x) < int(y))
        elif x.isdigit() or y.isdigit():
            return 1 if x.isdigit() else -1
        else:
            c = (x > y) - (x < y)
        if c:
            return c
    if len(ta) != len(tb):
        rest = ta[len(tb) :] if len(ta) > len(tb) else tb[len(ta) :]
        if rest[0] == "~":
            return -1 if len(ta) > len(tb) else 1
        return 1 if len(ta) > len(tb) else -1
    return 0


def _evr(v: str) -> tuple[int, str, str]:
    """Split a version into epoch, version and release."""
    epoch, _, rest = v.partition(":") if ":" in v else ("0", "", v)
    ver, _, rel = rest.partition("-")
    return int(epoch) if epoch.isdigit() else 0, ver, rel


def vercmp(a: str, b: str) -> int:
    """Return -1, 0 or 1 as a sorts before, with or after b, in rpm's order."""
    ea, va, ra = _evr(a)
    eb, vb, rb = _evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _rpmvercmp(va, vb)
    if c or not ra or not rb:  # a constraint without a release matches any release
        return c
    return _rpmvercmp(ra, rb)


def satisfies(version: str, op: str | None, want: str | None) -> bool:
    """Return whether version meets the constraint `op want`; no operator is always met."""
    if op is None:
        return True
    assert want is not None  # an operator always comes with its version
    c = vercmp(version, want)
    return {"=": c == 0, "<": c < 0, ">": c > 0, "<=": c <= 0, ">=": c >= 0}.get(op, True)
