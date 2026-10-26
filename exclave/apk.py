"""The Alpine package reader (DESIGN.md 10.1).

An .apk is three gzip members back to back, each a tar stream: the signature, the control files
(.PKGINFO and the install scripts, dot-files at the top level), and the data. Decompressed as one
stream they read as one tar archive, since the first two streams carry no end-of-archive blocks.

Alpine's formats differ from Debian's in ways the rest of the tool sees through this reader:

- `depend` and `provides` name packages, shared objects (`so:libc.musl-x86_64.so.1`), commands
  (`cmd:gcc`) and pkg-config modules (`pc:zlib`). There are no alternatives. A file dependency,
  such as `/bin/sh`, names something some package must ship.
- Versions are ordered as apk-tools orders them: `_rc` before the release, `-r` revisions after.
- Alpine's /bin, /sbin and /lib are directories of their own, not links into /usr.
- busybox's post-install makes its applet links with `busybox --install`. The tool makes them
  instead from the paths busybox lists in /etc/busybox-paths.d, each a relative link to
  /bin/busybox, so that tree/bin/sh run from outside the exclave reaches the wrapper in the tree
  (DESIGN.md 13 item 37).
- musl's loader reads no ld.so.cache, so the static check asks for none.
- A package's licence text comes only in its `-doc` package.
"""

import gzip
import io
import re
import tarfile
import zlib
from typing import IO, Self

from exclave.reader import Dep, PackageError


class ApkError(PackageError):
    """An .apk, or a field in one, that cannot be read."""


MERGED_USR: bool = False
SCRIPTS = (
    ".pre-install",
    ".post-install",
    ".pre-upgrade",
    ".post-upgrade",
    ".pre-deinstall",
    ".post-deinstall",
    ".trigger",
)


def _norm(name: str) -> str:
    """Return a member name without its leading ./ or /, so control files start with a dot."""
    while name.startswith("./"):
        name = name[2:]
    return name.lstrip("/")


class _Members:
    """The data members of an .apk, the archive without its top-level control dot-files."""

    def __init__(self, tar: tarfile.TarFile) -> None:
        self.tar = tar

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.tar.close()

    def getmembers(self) -> list[tarfile.TarInfo]:
        return [m for m in self.tar.getmembers() if not _norm(m.name).startswith(".")]

    def extractfile(self, m: tarfile.TarInfo) -> IO[bytes] | None:
        return self.tar.extractfile(m)


def _open(path: str) -> tarfile.TarFile:
    """Open the .apk as one tar archive held in memory, every header read.

    Raises:
        ApkError: When the file is not gzip or the archive inside is corrupt.
    """
    try:
        with open(path, "rb") as f:
            data = gzip.decompress(f.read())
        t = tarfile.open(fileobj=io.BytesIO(data), mode="r:")  # noqa: SIM115 -- returned open
        t.getmembers()
    except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
        msg = f"{path}: not an apk: {e}"
        raise ApkError(msg) from e
    return t


def open_data(path: str) -> _Members:
    """Return the package's payload, the files it installs."""
    return _Members(_open(path))


def control(path: str) -> tuple[dict[str, str], dict[str, str]]:
    """Return the package's control fields and its install scripts by name.

    .PKGINFO's keys are given Debian's field names: pkgname is Package, depend is Depends, and so
    on; noarch is spelt all.
    """
    fields: dict[str, str] = {}
    scripts: dict[str, str] = {}
    raw: dict[str, list[str]] = {}
    with _open(path) as t:
        for m in t.getmembers():
            n = _norm(m.name)
            if not n.startswith(".") or not m.isfile():
                continue
            f = t.extractfile(m)
            assert f is not None  # a regular file always has its content
            data = f.read()
            if n == ".PKGINFO":
                for line in data.decode("utf-8", "replace").split("\n"):
                    if not line or line.startswith("#") or " = " not in line:
                        continue
                    k, _, v = line.partition(" = ")
                    raw.setdefault(k.strip(), []).append(v.strip())
            elif n in SCRIPTS:
                scripts[n] = data.decode("utf-8", "replace")
    if "pkgname" not in raw or "pkgver" not in raw:
        msg = f"{path}: no pkgname or pkgver in .PKGINFO"
        raise ApkError(msg)
    fields["Package"] = raw["pkgname"][0]
    fields["Version"] = raw["pkgver"][0]
    fields["Architecture"] = raw.get("arch", ["noarch"])[0]
    if fields["Architecture"] == "noarch":
        fields["Architecture"] = "all"
    for src, dst in (
        ("depend", "Depends"),
        ("provides", "Provides"),
        ("replaces", "Replaces"),
        ("install_if", "Install-If"),
    ):
        if src in raw:
            fields[dst] = " ".join(raw[src])
    return fields, scripts


# a name is anything up to an operator: cmd:[ and so:libstdc++.so.6 are names
_TOKEN = re.compile(r"^(!?)([^\s<>=~!][^\s<>=~]*?)(?:(<=|>=|><|<|>|=|~)(.+))?$")


def parse_deps(field: str | None) -> list[list[Dep]]:
    """Parse a depend or provides field into groups of one alternative each.

    For example, `so:libc.musl-x86_64.so.1 zlib>=1.2 !conflict /bin/sh` gives
    `[[("so:libc.musl-x86_64.so.1", None, None)], [("zlib", ">=", "1.2")], [("/bin/sh", None,
    None)]]`: a `!` item is a conflict, not a dependency, and is dropped.

    Raises:
        ApkError: For an item that is not a dependency.
    """
    out: list[list[Dep]] = []
    for tok in (field or "").split():
        m = _TOKEN.match(tok)
        if not m:
            msg = f"cannot parse dependency {tok!r}"
            raise ApkError(msg)
        if m.group(1):
            continue
        out.append([(m.group(2), m.group(3), m.group(4))])
    return out


# ------------------------------------------------------------ versions, as apk-tools orders them
_SUFFIX = {
    "alpha": -4,
    "beta": -3,
    "pre": -2,
    "rc": -1,
    "cvs": 1,
    "svn": 2,
    "git": 3,
    "hg": 4,
    "p": 5,
}
_VER = re.compile(
    r"^(\d+(?:\.\d+)*)([a-z])?((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:-r(\d+))?$"
)


def _key(v: str) -> tuple[list[int], str, list[tuple[int, int]], int]:
    """Split a version into numbers, letter, suffixes and revision, the parts apk-tools compares."""
    m = _VER.match(v)
    if not m:
        return ([0], "", [], 0)  # a version apk would not accept: compared as 0
    nums = [int(x) for x in m.group(1).split(".")]
    sufs = [
        (_SUFFIX[s.rstrip("0123456789")], int(s[len(s.rstrip("0123456789")) :] or 0))
        for s in m.group(3).split("_")
        if s
    ]
    return (nums, m.group(2) or "", sufs, int(m.group(4) or 0))


def vercmp(a: str, b: str) -> int:
    """Return -1, 0 or 1 as a sorts before, with or after b, in apk-tools' order."""
    ka, kb = _key(a), _key(b)
    for x, y in zip(ka[0], kb[0], strict=False):
        if x != y:
            return -1 if x < y else 1
    if len(ka[0]) != len(kb[0]):
        return -1 if len(ka[0]) < len(kb[0]) else 1
    if ka[1] != kb[1]:
        return -1 if ka[1] < kb[1] else 1
    sa, sb = ka[2] or [(0, 0)], kb[2] or [(0, 0)]
    for x, y in zip(sa, sb, strict=False):
        if x != y:
            return -1 if x < y else 1
    if len(sa) != len(sb):
        return -1 if len(sa) < len(sb) else 1
    if ka[3] != kb[3]:
        return -1 if ka[3] < kb[3] else 1
    return 0


def satisfies(version: str, op: str | None, want: str | None) -> bool:
    """Return whether version meets the constraint `op want`; no operator is always met.

    `~` is a fuzzy match: the version is want, or starts with want and a separator.
    """
    if op is None:
        return True
    assert want is not None  # an operator always comes with its version
    if op == "~":
        return version == want or version.startswith((want + ".", want + "-"))
    c = vercmp(version, want)
    return {"=": c == 0, "<": c < 0, ">": c > 0, "<=": c <= 0, ">=": c >= 0, "><": True}.get(
        op, True
    )
