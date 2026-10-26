"""apk.py — reading Alpine packages (DESIGN.md 10.1): the second reader of `unpack`, chosen by the file.

An .apk is three gzip members back to back, each a tar stream: the signature, the control files
(.PKGINFO and the install scripts, dot-files at the top), and the data. Python's gzip reads the members
as one stream and tarfile reads the headers as one archive, since the first two streams carry no end-of-
archive blocks. The interface is deb.py's, so build.py serves every reader: control(path) -> (fields, scripts)
with Debian's field names, open_tar(path, "data.tar") -> the data members, parse_deps, satisfies.

What unpack does differently for an Alpine set, here and in build.py:

- `depend` and `provides` name packages, shared objects (`so:libc.musl-x86_64.so.1`), commands
  (`cmd:gcc`) and pkg-config modules (`pc:zlib`). Versions are ordered as apk-tools orders them, `_rc`
  before the release and `-r` revisions after. A file dependency, such as `/bin/sh`, names something
  some package must ship; the dependency report asks the extracted tree whether one does.
- Alpine's /bin, /sbin and /lib are directories of their own, so the merged-/usr links are not made.
- One synthesis rule: busybox's post-install makes its applet links with `busybox --install`; build.py
  makes them from the paths the package ships in /etc/busybox-paths.d, each a relative link to
  /bin/busybox, so that tree/bin/sh run from outside the exclave reaches the wrapper in the tree
  (DESIGN.md 13 item 37).
- musl has no ld.so.cache, and the static check asks for none.
- Licence texts come only with a package's `-doc` package (DESIGN.md 10.4).
"""

import io
import re
import tarfile


class ApkError(Exception):
    pass


MERGED_USR = False  # Alpine's /bin, /sbin and /lib are directories of their own
SCRIPTS = (
    ".pre-install",
    ".post-install",
    ".pre-upgrade",
    ".post-upgrade",
    ".pre-deinstall",
    ".post-deinstall",
    ".trigger",
)


def _norm(name):
    """A member name without its leading ./ or /: the control files are then the ones that start with a dot."""
    while name.startswith("./"):
        name = name[2:]
    return name.lstrip("/")


class _Members:
    """The data members of an .apk as a tarfile would present them: the top-level dot-files are control."""

    def __init__(self, tar):
        self.tar = tar

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.tar.close()

    def getmembers(self):
        return [m for m in self.tar.getmembers() if not _norm(m.name).startswith(".")]

    def extractfile(self, m):
        return self.tar.extractfile(m)


def _open(path):
    try:
        return tarfile.open(path, mode="r:gz")
    except (tarfile.TarError, OSError, EOFError) as e:
        raise ApkError("%s: not an apk: %s" % (path, e))


def open_tar(path, member):
    """The data members; `member` is accepted for deb.py's signature and ignored."""
    return _Members(_open(path))


def control(path):
    """(fields, scripts): .PKGINFO as Debian-style fields, the install scripts by their apk names."""
    fields, scripts, raw = {}, {}, {}
    with _open(path) as t:
        for m in t.getmembers():
            n = _norm(m.name)
            if not n.startswith(".") or not m.isfile():
                continue
            data = t.extractfile(m).read()
            if n == ".PKGINFO":
                for line in data.decode("utf-8", "replace").split("\n"):
                    if not line or line.startswith("#") or " = " not in line:
                        continue
                    k, _, v = line.partition(" = ")
                    raw.setdefault(k.strip(), []).append(v.strip())
            elif n in SCRIPTS:
                scripts[n] = data.decode("utf-8", "replace")
    if "pkgname" not in raw or "pkgver" not in raw:
        raise ApkError("%s: no pkgname or pkgver in .PKGINFO" % path)
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
    fields["_format"] = "apk"
    return fields, scripts


_TOKEN = re.compile(
    r"^(!?)([^\s<>=~!][^\s<>=~]*?)(?:(<=|>=|><|<|>|=|~)(.+))?$"
)  # a name is anything up to an operator: cmd:[ and so:libstdc++.so.6 are names


def parse_deps(field):
    """'so:libc.musl-x86_64.so.1 zlib>=1.2 !conflict /bin/sh' -> [[(name, op, version)]]: one alternative each,
    since apk has none; a '!' item is a conflict and is not a dependency; a path item, /bin/sh, names a file
    some package must ship, which the fetcher skips and the report asks of the extracted tree."""
    out = []
    for tok in (field or "").split():
        m = _TOKEN.match(tok)
        if not m:
            raise ApkError("cannot parse dependency %r" % tok)
        if m.group(1):
            continue
        out.append([(m.group(2), m.group(3), m.group(4))])
    return out


# ---------------------------------------------------------------- versions, as apk-tools orders them
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


def _key(v):
    m = _VER.match(v)
    if not m:
        return ([0], "", [], 0, v)  # a version apk would not accept: compared as 0
    nums = [int(x) for x in m.group(1).split(".")]
    sufs = [
        (_SUFFIX[s.rstrip("0123456789")], int(s[len(s.rstrip("0123456789")) :] or 0))
        for s in m.group(3).split("_")
        if s
    ]
    return (nums, m.group(2) or "", sufs, int(m.group(4) or 0), "")


def vercmp(a, b):
    ka, kb = _key(a), _key(b)
    for x, y in zip(ka[0], kb[0]):
        if x != y:
            return -1 if x < y else 1
    if len(ka[0]) != len(kb[0]):
        return -1 if len(ka[0]) < len(kb[0]) else 1
    if ka[1] != kb[1]:
        return -1 if ka[1] < kb[1] else 1
    sa, sb = ka[2] or [(0, 0)], kb[2] or [(0, 0)]
    for x, y in zip(sa, sb):
        if x != y:
            return -1 if x < y else 1
    if len(sa) != len(sb):
        return -1 if len(sa) < len(sb) else 1
    if ka[3] != kb[3]:
        return -1 if ka[3] < kb[3] else 1
    return 0


def satisfies(version, op, want):
    if op is None:
        return True
    if op == "~":
        return version == want or version.startswith(want + ".") or version.startswith(want + "-")
    c = vercmp(version, want)
    return {"=": c == 0, "<": c < 0, ">": c > 0, "<=": c <= 0, ">=": c >= 0, "><": True}.get(
        op, True
    )
