"""rpm.py — reading RPM packages (PROPOSAL.md 10.1): the third reader of `unpack`, chosen by the file.

An .rpm is a 96-byte lead, a signature header, a header and a compressed cpio payload. The header is an
index of tagged entries; the reader takes the names, versions, architecture, dependencies and the
install scripts from it, and the payload's compressor. The payload is cpio in the "newc" form (or "crc"),
gzip, xz or zstd, and is read in Python, zstd through the tool the cannery can ships. The interface is
deb.py's, so build.py serves every reader: control(path) -> (fields, scripts) with Debian's field names,
open_tar(path, "data.tar") -> the payload members with tarfile's shape, parse_deps, satisfies.
"""
import bz2
import gzip
import io
import lzma
import re
import shutil
import struct
import subprocess
import tarfile


class RpmError(Exception):
    pass


MERGED_USR = True           # Fedora, RHEL 7 and later: the filesystem package ships /bin -> usr/bin and /lib64 -> usr/lib64 as links, which the merged-usr links match
LEAD = 96
HEADER_MAGIC = b"\x8e\xad\xe8\x01"
# the tags the reader uses (rpm's rpmtag.h)
T = {"NAME": 1000, "VERSION": 1001, "RELEASE": 1002, "EPOCH": 1003, "ARCH": 1022, "POSTIN": 1024, "PREIN": 1023, "POSTTRANS": 1152,
     "REQUIREFLAGS": 1048, "REQUIRENAME": 1049, "REQUIREVERSION": 1050,
     "PROVIDEFLAGS": 1112, "PROVIDENAME": 1047, "PROVIDEVERSION": 1113, "OBSOLETENAME": 1090, "OBSOLETEVERSION": 1115, "OBSOLETEFLAGS": 1114,
     "PAYLOADCOMPRESSOR": 1125}
SENSE = {2: "<", 4: ">", 8: "="}     # RPMSENSE_LESS, GREATER, EQUAL bits
SENSE_RPMLIB = 1 << 24


def _header(f):
    """One header section: {tag: value} where a value is bytes, int, str or a list of them."""
    magic = f.read(8)
    if magic[:4] != HEADER_MAGIC:
        raise RpmError("bad header magic")
    nindex, hsize = struct.unpack(">II", f.read(8))
    index = f.read(16 * nindex)
    data = f.read(hsize)
    out = {}
    for i in range(nindex):
        tag, typ, off, count = struct.unpack(">IIII", index[16 * i:16 * i + 16])
        if typ in (3, 4, 5):                                   # int16, int32, int64
            size = {3: 2, 4: 4, 5: 8}[typ]
            fmt = {3: ">h", 4: ">i", 5: ">q"}[typ]
            vals = [struct.unpack(fmt, data[off + k * size:off + (k + 1) * size])[0] for k in range(count)]
            out[tag] = vals if count > 1 else vals[0]
        elif typ == 6:                                         # one string
            out[tag] = data[off:data.index(b"\0", off)].decode("utf-8", "replace")
        elif typ in (8, 9):                                    # string array, i18n string array
            vals, p = [], off
            for _ in range(count):
                e = data.index(b"\0", p)
                vals.append(data[p:e].decode("utf-8", "replace"))
                p = e + 1
            out[tag] = vals
        elif typ == 7:                                         # binary
            out[tag] = data[off:off + count]
        elif typ == 1:                                         # char
            out[tag] = data[off:off + count]
    return out


def _sections(path):
    """(header dict, payload offset, compressor) of an rpm file."""
    with open(path, "rb") as f:
        lead = f.read(LEAD)
        if len(lead) < LEAD or lead[:4] != b"\xed\xab\xee\xdb":
            raise RpmError("%s: not an rpm" % path)
        _header(f)                                             # the signature header, then padding to 8 bytes
        pos = f.tell()
        f.seek((pos + 7) & ~7)
        h = _header(f)
        payload = f.tell()
    comp = h.get(T["PAYLOADCOMPRESSOR"], "gzip")
    return h, payload, comp


def _decompress(comp, data):
    if comp == "gzip":
        return gzip.decompress(data)
    if comp in ("xz", "lzma"):
        return lzma.decompress(data)
    if comp == "bzip2":
        return bz2.decompress(data)
    if comp == "zstd":
        tool = shutil.which("zstd")
        if not tool:
            raise RpmError("zstd tool not found; needed for a zstd payload")
        p = subprocess.run([tool, "-d", "-q", "--stdout"], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode:
            raise RpmError("zstd failed: " + p.stderr.decode(errors="replace"))
        return p.stdout
    raise RpmError("unknown payload compressor %r" % comp)


def _cpio_members(data):
    """The entries of a newc or crc cpio archive as (name, mode, mtime, content, nlink, (devmaj, devmin, ino))."""
    out, p = [], 0
    while p + 110 <= len(data):
        magic = data[p:p + 6]
        if magic not in (b"070701", b"070702"):
            raise RpmError("bad cpio header at %d" % p)
        fields = [int(data[p + 6 + 8 * k:p + 14 + 8 * k], 16) for k in range(13)]
        ino, mode, uid, gid, nlink, mtime, size, devmaj, devmin, rdevmaj, rdevmin, namesize, _chk = fields
        name = data[p + 110:p + 110 + namesize - 1].decode("utf-8", "surrogateescape")
        start = (p + 110 + namesize + 3) & ~3
        if name == "TRAILER!!!":
            break
        content = data[start:start + size]
        out.append((name, mode, mtime, content, nlink, (devmaj, devmin, ino)))
        p = (start + size + 3) & ~3
    return out


class _Member:
    """The part of tarfile.TarInfo that build.extract reads."""

    def __init__(self, name, mode, mtime, kind, linkname, content):
        self.name, self.mode, self.mtime, self.kind, self.linkname, self.content = name, mode & 0o7777, mtime, kind, linkname, content

    def isdir(self):
        return self.kind == "dir"

    def issym(self):
        return self.kind == "sym"

    def islnk(self):
        return self.kind == "lnk"

    def isfile(self):
        return self.kind == "file"


class _Payload:
    def __init__(self, members):
        self.members = members

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def getmembers(self):
        return self.members

    def extractfile(self, m):
        return io.BytesIO(m.content)


def open_tar(path, member):
    """The payload's members. Hard links in cpio are entries of one inode with the content on the last of
    them; the reader gives the content to the first and makes the rest links to it, as tar would."""
    h, payload, comp = _sections(path)
    with open(path, "rb") as f:
        f.seek(payload)
        data = _decompress(comp, f.read())
    raw = _cpio_members(data)
    first = {}
    members = []
    for name, mode, mtime, content, nlink, ident in raw:
        name = name[2:] if name.startswith("./") else name
        fmt = mode & 0o170000
        if fmt == 0o040000:
            members.append(_Member(name, mode, mtime, "dir", "", b""))
        elif fmt == 0o120000:
            members.append(_Member(name, mode, mtime, "sym", content.decode("utf-8", "surrogateescape"), b""))
        elif fmt == 0o100000:
            if nlink > 1 and ident in first:
                members.append(_Member(name, mode, mtime, "lnk", first[ident].name, b""))
                if content and not first[ident].content:
                    first[ident].content = content             # the content travels with the last link
            else:
                m = _Member(name, mode, mtime, "file", "", content)
                if nlink > 1:
                    first[ident] = m
                members.append(m)
        else:
            members.append(_Member(name, mode, mtime, "special", "", b""))
    return _Payload(members)


def _deps(h, names, versions, flags):
    out = []
    ns, vs, fs = h.get(names, []), h.get(versions, []), h.get(flags, [])
    ns, vs, fs = ([ns] if isinstance(ns, str) else ns), ([vs] if isinstance(vs, str) else vs), ([fs] if isinstance(fs, int) else fs)   # a count of one is a scalar
    for i, n in enumerate(ns):
        v = vs[i] if i < len(vs) else ""
        fl = fs[i] if i < len(fs) else 0
        if fl & SENSE_RPMLIB or n.startswith("rpmlib(") or n.startswith("("):   # rpm's own features; rich dependencies
            continue
        op = "".join(s for bit, s in sorted(SENSE.items()) if fl & bit) if v else ""
        out.append(n + op + v if v else n)
    return out


def control(path):
    """(fields, scripts): the header as Debian-style fields; the install scripts by rpm's names."""
    h, _, _ = _sections(path)
    fields = {"Package": h.get(T["NAME"], ""), "Version": "%s-%s" % (h.get(T["VERSION"], ""), h.get(T["RELEASE"], "")),
              "Architecture": h.get(T["ARCH"], ""), "_format": "rpm"}
    if fields["Architecture"] == "noarch":
        fields["Architecture"] = "all"
    if T["EPOCH"] in h:
        fields["Version"] = "%s:%s" % (h[T["EPOCH"]], fields["Version"])
    if not fields["Package"]:
        raise RpmError("%s: no NAME in its header" % path)
    fields["Depends"] = " ".join(_deps(h, T["REQUIRENAME"], T["REQUIREVERSION"], T["REQUIREFLAGS"]))
    fields["Provides"] = " ".join(_deps(h, T["PROVIDENAME"], T["PROVIDEVERSION"], T["PROVIDEFLAGS"]))
    fields["Replaces"] = " ".join(_deps(h, T["OBSOLETENAME"], T["OBSOLETEVERSION"], T["OBSOLETEFLAGS"]))
    scripts = {}
    for key, tag in (("postinst", T["POSTIN"]), ("preinst", T["PREIN"]), ("posttrans", T["POSTTRANS"])):
        if tag in h and h[tag]:
            scripts[key] = h[tag] if isinstance(h[tag], str) else "\n".join(h[tag])
    return fields, scripts


_TOKEN = re.compile(r"^([^\s<>=]+)(?:(<=|>=|<|>|=)([^\s<>=]+))?$")


def parse_deps(field):
    """'glibc>=2.17 libc.so.6(GLIBC_2.2.5)(64bit) /bin/sh' -> [[(name, op, version)]]: one alternative each. A
    version is 'epoch:version-release' as rpm spells it; a file item names a file some package must ship."""
    out = []
    for tok in (field or "").split():
        m = _TOKEN.match(tok)
        if not m:
            raise RpmError("cannot parse dependency %r" % tok)
        out.append([(m.group(1), m.group(2), m.group(3))])
    return out


# ---------------------------------------------------------------- versions, as rpmvercmp orders them
def _rpmvercmp(a, b):
    """rpmvercmp: alternating alpha and numeric segments, numeric beats alpha, '~' sorts before anything."""
    if a == b:
        return 0
    ta, tb = re.findall(r"[0-9]+|[a-zA-Z]+|~|\^", a), re.findall(r"[0-9]+|[a-zA-Z]+|~|\^", b)
    for x, y in zip(ta, tb):
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
        rest = ta[len(tb):] if len(ta) > len(tb) else tb[len(ta):]
        if rest[0] == "~":
            return -1 if len(ta) > len(tb) else 1
        return 1 if len(ta) > len(tb) else -1
    return 0


def _evr(v):
    epoch, _, rest = v.partition(":") if ":" in v else ("0", "", v)
    ver, _, rel = rest.partition("-")
    return int(epoch) if epoch.isdigit() else 0, ver, rel


def vercmp(a, b):
    ea, va, ra = _evr(a)
    eb, vb, rb = _evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _rpmvercmp(va, vb)
    if c or not ra or not rb:                                  # a constraint without a release matches any release
        return c
    return _rpmvercmp(ra, rb)


def satisfies(version, op, want):
    if op is None:
        return True
    c = vercmp(version, want)
    return {"=": c == 0, "<": c < 0, ">": c > 0, "<=": c <= 0, ">=": c >= 0}.get(op, True)
