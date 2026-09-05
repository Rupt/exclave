#!/usr/bin/env python3
"""cannery — builds cans (PROPOSAL.md sections 6 and 10). Milestone 1a subset.

    cannery.py mkcan SRC OUT [--manifest FILE] [--opener PATH] [--link]
        Make the can OUT from the tree SRC: copy (or hard-link with --link) SRC
        to OUT/root, install the opener as OUT/.can/opener, wrap every
        executable file, write OUT/.can/index.
    cannery.py wrap CAN        Wrap executables not yet wrapped (idempotent).
    cannery.py index CAN [--manifest FILE]
                               Rewrite OUT/.can/index from the tree.
    cannery.py check CAN       Verify wrappers, payloads and index agree.
    cannery.py fmt FILE...     Parse with the strict grammar and rewrite in
                               canonical form (--check: only report).
    cannery.py from-packages [--distro ubuntu] [--suite S]... [--arch amd64]
                             [--mirror URL | --snapshot DATE] [--cache DIR]
                             [--no-essential] [--choose VIRTUAL=PKG]...
                             [--entry NAME=/PATH]... [--manifest FILE]
                             [--add HOSTPATH=/VIRTUAL]... --out CAN PACKAGE...
                               Resolve, fetch, verify, extract, synthesise,
                               wrap, index, lock (10.1).
    cannery.py unwrap CAN      Move every payload back over its wrapper.
    cannery.py reopen CAN [--opener PATH]
                               Replace the opener and relink every wrapper.
    cannery.py hash CAN        The tree hash of 6.4.

Standard library only. Python 3.8 or later.
"""
import argparse
import os
import re
import shutil
import stat
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build  # noqa: E402
import deb  # noqa: E402
import elfcheck  # noqa: E402
import repo  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
# canonical key order per file kind (6.2, 6.3)
KEY_ORDER = {
    "can": ["can", "entry", "data", "host", "own", "env", "use"],
    "index": ["index", "arch", "isa", "libc", "interp", "own", "host", "data", "env", "wrap", "use"],
    "lock": ["lock", "cannery", "source", "pkg", "recipe", "tree", "modified"],
}
# 8.4: identity files the host answers unless the manifest claims them with own
IDENTITY_FILES = ["/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/host.conf", "/etc/localtime",
                  "/etc/resolv.conf", "/etc/hosts", "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"]
# key -> (min fields, max fields, kinds) ; kinds: s string, t token
SCHEMA = {
    "index": (1, 1, "t"), "can": (1, 1, "t"), "lock": (1, 1, "t"), "entry": (2, 2, "ss"), "arch": (1, 1, "s"), "isa": (1, 1, "s"),
    "libc": (2, 2, "ss"), "interp": (1, 1, "s"), "own": (1, 1, "s"), "host": (1, 1, "s"), "data": (1, 1, "s"),
    "env": (2, 2, "ss"), "wrap": (1, 1, "s"), "use": (1, 2, "ss"),
    "cannery": (1, 1, "s"), "source": (1, 8, "ssssssss"), "pkg": (3, 3, "sss"), "recipe": (2, 2, "ss"),
    "tree": (1, 1, "s"), "modified": (1, 1, "t"),
}
ONCE = {"index", "can", "lock", "arch", "isa", "libc", "interp", "cannery", "source", "tree", "modified"}


class GrammarError(Exception):
    pass


# ---------------------------------------------------------------- grammar (6.2)
class Record:
    __slots__ = ("key", "fields", "comments", "line")

    def __init__(self, key, fields, comments=(), line=0):
        self.key, self.fields, self.comments, self.line = key, list(fields), list(comments), line


def _fail(line, col, why):
    raise GrammarError("line %d col %d: %s" % (line, col, why))


def _utf8_len(b, i):
    """Length of the well-formed UTF-8 sequence at b[i] (Unicode Table 3-7), or 0."""
    c = b[i]
    n = len(b) - i
    if c < 0x80:
        return 1
    if c < 0xC2:
        return 0
    if c < 0xE0:
        return 2 if n >= 2 and 0x80 <= b[i + 1] <= 0xBF else 0
    if c < 0xF0:
        if n < 3 or not (0x80 <= b[i + 2] <= 0xBF):
            return 0
        lo, hi = (0xA0, 0xBF) if c == 0xE0 else (0x80, 0x9F) if c == 0xED else (0x80, 0xBF)
        return 3 if lo <= b[i + 1] <= hi else 0
    if c < 0xF5:
        if n < 4 or not (0x80 <= b[i + 2] <= 0xBF) or not (0x80 <= b[i + 3] <= 0xBF):
            return 0
        lo, hi = (0x90, 0xBF) if c == 0xF0 else (0x80, 0x8F) if c == 0xF4 else (0x80, 0xBF)
        return 4 if lo <= b[i + 1] <= hi else 0
    return 0


def parse(data, kind="manifest"):
    """Strict parse of the bytes of a manifest, index or lockfile. Returns [Record]."""
    if not isinstance(data, bytes):
        raise TypeError("bytes expected")
    if not data or data[-1:] != b"\n":
        _fail(1, 1, "file must end with LF")
    if data.startswith(b"\xef\xbb\xbf"):
        _fail(1, 1, "byte order mark")
    i, line = 0, 1
    while i < len(data):
        if data[i] == 0x0D:
            _fail(line, 1, "CR not allowed")
        n = _utf8_len(data, i)
        if not n:
            _fail(line, 1, "malformed UTF-8")
        if data[i] == 0x0A:
            line += 1
        i += n
    records, comments = [], []
    pos, line = 0, 1
    while pos < len(data):
        end = data.index(b"\n", pos)
        raw = data[pos:end]
        if raw == b"":
            pos, line = end + 1, line + 1
            continue
        if raw[:1] == b"#":
            comments.append(raw[1:].decode("utf-8"))
            pos, line = end + 1, line + 1
            continue
        m = re.match(rb"[a-z][a-z0-9-]*", raw)
        if not m:
            _fail(line, 1, "record must start with a lowercase key")
        key = m.group(0).decode()
        col = m.end()
        fields = []
        while col < len(raw):
            if raw[col:col + 1] != b" ":
                _fail(line, col + 1, "tab outside a string" if raw[col] == 9 else "expected a single space between fields")
            col += 1
            if col >= len(raw):
                _fail(line, col + 1, "trailing space")
            if raw[col] == 0x20:
                _fail(line, col + 1, "multiple spaces")
            if raw[col] == 0x22:
                val, col = _parse_string(raw, col, line)
                fields.append(("s", val))
            else:
                m = re.match(rb"[A-Za-z0-9_.+-]+", raw[col:])
                if not m:
                    _fail(line, col + 1, "expected a string or token")
                fields.append(("t", m.group(0)))
                col += m.end()
        rec = Record(key, fields, comments, line)
        comments = []
        _check_record(rec, kind)
        records.append(rec)
        pos, line = end + 1, line + 1
    if comments:
        _fail(line, 1, "comment after the last record")
    if not records:
        _fail(line, 1, "empty file")
    if records[0].key != kind or records[0].fields[0] != ("t", b"1"):
        _fail(records[0].line, 1, "first record must be %s 1" % kind)
    seen = set()
    for r in records:
        if r.key in ONCE:
            if r.key in seen:
                _fail(r.line, 1, "duplicate " + r.key)
            seen.add(r.key)
    return records


def _parse_string(raw, col, line):
    out = bytearray()
    col += 1
    while True:
        if col >= len(raw):
            _fail(line, col + 1, "unterminated string")
        c = raw[col]
        if c == 0x22:
            return bytes(out), col + 1
        if c == 0x5C:
            e = raw[col + 1:col + 2]
            if e in (b"\\", b'"'):
                out += e
                col += 2
            elif e == b"n":
                out += b"\n"
                col += 2
            elif e == b"t":
                out += b"\t"
                col += 2
            elif e == b"x":
                h = raw[col + 2:col + 4]
                if not re.fullmatch(rb"[0-9a-f]{2}", h):
                    _fail(line, col + 1, "\\x needs two lowercase hex digits")
                out.append(int(h, 16))
                col += 4
            else:
                _fail(line, col + 1, "unknown escape")
            continue
        n = _utf8_len(raw, col)
        cp = raw[col:col + n].decode("utf-8")
        o = ord(cp)
        if o < 0x20 or 0x7F <= o <= 0x9F:
            _fail(line, col + 1, "control character must be escaped")
        out += raw[col:col + n]
        col += n


def _check_record(rec, kind):
    if rec.key not in SCHEMA:
        _fail(rec.line, 1, "unknown key " + rec.key)
    lo, hi, kinds = SCHEMA[rec.key]
    if not lo <= len(rec.fields) <= hi:
        _fail(rec.line, 1, "wrong field count for " + rec.key)
    for (k, v), want in zip(rec.fields, kinds):
        if k != want:
            _fail(rec.line, 1, "wrong field type for " + rec.key)
    for k in ("own", "host", "data", "interp"):
        if rec.key == k and not rec.fields[0][1].startswith(b"/"):
            _fail(rec.line, 1, k + " must be an absolute path")
    if rec.key == "entry" and (not rec.fields[1][1].startswith(b"/") or b"/" in rec.fields[0][1] or not rec.fields[0][1]):
        _fail(rec.line, 1, "entry needs a bare name and an absolute path")
    if rec.key == "env" and (not rec.fields[0][1] or b"=" in rec.fields[0][1]):
        _fail(rec.line, 1, "env name must be non-empty and contain no '='")


def quote(b):
    """Canonical string literal for bytes b."""
    out = ['"']
    i = 0
    while i < len(b):
        c = b[i]
        n = _utf8_len(b, i)
        if c == 0x5C:
            out.append("\\\\")
        elif c == 0x22:
            out.append('\\"')
        elif c == 0x0A:
            out.append("\\n")
        elif c == 0x09:
            out.append("\\t")
        elif n == 0:
            out.append("\\x%02x" % c)
        else:
            s = b[i:i + n].decode("utf-8")
            o = ord(s)
            if o < 0x20 or 0x7F <= o <= 0x9F:
                out.append("\\x%02x" % o) if o < 0x80 else out.extend("\\x%02x" % x for x in b[i:i + n])
            else:
                out.append(s)
        i += max(n, 1)
    out.append('"')
    return "".join(out)


def dump(records, kind="can"):
    """Canonical form (6.2): key groups in fixed order, one blank line between groups, sorted within a group
    (use keeps its order), comments attached to their records."""
    groups = {}
    for r in records:
        groups.setdefault(r.key, []).append(r)
    out = []
    for key in KEY_ORDER[kind]:
        if key not in groups:
            continue
        recs = groups[key]
        if key != "use":
            recs = sorted(recs, key=lambda r: [v for _, v in r.fields])
        if out:
            out.append("")
        for r in recs:
            for c in r.comments:
                out.append("#" + c)
            out.append(" ".join([key] + [v.decode() if k == "t" else quote(v) for k, v in r.fields]))
    return ("\n".join(out) + "\n").encode("utf-8")


def load(path, kind):
    with open(path, "rb") as f:
        return parse(f.read(), kind)


def values(records, key):
    return [[v for _, v in r.fields] for r in records if r.key == key]


# ---------------------------------------------------------------- ELF
def elf_info(path):
    """(machine, interp or None) for an ELF file, or None if not ELF."""
    with open(path, "rb") as f:
        h = f.read(64)
        if len(h) < 64 or h[:4] != b"\x7fELF" or h[4] != 2 or h[5] != 1:
            return None
        machine = struct.unpack_from("<H", h, 18)[0]
        phoff, phentsize, phnum = struct.unpack_from("<Q", h, 32)[0], struct.unpack_from("<H", h, 54)[0], struct.unpack_from("<H", h, 56)[0]
        f.seek(phoff)
        ph = f.read(phentsize * phnum)
        interp = None
        for i in range(phnum):
            p_type, _, p_offset, _, _, p_filesz = struct.unpack_from("<IIQQQQ", ph, i * phentsize)
            if p_type == 3:
                f.seek(p_offset)
                interp = f.read(p_filesz).rstrip(b"\0")
        return machine, interp


# ---------------------------------------------------------------- tree walk
def walk_files(root):
    """Yield (real path, virtual path, lstat) for every non-directory entry under root, skipping .real dirs."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".real"]
        for name in filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]:
            real = os.path.join(dirpath, name)
            st = os.lstat(real)
            yield real, "/" + os.path.relpath(real, root).replace(os.sep, "/"), st


def link_or_copy(src, dst):
    """Hard-link when the filesystem allows it, else copy."""
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def opener_ino(can):
    st = os.stat(os.path.join(can, ".can", "opener"))
    return (st.st_dev, st.st_ino, st.st_size)


def is_wrapper(real, oi):
    st = os.lstat(real)
    if not stat.S_ISREG(st.st_mode):
        return False
    if (st.st_dev, st.st_ino) == oi[:2]:
        return True
    d, n = os.path.split(real)
    return st.st_size == oi[2] and os.path.exists(os.path.join(d, ".real", n))


# ---------------------------------------------------------------- commands
def cmd_wrap(can, quiet=False):
    """6.1: every executable file in root/ becomes a hard link to the opener; the original moves to .real/."""
    root = os.path.join(can, "root")
    opener = os.path.join(can, ".can", "opener")
    oi = opener_ino(can)
    n = 0
    for real, v, st in list(walk_files(root)):
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            continue
        if is_wrapper(real, oi):
            continue
        d, name = os.path.split(real)
        rd = os.path.join(d, ".real")
        os.makedirs(rd, exist_ok=True)
        os.rename(real, os.path.join(rd, name))
        try:
            os.link(opener, real)
        except OSError:
            shutil.copy2(opener, real)
        n += 1
    if not quiet:
        print("wrapped %d executables" % n)
    return n


def detect(root):
    """arch, interp, libc for the index by looking at the tree. Refuses mixed loaders or machines (7.3)."""
    machines, interps = set(), set()
    for real, v, st in walk_files(root):
        if not stat.S_ISREG(st.st_mode):
            continue
        p = payload_path(real)
        try:
            info = elf_info(p)
        except OSError:
            continue
        if info:
            machines.add(info[0])
            if info[1]:
                interps.add(info[1])
    if len(machines) > 1:
        raise build.BuildError("the tree mixes machines %s" % sorted(machines))
    if len(interps) > 1:
        raise build.BuildError("the tree mixes loaders %s (one world inside a can, 7.3)" % sorted(interps))
    arch = {62: "x86_64", 183: "aarch64"}.get(next(iter(machines), 62), "unknown")
    interp = next(iter(interps), None)
    libc = None
    for real, v, st in walk_files(root):
        if os.path.basename(v) == "libc.so.6" and stat.S_ISREG(st.st_mode):
            with open(payload_path(real), "rb") as f:
                m = re.search(rb"GNU C Library \([^)]*\) (?:\w+ )?release version (\d+\.\d+)", f.read())
            if m:
                libc = ("glibc", m.group(1).decode())
                break
        if os.path.basename(v).startswith("ld-musl-"):
            libc = ("musl", "unknown")
    return arch, interp, libc


def payload_path(real):
    d, n = os.path.split(real)
    p = os.path.join(d, ".real", n)
    return p if os.path.exists(p) else real


def top_level_owned(root):
    """8.1: the can owns a top-level directory when its tree ships at least one file in it."""
    owned = []
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if os.path.islink(p):
            owned.append("/" + name)
        elif os.path.isdir(p):
            if any(walk_files(p)):
                owned.append("/" + name)
        else:
            owned.append("/" + name)
    return owned


def cmd_index(can, manifest=None, quiet=False):
    root = os.path.join(can, "root")
    man = load(manifest, "can") if manifest else []
    arch, interp, libc = detect(root)
    recs = [Record("index", [("t", b"1")]), Record("arch", [("s", arch.encode())])]
    recs.append(Record("isa", [("s", b"x86-64")]))       # package trees are generic; ISA levels come with from-source (milestone 3)
    if libc:
        recs.append(Record("libc", [("s", libc[0].encode()), ("s", libc[1].encode())]))
    if interp:
        recs.append(Record("interp", [("s", interp)]))
    own = set(v.encode() for v in top_level_owned(root)) | set(f[0] for f in values(man, "own"))
    for o in sorted(own):
        recs.append(Record("own", [("s", o)]))
    hosts = set(f.encode() for f in IDENTITY_FILES) - set(f[0] for f in values(man, "own"))
    hosts |= set(f[0] for f in values(man, "host"))
    for h in sorted(hosts):
        recs.append(Record("host", [("s", h)]))
    for d in values(man, "data"):
        recs.append(Record("data", [("s", d[0])]))
    for e in values(man, "env"):
        recs.append(Record("env", [("s", e[0]), ("s", e[1])]))
    oi = opener_ino(can)
    for real, v, st in walk_files(root):
        if stat.S_ISREG(st.st_mode) and is_wrapper(real, oi):
            recs.append(Record("wrap", [("s", v.encode())]))
    for u in values(man, "use"):
        recs.append(Record("use", [("s", x) for x in u]))
    data = dump(recs, "index")
    parse(data, "index")  # the writer must produce what the reader accepts
    with open(os.path.join(can, ".can", "index"), "wb") as f:
        f.write(data)
    if not quiet:
        print("index: arch %s, interp %s, libc %s, own %s, %d wrappers" %
              (arch, interp.decode() if interp else "-", libc, sorted(own), sum(1 for r in recs if r.key == "wrap")))


def default_opener():
    """build/opener beside a checkout, or the opener shipped next to this file in the cannery can (10.5)."""
    for p in (os.path.join(HERE, "..", "build", "opener"), os.path.join(HERE, "opener")):
        if os.path.isfile(p):
            return p
    return os.path.join(HERE, "..", "build", "opener")


def cmd_mkcan(src, out, manifest=None, opener=None, link=False):
    if os.path.exists(out):
        sys.exit("refusing: %s exists" % out)
    opener = opener or default_opener()
    if not os.path.isfile(opener):
        sys.exit("no opener at %s (run make)" % opener)
    if manifest:
        load(manifest, "can")
    os.makedirs(os.path.join(out, ".can"))
    shutil.copy2(opener, os.path.join(out, ".can", "opener"))
    os.chmod(os.path.join(out, ".can", "opener"), 0o755)
    shutil.copytree(src, os.path.join(out, "root"), symlinks=True, copy_function=link_or_copy if link else shutil.copy2)
    cmd_wrap(out)
    cmd_index(out, manifest)
    make_entries(out, manifest)
    print("made", out)


def make_entries(can, manifest):
    """6.1: entry symlinks beside root/."""
    for name, vpath in values(load(manifest, "can"), "entry") if manifest else []:
        p = os.path.join(can, name.decode("utf-8", "surrogateescape"))
        if os.path.lexists(p):
            os.remove(p)
        os.symlink(os.path.join("root", vpath.decode("utf-8", "surrogateescape").lstrip("/")), p)


def cmd_reopen(can, opener=None):
    """Replace a can's opener and relink every wrapper to it (wrappers are hard links, 6.1)."""
    opener = opener or os.path.join(HERE, "..", "build", "opener")
    if not os.path.isfile(opener):
        sys.exit("no opener at %s" % opener)
    root = os.path.join(can, "root")
    new = os.path.join(can, ".can", "opener.new")
    shutil.copy2(opener, new)
    os.chmod(new, 0o755)
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        if os.path.basename(dirpath) != ".real":
            continue
        parent = os.path.dirname(dirpath)
        for name in filenames:
            w = os.path.join(parent, name)
            if os.path.lexists(w):
                os.remove(w)
            try:
                os.link(new, w)
            except OSError:
                shutil.copy2(new, w)
            n += 1
    os.replace(new, os.path.join(can, ".can", "opener"))
    print("relinked %d wrappers to the new opener" % n)


def cmd_from_packages(a):
    """10.1: resolve, fetch and verify, extract, synthesise, strip, wrap, check, index, entries, lockfile."""
    if os.path.exists(a.out):
        sys.exit("refusing: %s exists" % a.out)
    opener = a.opener or default_opener()
    if not os.path.isfile(opener):
        sys.exit("no opener at %s (run make)" % opener)
    suites = [s for x in a.suite for s in x.split(",")] or {"ubuntu": ["noble", "noble-updates", "noble-security"], "debian": ["bookworm"]}[a.distro]
    comps = a.components.split(",")
    r = repo.Repo(a.distro, suites, a.arch, comps, a.cache, a.mirror, a.snapshot)
    r.load_index()
    choose = dict(x.split("=", 1) for x in a.choose)
    selected, notes = r.resolve(a.packages, essential=not a.no_essential, choose=choose)
    print("closure: %d packages" % len(selected))
    debs, lock_pkgs = [], []
    for name in sorted(selected):
        st = selected[name]
        path, h = r.download(st)
        debs.append((name, path, st))
        lock_pkgs.append((name, st["Version"], h))
    os.makedirs(os.path.join(a.out, ".can"))
    shutil.copy2(opener, os.path.join(a.out, ".can", "opener"))
    os.chmod(os.path.join(a.out, ".can", "opener"), 0o755)
    root = os.path.join(a.out, "root")
    try:
        build.extract(root, debs)
        build.synthesise(root, debs)
        build.placeholders(root)
        for spec in a.add:                                    # 10.5: files of our own into the tree, e.g. the cannery
            src_, _, vpath = spec.partition("=")
            dst = os.path.join(root, vpath.lstrip("/"))
            if os.path.isdir(src_):
                shutil.copytree(src_, dst, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__"))
            else:
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src_, dst)
    except build.BuildError as e:
        shutil.rmtree(a.out)
        sys.exit("refusing: %s" % e)
    manifest = os.path.join(a.out, ".can", "manifest")
    if a.manifest:
        shutil.copy2(a.manifest, manifest)
    else:
        recs = [Record("can", [("t", b"1")])]
        for e in a.entry:
            name, _, vpath = e.partition("=")
            recs.append(Record("entry", [("s", name.encode()), ("s", vpath.encode())]))
        with open(manifest, "wb") as f:
            f.write(dump(recs, "can"))
    load(manifest, "can")
    cmd_wrap(a.out)
    cmd_index(a.out, manifest)
    make_entries(a.out, manifest)
    build.synthesise_in_can(a.out, debs)
    rep = static_report(a.out)
    if rep.errors:
        shutil.rmtree(a.out)
        sys.exit("refusing: the static check failed; the can is not kept")
    source = ["deb", a.distro, ",".join(suites), a.arch, "snapshot=" + a.snapshot if a.snapshot else "mirror=" + r.mirror]
    build.write_lock(a.out, source, lock_pkgs)
    print("made", a.out)


def index_info(idx):
    """interp, libc and data prefixes from parsed index records, for the checks."""
    interp = values(idx, "interp")
    libc = values(idx, "libc")
    return {"interp": interp[0][0].decode("utf-8", "surrogateescape") if interp else None,
            "libc": (libc[0][0].decode(), libc[0][1].decode()) if libc else ("glibc", "unknown"),
            "own": [d[0].decode("utf-8", "surrogateescape") for d in values(idx, "own")],
            "data": [d[0].decode("utf-8", "surrogateescape") for d in values(idx, "data")]}


def static_report(can, quiet=False):
    """10.3 static check; returns the Report."""
    idx = load(os.path.join(can, ".can", "index"), "index")
    info = index_info(idx)
    rep = elfcheck.static_check(can, info, info["data"])
    if not quiet:
        for w in rep.warnings:
            print("warning: " + w)
        for e in rep.errors:
            print("error: " + e)
        print("static check: %d ELF files, %d static executables, %d warnings, %d errors" % (len(rep.seen), len(rep.static), len(rep.warnings), len(rep.errors)))
    return rep


def cmd_check(can, run=None):
    root = os.path.join(can, "root")
    oi = opener_ino(can)
    idx = load(os.path.join(can, ".can", "index"), "index")
    wrapped = set(w[0].decode("utf-8", "surrogateescape") for w in values(idx, "wrap"))
    problems = []
    seen = set()
    for real, v, st in walk_files(root):
        if not stat.S_ISREG(st.st_mode):
            continue
        w = is_wrapper(real, oi)
        d_, n_ = os.path.split(real)
        if not w and os.path.exists(os.path.join(d_, ".real", n_)):
            problems.append("stale wrapper (not this can's opener): " + v)
        elif st.st_mode & 0o111 and not w:
            problems.append("executable not wrapped: " + v)
        if w:
            seen.add(v)
            if not os.path.exists(payload_path(real)) or payload_path(real) == real:
                problems.append("wrapper without payload: " + v)
            if v not in wrapped:
                problems.append("wrapper missing from index: " + v)
    for v in sorted(wrapped - seen):
        problems.append("index wrap without wrapper: " + v)
    for dirpath, dirnames, filenames in os.walk(root):
        if os.path.basename(dirpath) == ".real":
            for n in filenames:
                if not os.path.exists(os.path.join(os.path.dirname(dirpath), n)):
                    problems.append("payload without wrapper: " + os.path.join(dirpath, n))
    for p in problems:
        print(p)
    print("%d wrapper problems" % len(problems))
    rep = static_report(can)
    rc = 1 if problems or rep.errors else 0
    if run:
        drep, status = elfcheck.dynamic_check(can, index_info(idx), run, index_info(idx)["own"])
        for w in drep.warnings:
            print("warning: " + w)
        for e in drep.errors:
            print("error: " + e)
        print("dynamic check: command exited %d, %d errors" % (status, len(drep.errors)))
        rc = rc or (1 if drep.errors else 0)
    return rc


def cmd_fmt(paths, check):
    rc = 0
    for p in paths:
        with open(p, "rb") as f:
            data = f.read()
        kind = "index" if os.path.basename(p) == "index" else "lock" if p.endswith(".lock") else "can"
        try:
            recs = parse(data, kind)
        except GrammarError as e:
            print("%s: %s" % (p, e))
            rc = 1
            continue
        canon = dump(recs, kind)
        if canon != data:
            if check:
                print("%s: not canonical" % p)
                rc = 1
            else:
                with open(p, "wb") as f:
                    f.write(canon)
                print("%s: rewritten" % p)
    return rc


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("mkcan"); p.add_argument("src"); p.add_argument("out"); p.add_argument("--manifest"); p.add_argument("--opener"); p.add_argument("--link", action="store_true")
    p = sub.add_parser("wrap"); p.add_argument("can")
    p = sub.add_parser("index"); p.add_argument("can"); p.add_argument("--manifest")
    p = sub.add_parser("check"); p.add_argument("can"); p.add_argument("--run", nargs=argparse.REMAINDER)
    p = sub.add_parser("fmt"); p.add_argument("files", nargs="+"); p.add_argument("--check", action="store_true")
    p = sub.add_parser("from-packages")
    p.add_argument("packages", nargs="+"); p.add_argument("--out", required=True)
    p.add_argument("--distro", default="ubuntu", choices=["ubuntu", "debian"]); p.add_argument("--suite", action="append", default=[])
    p.add_argument("--arch", default="amd64"); p.add_argument("--components", default="main,universe")
    p.add_argument("--mirror"); p.add_argument("--snapshot"); p.add_argument("--cache", default=os.path.join(os.path.expanduser("~"), ".cache", "cont-cannery"))
    p.add_argument("--no-essential", action="store_true"); p.add_argument("--choose", action="append", default=[], metavar="VIRTUAL=PKG")
    p.add_argument("--entry", action="append", default=[], metavar="NAME=/PATH"); p.add_argument("--manifest"); p.add_argument("--opener")
    p.add_argument("--add", action="append", default=[], metavar="HOSTPATH=/VIRTUAL", help="copy a file or directory into the tree")
    p = sub.add_parser("unwrap"); p.add_argument("can")
    p = sub.add_parser("reopen"); p.add_argument("can"); p.add_argument("--opener")
    p = sub.add_parser("hash"); p.add_argument("can")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "mkcan":
            cmd_mkcan(a.src, a.out, a.manifest, a.opener, a.link)
        elif a.cmd == "wrap":
            cmd_wrap(a.can)
        elif a.cmd == "index":
            cmd_index(a.can, a.manifest)
        elif a.cmd == "check":
            return cmd_check(a.can, a.run or None)
        elif a.cmd == "fmt":
            return cmd_fmt(a.files, a.check)
        elif a.cmd == "from-packages":
            cmd_from_packages(a)
        elif a.cmd == "unwrap":
            build.unwrap(a.can)
        elif a.cmd == "reopen":
            cmd_reopen(a.can, a.opener)
        elif a.cmd == "hash":
            print(build.tree_hash(os.path.join(a.can, "root")))
    except GrammarError as e:
        sys.exit("grammar: %s" % e)
    except (repo.RepoError, build.BuildError, deb.DebError) as e:
        sys.exit("cannery: %s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
