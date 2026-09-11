#!/usr/bin/env python3
"""cannery — builds cans from files (PROPOSAL.md sections 6 and 10).

A can is a directory at every stage, and every command takes paths and nothing else:

    cannery.py unpack OUT DEB...   Make the open can OUT from package files: extract, synthesise what
                                   maintainer scripts would have done, add the placeholders, record every
                                   input in OUT/.can/lock, report dependencies the set does not satisfy.
    cannery.py wrap CAN            Close a can: wrap every executable, check the manifest (written as
                                   `can 1` if absent) and every ELF, write the tree hash to the lock.
                                   Idempotent; a bare directory holding root/ becomes a can.
    cannery.py unwrap CAN          Open a can: move every payload back over its wrapper.
    cannery.py check CAN [LOG...]  Wrappers, payloads and the static check; with CAN_LOG files, the
                                   dynamic check of what a workload actually opened.
    cannery.py prune CAN LOG...    Drop every file no logged workload touched (10.4).
    cannery.py fmt FILE...         Parse with the strict grammar and rewrite in canonical form
                                   (--check: only report).
    cannery.py hash CAN            The tree hash of 6.4.
    cannery.py reopen CAN [OPENER] Replace the opener and relink every wrapper.

The cannery never opens a network connection: the files it is given are its inputs, whoever fetched
them. Standard library only. Python 3.6 or later.
"""
import argparse
import hashlib
import os
import re
import shutil
import stat
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apk  # noqa: E402
import build  # noqa: E402
import deb  # noqa: E402
import rpm  # noqa: E402
import elfcheck  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
# canonical key order per file kind (6.2, 6.4)
KEY_ORDER = {
    "can": ["can", "isa", "data", "host", "own"],
    "lock": ["lock", "cannery", "opener", "pkg", "manifest", "tree"],
}
# key -> (min fields, max fields, kinds) ; kinds: s string, t token
SCHEMA = {
    "can": (1, 1, "t"), "isa": (1, 1, "s"), "data": (1, 1, "s"), "host": (1, 1, "s"), "own": (1, 1, "s"),
    "lock": (1, 1, "t"), "cannery": (1, 1, "s"), "opener": (1, 1, "s"), "pkg": (4, 4, "ssss"), "manifest": (1, 1, "s"), "tree": (1, 1, "s"),
}
ONCE = {"can", "isa", "lock", "cannery", "opener", "manifest", "tree"}
# the opener's tables (8.1): the manifest may carry this many records, the tree this many top-level entries
LIMITS = {"own": 256, "host": 32, "data": 32, "top": 256}


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


def parse(data, kind="can"):
    """Strict parse of the bytes of a manifest or lockfile. Returns [Record]."""
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
    if rec.key not in SCHEMA or rec.key not in KEY_ORDER[kind]:
        _fail(rec.line, 1, "unknown key " + rec.key)
    lo, hi, kinds = SCHEMA[rec.key]
    if not lo <= len(rec.fields) <= hi:
        _fail(rec.line, 1, "wrong field count for " + rec.key)
    for (k, v), want in zip(rec.fields, kinds):
        if k != want:
            _fail(rec.line, 1, "wrong field type for " + rec.key)
    for k in ("own", "host", "data"):
        if rec.key == k and (not rec.fields[0][1].startswith(b"/") or b"\0" in rec.fields[0][1]):
            _fail(rec.line, 1, k + " must be an absolute path")


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
    """Canonical form (6.2): key groups in fixed order, one blank line between groups, sorted within a group,
    comments attached to their records."""
    groups = {}
    for r in records:
        groups.setdefault(r.key, []).append(r)
    out = []
    for key in KEY_ORDER[kind]:
        if key not in groups:
            continue
        recs = sorted(groups[key], key=lambda r: [v for _, v in r.fields])
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


def b2_file(path):
    h = hashlib.blake2b(digest_size=32)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return "b2:" + h.hexdigest()


# ---------------------------------------------------------------- the can as the opener sees it
def manifest_path(can):
    return os.path.join(can, ".can", "manifest")


def manifest(can):
    """The manifest's records; `can 1` alone when the file is absent."""
    p = manifest_path(can)
    return load(p, "can") if os.path.exists(p) else [Record("can", [("t", b"1")])]


def owned(can):
    """8.1: the can's ownership set as the opener computes it at startup: the manifest's own records plus
    every top-level entry of root/ that is not an empty directory; a directory that cannot be listed is not
    a placeholder (review O4-8)."""
    root = os.path.join(can, "root")
    own = set(o[0].decode("utf-8", "surrogateescape") for o in values(manifest(can), "own"))
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        try:
            empty = not os.path.islink(p) and os.path.isdir(p) and not os.listdir(p)
        except PermissionError:
            empty = False
        if not empty:
            own.add("/" + name)
    return sorted(own)


def check_limits(can):
    """The opener's fixed tables (8.1): refuse what it would refuse, before closing (review O4-9, O4-10)."""
    m = manifest(can)
    for key in ("own", "host", "data"):
        n = len(values(m, key))
        if n > LIMITS[key]:
            raise build.BuildError("the manifest has %d %s records; the opener holds %d" % (n, key, LIMITS[key]))
    top = len(os.listdir(os.path.join(can, "root")))
    if top > LIMITS["top"]:
        raise build.BuildError("root/ has %d top-level entries; the opener holds %d" % (top, LIMITS["top"]))


def in_data(vpath, data):
    return any(vpath == d or vpath.startswith(d.rstrip("/") + "/") for d in data)


def data_prefixes(can):
    return [d[0].decode("utf-8", "surrogateescape") for d in values(manifest(can), "data")]


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


def payload_path(real):
    d, n = os.path.split(real)
    p = os.path.join(d, ".real", n)
    return p if os.path.exists(p) else real


MACHINE = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64", "all": None, "noarch": None}   # package spellings -> uname -m


def default_opener(arch=None):
    """build/opener beside a checkout, or the opener shipped next to this file in the cannery can (10.5); for packages
    of another architecture than this machine's, the cross-built build/opener-<machine> (7.1)."""
    import platform
    machine = MACHINE.get(arch, arch)
    if machine and machine != platform.machine():
        p = os.path.join(HERE, "..", "build", "opener-" + machine)
        if not os.path.isfile(p):
            sys.exit("no opener for %s here: %s is not built (make with the cross compiler), and this machine is %s" % (machine, p, platform.machine()))
        return p
    for p in (os.path.join(HERE, "..", "build", "opener"), os.path.join(HERE, "opener")):
        if os.path.isfile(p):
            return p
    return os.path.join(HERE, "..", "build", "opener")


def install_opener(can, opener=None, arch=None):
    """Put an opener at CAN/.can/opener unless one is there already: the one for the packages' architecture."""
    dst = os.path.join(can, ".can", "opener")
    if os.path.exists(dst):
        return
    opener = opener or default_opener(arch)
    if not os.path.isfile(opener):
        sys.exit("no opener at %s (run make)" % opener)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(opener, dst)
    os.chmod(dst, 0o755)


# ---------------------------------------------------------------- commands
def cmd_unpack(out, debs, log=print):
    """10.1: package files into an open can: extract, synthesise, placeholders, opener, lock inputs, dependency report."""
    if os.path.exists(out):
        sys.exit("refusing: %s exists" % out)
    if not debs:
        sys.exit("unpack needs at least one package file")
    pkgs, seen, arches = [], {}, set()
    kinds = set(build.reader(p).__name__ for p in debs)
    if len(kinds) > 1:
        raise build.BuildError("the package files mix formats %s: one format per can" % sorted(kinds))
    for path in debs:
        fields, _ = build.reader(path).control(path)
        name, ver, arch = fields.get("Package"), fields.get("Version"), fields.get("Architecture", "")
        if not name or not ver:
            raise build.BuildError("%s: no Package or Version in its control file" % path)
        if name in seen:
            raise build.BuildError("%s and %s both carry package %s: one version of a package per can" % (seen[name], path, name))
        seen[name] = path
        if arch and arch != "all":
            arches.add(arch)
        pkgs.append((name, path, fields, ver, arch))
    if len(arches) > 1:
        raise build.BuildError("the packages mix architectures %s" % sorted(arches))
    os.makedirs(os.path.join(out, ".can"))
    root = os.path.join(out, "root")
    triples = [(n, p, f) for n, p, f, _, _ in pkgs]
    try:
        build.extract(root, triples, log=log)
        build.synthesise(root, triples, log=log)
        build.placeholders(root, log=log)
    except build.BuildError:
        shutil.rmtree(out)
        raise
    for line in build.dependency_report([(n, f) for n, _, f, _, _ in pkgs], root):   # after synthesis: a file dependency asks the tree
        log("depends: " + line)
    install_opener(out, arch=next(iter(arches), None))
    build.write_lock(out, [(n, v, a, b2_file(p)) for n, p, _, v, a in pkgs])
    log("unpacked %d packages into %s" % (len(pkgs), out))


def wrapper_problems(can, data=()):
    """6.1 as the tree stands: a wrapper of another opener (stale), a wrapper without a payload, a payload
    without a wrapper (a stray under the reserved name), an executable not wrapped outside data prefixes,
    an executable its user cannot run. Returns the list of problems."""
    root = os.path.join(can, "root")
    oi = opener_ino(can)
    problems = []
    for real, v, st in walk_files(root):
        if not stat.S_ISREG(st.st_mode):
            continue
        if in_data(v, data):
            continue
        w = is_wrapper(real, oi)
        d_, n_ = os.path.split(real)
        if not w and os.path.exists(os.path.join(d_, ".real", n_)):
            problems.append("stale wrapper (not this can's opener): %s; run cannery reopen" % v)
        elif st.st_mode & 0o111 and not w and not os.access(real, os.X_OK):
            problems.append("executable file its user cannot execute: %s (mode %o); a wrapper would run as the opener's mode" % (v, st.st_mode & 0o7777))
        if w and (not os.path.exists(payload_path(real)) or payload_path(real) == real):
            problems.append("wrapper without payload: " + v)
    for dirpath, dirnames, filenames in os.walk(root):
        if os.path.basename(dirpath) == ".real":
            for n in filenames:
                if not os.path.lexists(os.path.join(os.path.dirname(dirpath), n)):
                    problems.append("payload without wrapper: /%s (.real is reserved for payloads, 6.1)" % os.path.relpath(os.path.join(dirpath, n), root))
    return problems


def wrap_files(can, data=(), quiet=False):
    """6.1: every executable file in root/ outside data prefixes becomes a hard link to the opener; the
    original moves to .real/. Never over an existing payload (review F4-2)."""
    root = os.path.join(can, "root")
    opener = os.path.join(can, ".can", "opener")
    oi = opener_ino(can)
    n = 0
    for real, v, st in list(walk_files(root)):
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111 or in_data(v, data):
            continue
        if is_wrapper(real, oi):
            continue
        d, name = os.path.split(real)
        rd = os.path.join(d, ".real")
        if os.path.lexists(os.path.join(rd, name)):
            raise build.BuildError("%s has a payload in .real/ already: a stale wrapper; run cannery reopen" % v)
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


def cmd_wrap(can, quiet=False):
    """Close a can: opener, placeholders, manifest, the wrapper and static checks on the tree as it stands,
    then the wrappers, then the lock's opener, manifest and tree hashes. A refusal happens before anything
    is wrapped, so a refused can is still the directory it was (review F4-8, O4-7)."""
    root = os.path.join(can, "root")
    if not os.path.isdir(root):
        sys.exit("refusing: %s has no root/ directory" % can)
    install_opener(can)
    build.placeholders(root, strip=False, log=lambda *a: None)   # 8.1: the conventional names and the identity files, if the tree lacks them
    mp = manifest_path(can)
    if not os.path.exists(mp):
        with open(mp, "wb") as f:
            f.write(b"can 1\n")
    with open(mp, "rb") as f:
        mdata = f.read()
    recs = parse(mdata, "can")
    if dump(recs, "can") != mdata:
        sys.exit("refusing: %s is not canonical; run cannery fmt on it" % mp)
    check_limits(can)
    data = data_prefixes(can)
    problems = wrapper_problems(can, data)
    for p in problems:
        print("error: " + p)
    rep = static_report(can, quiet)
    if problems or rep.errors:
        print("refused; %s is not closed and nothing was wrapped" % can)
        return 1
    wrap_files(can, data, quiet)
    build.write_lock(can, None, "b2:" + hashlib.blake2b(mdata, digest_size=32).hexdigest(), tree=True)
    if not quiet:
        print("closed %s" % can)
    return 0


def cmd_unwrap(can):
    """Open a can: payloads back over their wrappers; the lock keeps its inputs and loses the hashes of a
    closed can (review F4-6). A payload without a wrapper is refused, since it is not this can's (F4-5)."""
    strays = [p for p in wrapper_problems(can) if p.startswith("payload without wrapper")]
    if strays:
        raise build.BuildError("; ".join(strays))
    build.unwrap(can)
    build.write_lock(can, None)


def cmd_reopen(can, opener=None):
    """Replace a can's opener and relink every wrapper to it (wrappers are hard links, 6.1). A payload
    without a wrapper is reported, not given one (review F4-5, O4-11); the lock's opener record follows."""
    opener = opener or default_opener()
    if not os.path.isfile(opener):
        sys.exit("no opener at %s" % opener)
    root = os.path.join(can, "root")
    new = os.path.join(can, ".can", "opener.new")
    shutil.copy2(opener, new)
    os.chmod(new, 0o755)
    n, strays = 0, []
    for dirpath, dirnames, filenames in os.walk(root):
        if os.path.basename(dirpath) != ".real":
            continue
        parent = os.path.dirname(dirpath)
        for name in filenames:
            w = os.path.join(parent, name)
            if not os.path.lexists(w):
                strays.append("/" + os.path.relpath(os.path.join(dirpath, name), root))
                continue
            os.remove(w)
            try:
                os.link(new, w)
            except OSError:
                shutil.copy2(new, w)
            n += 1
    os.replace(new, os.path.join(can, ".can", "opener"))
    for s in strays:
        print("payload without wrapper, left alone: " + s)
    if os.path.exists(os.path.join(can, ".can", "lock")):
        recs = load(os.path.join(can, ".can", "lock"), "lock")
        if values(recs, "tree"):
            build.write_lock(can, None, keep_hashes=True)
    print("relinked %d wrappers to the new opener" % n)


def static_report(can, quiet=False):
    """10.3 static check; returns the Report."""
    rep = elfcheck.static_check(can, owned(can), data_prefixes(can))
    if not quiet:
        for w in rep.warnings:
            print("warning: " + w)
        for e in rep.errors:
            print("error: " + e)
        print("static check: %d ELF files, %d static executables, %d warnings, %d errors" % (len(rep.seen), len(rep.static), len(rep.warnings), len(rep.errors)))
    return rep


def cmd_check(can, logs=()):
    """A closed can: every executable outside data prefixes wrapped, no stray or stale wrapper, the static
    check, the tree against the lock's hash (review O4-18), and with logs the dynamic check."""
    root = os.path.join(can, "root")
    data = data_prefixes(can)
    oi = opener_ino(can)
    problems = wrapper_problems(can, data)
    for real, v, st in walk_files(root):
        if stat.S_ISREG(st.st_mode) and st.st_mode & 0o111 and not in_data(v, data) and not is_wrapper(real, oi) \
                and not os.path.exists(os.path.join(os.path.dirname(real), ".real", os.path.basename(real))):
            problems.append("executable not wrapped: " + v)
    lock = os.path.join(can, ".can", "lock")
    if os.path.exists(lock):
        recorded = values(load(lock, "lock"), "tree")
        if recorded:
            actual = build.tree_hash(root)
            if recorded[0][0].decode() != actual:
                problems.append("the tree differs from the lock: recorded %s, now %s" % (recorded[0][0].decode(), actual))
        else:
            problems.append("an open can: the lock has no tree hash; run cannery wrap")
    elif any(is_wrapper(real, oi) for real, v, st in walk_files(root) if stat.S_ISREG(st.st_mode)):
        problems.append("wrapped but never closed: no lock; run cannery wrap")   # the third state (review F5-3, N4)
    for p in problems:
        print(p)
    print("%d wrapper problems" % len(problems))
    rep = static_report(can)
    rc = 1 if problems or rep.errors else 0
    if logs:
        drep = elfcheck.dynamic_check(can, logs, owned(can))
        for w in drep.warnings:
            print("warning: " + w)
        for e in drep.errors:
            print("error: " + e)
        print("dynamic check: %d log lines, %d errors" % (drep.lines, len(drep.errors)))
        rc = rc or (1 if drep.errors else 0)
    return rc


def cmd_prune(can, logs):
    kept, removed, freed = build.prune(can, logs, owned(can))
    print("pruned %s: kept %d files, removed %d, %d bytes freed" % (can, kept, removed, freed))
    lock = os.path.join(can, ".can", "lock")
    if os.path.exists(lock) and values(load(lock, "lock"), "tree"):
        build.write_lock(can, None, keep_hashes=True)         # the lock records the output as it now is (review F4-6)
    rep = static_report(can)
    return 1 if rep.errors else 0


def cmd_fmt(paths, check):
    rc = 0
    for p in paths:
        with open(p, "rb") as f:
            data = f.read()
        first = next((l for l in data.split(b"\n") if l and not l.startswith(b"#")), b"")
        kind = "lock" if first.startswith(b"lock ") else "can"        # by the first record, not the file's name (review O4-16)
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
    sub = ap.add_subparsers(dest="cmd")
    sub.required = True                                       # required= is Python 3.7; the matrix runs 3.6
    p = sub.add_parser("unpack"); p.add_argument("out"); p.add_argument("debs", nargs="+")
    p = sub.add_parser("wrap"); p.add_argument("can")
    p = sub.add_parser("unwrap"); p.add_argument("can")
    p = sub.add_parser("check"); p.add_argument("can"); p.add_argument("logs", nargs="*")
    p = sub.add_parser("prune"); p.add_argument("can"); p.add_argument("logs", nargs="+")
    p = sub.add_parser("fmt"); p.add_argument("files", nargs="+"); p.add_argument("--check", action="store_true")
    p = sub.add_parser("hash"); p.add_argument("can")
    p = sub.add_parser("reopen"); p.add_argument("can"); p.add_argument("opener", nargs="?")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "unpack":
            cmd_unpack(a.out, a.debs)
        elif a.cmd == "wrap":
            return cmd_wrap(a.can)
        elif a.cmd == "unwrap":
            cmd_unwrap(a.can)
        elif a.cmd == "check":
            return cmd_check(a.can, a.logs)
        elif a.cmd == "prune":
            return cmd_prune(a.can, a.logs)
        elif a.cmd == "fmt":
            return cmd_fmt(a.files, a.check)
        elif a.cmd == "hash":
            if not os.path.isdir(os.path.join(a.can, "root")):
                sys.exit("refusing: %s has no root/ directory" % a.can)
            print(build.tree_hash(os.path.join(a.can, "root")))
        elif a.cmd == "reopen":
            cmd_reopen(a.can, a.opener)
    except GrammarError as e:
        sys.exit("grammar: %s" % e)
    except (build.BuildError, deb.DebError, apk.ApkError, rpm.RpmError) as e:
        sys.exit("cannery: %s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
