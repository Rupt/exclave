"""exclave — builds exclaves from files (DESIGN.md sections 6 and 10).

An exclave is a directory at every stage, and every command takes paths; `format --check` is the one flag:

    exclave unpack OUT PKG...       Make the unwrapped exclave OUT from package files: extract, synthesise
                                    what maintainer scripts would have done, add the placeholders, record
                                    every input in OUT/.exclave/hashes, report dependencies the set does
                                    not satisfy.
    exclave wrap EXCLAVE            Wrap it: check the manifest (written as `exclave 1` if absent), the
                                    wrappers and every ELF, then wrap every executable and write the
                                    launcher, manifest and tree hashes to .exclave/hashes. Idempotent; a
                                    bare directory holding tree/ becomes an exclave.
    exclave unwrap EXCLAVE          Unwrap it: move every original back over its wrapper.
    exclave check EXCLAVE [LOG...]  Wrappers, originals, the tree against its recorded hash and the static
                                    check; with EXCLAVE_LOG files, the dynamic check of what a workload
                                    opened.
    exclave prune EXCLAVE LOG...    Drop every file no logged workload touched (10.4).
    exclave format FILE...          Parse with the strict grammar and rewrite in canonical form
                                    (--check: only report).
    exclave hash EXCLAVE            The tree hash of 6.4.
    exclave relink EXCLAVE [LAUNCHER]  Replace the launcher and relink every wrapper.

Unpack, wrap and relink also write EXCLAVE/README, which tells whoever finds the exclave what it is and
how to run it, where the exclave has none.

The tool never opens a network connection: the files it is given are its inputs, whoever fetched
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
    "exclave": ["exclave", "cpu", "data", "host", "own"],
    "hashes": ["hashes", "tool", "launcher", "pkg", "manifest", "tree"],
}
# key -> (min fields, max fields, kinds) ; kinds: s string, t token
SCHEMA = {
    "exclave": (1, 1, "t"),
    "cpu": (1, 1, "s"),
    "data": (1, 1, "s"),
    "host": (1, 1, "s"),
    "own": (1, 1, "s"),
    "hashes": (1, 1, "t"),
    "tool": (1, 1, "s"),
    "launcher": (1, 1, "s"),
    "pkg": (4, 4, "ssss"),
    "manifest": (1, 1, "s"),
    "tree": (1, 1, "s"),
}
ONCE = {"exclave", "cpu", "hashes", "tool", "launcher", "manifest", "tree"}
# the launcher's tables (8.1): the manifest may carry this many records, the tree this many top-level entries
LIMITS = {"own": 256, "host": 32, "data": 32, "top": 256}
# 6.1: the exclave's README, for whoever finds the directory without knowing the project; written where it has none
README_TEXT = b"""\
This directory is an exclave: Linux software packed with the
libraries and files it needs, so that its programs run from here, by
path, with nothing installed. It was made by exclave, a tool that
builds such directories. It runs on Linux 3.10 or later, on the
machine type it was built for ("file .exclave/launcher" names it),
with no root, setup step, daemon or container, and running it changes
nothing in tree/ or .exclave/ and leaves nothing behind. It is not a
sandbox: its programs run as you, with your files and your network.

What is here

  tree/              the software's own /: usually the packages listed
                     in .exclave/hashes, unpacked as if installed.
  .exclave/launcher  a small program that starts the others. Every
                     program in tree/ is a hard link to it, a
                     "wrapper"; the original sits in a hidden .real/
                     directory beside it, and running tree/usr/bin/NAME
                     runs tree/usr/bin/.real/NAME inside the exclave.
  .exclave/manifest  the maker's settings; "exclave 1" alone means none.
  .exclave/hashes    one "pkg" line per package that went in: name,
                     version, architecture and hash of the package
                     file; then hashes of the launcher, the manifest
                     and, on the "tree" line, all of tree/. Not where
                     they came from.
  other names        shortcuts into tree/ that the maker added.

A hashes file with no "tree" line marks an unwrapped, unfinished
exclave: its programs would use this system's libraries.

Running it

With EX the path of this directory, run from your own directory:

  EX/NAME ARGS...                    a shortcut, if the maker made one
  EX/tree/usr/bin/NAME ARGS...       any program in the exclave
  EX/tree/bin/sh                     a shell inside the exclave, if it
                                     has one
  EX/.exclave/launcher PROG ARGS...  PROG run inside the exclave: one of
                                     your own, such as one the
                                     exclave's compiler built, or an
                                     exclave path, /usr/bin/NAME

A symlink to a program in tree/ works too; a copy does not, and a
program run straight from .real/ is likely to fail.

Inside, a program sees the top-level directories that tree/ fills,
/usr, /etc, /lib and the rest, as its own, read-only: writing there
fails as on a read-only disk. Everything else is this system's: /home,
/tmp, /proc, /dev, the working directory, and eight files such as
/etc/passwd and /etc/resolv.conf that say who you are and how network
names are looked up. PATH is the exclave's, so this system's commands
are not found by name. The locale is C.UTF-8 and the time zone UTC by
default, and sudo, su and other setuid programs do not work inside.

EXCLAVE_LOG=/some/file makes every process append one line per call
that names a file: the call, its result and the path. Messages that
begin "launcher:" come from the exclave, not from the program.

Moving, copying, removing

Nothing outside this directory refers to it: move it, copy it with
cp -a, pack it with tar, or remove it with rm -r. A copy that splits
the hard links (cp -r) still runs, larger by the launcher's size per
program. Do not edit a program in tree/ in place: they are all one
file. An exclave does not run from a filesystem mounted noexec.

Checking it

The hashes are BLAKE2b-256, so "b2sum -l 256 .exclave/launcher" prints
the recorded launcher hash, and a package file fetched again its pkg
hash. The exclave tool, which builds these directories, is not part
of this one:

  exclave check DIR   every program wrapped, the libraries each needs
                      found inside, tree/ against its recorded hash
  exclave unwrap DIR  unwrap the exclave for editing; exclave wrap DIR
                      wraps it again
  exclave relink DIR  put in another launcher, relinking every program

Licences

The software in tree/ keeps its packages' licences, and passing this
directory on passes their terms on with it. Their texts are in
tree/usr/share/doc/*/copyright and tree/usr/share/common-licenses/
(Debian, Ubuntu) or tree/usr/share/licenses/ (Fedora and others);
exclave prune keeps them. An Alpine package's licence text comes in
its -doc package, so an Alpine exclave has it only if that went in.
The launcher is part of exclave, Copyright (c) 2026 Rupert Tombs,
under the MIT licence, whose text it carries: "readelf -p
.exclave.license .exclave/launcher" prints it.

This file is the same in every exclave; a maker may replace it.
"""


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


def parse(data, kind="exclave"):
    """Strict parse of the bytes of a manifest or hashes file. Returns [Record]."""
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
    records, comments, counts = [], [], {}
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
            if raw[col : col + 1] != b" ":
                _fail(
                    line,
                    col + 1,
                    "tab outside a string"
                    if raw[col] == 9
                    else "expected a single space between fields",
                )
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
        if (
            kind == "exclave" and key in LIMITS
        ):  # the launcher's tables (8.1), refused where the launcher refuses
            counts[key] = counts.get(key, 0) + 1
            if counts[key] > LIMITS[key]:
                _fail(line, 1, "more than %d %s records" % (LIMITS[key], key))
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
            e = raw[col + 1 : col + 2]
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
                h = raw[col + 2 : col + 4]
                if not re.fullmatch(rb"[0-9a-f]{2}", h):
                    _fail(line, col + 1, "\\x needs two lowercase hex digits")
                out.append(int(h, 16))
                col += 4
            else:
                _fail(line, col + 1, "unknown escape")
            continue
        n = _utf8_len(raw, col)
        cp = raw[col : col + n].decode("utf-8")
        o = ord(cp)
        if o < 0x20 or 0x7F <= o <= 0x9F:
            _fail(line, col + 1, "control character must be escaped")
        out += raw[col : col + n]
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
        if rec.key == k and not _normalised_abs(rec.fields[0][1]):
            _fail(rec.line, 1, k + " must be a normalised absolute path")


def _normalised_abs(b):
    """An absolute path in its one spelling (6.2): no NUL, no empty, "." or ".." component, no trailing slash but on "/"."""
    if not b.startswith(b"/") or b"\0" in b:
        return False
    if b == b"/":
        return True
    return not b.endswith(b"/") and all(c not in (b"", b".", b"..") for c in b[1:].split(b"/"))


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
            s = b[i : i + n].decode("utf-8")
            o = ord(s)
            if o < 0x20 or 0x7F <= o <= 0x9F:
                out.append("\\x%02x" % o) if o < 0x80 else out.extend(
                    "\\x%02x" % x for x in b[i : i + n]
                )
            else:
                out.append(s)
        i += max(n, 1)
    out.append('"')
    return "".join(out)


def dump(records, kind="exclave"):
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
            out.append(
                " ".join([key] + [v.decode() if k == "t" else quote(v) for k, v in r.fields])
            )
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


# ---------------------------------------------------------------- the exclave as the launcher sees it
def manifest_path(ex):
    return os.path.join(ex, ".exclave", "manifest")


def manifest(ex):
    """The manifest's records; `exclave 1` alone when the file is absent."""
    p = manifest_path(ex)
    return load(p, "exclave") if os.path.exists(p) else [Record("exclave", [("t", b"1")])]


def owned_top(ex):
    """8.1 rule 1: every top-level entry of tree/ that is not an empty directory; a directory that cannot be
    listed is not a placeholder."""
    root = os.path.join(ex, "tree")
    top = []
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        try:
            empty = not os.path.islink(p) and os.path.isdir(p) and not os.listdir(p)
        except PermissionError:
            empty = False
        if not empty:
            top.append("/" + name)
    return top


def owned(ex):
    """8.1: the exclave's ownership as the launcher computes it at startup: the manifest's own records plus the
    tree's top-level entries of rule 1, with the host records that take paths back from them."""
    m = manifest(ex)
    own = set(o[0].decode("utf-8", "surrogateescape") for o in values(m, "own"))
    host = [h[0].decode("utf-8", "surrogateescape") for h in values(m, "host")]
    return elfcheck.Owned(sorted(own | set(owned_top(ex))), host)


def check_limits(ex):
    """The launcher's fixed tables (8.1): refuse what it would refuse, before wrapping; the
    manifest's records are counted by parse, the tree's top-level entries here."""
    manifest(ex)
    top = len(owned_top(ex))  # as the launcher counts them: a placeholder takes no slot
    if top > LIMITS["top"]:
        raise build.BuildError(
            "tree/ has %d top-level entries; the launcher holds %d" % (top, LIMITS["top"])
        )


def in_data(vpath, data):
    return any(vpath == d or vpath.startswith(d.rstrip("/") + "/") for d in data)


def data_prefixes(ex):
    return [d[0].decode("utf-8", "surrogateescape") for d in values(manifest(ex), "data")]


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


def launcher_ino(ex):
    st = os.stat(os.path.join(ex, ".exclave", "launcher"))
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


MACHINE = {
    "amd64": "x86_64",
    "x86_64": "x86_64",
    "arm64": "aarch64",
    "aarch64": "aarch64",
    "all": None,
    "noarch": None,
}  # package spellings -> uname -m


def default_launcher(arch=None):
    """build/launcher beside a checkout, or the launcher shipped next to this file in the tool's own exclave (10.5); for packages
    of another architecture than this machine's, the cross-built build/launcher-<machine> (7.1)."""
    import platform

    machine = MACHINE.get(arch, arch)
    if machine and machine != platform.machine():
        p = os.path.join(HERE, "..", "build", "launcher-" + machine)
        if not os.path.isfile(p):
            sys.exit(
                "no launcher for %s here: %s is not built (make with the cross compiler), and this machine is %s"
                % (machine, p, platform.machine())
            )
        return p
    for p in (os.path.join(HERE, "..", "build", "launcher"), os.path.join(HERE, "launcher")):
        if os.path.isfile(p):
            return p
    return os.path.join(HERE, "..", "build", "launcher")


def write_readme(ex):
    """EXCLAVE/README for whoever finds the exclave (6.1), unless the exclave has one: the maker's own, or a shortcut by that name."""
    p = os.path.join(ex, "README")
    if not os.path.lexists(p):
        with open(p, "wb") as f:
            f.write(README_TEXT)


def install_launcher(ex, launcher=None, arch=None):
    """Put a launcher at EXCLAVE/.exclave/launcher unless one is there already: the one for the packages' architecture."""
    dst = os.path.join(ex, ".exclave", "launcher")
    if os.path.exists(dst):
        return
    launcher = launcher or default_launcher(arch)
    if not os.path.isfile(launcher):
        sys.exit("no launcher at %s (run make)" % launcher)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(launcher, dst)
    os.chmod(dst, 0o755)


# ---------------------------------------------------------------- commands
def cmd_unpack(out, debs, log=print):
    """10.1: package files into an unwrapped exclave: extract, synthesise, placeholders, launcher, inputs hashed, dependency report."""
    if os.path.exists(out):
        sys.exit("refusing: %s exists" % out)
    if not debs:
        sys.exit("unpack needs at least one package file")
    pkgs, seen, arches = [], {}, set()
    kinds = set(build.reader(p).__name__ for p in debs)
    if len(kinds) > 1:
        raise build.BuildError(
            "the package files mix formats %s: one format per exclave" % sorted(kinds)
        )
    for path in debs:
        fields, _ = build.reader(path).control(path)
        name, ver, arch = (
            fields.get("Package"),
            fields.get("Version"),
            fields.get("Architecture", ""),
        )
        if not name or not ver:
            raise build.BuildError("%s: no Package or Version in its control file" % path)
        if name in seen:
            raise build.BuildError(
                "%s and %s both carry package %s: one version of a package per exclave"
                % (seen[name], path, name)
            )
        seen[name] = path
        if arch and arch != "all":
            arches.add(arch)
        pkgs.append((name, path, fields, ver, arch))
    if len(arches) > 1:
        raise build.BuildError("the packages mix architectures %s" % sorted(arches))
    os.makedirs(os.path.join(out, ".exclave"))
    root = os.path.join(out, "tree")
    triples = [(n, p, f) for n, p, f, _, _ in pkgs]
    try:
        build.extract(root, triples, log=log)
        build.synthesise(root, triples, log=log)
        build.placeholders(root, log=log)
    except build.BuildError:
        shutil.rmtree(out)
        raise
    for line in build.dependency_report(
        [(n, f) for n, _, f, _, _ in pkgs], root
    ):  # after synthesis: a file dependency asks the tree
        log("depends: " + line)
    install_launcher(out, arch=next(iter(arches), None))
    build.write_lock(out, [(n, v, a, b2_file(p)) for n, p, _, v, a in pkgs])
    write_readme(out)
    log("unpacked %d packages into %s" % (len(pkgs), out))


def wrapper_problems(ex, data=()):
    """6.1 as the tree stands: a wrapper of another launcher (stale), a wrapper without an original, an original
    without a wrapper (a stray under the reserved name), an executable its user cannot run. Returns the list
    of problems; cmd_check adds the executables not wrapped, which wrap is about to wrap."""
    root = os.path.join(ex, "tree")
    oi = launcher_ino(ex)
    problems = []
    for real, v, st in walk_files(root):
        if not stat.S_ISREG(st.st_mode):
            continue
        if in_data(v, data):
            continue
        w = is_wrapper(real, oi)
        d_, n_ = os.path.split(real)
        if not w and os.path.exists(os.path.join(d_, ".real", n_)):
            problems.append(
                "stale wrapper (not this exclave's launcher): %s; run exclave relink" % v
            )
        elif st.st_mode & 0o111 and not w and not os.access(real, os.X_OK):
            problems.append(
                "executable file its user cannot execute: %s (mode %o); a wrapper would run as the launcher's mode"
                % (v, st.st_mode & 0o7777)
            )
        if w and (not os.path.exists(payload_path(real)) or payload_path(real) == real):
            problems.append("wrapper without original: " + v)
    for dirpath, dirnames, filenames in os.walk(root):
        if os.path.basename(dirpath) == ".real":
            for n in filenames:
                if not os.path.lexists(os.path.join(os.path.dirname(dirpath), n)):
                    problems.append(
                        "original without wrapper: /%s (.real is reserved for originals, 6.1)"
                        % os.path.relpath(os.path.join(dirpath, n), root)
                    )
    return problems


def wrap_files(ex, data=(), quiet=False):
    """6.1: every executable file in tree/ outside data directories becomes a hard link to the launcher; the
    original moves to .real/. Never over an existing original."""
    root = os.path.join(ex, "tree")
    launcher = os.path.join(ex, ".exclave", "launcher")
    oi = launcher_ino(ex)
    n = 0
    for real, v, st in list(walk_files(root)):
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111 or in_data(v, data):
            continue
        if is_wrapper(real, oi):
            continue
        d, name = os.path.split(real)
        rd = os.path.join(d, ".real")
        if os.path.lexists(os.path.join(rd, name)):
            raise build.BuildError(
                "%s has an original in .real/ already: a stale wrapper; run exclave relink" % v
            )
        os.makedirs(rd, exist_ok=True)
        os.rename(real, os.path.join(rd, name))
        try:
            os.link(launcher, real)
        except OSError:
            shutil.copy2(launcher, real)
        n += 1
    if not quiet:
        print("wrapped %d executables" % n)
    return n


def cmd_wrap(ex, quiet=False):
    """Wrap an exclave: launcher, placeholders, manifest, the wrapper and static checks on the tree as it stands,
    then the wrappers, then the launcher, manifest and tree hashes in the hashes file. A refusal happens before
    anything is wrapped, so a refused exclave is left unwrapped."""
    root = os.path.join(ex, "tree")
    if not os.path.isdir(root):
        sys.exit("refusing: %s has no tree/ directory" % ex)
    install_launcher(ex)
    build.placeholders(
        root, strip=False, log=lambda *a: None
    )  # 8.1: the conventional names and the identity files, if the tree lacks them
    mp = manifest_path(ex)
    if not os.path.exists(mp):
        with open(mp, "wb") as f:
            f.write(b"exclave 1\n")
    with open(mp, "rb") as f:
        mdata = f.read()
    recs = parse(mdata, "exclave")
    if dump(recs, "exclave") != mdata:
        sys.exit("refusing: %s is not canonical; run exclave format on it" % mp)
    check_limits(ex)
    data = data_prefixes(ex)
    problems = wrapper_problems(ex, data)
    for p in problems:
        print("error: " + p)
    rep = static_report(ex, quiet)
    if problems or rep.errors:
        print("refused; %s is left as it was: nothing was wrapped" % ex)
        return 1
    wrap_files(ex, data, quiet)
    write_readme(ex)
    build.write_lock(
        ex, None, "b2:" + hashlib.blake2b(mdata, digest_size=32).hexdigest(), tree=True
    )
    if not quiet:
        print("%s is wrapped" % ex)
    return 0


def cmd_unwrap(ex):
    """Unwrap an exclave: originals back over their wrappers; the hashes file keeps its inputs and loses the
    hashes of a wrapped exclave. An original without a wrapper is refused, since it is not this
    exclave's."""
    strays = [p for p in wrapper_problems(ex) if p.startswith("original without wrapper")]
    if strays:
        raise build.BuildError("; ".join(strays))
    build.unwrap(ex)
    build.write_lock(ex, None)


def cmd_relink(ex, launcher=None):
    """Replace an exclave's launcher and relink every wrapper to it (wrappers are hard links, 6.1). An original
    without a wrapper is reported, not given one; the hashes file's launcher record follows."""
    launcher = launcher or default_launcher()
    if not os.path.isfile(launcher):
        sys.exit("no launcher at %s" % launcher)
    root = os.path.join(ex, "tree")
    new = os.path.join(ex, ".exclave", "launcher.new")
    shutil.copy2(launcher, new)
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
    os.replace(new, os.path.join(ex, ".exclave", "launcher"))
    write_readme(ex)
    for s in strays:
        print("original without wrapper, left alone: " + s)
    if os.path.exists(os.path.join(ex, ".exclave", "hashes")):
        recs = load(os.path.join(ex, ".exclave", "hashes"), "hashes")
        if values(recs, "tree"):
            build.write_lock(ex, None, keep_hashes=True)
    print("relinked %d wrappers to the new launcher" % n)


def static_report(ex, quiet=False):
    """10.3 static check; returns the Report."""
    rep = elfcheck.static_check(ex, owned(ex), data_prefixes(ex))
    if not quiet:
        for w in rep.warnings:
            print("warning: " + w)
        for e in rep.errors:
            print("error: " + e)
        print(
            "static check: %d ELF files, %d static executables, %d warnings, %d errors"
            % (len(rep.seen), len(rep.static), len(rep.warnings), len(rep.errors))
        )
    return rep


def cmd_check(ex, logs=()):
    """A wrapped exclave: every executable outside data directories wrapped, no stray or stale wrapper, the
    static check, the tree against its recorded hash, and with logs the dynamic check."""
    root = os.path.join(ex, "tree")
    data = data_prefixes(ex)
    oi = launcher_ino(ex)
    problems = wrapper_problems(ex, data)
    for real, v, st in walk_files(root):
        if (
            stat.S_ISREG(st.st_mode)
            and st.st_mode & 0o111
            and not in_data(v, data)
            and not is_wrapper(real, oi)
            and not os.path.exists(
                os.path.join(os.path.dirname(real), ".real", os.path.basename(real))
            )
        ):
            problems.append("executable not wrapped: " + v)
    lock = os.path.join(ex, ".exclave", "hashes")
    if os.path.exists(lock):
        recorded = values(load(lock, "hashes"), "tree")
        if recorded:
            actual = build.tree_hash(root)
            if recorded[0][0].decode() != actual:
                problems.append(
                    "the tree differs from the hashes file: recorded %s, now %s"
                    % (recorded[0][0].decode(), actual)
                )
        else:
            problems.append(
                "an unwrapped exclave: the hashes file has no tree hash; run exclave wrap"
            )
    elif any(is_wrapper(real, oi) for real, v, st in walk_files(root) if stat.S_ISREG(st.st_mode)):
        problems.append(
            "wrappers but no hashes file: wrap never finished; run exclave wrap"
        )  # the third state: wrapped, never finished
    for p in problems:
        print(p)
    print("%d wrapper problems" % len(problems))
    rep = static_report(ex)
    rc = 1 if problems or rep.errors else 0
    if logs:
        drep = elfcheck.dynamic_check(ex, logs, owned(ex))
        for w in drep.warnings:
            print("warning: " + w)
        for e in drep.errors:
            print("error: " + e)
        print("dynamic check: %d log lines, %d errors" % (drep.lines, len(drep.errors)))
        rc = rc or (1 if drep.errors else 0)
    return rc


def cmd_prune(ex, logs):
    kept, removed, freed = build.prune(ex, logs, owned(ex))
    print("pruned %s: kept %d files, removed %d, %d bytes freed" % (ex, kept, removed, freed))
    lock = os.path.join(ex, ".exclave", "hashes")
    if os.path.exists(lock) and values(load(lock, "hashes"), "tree"):
        build.write_lock(
            ex, None, keep_hashes=True
        )  # the hashes file records the output as it now is
    rep = static_report(ex)
    return 1 if rep.errors else 0


def cmd_format(paths, check):
    rc = 0
    for p in paths:
        with open(p, "rb") as f:
            data = f.read()
        first = next((l for l in data.split(b"\n") if l and not l.startswith(b"#")), b"")
        kind = (
            "hashes" if first.startswith(b"hashes ") else "exclave"
        )  # by the first record, not the file's name
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


def require_exclave(ex, cmd):
    """Refuse, in one line and before reading or writing anything, a directory the command cannot act on:
    a can, an exclave from before the rename, is named as one, since its launcher's own refusal sends its user here."""
    if os.path.isdir(os.path.join(ex, ".can")) and not os.path.isdir(os.path.join(ex, ".exclave")):
        sys.exit(
            "refusing: %s is a can, an exclave from before the rename, with .can/ and root/; convert it first "
            "(docs/DESIGN.md 13 item 45)" % ex
        )
    if not os.path.isdir(os.path.join(ex, "tree")):
        sys.exit("refusing: %s has no tree/ directory" % ex)
    if cmd != "wrap" and not os.path.isdir(os.path.join(ex, ".exclave")):
        sys.exit("refusing: %s has no .exclave/ directory; wrap makes one" % ex)


def main(argv):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd")
    sub.required = True  # required= is Python 3.7; the matrix runs 3.6
    p = sub.add_parser("unpack")
    p.add_argument("out")
    p.add_argument("debs", nargs="+")
    p = sub.add_parser("wrap")
    p.add_argument("exclave")
    p = sub.add_parser("unwrap")
    p.add_argument("exclave")
    p = sub.add_parser("check")
    p.add_argument("exclave")
    p.add_argument("logs", nargs="*")
    p = sub.add_parser("prune")
    p.add_argument("exclave")
    p.add_argument("logs", nargs="+")
    p = sub.add_parser("format")
    p.add_argument("files", nargs="+")
    p.add_argument("--check", action="store_true")
    p = sub.add_parser("hash")
    p.add_argument("exclave")
    p = sub.add_parser("relink")
    p.add_argument("exclave")
    p.add_argument("launcher", nargs="?")
    a = ap.parse_args(argv)
    if a.cmd not in ("unpack", "format"):
        require_exclave(a.exclave, a.cmd)
    try:
        if a.cmd == "unpack":
            cmd_unpack(a.out, a.debs)
        elif a.cmd == "wrap":
            return cmd_wrap(a.exclave)
        elif a.cmd == "unwrap":
            cmd_unwrap(a.exclave)
        elif a.cmd == "check":
            return cmd_check(a.exclave, a.logs)
        elif a.cmd == "prune":
            return cmd_prune(a.exclave, a.logs)
        elif a.cmd == "format":
            return cmd_format(a.files, a.check)
        elif a.cmd == "hash":
            print(build.tree_hash(os.path.join(a.exclave, "tree")))
        elif a.cmd == "relink":
            cmd_relink(a.exclave, a.launcher)
    except GrammarError as e:
        sys.exit("grammar: %s" % e)
    except (build.BuildError, deb.DebError, apk.ApkError, rpm.RpmError) as e:
        sys.exit("exclave: %s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
