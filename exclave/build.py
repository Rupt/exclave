"""The tool's build steps (DESIGN.md 10.1, 10.4, 6.4).

Placeholders, pruning, unwrapping, the tree hash and the hashes file.
"""

import glob
import hashlib
import os
import stat
from typing import NamedTuple
lazy from collections.abc import Callable, Iterable

from exclave import __version__, elfcheck, grammar, layout

# The conventional top-level names, shipped as empty directories (8.1, 6.1).
PLACEHOLDERS = [
    "proc",
    "dev",
    "sys",
    "tmp",
    "run",
    "var/tmp",
    "home",
    "root",
    "boot",
    "mnt",
    "media",
    "opt",
    "srv",
]

type Log = Callable[[str], object]


class PkgRecord(NamedTuple):
    """A pkg record of the hashes file (6.4)."""

    name: str
    version: str
    arch: str
    hash: str


class BuildError(Exception):
    """A refusal: an input the tool will not build from, or a step that cannot be done."""


# ---------------------------------------------------------------- the placeholders (8.1, 8.4)
def _v(root: str, vpath: str) -> str:
    """Return the real path of a virtual path in root, symlinks unresolved."""
    return os.path.join(root, vpath.lstrip("/"))


# The host identity files (8.4): shipped empty, the host's at run time.
IDENTITY_FILES = [
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
]


def placeholders(root: str, log: Log = print) -> None:
    """Add the conventional names as empty directories and the identity files as empty files (8.1).

    Each is added only where the tree lacks it.
    """
    for d in PLACEHOLDERS:
        p = os.path.join(root, d)
        if not os.path.lexists(p):
            os.makedirs(p)
    tree = elfcheck.Tree(root)
    for f in IDENTITY_FILES:
        d, b = os.path.split(f)
        # the directory as the tree resolves it: Fedora's /etc/ssl/certs is a link into /etc/pki
        rd = tree.resolve(d)
        if rd is None and os.path.islink(_v(root, d)):
            log(f"identity file {f} not placed: its directory is a dangling link in the tree")
            continue
        p = os.path.join(_v(root, rd or d), b)
        if not os.path.lexists(p):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb"):
                pass


# ---------------------------------------------------------------- tree hash and hashes file (6.4)
def tree_hash(root: str) -> str:
    """Return the tree hash of 6.4: BLAKE2b-256 of a sorted listing of every entry in the tree.

    Each wrapper is listed with its original's contents, and `.real/` is not listed, except that an
    original without a wrapper is listed under its own path, so that no file goes unhashed.

    Raises:
        BuildError: When a file cannot be read.
    """
    entries: list[bytes] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != ".real")
        strays = []
        if os.path.isdir(os.path.join(dirpath, ".real")):
            strays = [
                os.path.join(".real", n)
                for n in sorted(os.listdir(os.path.join(dirpath, ".real")))
                if not os.path.lexists(os.path.join(dirpath, n))
            ]
        for name in dirnames + filenames + strays:
            real = os.path.join(dirpath, name)
            rel = os.path.relpath(real, root).encode("utf-8", "surrogateescape")
            st = os.lstat(real)
            if stat.S_ISLNK(st.st_mode):
                entries.append(
                    rel + b"\0l\0" + os.readlink(real).encode("utf-8", "surrogateescape") + b"\0"
                )
            elif stat.S_ISDIR(st.st_mode):
                entries.append(rel + b"\0d\0\0")
            elif stat.S_ISREG(st.st_mode):
                kind = b"x" if st.st_mode & 0o111 else b"f"
                payload = layout.payload_path(real)
                try:
                    with open(payload, "rb") as f:
                        h = hashlib.file_digest(f, lambda: hashlib.blake2b(digest_size=32))
                except PermissionError as e:
                    msg = f"cannot read {payload}: the tree hash needs every file readable"
                    raise BuildError(msg) from e
                entries.append(rel + b"\0" + kind + b"\0" + h.hexdigest().encode() + b"\0")
    entries.sort()
    return "b2:" + hashlib.blake2b(b"".join(entries), digest_size=32).hexdigest()


def write_hashes(
    ex: str,
    pkgs: list[PkgRecord] | None,
    manifest_hash: str | None = None,
    *,
    tree: bool = False,
    keep_hashes: bool = False,
) -> None:
    """Write the exclave's hashes file, the record of its inputs and its output (6.4).

    Args:
        ex: The exclave.
        pkgs: The pkg records, or None to keep those already in the file.
        manifest_hash: The manifest's hash, which marks a wrapped exclave; with it, the launcher's
            hash is recorded too.
        tree: Whether to record the tree hash.
        keep_hashes: Keep the file's manifest hash, and its tree record if it has one, recomputing
            the launcher and tree hashes, as after prune or relink. Without it or manifest_hash,
            the launcher, manifest and tree records are dropped, as after unwrap.
    """
    hashes = layout.hashes_path(ex)
    old = grammar.load(hashes, "hashes") if os.path.exists(hashes) else []
    if pkgs is None:
        pkgs = [
            PkgRecord(*(f.decode("utf-8", "surrogateescape") for f in v))
            for v in grammar.values(old, "pkg")
        ]
    if keep_hashes:
        m = grammar.values(old, "manifest")
        manifest_hash, tree = (m[0][0].decode() if m else None), bool(grammar.values(old, "tree"))

    def record(key: str, *strings: str) -> grammar.Record:
        return grammar.Record(key, [("s", v.encode()) for v in strings])

    recs = [grammar.Record("hashes", [("t", b"1")]), record("tool", __version__)]
    if manifest_hash or tree:
        recs.append(record("launcher", layout.b2_file(layout.launcher_path(ex))))
    recs += [record("pkg", *p) for p in sorted(pkgs)]
    if manifest_hash:
        recs.append(record("manifest", manifest_hash))
    if tree:
        recs.append(record("tree", tree_hash(os.path.join(ex, "tree"))))
    data = grammar.dump(recs, "hashes")
    grammar.parse(data, "hashes")
    with open(hashes, "wb") as f:
        f.write(data)


# ---------------------------------------------------------------- the pruning (10.4)
def licence_files(root: str) -> list[str]:
    """Return the virtual paths of the packages' licence texts in a tree, which prune keeps (10.4).

    They are looked for under every usr/share/ in the tree, a data directory's included: Debian's
    doc/PKG/copyright and the common-licenses those refer to, and licenses/, where RPM's %license
    files and Alpine's -doc packages put theirs.
    """
    found = []
    for dirpath, dirnames, _ in os.walk(root):
        if (
            os.path.basename(dirpath) != "share"
            or os.path.basename(os.path.dirname(dirpath)) != "usr"
        ):
            continue
        dirnames[:] = []  # below a usr/share/, only its licence texts
        found += sorted(glob.glob(os.path.join(dirpath, "doc", "*", "copyright")))
        for top in ("common-licenses", "licenses"):
            for d, _, filenames in os.walk(os.path.join(dirpath, top)):
                found += sorted(os.path.join(d, n) for n in filenames)
    return ["/" + os.path.relpath(f, root) for f in found]


class Pruned(NamedTuple):
    kept: int
    removed: int
    freed: int  # bytes


def prune(ex: str, logs: Iterable[str], own: elfcheck.Ownership) -> Pruned:
    """Prune the tree to what the logged workloads touched (10.4).

    Kept are the files the workloads touched, the entries of directories they opened, the symlink
    chains that reach kept files, the libraries kept ELF files need, the identity files and the
    licence texts; every other file and symlink is removed. Directories are never removed, so
    ownership and `ls` do not change.

    Raises:
        BuildError: When the logs name no program in the exclave.
    """
    root = os.path.join(ex, "tree")
    tree = elfcheck.Tree(root)
    keep: set[str] = set()
    whole: set[str] = set()
    programs = 0
    for what, r, v in layout.log_lines(logs):
        if what == "launcher" or not v.startswith("/") or r < 0:
            continue
        if elfcheck.host_owned(v, own):
            continue
        final = tree.resolve(v, links=keep)
        if final is None:
            continue
        real = tree.real(final)
        if os.path.isdir(real):
            if what == "open":  # a directory a program opened may be listed: keep it whole
                whole.add(final)
        else:
            keep.add(final)
            if what in ("exec", "load"):
                programs += 1
    if not programs:  # an empty, foreign or failed log would empty the exclave
        msg = "the logs name no program in this exclave; nothing to prune to"
        raise BuildError(msg)
    for f in [*IDENTITY_FILES, "/etc/ld.so.cache"]:
        if os.path.lexists(_v(root, f)):
            keep.add(f)
    for v in licence_files(root):  # the packages' licence texts go with every copy
        final = tree.resolve(v, links=keep)
        if final:
            keep.add(final)
    for d in whole:  # its own entries: a getdents shows names, nothing below them
        for name in os.listdir(_v(root, d)):
            if not os.path.isdir(os.path.join(_v(root, d), name)) or os.path.islink(
                os.path.join(_v(root, d), name)
            ):
                keep.add("/" + os.path.relpath(os.path.join(_v(root, d), name), root))
    # the libraries every kept ELF needs, by the loader's own search (10.3)
    elfs = []
    for v in sorted(keep):
        real = os.path.join(root, v.lstrip("/"))
        if os.path.isfile(real) and not os.path.islink(real) and "/.real/" not in v:
            with open(tree.payload(v), "rb") as f:
                if f.read(4) == b"\x7fELF":
                    elfs.append(v)
    for lib in elfcheck.needed_closure(tree, elfs, elfcheck.machine_for(ex)):
        final = tree.resolve(lib, links=keep)  # the chain of links, then the file they reach
        if final:
            keep.add(final)
    # the log names canonical paths, so every alias a program used is a symlink to keep:
    # every symlink in the tree that reaches a kept file, or a directory, stays with its chain;
    # the rest go
    for _real, v, st in layout.walk_files(root):
        if not stat.S_ISLNK(st.st_mode) or v in keep:
            continue
        chain: set[str] = set()
        final = tree.resolve(v, links=chain)
        if final and (final in keep or os.path.isdir(tree.real(final))):
            keep |= chain
            keep.add(v)
    kept = removed = freed = 0
    for dirpath, dirnames, filenames in os.walk(root):
        in_real = os.path.basename(dirpath) == ".real"
        for name in filenames + [x for x in dirnames if os.path.islink(os.path.join(dirpath, x))]:
            real = os.path.join(dirpath, name)
            v = "/" + os.path.relpath(real, root)
            w = (
                "/" + os.path.relpath(os.path.join(os.path.dirname(dirpath), name), root)
                if in_real
                else v
            )
            if w in keep:
                kept += 1
                continue
            st = os.lstat(real)
            is_wrap = not in_real and os.path.exists(os.path.join(dirpath, ".real", name))
            # originals and plain files; a wrapper is a link to the launcher
            if stat.S_ISREG(st.st_mode) and not is_wrap:
                freed += st.st_size
            os.remove(real)
            removed += 1
    return Pruned(kept, removed, freed)


def unwrap(ex: str, log: Log = print) -> int:
    """Move every original in `.real/` back over its wrapper, leaving a plain tree (10.1)."""
    root = os.path.join(ex, "tree")
    n = 0
    for dirpath, _dirnames, filenames in os.walk(root, topdown=False):
        if os.path.basename(dirpath) != ".real":
            continue
        parent = os.path.dirname(dirpath)
        for name in filenames:
            w = os.path.join(parent, name)
            if os.path.lexists(w):
                os.remove(w)
            os.rename(os.path.join(dirpath, name), w)
            n += 1
        os.rmdir(dirpath)
    log(f"unwrapped {n} executables")
    return n
