"""Read what a tree says about itself, for the suite and the oracles (DESIGN.md 17).

A test asserts what the tree says, never what one distribution spells, so the first functions here
each take a tree's root directory and answer a question about it. The next read and make an
exclave's files as the format states them (6.1, 6.4), so that the drivers judge the exclave command
only through its commands, whatever language answers them. The rest serve the drivers:
copy_exclave and fresh_exclave give a driver a copy of an exclave relinked with the build, so the
launcher under test is always build/launcher and never the one the exclave was wrapped with, and
kept_worlds keeps such a copy and an unwrapped tree between a driver's runs; and go_build makes the
Go regression's programs, which the matrix builds on the host for VMs that have no go.
"""

import fcntl
import filecmp
import functools
import glob
import hashlib
import os
import platform
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
lazy from collections.abc import Iterator

from b3 import blake3

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_LAUNCHER = os.path.join(REPO, "build", "launcher")
# the exclave command, as scripts/build built it
TOOL = (os.path.join(REPO, "build", "exclave"),)
# the step before it (10.1), the command's unpack subcommand
UNPACK = (*TOOL, "unpack")
# The host identity files (8.4), which an exclave ships empty and the host answers for.
IDENTITY_FILES = (
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/localtime",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/certs/java/cacerts",
    "/etc/pki/java/cacerts",
)
# The identity directories (8.1 rule 5, 8.4): the two trust directories and SSSD's state.
IDENTITY_DIRS = ("/etc/ssl/certs", "/etc/pki/tls/certs", "/var/lib/sss")


VOLATILE_TOPS = ("/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run")


def tree_real_dir(root: str, d: str) -> str | None:
    """The directory d as the tree resolves it, as the launcher maps an identity file's copy (8.4).

    A chroot's view: the tree's links followed in the tree, a component the tree lacks taken as a
    directory to be made, as tool/paths.go's treeRealDir and src/vis.c's tree_real_of do. None
    where the launcher gives the copy no place: a file on the way, a loop, a link that cannot be
    read, or a directory under a volatile one, which is the host's.
    """
    cur, rest, hops = "", [p for p in d.split("/") if p], 0
    while rest:
        comp = rest.pop(0)
        if comp == ".":
            continue
        if comp == "..":
            cur = cur.rsplit("/", 1)[0] if "/" in cur else ""
            continue
        cand = cur + "/" + comp
        real = os.path.join(root, cand.lstrip("/"))
        if not os.path.lexists(real) or (os.path.isdir(real) and not os.path.islink(real)):
            cur = cand
            continue
        if not os.path.islink(real):
            return None
        hops += 1
        if hops > 40:
            return None
        try:
            text = os.readlink(real)
        except OSError:
            return None
        rest = [p for p in text.split("/") if p] + rest
        if text.startswith("/"):
            cur = ""
    cur = cur or "/"
    if any(cur == v or cur.startswith(v + "/") for v in VOLATILE_TOPS):
        return None
    return cur


def tree_place(root: str, v: str) -> str | None:
    """The real path in the tree where the launcher looks for v's copy, or None (tree_real_dir)."""
    d = tree_real_dir(root, os.path.dirname(v))
    if d is None:
        return None
    return os.path.join(root, d.lstrip("/"), os.path.basename(v))


def identity_links(root: str) -> None:
    """Give a kernel's root for bwrap the identity files as the launcher has them.

    Each identity file the tree lacks gets the empty placeholder `exclave wrap` ships (8.1 rule 5),
    so a tree wrapped by an earlier build has every one. One that is a host symlink gets the host's
    chain of links, each at its own name, since a bind of the host's file would hide the text the
    launcher reports and the kernel follows the whole chain on the host for it (8.4): Ubuntu
    18.04's /etc/localtime -> /usr/share/zoneinfo/Etc/UTC -> ../UCT. The oracles bind the file the
    chain ends at, at its own path, which needs a mount point in the read-only root, made here
    where that path is not under a volatile directory. Done again on a kept root.
    """
    for f in IDENTITY_FILES:
        # where the launcher maps the copy: Fedora's tree has /etc/ssl/certs -> /etc/pki/tls/certs,
        # which the tree resolves, never the host
        p = tree_place(root, f)
        if p is None:
            print(f"identity file {f} not placed in the kernel's root: no place in the tree (8.4)")
            continue
        if not os.path.lexists(p):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb"):
                pass
        if not os.path.islink(f):
            continue
        name = f
        for _ in range(40):  # the kernel's own limit on a chain
            if not os.path.islink(name):
                break
            text = os.readlink(name)
            at = tree_place(root, name)
            if at is None:
                break
            if os.path.lexists(at):
                os.remove(at)
            os.makedirs(os.path.dirname(at), exist_ok=True)
            os.symlink(text, at)
            if text.startswith("/"):
                name = text
            else:
                name = os.path.normpath(os.path.join(os.path.dirname(name), text))
        tp = tree_place(root, name)
        if tp is not None and not os.path.lexists(tp):
            os.makedirs(os.path.dirname(tp), exist_ok=True)
            with open(tp, "wb"):
                pass


def vbin(root: str, name: str) -> str:
    """Return a tool's virtual path as the tree spells it: /usr/bin, or /bin in an unmerged tree."""
    for d in ("usr/bin", "bin"):
        if os.path.lexists(os.path.join(root, d, name)):
            return "/" + d + "/" + name
    return "/usr/bin/" + name


def dir_link(root: str) -> str:
    """Return the virtual path of a top-level symlink of the tree to a directory, or "-" for none.

    /bin in a merged-usr tree; an unmerged one may have none.
    """
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if os.path.islink(p) and os.path.isdir(p):
            return "/" + name
    return "-"


def compiler(root: str, machine: str) -> str | None:
    """Return the name of the tree's C compiler, or None if it has none.

    The names tried are Debian's gcc-13 spellings, gcc, cc, clang and a versioned clang.
    """
    clangs = sorted(
        n
        for d in ("usr/bin", "bin")
        if os.path.isdir(os.path.join(root, d))
        for n in os.listdir(os.path.join(root, d))
        if re.match(r"clang-\d+$", n)
    )
    for name in [
        f"{machine}-linux-gnu-gcc-13",
        "x86_64-linux-gnu-gcc-13",
        "gcc-13",
        "gcc",
        "cc",
        "clang",
        *clangs,
    ]:
        if os.path.lexists(os.path.join(root, vbin(root, name).lstrip("/"))):
            return name
    return None


def triplet(root: str, machine: str) -> str:
    """Return the multiarch directory under /usr/lib where libc lives, or Debian's name for it."""
    d = os.path.join(root, "usr", "lib")
    for n in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if n.endswith("-linux-gnu") and os.path.exists(os.path.join(d, n, "libc.so.6")):
            return n
    return f"{machine}-linux-gnu"


def resolve(root: str, vpath: str) -> str:
    """Follow the tree's symlinks in a virtual path, as a chroot would resolve it.

    Returns the path unchanged if a component is missing or the links loop.
    """
    cur, rest, hops = "", [p for p in vpath.split("/") if p], 0
    while rest:
        comp = rest.pop(0)
        if comp == ".":
            continue
        if comp == "..":
            cur = cur.rsplit("/", 1)[0] if "/" in cur else ""
            continue
        cand = cur + "/" + comp
        real = os.path.join(root, cand.lstrip("/"))
        if not os.path.lexists(real):
            return vpath
        if os.path.islink(real):
            hops += 1
            if hops > 40:
                return vpath
            t = os.readlink(real)
            rest = [p for p in t.split("/") if p] + rest
            if t.startswith("/"):
                cur = ""
            continue
        cur = cand
    return cur or "/"


def libc(root: str, machine: str) -> str:
    """Return libc.so.6's virtual path as the loader names it, or musl's loader, its libc."""
    for v in (
        f"/lib/{triplet(root, machine)}/libc.so.6",
        "/lib64/libc.so.6",
        "/lib/libc.so.6",
        "/usr/lib/libc.so.6",
        f"/lib/ld-musl-{machine}.so.1",
    ):
        if os.path.lexists(os.path.join(root, v.lstrip("/"))):
            return v
    return "/lib/libc.so.6"


def glibc_version(root: str, machine: str) -> tuple[int, int] | None:
    """Return the version libc.so.6's banner names, or None for a tree without a glibc."""
    v = libc(root, machine)
    if not v.endswith("libc.so.6"):
        return None
    p = payload(root, resolve(root, v))
    if not os.path.isfile(p):
        return None
    with open(p, "rb") as f:
        m = re.search(rb"release version (\d+)\.(\d+)", f.read())
    return (int(m.group(1)), int(m.group(2))) if m else None


def has_static_libc(root: str) -> bool:
    """The tree holds a libc.a, in /usr/lib or a directory of it, as glibc and musl install one."""
    lib = os.path.join(root, "usr", "lib")
    return any(
        os.path.exists(os.path.join(d, "libc.a"))
        for d in [lib, lib + "64", *glob.glob(os.path.join(lib, "*-linux-*"))]
    )


def mount_of(path: str) -> str:
    """The mount point holding path, the longest in /proc/self/mountinfo."""
    real = os.path.realpath(path)
    best = "/"
    with open("/proc/self/mountinfo") as mountinfo:
        for entry in mountinfo:
            mp = entry.split()[4].encode().decode("unicode_escape")
            if (real == mp or real.startswith(mp.rstrip("/") + "/")) and len(mp) > len(best):
                best = mp
    return best


@functools.cache
def memfd_exec_under_bwrap() -> int | None:
    """The errno of running an empty executable memfd under bwrap, or None where bwrap cannot.

    ENOEXEC where the kernel reads it, as it does natively on every kernel of the matrix; EACCES
    where an AppArmor profile confines bwrap's child, as Ubuntu 26.10's bwrap-userns-restrict
    does (unpriv_bwrap), whose exec rule names paths under / and so refuses a file with none. The
    oracles accept EACCES for every exec of a memfd under bwrap on such a host, where the launcher
    answers as the host does natively.
    """
    script = (
        "import os\n"
        # MFD_EXEC (6.3; EINVAL before, where nothing seals a plain memfd against exec)
        "try:\n    fd = os.memfd_create('probe', 0x10)\n"
        "except OSError:\n    fd = os.memfd_create('probe', 0)\n"
        "try:\n    os.execve(f'/proc/self/fd/{fd}', ['x'], {})\n"
        "except OSError as e:\n    print(e.errno)\n"
    )
    bwrap = ["bwrap", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev"]
    try:
        p = subprocess.run(
            [*bwrap, sys.executable, "-I", "-c", script], capture_output=True, check=False
        )
    except FileNotFoundError:
        return None
    out = p.stdout.decode().strip()
    return int(out) if p.returncode == 0 and out.isdigit() else None


def interp(path: str) -> str | None:
    """Return the loader an ELF64 file's PT_INTERP names, or None when it names none."""
    with open(path, "rb") as f:
        h = f.read(64)
        phoff, phentsize, phnum = (
            struct.unpack_from("<Q", h, 32)[0],
            struct.unpack_from("<H", h, 54)[0],
            struct.unpack_from("<H", h, 56)[0],
        )
        f.seek(phoff)
        ph = f.read(phentsize * phnum)
        for i in range(phnum):
            kind, _flags, off, _vaddr, _paddr, size = struct.unpack_from(
                "<IIQQQQ", ph, i * phentsize
            )
            if kind == 3 and size > 1:  # PT_INTERP; one byte is a debug file's empty one
                f.seek(off)
                return f.read(size).rstrip(b"\0").decode()
    return None


def soname(path: str) -> str | None:
    """Return the DT_SONAME an ELF64 shared object carries, or None when it has none."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 64 or data[:5] != b"\x7fELF\x02":
        return None
    phoff, phnum = struct.unpack_from("<Q", data, 32)[0], struct.unpack_from("<H", data, 56)[0]
    loads: list[tuple[int, int, int]] = []
    dyn = None
    for i in range(phnum):
        kind, _flags, off, vaddr, _paddr, size = struct.unpack_from("<IIQQQQ", data, phoff + 56 * i)
        if kind == 1:  # PT_LOAD
            loads.append((off, vaddr, size))
        elif kind == 2:  # PT_DYNAMIC
            dyn = (off, size)
    if dyn is None:
        return None
    tags: dict[int, int] = {}
    for d in range(dyn[0], dyn[0] + dyn[1], 16):
        tag, val = struct.unpack_from("<qQ", data, d)
        if tag == 0:
            break
        if tag not in tags:
            tags[tag] = val
    if 5 not in tags or 14 not in tags:  # DT_STRTAB, DT_SONAME
        return None
    strtab = tags[5]
    for off, vaddr, size in loads:
        if vaddr <= strtab < vaddr + size:
            strtab = strtab - vaddr + off
            break
    at = strtab + tags[14]
    end = data.find(b"\0", at)
    return data[at:end].decode(errors="replace") if 0 <= at < len(data) and end >= 0 else None


# ---------------------------------------------------------------- an exclave's files (6.1, 6.4)
def link_or_copy(src: str, dst: str) -> None:
    """Hard-link src at dst where the filesystem allows it, and copy it otherwise."""
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def payload(root: str, vpath: str) -> str:
    """Return the real path of the file vpath names: a wrapper's original in .real/, or the file."""
    real = os.path.join(root, vpath.lstrip("/"))
    d, n = os.path.split(real)
    orig = os.path.join(d, ".real", n)
    return orig if os.path.exists(orig) else real


def walk_files(root: str) -> Iterator[str]:
    """Yield the real path of every entry under root but a directory, .real/ left out."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".real"]
        for name in filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]:
            yield os.path.join(dirpath, name)


def is_wrapper(path: str, ex: str) -> bool:
    """Return whether path is a wrapper of ex's launcher: a hard link to it, or a copy (6.1)."""
    st, ls = os.lstat(path), os.stat(os.path.join(ex, ".exclave", "launcher"))
    if not stat.S_ISREG(st.st_mode):
        return False
    d, n = os.path.split(path)
    return (st.st_dev, st.st_ino) == (ls.st_dev, ls.st_ino) or (
        os.path.exists(os.path.join(d, ".real", n))
        and filecmp.cmp(path, os.path.join(ex, ".exclave", "launcher"), shallow=False)
    )


def licence_files(root: str) -> set[str]:
    """Return the virtual paths of the packages' licence texts, which prune keeps (10.4).

    Under every usr/share/ of the tree: doc/PKG/copyright, and every file under common-licenses/
    and licenses/; and apk's database, /lib/apk/db/installed, which records Alpine's licences by
    name.
    """
    found = []
    for dirpath, dirnames, _ in os.walk(root):
        if not dirpath.endswith("/usr/share"):
            continue
        dirnames[:] = []
        doc = os.path.join(dirpath, "doc")
        found += [
            os.path.join(doc, pkg, "copyright")
            for pkg in (os.listdir(doc) if os.path.isdir(doc) else [])
            if os.path.isfile(os.path.join(doc, pkg, "copyright")) and not pkg.startswith(".")
        ]
        for top in ("common-licenses", "licenses"):
            for d, _, filenames in os.walk(os.path.join(dirpath, top)):
                found += [os.path.join(d, n) for n in filenames]
    apk_db = os.path.join(root, "lib", "apk", "db", "installed")
    return {"/" + os.path.relpath(f, root) for f in found} | (
        {"/lib/apk/db/installed"} if os.path.lexists(apk_db) else set()
    )


def _unquote(field: str) -> str:
    """Return a quoted string of the grammar (6.2) with its escapes undone.

    The escapes are undone in the string's bytes, which are then read as a path's are: a byte that
    is not UTF-8, escaped or not, comes back as os.fsdecode gives it.
    """
    escapes = {b"\\": b"\\", b'"': b'"', b"n": b"\n", b"t": b"\t"}
    return os.fsdecode(
        re.sub(
            rb"\\(x[0-9a-f]{2}|.)",
            lambda m: (
                bytes([int(m.group(1)[1:], 16)]) if len(m.group(1)) == 3 else escapes[m.group(1)]
            ),
            os.fsencode(field[1:-1]),
        )
    )


def records(path: str) -> dict[str, list[list[str]]]:
    """Return the fields of each record of a manifest or hashes file (6.2, 6.4), by key."""
    out: dict[str, list[list[str]]] = {}
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                continue
            key, _, rest = line.rstrip("\n").partition(" ")
            fields = re.findall(r'"(?:[^"\\]|\\.)*"|\S+', rest)
            out.setdefault(key, []).append(
                [_unquote(v) if v.startswith('"') else v for v in fields]
            )
    return out


def owned(ex: str) -> list[str]:
    """Return the prefixes ex owns (8.1): its own records and its tree's non-empty top names."""
    m = os.path.join(ex, ".exclave", "manifest")
    own = [r[0] for r in records(m).get("own", [])] if os.path.exists(m) else []
    root = os.path.join(ex, "tree")
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        try:
            empty = not os.path.islink(p) and os.path.isdir(p) and not os.listdir(p)
        except PermissionError:
            empty = False
        if not empty:
            own.append("/" + name)
    return own


def b3(data: bytes) -> str:
    """The hash the hashes file writes (6.4): "b3:" and the BLAKE3-256 of data, in Python."""
    return "b3:" + blake3(data)


def tree_hash(root: str) -> str:
    """Return the tree hash of 6.4, computed here as the design states it.

    Its BLAKE3 is Python's (test/b3.py), slow but independent of the command's: for the small
    trees a test makes.
    """
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".real"]
        names = dirnames + filenames
        rd = os.path.join(dirpath, ".real")
        if os.path.isdir(rd) and not os.path.islink(rd):
            names += [
                ".real/" + n
                for n in os.listdir(rd)
                if not os.path.lexists(os.path.join(dirpath, n))
            ]
        for name in names:
            real = os.path.join(dirpath, name)
            rel = os.fsencode(os.path.relpath(real, root))
            st = os.lstat(real)
            if stat.S_ISLNK(st.st_mode):
                entries.append(rel + b"\0l\0" + os.fsencode(os.readlink(real)) + b"\0")
            elif stat.S_ISDIR(st.st_mode):
                entries.append(rel + b"\0d\0\0")
            elif stat.S_ISREG(st.st_mode):
                d, n = os.path.split(real)
                orig = os.path.join(d, ".real", n)
                with open(orig if os.path.exists(orig) else real, "rb") as f:
                    h = blake3(f.read())
                kind = b"x" if st.st_mode & 0o111 else b"f"
                entries.append(rel + b"\0" + kind + b"\0" + h.encode() + b"\0")
    return b3(b"".join(sorted(entries)))


def unwrap_tree(ex: str) -> None:
    """Move every original in ex's tree back over its wrapper, without the exclave command.

    For a copy that is no exclave of its own, such as the oracles' bare tree.
    """
    for dirpath, dirnames, _filenames in os.walk(os.path.join(ex, "tree"), topdown=False):
        if ".real" not in dirnames:
            continue
        rd = os.path.join(dirpath, ".real")
        for n in os.listdir(rd):
            os.replace(os.path.join(rd, n), os.path.join(dirpath, n))
        os.rmdir(rd)


def wrap_unchecked(ex: str, manifest: bytes) -> None:
    """Wrap every executable of ex's tree and write its manifest and hashes file (6.1, 6.4).

    The suite's own wrap of the tree it is given, which need not pass the static check: each
    original moves to .real/ beside a hard link to .exclave/launcher, and the hashes file records
    the launcher, the manifest and the tree, and no tool, since no tool wrote it. The tree's hash is
    the command's (`exclave hash`), since a whole tree is too large for the Python BLAKE3;
    test/regress_tool.py holds the command's to tree_hash.
    """
    ld = os.path.join(ex, ".exclave", "launcher")
    root = os.path.join(ex, "tree")
    for path in list(walk_files(root)):
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111 or is_wrapper(path, ex):
            continue
        d, n = os.path.split(path)
        os.makedirs(os.path.join(d, ".real"), exist_ok=True)
        os.rename(path, os.path.join(d, ".real", n))
        link_or_copy(ld, path)
    with open(os.path.join(ex, ".exclave", "manifest"), "wb") as f:
        f.write(manifest)
    with open(ld, "rb") as f:
        launcher = f.read()
    p = subprocess.run([*TOOL, "hash", ex], capture_output=True, text=True, check=False)
    if p.returncode or not p.stdout.startswith("b3:"):
        sys.exit(f"exclave hash {ex}: {p.stdout}{p.stderr}")
    with open(os.path.join(ex, ".exclave", "hashes"), "w") as f:
        f.write(
            f'hashes 1\n\nlauncher "{b3(launcher)}"\n\n'
            f'manifest "{b3(manifest)}"\n\ntree "{p.stdout.strip()}"\n'
        )


# ---------------------------------------------------------------- an exclave for a driver (17)
def socket_file(path: str) -> None:
    """Make a socket file at path, replacing any there, bound through its directory's descriptor.

    Only the name counts against sun_path's 108 bytes, so a deep checkout or work directory does
    not.
    """
    d, name = os.path.split(path)
    if os.path.lexists(path):
        os.remove(path)
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    sk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sk.bind(f"/proc/self/fd/{fd}/{name}")
    finally:
        sk.close()
        os.close(fd)


def copy_exclave(src: str, dst: str) -> str:
    """Copy an exclave for a driver or a test to alter, and return the copy.

    The tree's files are hard-linked and the files under .exclave/ copied, since a manifest or
    hashes file written through a hard link would change the given exclave's.
    """
    shutil.copytree(src, dst, symlinks=True, copy_function=link_or_copy)
    for name in os.listdir(os.path.join(dst, ".exclave")):
        p = os.path.join(dst, ".exclave", name)
        if os.path.isfile(p) and not os.path.islink(p):
            with open(p, "rb") as f:
                data = f.read()
            mode = os.stat(p).st_mode
            os.remove(p)
            with open(p, "wb") as f:
                f.write(data)
            os.chmod(p, mode)
    return dst


def fresh_exclave(src: str, dst: str, launcher: str = BUILD_LAUNCHER) -> str:
    """Copy an exclave as copy_exclave does, then relink every wrapper to launcher.

    The launcher a driver runs is always the checkout's build, never the one an exclave carries,
    which is the one it was wrapped with and which a rebuild leaves behind. The copy is made anew on
    every run, so nothing has to be remembered.
    """
    if not os.path.isfile(launcher):
        sys.exit(f"no launcher at {launcher}: run scripts/build")
    copy_exclave(src, dst)
    relink(dst, launcher)
    return dst


def relink(ex: str, launcher: str) -> None:
    """Relink every wrapper of ex to launcher with the exclave command (10.1)."""
    p = subprocess.run([*TOOL, "relink", ex, launcher], capture_output=True, check=False)
    if p.returncode:
        msg = f"relink {ex}: {(p.stdout + p.stderr).decode(errors='replace')[-600:]}"
        raise RuntimeError(msg)


def relink_if_stale(ex: str, launcher: str = BUILD_LAUNCHER) -> bool:
    """Relink a copy kept between runs when the build has changed; return whether it did.

    The check compares the two launchers byte for byte, so a rebuild never has to be remembered by
    hand.
    """
    if not filecmp.cmp(launcher, os.path.join(ex, ".exclave", "launcher"), shallow=False):
        relink(ex, launcher)
        return True
    return False


# the locks kept_worlds holds until the process exits
_KEPT_LOCKS: list[int] = []


def host_trust_link() -> tuple[str, str] | None:
    """A subject-hash link in the host's /etc/ssl/certs and the name it points at, or None."""
    d = "/etc/ssl/certs"
    if not os.path.isdir(d):
        return None
    for n in sorted(os.listdir(d)):
        p = os.path.join(d, n)
        if n.endswith(".0") and os.path.islink(p) and os.path.exists(p):
            t = os.readlink(p)
            if "/" not in t and os.path.islink(os.path.join(d, t)):
                return n, t
    return None


def identity_dir_binds(root: str, *, targets: bool = False) -> list[str]:
    """The bwrap arguments giving a kernel's root the identity directories as the launcher has them.

    Each identity directory the host has is bound, writable, so that a write answers with the host's
    permissions as the launcher's does (8.4), at its own name, or, where the host's name is a link,
    the host's link is laid at the name in the kernel's root, as identity_links lays a file's, and
    the directory it reaches is bound at its own name, which the launcher makes an identity
    directory too (8.1 rule 5). The mount points are made in root, replacing a link the tree has
    there. With targets, the directory of each link's target that lies outside the identity
    directory is bound at its own name as well, so that the kernel reaches the host's certificate
    as the launcher's hand-off does; that changes every path that names those directories, so only
    the syscall probe, whose forms never name them, asks for it. Done again on a kept root.
    """
    args: list[str] = []
    seen: list[str] = []

    def mount_point(p: str) -> None:
        at = os.path.join(root, p.lstrip("/"))
        if os.path.islink(at):
            os.remove(at)
        os.makedirs(at, exist_ok=True)

    for d in IDENTITY_DIRS:
        if not os.path.isdir(d):
            continue
        reached = os.path.realpath(d)
        if os.path.islink(d):
            at = os.path.join(root, d.lstrip("/"))
            if os.path.lexists(at) and not os.path.islink(at) and os.path.isdir(at):
                shutil.rmtree(at)
            elif os.path.lexists(at):
                os.remove(at)
            os.makedirs(os.path.dirname(at), exist_ok=True)
            os.symlink(os.readlink(d), at)
            mount = reached
        else:
            mount = d
        mount_point(mount)
        args += ["--bind", reached, mount]
        seen.append(reached)
        if not targets:
            continue
        for name in sorted(os.listdir(reached)):
            p = os.path.join(reached, name)
            if not os.path.islink(p) or not os.path.exists(p):
                continue
            t = os.path.dirname(os.path.realpath(p))
            if any(t == s or t.startswith(s + "/") for s in seen):
                continue
            mount_point(t)
            args += ["--bind", t, t]
            seen.append(t)
    return args


def kept_worlds(src: str, driver: str) -> tuple[str, str]:
    """The two worlds an oracle runs in, kept between its runs.

    Returns the launcher's exclave and the kernel's root, under
    build/kept/DRIVER/<exclave>-<hashes file's hash>: a copy of src relinked with the build,
    and relinked again whenever the build has changed since, and an unwrapped copy of its tree for
    bwrap, both hard links to src's tree. They are made once per input, whole or not at all, and the
    caller holds them, locked, until it exits; what a driver adds to either is its own to redo on
    every run. A copy made on every run cost the oracles about half their time.
    """
    with open(os.path.join(src, ".exclave", "hashes"), "rb") as f:
        key = hashlib.blake2b(f.read(), digest_size=6).hexdigest()
    top = os.path.join(REPO, "build", "kept", driver)
    os.makedirs(top, exist_ok=True)
    name = os.path.basename(os.path.normpath(src)).removesuffix(".exclave") + "-" + key
    lock = os.open(os.path.join(top, name + ".lock"), os.O_RDWR | os.O_CREAT, 0o644)
    fcntl.flock(lock, fcntl.LOCK_EX)
    _KEPT_LOCKS.append(lock)
    kept = os.path.join(top, name)
    if not os.path.isdir(kept):
        part = kept + ".part"
        shutil.rmtree(part, ignore_errors=True)
        ex = fresh_exclave(src, os.path.join(part, "exclave"))
        shutil.copytree(
            os.path.join(ex, "tree"),
            os.path.join(part, "bare", "tree"),
            symlinks=True,
            copy_function=link_or_copy,
        )
        unwrap_tree(os.path.join(part, "bare"))
        os.rename(part, kept)
    else:
        relink_if_stale(os.path.join(kept, "exclave"))
    return os.path.join(kept, "exclave"), os.path.join(kept, "bare", "tree")


# the Go regression's programs (17.4), as go links them for the machine; low_image is the image
# from 0x10000 that Go's aarch64 linker lays out (13 item 24)
GO_BUILDS: tuple[tuple[str, list[str]], ...] = (("go_paths", []),)
GOARCH = {"x86_64": "amd64", "aarch64": "arm64"}


def go_toolchain() -> str | None:
    """Return the pinned go in .go/ (scripts/install-go), else the host's, else None."""
    pinned = os.path.join(REPO, ".go", "go", "bin", "go")
    if os.path.exists(pinned):
        return pinned
    return shutil.which("go") or next(
        (g for g in ("/usr/lib/go/bin/go", "/usr/local/go/bin/go") if os.path.exists(g)), None
    )


def go_build(go: str, out_dir: str, machine: str, work: str) -> list[tuple[str, str]]:
    """Build GO_BUILDS of test/progs/go_paths.go into out_dir, static with cgo off, for machine.

    Returns (name, path) for each build, or raises RuntimeError with go's message. work holds
    GOPATH; the build cache is build/gocache.
    """
    env = dict(
        os.environ,
        GOCACHE=os.path.join(REPO, "build", "gocache"),
        GOPATH=os.path.join(work, "gopath"),
        HOME=work,
        GO111MODULE="off",
        CGO_ENABLED="0",
        GOFLAGS="",
        GOTOOLCHAIN="local",
        GOOS="linux",
        GOARCH=GOARCH[machine],
    )
    os.makedirs(out_dir, exist_ok=True)
    out = []
    for name, flags in GO_BUILDS:
        path = os.path.join(out_dir, name)
        p = subprocess.run(
            [go, "build", *flags, "-o", path, os.path.join(REPO, "test", "progs", "go_paths.go")],
            cwd=work,
            env=env,
            capture_output=True,
            timeout=600,
            check=False,
        )
        if p.returncode:
            msg = "go build {} for {}: {}".format(
                name, machine, p.stderr.decode(errors="replace")[-600:]
            )
            raise RuntimeError(msg)
        out.append((name, path))
    return out


def go_build_cgo(go: str, out_dir: str, machine: str, work: str) -> str | None:
    """Build test/progs/go_fwd.go into out_dir as go_fwd, static with cgo, for machine.

    The C compiler is gcc for the host's own machine and aarch64-linux-gnu-gcc for aarch64 on
    another; returns None where that compiler is not installed, the one reason cgo cannot build
    here, and raises RuntimeError with go's message on any other failure.
    """
    cc = "gcc" if machine == platform.machine() else f"{machine}-linux-gnu-gcc"
    if not shutil.which(cc):
        return None
    env = dict(
        os.environ,
        GOCACHE=os.path.join(REPO, "build", "gocache"),
        GOPATH=os.path.join(work, "gopath"),
        HOME=work,
        GO111MODULE="off",
        CGO_ENABLED="1",
        CC=cc,
        GOFLAGS="",
        GOTOOLCHAIN="local",
        GOOS="linux",
        GOARCH=GOARCH[machine],
    )
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "go_fwd")
    p = subprocess.run(
        [
            go,
            "build",
            "-ldflags",
            "-linkmode external -extldflags -static",
            "-o",
            path,
            os.path.join(REPO, "test", "progs", "go_fwd.go"),
        ],
        cwd=work,
        env=env,
        capture_output=True,
        timeout=600,
        check=False,
    )
    if p.returncode:
        msg = f"go build go_fwd for {machine}: {p.stderr.decode(errors='replace')[-600:]}"
        raise RuntimeError(msg)
    return path
