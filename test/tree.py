"""Read what a tree says about itself, for the suite and the oracles (DESIGN.md 17).

A test asserts what the tree says, never what one distribution spells, so the first functions here
each take a tree's root directory and answer a question about it. The next read and make an
exclave's files as the format states them (6.1, 6.4), so that the drivers judge the exclave command
only through its commands, whatever language answers them. The rest serve the drivers:
copy_exclave and fresh_exclave give a driver a copy of an exclave relinked with the build, so the
launcher under test is always build/launcher and never the one the exclave was wrapped with; and
go_build makes the Go regression's programs, which the matrix builds on the host for VMs that have
no go.
"""

import filecmp
import hashlib
import os
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tomllib
lazy from collections.abc import Iterator

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_LAUNCHER = os.path.join(REPO, "build", "launcher")
# the exclave command, as every driver runs it
TOOL = (sys.executable, "-m", "exclave")
# The host identity files (8.4), which an exclave ships empty and the host answers for.
IDENTITY_FILES = (
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
)


def vbin(root: str, name: str) -> str:
    """Return a tool's virtual path as the tree spells it: /usr/bin, or /bin in an unmerged tree."""
    for d in ("usr/bin", "bin"):
        if os.path.lexists(os.path.join(root, d, name)):
            return "/" + d + "/" + name
    return "/usr/bin/" + name


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
    and licenses/.
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
    return {"/" + os.path.relpath(f, root) for f in found}


def _unquote(field: str) -> str:
    """Return a quoted string of the grammar (6.2) with its escapes undone."""
    escapes = {"\\": "\\", '"': '"', "n": "\n", "t": "\t"}
    return re.sub(
        r"\\(x[0-9a-f]{2}|.)",
        lambda m: chr(int(m.group(1)[1:], 16)) if len(m.group(1)) == 3 else escapes[m.group(1)],
        field[1:-1],
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


def b2(data: bytes) -> str:
    return "b2:" + hashlib.blake2b(data, digest_size=32).hexdigest()


def tree_hash(root: str) -> str:
    """Return the tree hash of 6.4, computed here as the design states it."""
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
                    h = hashlib.file_digest(f, lambda: hashlib.blake2b(digest_size=32)).hexdigest()
                kind = b"x" if st.st_mode & 0o111 else b"f"
                entries.append(rel + b"\0" + kind + b"\0" + h.encode() + b"\0")
    return b2(b"".join(sorted(entries)))


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
    the launcher, the manifest and the tree.
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
    with open(os.path.join(REPO, "pyproject.toml"), "rb") as f:
        version = tomllib.load(f)["project"]["version"]
    with open(os.path.join(ex, ".exclave", "hashes"), "w") as f:
        f.write(
            f'hashes 1\n\ntool "{version}"\n\nlauncher "{b2(launcher)}"\n\n'
            f'manifest "{b2(manifest)}"\n\ntree "{tree_hash(root)}"\n'
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


# the Go regression's programs (17.4): as go links for the machine, and from 0x10000 as its
# aarch64 linker does, an image reaching past the syscall page's former address (13 item 24)
GO_BUILDS: tuple[tuple[str, list[str]], ...] = (
    ("go_paths", []),
    ("go_paths_low", ["-ldflags=-T 0x11000"]),
)
GOARCH = {"x86_64": "amd64", "aarch64": "arm64"}


def go_toolchain() -> str | None:
    """Return the host's go, or None."""
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


def load_span(path: str) -> tuple[int, int]:
    """Return the lowest and highest addresses an ELF64 file's PT_LOAD segments cover, with bss."""
    with open(path, "rb") as f:
        h = f.read(64)
        phoff, phentsize, phnum = (
            struct.unpack_from("<Q", h, 32)[0],
            struct.unpack_from("<H", h, 54)[0],
            struct.unpack_from("<H", h, 56)[0],
        )
        f.seek(phoff)
        ph = f.read(phentsize * phnum)
    headers = [struct.unpack_from("<IIQQQQQQ", ph, i * phentsize) for i in range(phnum)]
    loads = [(h[3], h[3] + h[6]) for h in headers if h[0] == 1]
    return min(a for a, _ in loads), max(b for _, b in loads)
