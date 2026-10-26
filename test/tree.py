"""Read what a tree says about itself, for the suite and the oracles (DESIGN.md 17).

A test asserts what the tree says, never what one distribution spells, so the first functions here
each take a tree's root directory and answer a question about it. The rest serve the drivers:
copy_exclave and fresh_exclave give a driver a copy of an exclave relinked with the build, so the
launcher under test is always build/launcher and never the one the exclave was wrapped with; and
go_build makes the Go regression's programs, which the matrix builds on the host for VMs that have
no go.
"""

import filecmp
import os
import re
import shutil
import socket
import struct
import subprocess
import sys

lazy from exclave import cli, layout

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_LAUNCHER = os.path.join(REPO, "build", "launcher")


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
    shutil.copytree(src, dst, symlinks=True, copy_function=layout.link_or_copy)
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
    cli.cmd_relink(dst, launcher)
    return dst


def relink_if_stale(ex: str, launcher: str = BUILD_LAUNCHER) -> bool:
    """Relink a copy kept between runs when the build has changed; return whether it did.

    The check compares the two launchers byte for byte, so a rebuild never has to be remembered by
    hand.
    """
    if not filecmp.cmp(launcher, os.path.join(ex, ".exclave", "launcher"), shallow=False):
        cli.cmd_relink(ex, launcher)
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
