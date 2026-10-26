"""tree.py — what a tree says about itself, for the suite and the oracles (DESIGN.md 17): a test asserts what the
tree says, never what one distribution spells. Every function takes the tree's root directory; then the one way a
driver takes an exclave: a copy of its own, relinked with the build, so that the launcher under test is always build/launcher
and never the one an exclave was wrapped with; and the Go regression's builds, which the matrix makes on the host for VMs
that have no go.
"""

import filecmp
import os
import re
import shutil
import socket
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_LAUNCHER = os.path.join(REPO, "build", "launcher")
sys.path.insert(0, os.path.join(REPO, "exclave"))


def vbin(root, name):
    """A tool's virtual path as the tree spells it: /usr/bin, or /bin where the tree is not merged."""
    for d in ("usr/bin", "bin"):
        if os.path.lexists(os.path.join(root, d, name)):
            return "/" + d + "/" + name
    return "/usr/bin/" + name


def compiler(root, machine):
    """The tree's C compiler by name: Debian's gcc-13 spellings, gcc, cc, clang, or a versioned clang; None if none."""
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


def triplet(root, machine):
    """Debian's multiarch directory under /usr/lib where libc lives, or the machine's conventional name."""
    d = os.path.join(root, "usr", "lib")
    for n in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if n.endswith("-linux-gnu") and os.path.exists(os.path.join(d, n, "libc.so.6")):
            return n
    return f"{machine}-linux-gnu"


def resolve(root, vpath):
    """A virtual path with the tree's symlinks followed, as a chroot would resolve it; the path itself if a
    component is missing.
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


def libc(root, machine):
    """libc.so.6 as the loader names it, or musl's loader, which is its libc."""
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
def socket_file(path) -> None:
    """A socket file at path, bound through its directory's descriptor, so that only the name counts against sun_path's
    108 bytes and a deep checkout or work directory does not. A stale one is replaced.
    """
    d, name = os.path.split(path)
    if os.path.lexists(path):
        os.remove(path)
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    sk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sk.bind("/proc/self/fd/%d/%s" % (fd, name))
    finally:
        sk.close()
        os.close(fd)


def copy_exclave(src, dst):
    """A copy of an exclave for a driver or a test to alter: the tree's files hard-linked, the files under .exclave/ copied, since a
    manifest or hashes file written through a hard link would change the given exclave's.
    """
    import exclave

    shutil.copytree(src, dst, symlinks=True, copy_function=exclave.link_or_copy)
    for name in os.listdir(os.path.join(dst, ".exclave")):
        p = os.path.join(dst, ".exclave", name)
        if os.path.isfile(p) and not os.path.islink(p):
            data = open(p, "rb").read()
            mode = os.stat(p).st_mode
            os.remove(p)
            with open(p, "wb") as f:
                f.write(data)
            os.chmod(p, mode)
    return dst


def fresh_exclave(src, dst, launcher=BUILD_LAUNCHER):
    """copy_exclave, then every wrapper relinked to build/launcher (exclave relink, about a second for a gcc exclave): the
    launcher a driver runs is always the checkout's build, never the one an exclave carries, which is the one it was wrapped with and
    which a rebuild leaves behind. The copy is made anew on every run, so nothing has to be remembered.
    """
    import exclave

    if not os.path.isfile(launcher):
        sys.exit(f"no launcher at {launcher}: run make")
    copy_exclave(src, dst)
    exclave.cmd_relink(dst, launcher)
    return dst


def relink_if_stale(ex, launcher=BUILD_LAUNCHER) -> bool:
    """A copy kept between runs, relinked again when the build has changed since it was made: the check is a byte
    comparison of two small files, the relink a second, so a rebuild never has to be remembered by hand.
    """
    import exclave

    if not filecmp.cmp(launcher, os.path.join(ex, ".exclave", "launcher"), shallow=False):
        exclave.cmd_relink(ex, launcher)
        return True
    return False


# the Go regression's programs (17.4): as go links for the machine, and from 0x10000 as its aarch64 linker does, an image
# past where the syscall page lay in early versions (13 item 24)
GO_BUILDS = (("go_paths", []), ("go_paths_low", ["-ldflags=-T 0x11000"]))
GOARCH = {"x86_64": "amd64", "aarch64": "arm64"}


def go_toolchain():
    return shutil.which("go") or next(
        (g for g in ("/usr/lib/go/bin/go", "/usr/local/go/bin/go") if os.path.exists(g)), None
    )


def go_build(go, out_dir, machine, work):
    """GO_BUILDS of test/progs/go_paths.go into out_dir, static with cgo off, for machine; [(name, path)], or a
    RuntimeError with go's message. work holds GOPATH; the build cache is build/gocache.
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
        )
        if p.returncode:
            msg = "go build {} for {}: {}".format(
                name, machine, p.stderr.decode(errors="replace")[-600:]
            )
            raise RuntimeError(msg)
        out.append((name, path))
    return out


def load_span(path):
    """The lowest and highest addresses an ELF64 file's PT_LOAD segments cover, bss included."""
    import struct

    with open(path, "rb") as f:
        h = f.read(64)
        phoff, phentsize, phnum = (
            struct.unpack_from("<Q", h, 32)[0],
            struct.unpack_from("<H", h, 54)[0],
            struct.unpack_from("<H", h, 56)[0],
        )
        f.seek(phoff)
        ph = f.read(phentsize * phnum)
    loads = [struct.unpack_from("<IIQQQQQQ", ph, i * phentsize) for i in range(phnum)]
    loads = [(l[3], l[3] + l[6]) for l in loads if l[0] == 1]
    return min(a for a, b in loads), max(b for a, b in loads)
