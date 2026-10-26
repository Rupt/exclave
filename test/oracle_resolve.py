"""oracle_resolve.py — the kernel as the oracle for canonicalisation (DESIGN.md 17, item 2).

A random maze of directories, files and symlinks (relative, absolute, dangling, looping, with `..`
and trailing slashes) is added to a copy of an exclave under /maze. Every generated path is resolved
twice: by the kernel with openat2(RESOLVE_IN_ROOT) on the tree, which has chroot semantics, and by
the launcher from inside the exclave. The resulting paths and errnos must agree.

    test/oracle_resolve.py --exclave EXCLAVE [--work DIR] [--paths N] [--seed S] [--keep]
"""

import argparse
import ctypes
import errno
import os
import random
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

SYS_openat2 = 437
# this machine's bits: aarch64's O_NOFOLLOW is not x86-64's
O_PATH, O_NOFOLLOW = os.O_PATH, os.O_NOFOLLOW
RESOLVE_IN_ROOT = 0x10
libc = ctypes.CDLL(None, use_errno=True)


class OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]


def kernel_resolve(
    rootfd: int, root: str, path: str, *, follow: bool
) -> tuple[str, None] | tuple[None, int]:
    """(virtual path, None) or (None, errno) via openat2 RESOLVE_IN_ROOT."""
    how = OpenHow(O_PATH | (0 if follow else O_NOFOLLOW), 0, RESOLVE_IN_ROOT)
    rel = path.lstrip("/") or "."
    if path.startswith("/") and rel == ".":
        rel = "."
    fd = libc.syscall(SYS_openat2, rootfd, rel.encode(), ctypes.byref(how), ctypes.sizeof(how))
    # EAGAIN under RESOLVE_IN_ROOT means "retry": the kernel saw what it
    # took for a concurrent rename or mount (openat2(2)); RHEL 8's 4.18 says so for ..
    for _ in range(20):
        if fd >= 0 or ctypes.get_errno() != errno.EAGAIN:
            break
        fd = libc.syscall(SYS_openat2, rootfd, rel.encode(), ctypes.byref(how), ctypes.sizeof(how))
    if fd < 0:
        return None, ctypes.get_errno()
    real = os.readlink(f"/proc/self/fd/{fd}")
    os.close(fd)
    if real == root:
        return "/", None
    if real.startswith(root + "/"):
        return real[len(root) :], None
    return real, None  # should not happen under RESOLVE_IN_ROOT


def make_maze(
    root: str, rng: random.Random, ndirs: int = 12, nfiles: int = 15, nlinks: int = 40
) -> tuple[list[str], list[str], list[str]]:
    base = os.path.join(root, "maze")
    os.makedirs(base)
    dirs = ["/maze"]
    for i in range(ndirs):
        parent = rng.choice(dirs)
        d = f"{parent}/d{i}"
        os.makedirs(os.path.join(root, d.lstrip("/")), exist_ok=True)
        dirs.append(d)
    files = []
    for i in range(nfiles):
        f = f"{rng.choice(dirs)}/f{i}"
        with open(os.path.join(root, f.lstrip("/")), "w") as fh:
            fh.write("x")
        files.append(f)
    names = dirs + files
    links = []
    for i in range(nlinks):
        where = f"{rng.choice(dirs)}/l{i}"
        kind = rng.random()
        if kind < 0.35:
            target = rng.choice(names)  # absolute, into the maze
        elif kind < 0.6:
            t = rng.choice(names)
            depth = where.count("/") - 1
            # relative with .. (may overshoot)
            target = "/".join([".."] * rng.randint(0, depth)) + t
            target = target.lstrip("/") or "."
        elif kind < 0.75:
            target = rng.choice(
                [
                    "../" * rng.randint(1, 8) + "usr/bin",
                    "/usr/../maze",
                    "./d0/../",
                    "/etc/../maze/d1/",
                ]
            )
        elif kind < 0.85:
            target = f"{rng.choice(dirs)}/missing{i}"  # dangling
        elif kind < 0.93:
            target = where  # loop to itself
        else:
            target = f"/maze/l{rng.randint(0, nlinks - 1)}"  # possible longer loop
        os.symlink(target, os.path.join(root, where.lstrip("/")))
        links.append(where)
    return dirs, files, links


def gen_paths(
    rng: random.Random, dirs: list[str], files: list[str], links: list[str], n: int
) -> list[str]:
    names = dirs + files + links
    out = []
    for _ in range(n):
        base = rng.choice(names)
        parts = [p for p in base.split("/") if p]
        for _ in range(rng.randint(0, 3)):
            r = rng.random()
            if r < 0.3:
                parts.append("..")
            elif r < 0.4:
                parts.append(".")
            elif r < 0.6:
                parts.append(rng.choice(names).split("/")[-1])
            elif r < 0.7:
                parts.append("nonexistent")
            else:
                parts.insert(rng.randint(0, len(parts)), rng.choice(names).split("/")[-1])
        p = "/" + "/".join(parts)
        if rng.random() < 0.15:
            p += "/"
        if rng.random() < 0.1:
            p = p.replace("/", "//", 1)
        out.append(("nofollow " if rng.random() < 0.25 else "") + p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--exclave", required=True)
    ap.add_argument("--work", default=os.path.join(REPO, "build", "resolve-work"))
    ap.add_argument("--paths", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    rng = random.Random(a.seed)
    probe = OpenHow(O_PATH, 0, RESOLVE_IN_ROOT)
    if (
        libc.syscall(SYS_openat2, -100, b".", ctypes.byref(probe), ctypes.sizeof(probe)) < 0
        and ctypes.get_errno() == errno.ENOSYS
    ):
        print(
            "openat2 is not available on this kernel (5.6 and later); "
            "the resolution oracle cannot run here"
        )
        return 0
    work = os.path.abspath(a.work)
    if os.path.exists(work):
        shutil.rmtree(work)
    import tree

    # a copy relinked with the build (17)
    ex = tree.fresh_exclave(os.path.abspath(a.exclave), os.path.join(work, "exclave"))
    root = os.path.join(ex, "tree")
    dirs, files, links = make_maze(root, rng)
    with open(os.path.join(ex, ".exclave", "manifest"), "w") as f:
        # /maze is a non-empty top-level directory: the exclave's by the tree alone (8.1)
        f.write("exclave 1\n")
    import platform

    cc = tree.compiler(root, platform.machine())
    if not cc:
        sys.exit("no C compiler in the exclave")
    gcc = os.path.join(root, tree.vbin(root, cc).lstrip("/"))
    prog = os.path.join(work, "resolve")
    r = subprocess.run(
        [gcc, "-O1", "-o", prog, os.path.join(HERE, "progs", "resolve.c")],
        cwd=work,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        check=False,
    )
    if r.returncode:
        sys.exit("cannot compile resolve.c: " + r.stderr.decode(errors="replace"))
    paths = gen_paths(rng, dirs, files, links, a.paths)
    p = subprocess.run(
        [os.path.join(ex, ".exclave", "launcher"), prog],
        input="\n".join(paths).encode() + b"\n",
        cwd=work,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        check=False,
    )
    answers = p.stdout.decode(errors="replace").splitlines()
    if len(answers) != len(paths):
        sys.exit(
            f"the launcher answered {len(answers)} of {len(paths)} paths: "
            f"{p.stderr.decode(errors='replace')[-500:]}"
        )
    rootfd = os.open(root, os.O_PATH)
    fails, agree = 0, 0
    for path, ans in zip(paths, answers, strict=False):
        follow = not path.startswith("nofollow ")
        bare = path[9:] if not follow else path
        want, err = kernel_resolve(rootfd, root, bare, follow=follow)
        k = f"ERR {err}" if err is not None else f"OK {want}"
        if k == ans:
            agree += 1
        else:
            fails += 1
            if fails <= 25:
                print(f"DIFF {path[:60]:<60} kernel={k} launcher={ans}")
    print(f"{len(paths)} paths: {agree} agree, {fails} differ")
    if not a.keep and not fails:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
