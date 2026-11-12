"""Check the launcher's path resolution against the kernel's: the resolution oracle (17 item 2).

A random maze of directories, files and symlinks (relative, absolute, dangling, looping, with `..`
and trailing slashes) is added to a copy of an exclave under /maze. Every generated path is resolved
twice: by the kernel with openat2(RESOLVE_IN_ROOT) on the tree, which has chroot semantics, and by
the launcher from inside the exclave. The resulting paths and errnos must agree. The paths are
spread over mazes of MAZE_PATHS each, made one after another in the same copy.

    test/oracle_resolve.py --exclave EXCLAVE [--work DIR] [--paths N] [--seed S] [--keep]

The seed is the commit's, the hex of `git rev-parse --short=8 HEAD`, when none is given, so that
each commit explores new mazes and a run is reproduced from its commit; outside a git checkout, as
in the matrix's VMs, it is 1. It is printed with any difference.
"""

import argparse
import ctypes
import errno
import os
import platform
import random
import shutil
import subprocess
import sys

import tree
from harness import cannot_run, run

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

SYS_openat2 = 437
# this machine's bits: aarch64's O_NOFOLLOW is not x86-64's
O_PATH, O_NOFOLLOW = os.O_PATH, os.O_NOFOLLOW
RESOLVE_IN_ROOT = 0x10
# seconds the launcher's run of one maze's paths may take, a few hundred times what it takes
TIMEOUT = 60
# paths asked of each maze
MAZE_PATHS = 3000
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


def head_seed() -> int:
    """The commit's seed: HEAD's short hash as a number, or 1 outside a git checkout."""
    try:
        r = subprocess.run(
            ["git", "-C", REPO, "rev-parse", "--short=8", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return 1
    return int(r.stdout.strip(), 16) if r.returncode == 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--exclave", required=True)
    ap.add_argument("--work", default=os.path.join(REPO, "build", "resolve-work"))
    ap.add_argument("--paths", type=int, default=30000)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    seed = head_seed() if args.seed is None else args.seed
    rng = random.Random(seed)
    probe = OpenHow(O_PATH, 0, RESOLVE_IN_ROOT)
    if (
        libc.syscall(SYS_openat2, -100, b".", ctypes.byref(probe), ctypes.sizeof(probe)) < 0
        and ctypes.get_errno() == errno.ENOSYS
    ):
        return cannot_run(
            "the resolution oracle", "openat2 is not available on this kernel (5.6 and later)"
        )
    work = os.path.abspath(args.work)
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)
    # a copy relinked with the build (17), kept between runs; its maze and manifest made anew
    ex, _bare = tree.kept_worlds(os.path.abspath(args.exclave), "resolve")
    root = os.path.join(ex, "tree")
    with open(os.path.join(ex, ".exclave", "manifest"), "w") as f:
        # /maze is a non-empty top-level directory: the exclave's by the tree alone (8.1)
        f.write("exclave 1\n")
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
    rootfd = os.open(root, os.O_PATH)
    fails = agree = asked = 0
    failed_run = False
    for m in range((args.paths + MAZE_PATHS - 1) // MAZE_PATHS):
        shutil.rmtree(os.path.join(root, "maze"), ignore_errors=True)
        dirs, files, links = make_maze(root, rng)
        paths = gen_paths(rng, dirs, files, links, min(MAZE_PATHS, args.paths - asked))
        asked += len(paths)
        try:
            rc, out, stderr = run(
                [os.path.join(ex, ".exclave", "launcher"), prog],
                inp="\n".join(paths).encode() + b"\n",
                cwd=work,
                env={"PATH": "/usr/bin:/bin"},
                timeout=TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            sys.exit(
                f"the launcher's run of maze {m}'s {len(paths)} paths killed after {TIMEOUT} s; "
                f"seed {seed}"
            )
        answers = out.splitlines()
        if len(answers) != len(paths):
            sys.exit(
                f"the launcher answered {len(answers)} of maze {m}'s {len(paths)} paths: "
                f"{stderr[-500:]}; seed {seed}"
            )
        # the program answers every path on stdout and exits 0 with nothing on stderr
        if rc or stderr:
            failed_run = True
            print(f"FAIL the launcher's run of maze {m}: rc {rc}, stderr {stderr.strip()[-300:]!r}")
        for path, ans in zip(paths, answers, strict=True):
            follow = not path.startswith("nofollow ")
            bare = path[9:] if not follow else path
            want, err = kernel_resolve(rootfd, root, bare, follow=follow)
            k = f"ERR {err}" if err is not None else f"OK {want}"
            if k == ans:
                agree += 1
            else:
                fails += 1
                if fails <= 25:
                    print(f"DIFF maze {m} {path[:60]:<60} kernel={k} launcher={ans}")
    print(
        f"{asked} paths: {agree} agree, {fails} differ"
        + ("; a run failed" if failed_run else "")
        + (f"; seed {seed}" if fails or failed_run else "")
    )
    if not args.keep and not fails and not failed_run:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if fails or failed_run else 0


if __name__ == "__main__":
    sys.exit(main())
