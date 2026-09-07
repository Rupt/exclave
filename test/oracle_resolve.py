#!/usr/bin/env python3
"""oracle_resolve.py — the kernel as the oracle for canonicalisation (PROPOSAL.md 17, item 2).

A random maze of directories, files and symlinks (relative, absolute, dangling, looping, with `..` and
trailing slashes) is added to a copy of a can under /maze. Every generated path is resolved twice: by
the kernel with openat2(RESOLVE_IN_ROOT) on the tree, which has chroot semantics, and by the opener
from inside the can. The resulting paths and errnos must agree.

    test/oracle_resolve.py --can CAN [--work DIR] [--paths N] [--seed S] [--keep]
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
sys.path.insert(0, os.path.join(REPO, "cannery"))
import cannery  # noqa: E402

SYS_openat2 = 437
O_PATH, O_NOFOLLOW = os.O_PATH, os.O_NOFOLLOW                  # this machine's bits: aarch64's O_NOFOLLOW is not x86-64's
RESOLVE_IN_ROOT = 0x10
libc = ctypes.CDLL(None, use_errno=True)


class OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]


def kernel_resolve(rootfd, root, path, follow):
    """(virtual path, None) or (None, errno) via openat2 RESOLVE_IN_ROOT."""
    how = OpenHow(O_PATH | (0 if follow else O_NOFOLLOW), 0, RESOLVE_IN_ROOT)
    rel = path.lstrip("/") or "."
    if path.startswith("/") and rel == ".":
        rel = "."
    fd = libc.syscall(SYS_openat2, rootfd, rel.encode(), ctypes.byref(how), ctypes.sizeof(how))
    for _ in range(20):                                       # EAGAIN under RESOLVE_IN_ROOT means "retry": the kernel saw what it
        if fd >= 0 or ctypes.get_errno() != errno.EAGAIN:    # took for a concurrent rename or mount (openat2(2)); RHEL 8's 4.18 says so for ..
            break
        fd = libc.syscall(SYS_openat2, rootfd, rel.encode(), ctypes.byref(how), ctypes.sizeof(how))
    if fd < 0:
        return None, ctypes.get_errno()
    real = os.readlink("/proc/self/fd/%d" % fd)
    os.close(fd)
    if real == root:
        return "/", None
    if real.startswith(root + "/"):
        return real[len(root):], None
    return real, None                                        # should not happen under RESOLVE_IN_ROOT


def make_maze(root, rng, ndirs=12, nfiles=15, nlinks=40):
    base = os.path.join(root, "maze")
    os.makedirs(base)
    dirs = ["/maze"]
    for i in range(ndirs):
        parent = rng.choice(dirs)
        d = "%s/d%d" % (parent, i)
        os.makedirs(os.path.join(root, d.lstrip("/")), exist_ok=True)
        dirs.append(d)
    files = []
    for i in range(nfiles):
        f = "%s/f%d" % (rng.choice(dirs), i)
        with open(os.path.join(root, f.lstrip("/")), "w") as fh:
            fh.write("x")
        files.append(f)
    names = dirs + files
    links = []
    for i in range(nlinks):
        where = "%s/l%d" % (rng.choice(dirs), i)
        kind = rng.random()
        if kind < 0.35:
            target = rng.choice(names)                        # absolute, into the maze
        elif kind < 0.6:
            t = rng.choice(names)
            depth = where.count("/") - 1
            target = "/".join([".."] * rng.randint(0, depth)) + t   # relative with .. (may overshoot)
            target = target.lstrip("/") or "."
        elif kind < 0.75:
            target = rng.choice(["../" * rng.randint(1, 8) + "usr/bin", "/usr/../maze", "./d0/../", "/etc/../maze/d1/"])
        elif kind < 0.85:
            target = "%s/missing%d" % (rng.choice(dirs), i)   # dangling
        elif kind < 0.93:
            target = where                                    # loop to itself
        else:
            target = "/maze/l%d" % rng.randint(0, nlinks - 1)  # possible longer loop
        os.symlink(target, os.path.join(root, where.lstrip("/")))
        links.append(where)
    return dirs, files, links


def gen_paths(rng, dirs, files, links, n):
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


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--can", required=True)
    ap.add_argument("--work", default=os.path.join(REPO, "build", "resolve-work"))
    ap.add_argument("--paths", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    rng = random.Random(a.seed)
    probe = OpenHow(O_PATH, 0, RESOLVE_IN_ROOT)
    if libc.syscall(SYS_openat2, -100, b".", ctypes.byref(probe), ctypes.sizeof(probe)) < 0 and ctypes.get_errno() == errno.ENOSYS:
        print("openat2 is not available on this kernel (5.6 and later); the resolution oracle cannot run here")
        return 0
    work = os.path.abspath(a.work)
    if os.path.exists(work):
        shutil.rmtree(work)
    can = os.path.join(work, "can")
    os.makedirs(os.path.join(can, ".can"))
    shutil.copy2(os.path.join(a.can, ".can", "opener"), os.path.join(can, ".can", "opener"))
    root = os.path.join(can, "root")
    shutil.copytree(os.path.join(a.can, "root"), root, symlinks=True, copy_function=cannery.link_or_copy)
    dirs, files, links = make_maze(root, rng)
    with open(os.path.join(can, ".can", "manifest"), "w") as f:
        f.write("can 1\n")                                       # /maze is a non-empty top-level directory: can-owned by the tree alone (8.1)
    import platform
    gcc = next(os.path.join(root, "usr", "bin", n) for n in ("%s-linux-gnu-gcc-13" % platform.machine(), "x86_64-linux-gnu-gcc-13", "gcc")
               if os.path.exists(os.path.join(root, "usr", "bin", n)))
    prog = os.path.join(work, "resolve")
    r = subprocess.run([gcc, "-O1", "-o", prog, os.path.join(HERE, "progs", "resolve.c")], cwd=work, env={"PATH": "/usr/bin:/bin"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode:
        sys.exit("cannot compile resolve.c: " + r.stderr.decode(errors="replace"))
    paths = gen_paths(rng, dirs, files, links, a.paths)
    p = subprocess.run([os.path.join(can, ".can", "opener"), prog], input="\n".join(paths).encode() + b"\n", cwd=work, env={"PATH": "/usr/bin:/bin"},
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    answers = p.stdout.decode(errors="replace").splitlines()
    if len(answers) != len(paths):
        sys.exit("the opener answered %d of %d paths: %s" % (len(answers), len(paths), p.stderr.decode(errors="replace")[-500:]))
    rootfd = os.open(root, os.O_PATH)
    fails, agree = 0, 0
    for path, ans in zip(paths, answers):
        follow = not path.startswith("nofollow ")
        bare = path[9:] if not follow else path
        want, err = kernel_resolve(rootfd, root, bare, follow)
        if err is not None:
            k = "ERR %d" % err
        else:
            k = "OK " + want
        if k == ans:
            agree += 1
        else:
            fails += 1
            if fails <= 25:
                print("DIFF %-60s kernel=%s opener=%s" % (path[:60], k, ans))
    print("%d paths: %d agree, %d differ" % (len(paths), agree, fails))
    if not a.keep and not fails:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
