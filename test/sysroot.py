#!/usr/bin/env python3
"""sysroot.py — a sysroot as a data prefix (PROPOSAL.md 9, 6.2): a glibc from one distribution inside a gcc can
from another, and an output of that gcc that runs wherever that glibc's version is old enough.

    test/sysroot.py --can GCC_CAN --rpms DIR --out FILE [--work DIR] [--prefix /opt/sysroot-el7]

Makes a copy of the gcc can, opens it, unpacks the rpm files (a glibc, its headers, kernel headers, libgcc)
into a can of their own with the cannery, copies that tree into the copy at the prefix, records the prefix
as `data` in the manifest and closes the copy: nothing under the prefix is wrapped, checked or executed.
Then compiles a hello with `--sysroot=PREFIX -B PREFIX/usr/lib64/` inside, checks that it binds no glibc
symbol version newer than the sysroot's, runs it inside and on the host, and writes it to FILE; the kernel
matrix packs that file and runs it natively in every VM, CentOS 7 at glibc 2.17 included.
"""
import argparse
import glob
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "cannery"))
sys.path.insert(0, HERE)
import build  # noqa: E402
import cannery  # noqa: E402
import tree  # noqa: E402

HELLO = '#include <stdio.h>\n#include <stdlib.h>\nint main(void) { printf("hello from a sysroot build\\n"); return 0; }\n'


def run(cmd, cwd=None, env=None):
    p = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--can", required=True, help="a closed gcc can")
    ap.add_argument("--rpms", required=True, help="directory of rpm files: glibc glibc-devel glibc-headers kernel-headers libgcc")
    ap.add_argument("--out", required=True, help="where to put the built program")
    ap.add_argument("--work", default=os.path.join(REPO, "build", "sysroot-work"))
    ap.add_argument("--prefix", default="/opt/sysroot-el7")
    a = ap.parse_args()
    work = os.path.abspath(a.work)
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)
    can, sysroot_can = os.path.join(work, "gcc.can"), os.path.join(work, "sysroot.can")
    cannery_py = os.path.join(REPO, "cannery", "cannery.py")
    tree.fresh_can(a.can, can)                                 # a copy of its own, reopened with the build (17)
    rc, out, err = run([sys.executable, cannery_py, "unwrap", can])
    if rc:
        sys.exit("unwrap: " + out + err)
    rpms = sorted(glob.glob(os.path.join(a.rpms, "*.rpm")))
    rc, out, err = run([sys.executable, cannery_py, "unpack", sysroot_can] + rpms)
    if rc:
        sys.exit("unpack: " + out + err)
    dst = os.path.join(can, "root", a.prefix.lstrip("/"))
    shutil.copytree(os.path.join(sysroot_can, "root"), dst, symlinks=True, copy_function=cannery.link_or_copy)
    with open(os.path.join(can, ".can", "manifest"), "wb") as f:
        f.write(cannery.dump([cannery.Record("can", [("t", b"1")]), cannery.Record("data", [("s", a.prefix.encode())])], "can"))
    rc, out, err = run([sys.executable, cannery_py, "wrap", can])
    if rc:
        sys.exit("wrap: " + out + err)
    print([l for l in out.splitlines() if l.startswith("static check")][-1])
    gcc = next(n for n in ("x86_64-linux-gnu-gcc-13", "gcc") if os.path.exists(os.path.join(can, "root", "usr", "bin", n)))
    src = os.path.join(work, "hello.c")
    with open(src, "w") as f:
        f.write(HELLO)
    prog = os.path.join(work, "hello")
    env = {"PATH": "/usr/bin:/bin"}
    rc, out, err = run([os.path.join(can, "root", "usr", "bin", gcc), "--sysroot=" + a.prefix, "-B" + a.prefix + "/usr/lib64/", "-o", prog, src], cwd=work, env=env)
    if rc:
        sys.exit("compile against the sysroot: " + err)
    rc, out, err = run([os.path.join(can, "root", "usr", "bin", "objdump"), "-T", prog], cwd=work, env=env)
    versions = sorted(set(re.findall(r"GLIBC_([0-9.]+)", out)), key=lambda v: [int(x) for x in v.split(".")])
    import elfcheck
    gv = elfcheck.glibc_version(elfcheck.Tree(os.path.join(sysroot_can, "root")))   # the banner in libc.so.6, any glibc (review O5-7)
    if gv is None:
        sys.exit("cannot read the sysroot's glibc version from its libc.so.6")
    have = "%d.%d" % gv
    print("symbol versions bound: %s; the sysroot's glibc: %s" % (" ".join(versions), have))
    if not versions or [int(x) for x in versions[-1].split(".")] > [int(x) for x in have.split(".")]:
        sys.exit("the output binds a glibc newer than the sysroot's, or none")
    rc, inside, err = run([os.path.join(can, "root", "usr", "bin", "sh"), "-c", prog], cwd=work, env=env)
    rc2, native, err2 = run([prog], cwd=work, env=env)
    print("inside the can: %r; on this host: %r" % (inside.strip(), native.strip()))
    if rc or rc2 or inside != native:
        sys.exit("the output does not run the same inside and outside: " + err + err2)
    shutil.copy2(prog, a.out)
    print("wrote " + a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
