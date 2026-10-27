"""Build against a sysroot shipped as a data directory of a gcc exclave (DESIGN.md 9, 6.2).

A glibc from one distribution inside a gcc exclave from another, and an output of that gcc that runs
wherever that glibc's version is old enough.

    scripts/sysroot --exclave GCC_EXCLAVE --rpms DIR --out FILE [--work DIR]
                    [--prefix /opt/sysroot-el7]

Makes a copy of the gcc exclave, unwraps it, unpacks the rpm files (a glibc, its headers, kernel
headers, libgcc) into a tree of their own with unpack, copies that tree into the copy at the
prefix, records the prefix as `data` in the manifest and wraps the copy: nothing under the prefix is
wrapped, checked or executed. Then compiles a hello with `--sysroot=PREFIX -B PREFIX/usr/lib64/`
inside, checks that it binds no glibc symbol version newer than the sysroot's, runs it inside and on
the host, and writes it to FILE; the kernel matrix packs that file and runs it natively in every VM,
CentOS 7 at glibc 2.17 included.
"""

import argparse
import glob
import os
import platform
import re
import shutil
import subprocess
import sys

import tree

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TOOL = tree.TOOL
UNPACK = (sys.executable, "-m", "unpack")


HELLO = (
    "#include <stdio.h>\n#include <stdlib.h>\n"
    'int main(void) { printf("hello from a sysroot build\\n"); return 0; }\n'
)


def run(
    cmd: list[str], cwd: str | None = None, env: dict[str, str] | None = None
) -> tuple[int, str, str]:
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, check=False)
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--exclave", required=True, help="a wrapped gcc exclave")
    ap.add_argument(
        "--rpms",
        required=True,
        help="directory of rpm files: glibc glibc-devel glibc-headers kernel-headers libgcc",
    )
    ap.add_argument("--out", required=True, help="where to put the built program")
    ap.add_argument("--work", default=os.path.join(REPO, "build", "sysroot-work"))
    ap.add_argument("--prefix", default="/opt/sysroot-el7")
    args = ap.parse_args()
    work = os.path.abspath(args.work)
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)
    ex, sysroot_ex = os.path.join(work, "gcc.exclave"), os.path.join(work, "sysroot.exclave")
    tree.fresh_exclave(args.exclave, ex)  # a copy of its own, relinked with the build (17)
    rc, out, err = run([*TOOL, "unwrap", ex])
    if rc:
        sys.exit("unwrap: " + out + err)
    rpms = sorted(glob.glob(os.path.join(args.rpms, "*.rpm")))
    rc, out, err = run([*UNPACK, sysroot_ex, *rpms])
    if rc:
        sys.exit("unpack: " + out + err)
    dst = os.path.join(ex, "tree", args.prefix.lstrip("/"))
    shutil.copytree(
        os.path.join(sysroot_ex, "tree"), dst, symlinks=True, copy_function=tree.link_or_copy
    )
    with open(os.path.join(ex, ".exclave", "manifest"), "wb") as f:
        f.write(f'exclave 1\n\ndata "{args.prefix}"\n'.encode())
    rc, out, err = run([*TOOL, "wrap", ex])
    if rc:
        sys.exit("wrap: " + out + err)
    print([line for line in out.splitlines() if line.startswith("static check")][-1])
    gcc = next(
        n
        for n in ("x86_64-linux-gnu-gcc-13", "gcc")
        if os.path.exists(os.path.join(ex, "tree", "usr", "bin", n))
    )
    src = os.path.join(work, "hello.c")
    with open(src, "w") as f:
        f.write(HELLO)
    prog = os.path.join(work, "hello")
    env = {"PATH": "/usr/bin:/bin"}
    rc, out, err = run(
        [
            os.path.join(ex, "tree", "usr", "bin", gcc),
            "--sysroot=" + args.prefix,
            "-B" + args.prefix + "/usr/lib64/",
            "-o",
            prog,
            src,
        ],
        cwd=work,
        env=env,
    )
    if rc:
        sys.exit("compile against the sysroot: " + err)
    rc, out, err = run(
        [os.path.join(ex, "tree", "usr", "bin", "objdump"), "-T", prog], cwd=work, env=env
    )
    versions = sorted(
        set(re.findall(r"GLIBC_([0-9.]+)", out)), key=lambda v: [int(x) for x in v.split(".")]
    )
    # the banner in libc.so.6, any glibc
    gv = tree.glibc_version(os.path.join(sysroot_ex, "tree"), platform.machine())
    if gv is None:
        sys.exit("cannot read the sysroot's glibc version from its libc.so.6")
    have = f"{gv[0]:d}.{gv[1]:d}"
    print("symbol versions bound: {}; the sysroot's glibc: {}".format(" ".join(versions), have))
    if not versions or [int(x) for x in versions[-1].split(".")] > [
        int(x) for x in have.split(".")
    ]:
        sys.exit("the output binds a glibc newer than the sysroot's, or none")
    rc, inside, err = run(
        [os.path.join(ex, "tree", "usr", "bin", "sh"), "-c", prog], cwd=work, env=env
    )
    rc2, native, err2 = run([prog], cwd=work, env=env)
    print(f"inside the exclave: {inside.strip()!r}; on this host: {native.strip()!r}")
    if rc or rc2 or inside != native:
        sys.exit("the output does not run the same inside and outside: " + err + err2)
    shutil.copy2(prog, args.out)
    print("wrote " + args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
