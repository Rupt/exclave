#!/usr/bin/env python3
"""dogfood.py — the cannery as a can, and a cross-can build that must reproduce (PROPOSAL.md 10.5).

    test/dogfood.py --cache DIR [--work DIR] [--mirror URL] [--keep]

Builds the cannery can (python3, zstd, xz-utils, ca-certificates, the cannery source and the opener), then
builds a gcc can twice: with the checkout's cannery on the host, and with the cannery running inside its
can (two openers, a cross-can invocation). The two lockfiles, and so the two tree hashes, must be identical.
Needs the network; the package cache makes repeats fast.
"""
import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def run(cmd, cwd):
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode:
        sys.exit("failed: %s\n%s" % (" ".join(cmd), p.stdout.decode(errors="replace")[-1500:]))
    return p.stdout.decode(errors="replace")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cache", required=True)
    ap.add_argument("--work", default=os.path.join(REPO, "build", "dogfood-work"))
    ap.add_argument("--mirror", default="http://archive.ubuntu.com/ubuntu")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    work = os.path.abspath(a.work)
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)
    cannery = os.path.join(REPO, "cannery", "cannery.py")
    entry = os.path.join(work, "cannery-entry.sh")
    with open(entry, "w") as f:
        f.write('#!/bin/sh\nexec python3 /usr/lib/cont/cannery.py "$@"\n')
    os.chmod(entry, 0o755)
    common = ["--mirror", a.mirror, "--cache", a.cache]
    ccan = os.path.join(work, "cannery.can")
    print("building the cannery can")
    run([sys.executable, cannery, "from-packages"] + common + ["--add", os.path.join(REPO, "cannery") + "=/usr/lib/cont", "--add", os.path.join(REPO, "build", "opener") + "=/usr/lib/cont/opener",
         "--add", entry + "=/usr/bin/cannery", "--entry", "cannery=/usr/bin/cannery", "--entry", "sh=/usr/bin/sh", "--out", ccan,
         "python3", "zstd", "xz-utils", "ca-certificates"], work)
    out = run([os.path.join(ccan, "cannery"), "fmt", "--check", os.path.join(ccan, ".can", "index")], work)
    gcc_args = common + ["--entry", "gcc=/usr/bin/gcc-13", "--out"]
    print("building the gcc can on the host")
    run([sys.executable, cannery, "from-packages"] + gcc_args + [os.path.join(work, "gcc-host.can"), "gcc-13", "libc6-dev"], work)
    print("building the gcc can inside the cannery can")
    run([os.path.join(ccan, "cannery"), "from-packages"] + gcc_args + [os.path.join(work, "gcc-can.can"), "gcc-13", "libc6-dev"], work)
    a_lock = open(os.path.join(work, "gcc-host.can", ".can", "lock"), "rb").read()
    b_lock = open(os.path.join(work, "gcc-can.can", ".can", "lock"), "rb").read()
    tree = [l for l in a_lock.decode().splitlines() if l.startswith("tree")]
    if a_lock == b_lock:
        print("PASS lockfiles identical; %s" % tree[0])
        out = run([os.path.join(work, "gcc-can.can", "gcc"), "--version"], work)
        print("     " + out.splitlines()[0])
        if not a.keep:
            shutil.rmtree(work, ignore_errors=True)
        return 0
    print("FAIL the two lockfiles differ:")
    for x, y in zip(a_lock.decode().splitlines(), b_lock.decode().splitlines()):
        if x != y:
            print("     host: %s\n     can:  %s" % (x, y))
    return 1


if __name__ == "__main__":
    sys.exit(main())
