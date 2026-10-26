#!/usr/bin/env python3
"""dogfood.py — the cannery as a can, and a can built from inside it (PROPOSAL.md 10.5).

    test/dogfood.py --cache DIR [--work DIR] [--mirror URL] [--keep]

Fetches two package sets with tools/fetch-debs.py (the one step that touches the network, and not the
cannery's), makes the cannery can from python3, zstd and xz-utils plus this checkout's cannery and launcher,
then makes the same gcc can twice from the same files: once with the checkout's cannery on the host, once
with the cannery can's own entry from inside its can. The two lockfiles must be identical, tree hash
included. Exit status 0 on success.
"""
import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def run(cmd, cwd, check=True):
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = p.stdout.decode(errors="replace")
    if check and p.returncode:
        sys.exit("FAIL %s\n%s" % (" ".join(cmd), out[-2000:]))
    return out


def debs(d):
    return sorted(os.path.join(d, f) for f in os.listdir(d) if f.endswith(".deb"))


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
    fetch = [sys.executable, os.path.join(REPO, "tools", "fetch-debs.py"), "--mirror", a.mirror, "--cache", a.cache]
    print("fetching the package sets")
    run(fetch + ["--out", os.path.join(work, "debs-cannery"), "python3", "zstd", "xz-utils"], work)
    run(fetch + ["--out", os.path.join(work, "debs-gcc"), "gcc-13", "libc6-dev"], work)
    print("building the cannery can")
    ccan = os.path.join(work, "cannery.can")
    run([sys.executable, cannery, "unpack", ccan] + debs(os.path.join(work, "debs-cannery")), work)
    lib = os.path.join(ccan, "tree", "usr", "lib", "cont")                # the cannery's own source and the launcher, by hand: the can is a directory
    shutil.copytree(os.path.join(REPO, "cannery"), lib, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(os.path.join(REPO, "build", "launcher"), os.path.join(lib, "launcher"))
    entry = os.path.join(ccan, "tree", "usr", "bin", "cannery")
    with open(entry, "w") as f:
        f.write('#!/bin/sh\nexec python3 /usr/lib/cont/cannery.py "$@"\n')
    os.chmod(entry, 0o755)
    run([sys.executable, cannery, "wrap", ccan], work)
    os.symlink("tree/usr/bin/cannery", os.path.join(ccan, "cannery"))
    run([os.path.join(ccan, "cannery"), "fmt", "--check", os.path.join(ccan, ".exclave", "manifest")], work)
    gcc_debs = debs(os.path.join(work, "debs-gcc"))
    print("building the gcc can on the host")
    run([sys.executable, cannery, "unpack", os.path.join(work, "gcc-host.can")] + gcc_debs, work)
    run([sys.executable, cannery, "wrap", os.path.join(work, "gcc-host.can")], work)
    print("building the gcc can inside the cannery can")
    run([os.path.join(ccan, "cannery"), "unpack", os.path.join(work, "gcc-can.can")] + gcc_debs, work)
    run([os.path.join(ccan, "cannery"), "wrap", os.path.join(work, "gcc-can.can")], work)
    a_lock = open(os.path.join(work, "gcc-host.can", ".exclave", "hashes"), "rb").read()
    b_lock = open(os.path.join(work, "gcc-can.can", ".exclave", "hashes"), "rb").read()
    tree = [l for l in a_lock.decode().splitlines() if l.startswith("tree")]
    if a_lock == b_lock:
        print("PASS lockfiles identical; %s" % tree[0])
        out = run([os.path.join(work, "gcc-can.can", "tree", "usr", "bin", "gcc-13"), "--version"], work)
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
