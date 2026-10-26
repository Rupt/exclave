#!/usr/bin/env python3
"""dogfood.py — the tool as an exclave, and an exclave built from inside it (DESIGN.md 10.5).

    test/dogfood.py --inputs DIR [--work DIR] [--keep]

Takes two package sets test/inputs.sh fetched into DIR, debs-tool and debs-gcc13, and touches no network.
It makes the tool's own exclave from python3, zstd and xz-utils plus this checkout's exclave and launcher,
then makes the same gcc exclave twice from the same files: once with the checkout's exclave on the host, once
with the tool's own exclave's shortcut from inside it. The two hashes files must be identical, tree hash
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
    ap.add_argument("--inputs", required=True)
    ap.add_argument("--work", default=os.path.join(REPO, "build", "dogfood-work"))
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    tool_debs, gcc_debs = (os.path.join(a.inputs, d) for d in ("debs-tool", "debs-gcc13"))
    for d in (tool_debs, gcc_debs):
        if not os.path.isdir(d) or not debs(d):
            sys.exit("FAIL %s has no .deb files: run test/inputs.sh %s" % (d, a.inputs))
    work = os.path.abspath(a.work)
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)
    exclave = os.path.join(REPO, "exclave", "exclave.py")
    print("building the tool's own exclave")
    tool_ex = os.path.join(work, "tool.exclave")
    run([sys.executable, exclave, "unpack", tool_ex] + debs(tool_debs), work)
    lib = os.path.join(tool_ex, "tree", "usr", "lib", "exclave")                # the tool's own source and the launcher, by hand: the exclave is a directory
    shutil.copytree(os.path.join(REPO, "exclave"), lib, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(os.path.join(REPO, "build", "launcher"), os.path.join(lib, "launcher"))
    entry = os.path.join(tool_ex, "tree", "usr", "bin", "exclave")
    with open(entry, "w") as f:
        f.write('#!/bin/sh\nexec python3 /usr/lib/exclave/exclave.py "$@"\n')
    os.chmod(entry, 0o755)
    run([sys.executable, exclave, "wrap", tool_ex], work)
    os.symlink("tree/usr/bin/exclave", os.path.join(tool_ex, "exclave"))
    run([os.path.join(tool_ex, "exclave"), "format", "--check", os.path.join(tool_ex, ".exclave", "manifest")], work)
    gcc_debs = debs(gcc_debs)
    print("building the gcc exclave on the host")
    run([sys.executable, exclave, "unpack", os.path.join(work, "gcc-host.exclave")] + gcc_debs, work)
    run([sys.executable, exclave, "wrap", os.path.join(work, "gcc-host.exclave")], work)
    print("building the gcc exclave inside the tool's own exclave")
    run([os.path.join(tool_ex, "exclave"), "unpack", os.path.join(work, "gcc-inside.exclave")] + gcc_debs, work)
    run([os.path.join(tool_ex, "exclave"), "wrap", os.path.join(work, "gcc-inside.exclave")], work)
    a_lock = open(os.path.join(work, "gcc-host.exclave", ".exclave", "hashes"), "rb").read()
    b_lock = open(os.path.join(work, "gcc-inside.exclave", ".exclave", "hashes"), "rb").read()
    tree = [l for l in a_lock.decode().splitlines() if l.startswith("tree")]
    if a_lock == b_lock:
        print("PASS hashes files identical; %s" % tree[0])
        out = run([os.path.join(work, "gcc-inside.exclave", "tree", "usr", "bin", "gcc-13"), "--version"], work)
        print("     " + out.splitlines()[0])
        if not a.keep:
            shutil.rmtree(work, ignore_errors=True)
        return 0
    print("FAIL the two hashes files differ:")
    for x, y in zip(a_lock.decode().splitlines(), b_lock.decode().splitlines()):
        if x != y:
            print("     host:    %s\n     exclave: %s" % (x, y))
    return 1


if __name__ == "__main__":
    sys.exit(main())
