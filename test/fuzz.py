"""Fuzz the launcher's parsers from an exclave's files: scripts/extra's fuzz step (DESIGN.md 17).

    fuzz.py --exclave EXCLAVE --work DIR --launcher BIN [--seconds N]

The seeds are the exclave's manifest and hashes file, and an EXCLAVE_LOG file and #! lines written
here. The harness, test/fuzz.c built with test/launcher_fuzz.c under ASan and UBSan, runs for N
seconds (10 by default) on every seed. A finding's input is at DIR/launcher/crash, and the exit
status is the number of harnesses with one. The command's parsers are Go's, fuzzed by Go's own
fuzzer (scripts/extra's gofuzz step).
"""

import argparse
import os
import subprocess
import sys

LOG = b"""openat 3 /usr/lib/x86_64-linux-gnu/libc.so.6
execve 0 /usr/bin/true
openat -2 /etc/ld.so.preload
stat 0 /usr/share/zoneinfo/Europe/London
readlink -22 /proc/self/exe
openat 4 /tmp/a\\x20b\\n
"""
SHEBANGS = [b"#!/bin/sh -e\nexit 0\n", b"#! /usr/bin/env  python3  \n", b"#!" + b"x" * 300 + b"\n"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--exclave", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--launcher", required=True, help="test/fuzz.c with test/launcher_fuzz.c")
    ap.add_argument("--seconds", type=float, default=10)
    args = ap.parse_args()

    ex, work = args.exclave, args.work
    seeds = os.path.join(work, "seeds")
    os.makedirs(seeds, exist_ok=True)
    with open(os.path.join(seeds, "log"), "wb") as f:
        f.write(LOG)
    shebangs = []
    for i, text in enumerate(SHEBANGS):
        shebangs.append(os.path.join(seeds, f"shebang{i}"))
        with open(shebangs[-1], "wb") as f:
            f.write(text)
    files = [os.path.join(ex, ".exclave", name) for name in ("manifest", "hashes")]
    launcher_seeds = [*files, *shebangs, os.path.join(seeds, "log")]

    runs = []
    harnesses = (("launcher", args.launcher, launcher_seeds),)
    for name, binary, inputs in harnesses:
        d = os.path.join(work, name)
        os.makedirs(d, exist_ok=True)
        cmd = [binary, d, str(args.seconds), *inputs]
        runs.append((name, subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)))
    failures = 0
    for name, p in runs:
        out, _ = p.communicate()
        sys.stdout.write(out.decode("utf-8", "replace"))
        if p.returncode:
            failures += 1
            print(f"fuzz: the {name} harness exited {p.returncode}")
    print(f"fuzz: {len(runs)} harnesses, {failures} with a finding")
    return failures


if __name__ == "__main__":
    sys.exit(main())
