"""realsoft.py — build real projects inside an exclave and on the host, compare results and time.

    test/realsoft.py --exclave EXCLAVE --src DIR [--work DIR] [--jobs N] [--only NAME,...]

DIR holds source tarballs: zlib, lua, sqlite-autoconf, re2c. Each is extracted twice and built with the
host's toolchain and with the exclave's (through the exclave's own sh, so configure scripts run inside it).
The built program is run in both worlds. Times are wall-clock for configure and for make.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

PROJECTS = {
    # name: (tarball prefix, configure command or None, make command, check command)
    "zlib": ("zlib-", "./configure", "make -j$J", "make test 2>&1 | tail -1"),
    "lua": ("lua-", None, "make -j$J linux", "src/lua -e 'print(_VERSION, 2^10)'"),
    "sqlite": (
        "sqlite-autoconf-",
        "./configure --disable-tcl",
        "make -j$J",
        "./sqlite3 :memory: 'select sqlite_version(), 6*7'",
    ),
    "re2c": (
        "re2c-",
        "./configure --disable-golang --disable-rust --disable-libs",
        "make -j$J",
        "./re2c --version",
    ),
}


def sh(cmd, cwd, env, ex=None):
    if ex:
        p = subprocess.run(
            [os.path.join(ex, "tree", "usr", "bin", "sh"), "-c", cmd],
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    else:
        p = subprocess.run(
            ["/bin/sh", "-c", cmd],
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    return p.returncode, p.stdout.decode(errors="replace")


def timed(cmd, cwd, env, ex):
    t = time.time()
    rc, out = sh(cmd, cwd, env, ex)
    return time.time() - t, rc, out


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--exclave", required=True)
    ap.add_argument("--src", required=True)
    ap.add_argument("--work", default=os.path.join(REPO, "build", "realsoft-work"))
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--only")
    a = ap.parse_args()
    work = os.path.abspath(a.work)
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)
    import tree

    ex = tree.fresh_exclave(
        os.path.abspath(a.exclave), os.path.join(work, "exclave")
    )  # a copy relinked with the build (17)
    env = {"PATH": "/usr/bin:/bin", "HOME": work, "J": str(a.jobs), "LANG": "C"}
    rows, failures = [], []
    for name, (prefix, conf, mk, check) in PROJECTS.items():
        if a.only and name not in a.only.split(","):
            continue
        tarballs = [f for f in os.listdir(a.src) if f.startswith(prefix)]
        if not tarballs:
            rows.append((name, "no tarball", "", "", ""))
            continue
        tb = os.path.join(a.src, sorted(tarballs)[-1])
        results = {}
        for world in ("host", "exclave"):
            d = os.path.join(work, world)
            os.makedirs(d, exist_ok=True)
            with tarfile.open(tb) as t:
                t.extractall(d, filter="data")
            src = os.path.join(d, [e for e in os.listdir(d) if e.startswith(prefix)][0])
            c = ex if world == "exclave" else None
            ct = 0.0
            if conf:
                ct, rc, out = timed(conf, src, env, c)
                if rc:
                    failures.append("%s %s configure: %s" % (name, world, out[-800:]))
                    results[world] = (ct, None, "configure failed")
                    continue
            mt, rc, out = timed(mk, src, env, c)
            if rc:
                failures.append("%s %s make: %s" % (name, world, out[-1200:]))
                results[world] = (ct, mt, "make failed")
                continue
            rc, out = sh(check, src, env, c)
            results[world] = (ct, mt, out.strip().splitlines()[-1] if out.strip() else "rc=%d" % rc)
        h, k = results.get("host", (0, None, "-")), results.get("exclave", (0, None, "-"))
        rows.append(
            (
                name,
                "%.1f / %.1f" % (h[0], k[0]) if conf else "-",
                "%s / %s"
                % (
                    "%.1f" % h[1] if h[1] is not None else "fail",
                    "%.1f" % k[1] if k[1] is not None else "fail",
                ),
                h[2],
                k[2],
            )
        )
    print(
        "| Project | configure host / exclave (s) | make -j%d host / exclave (s) | result on the host | result in the exclave |"
        % a.jobs
    )
    print("|---|---|---|---|---|")
    for r in rows:
        print("| %s | %s | %s | %s | %s |" % r)
    for f in failures:
        print("\nFAIL " + f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
