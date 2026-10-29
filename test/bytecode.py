"""Python bytecode by the two-phase pattern: a cache only the tree's own binary makes (10.1).

    test/bytecode.py --exclave EXCLAVE [--work DIR]

The exclave must hold python3. Debian ships no bytecode, and inside an exclave Python cannot write
`__pycache__` next to the sources (8.2), so every import compiles its module. The pattern: wrap;
run the generator inside the exclave, writing to a host staging directory
(`PYTHONPYCACHEPREFIX`); copy its output into the unwrapped tree; wrap again. The maintainer
script is never run, the maker chooses the generator, and the tree hash records the output. The
zero-code alternative, `PYTHONPYCACHEPREFIX` on a host directory at run time, is measured too.
Prints the import time of a few standard modules in each state, best of five; exit 0 when the
bytecode is in the tree afterwards and Python imports from it.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time

import tree

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TOOL = tree.TOOL
MODULES = "json, argparse, re, email.parser, http.client, urllib.request"


def run(cmd: list[str], env: dict[str, str], cwd: str) -> tuple[int, str]:
    p = subprocess.run(cmd, env=env, cwd=cwd, capture_output=True, check=False, timeout=600)
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


def import_time(python: list[str], env: dict[str, str], cwd: str) -> float:
    """Seconds for python3 -c 'import ...', best of five."""
    best = None
    for _ in range(5):
        t = time.monotonic()
        rc, out = run([*python, "-c", f"import {MODULES}"], env, cwd)
        t = time.monotonic() - t
        if rc:
            sys.exit(f"import inside the exclave failed: {out[-400:]}")
        best = t if best is None else min(best, t)
    return best or 0.0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--exclave", required=True, help="a wrapped exclave holding python3")
    ap.add_argument("--work", default=os.path.join(REPO, "build", "bytecode-work"))
    args = ap.parse_args()
    work = os.path.abspath(args.work)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    ex = tree.fresh_exclave(os.path.abspath(args.exclave), os.path.join(work, "py.exclave"))
    root = os.path.join(ex, "tree")
    if not os.path.exists(os.path.join(root, tree.vbin(root, "python3").lstrip("/"))):
        sys.exit(f"no python3 in {args.exclave}")
    # python3 through the exclave's own shell, so that it finds itself by its virtual path and
    # names its library in virtual terms, as it does for a program inside
    sh = os.path.join(root, tree.vbin(root, "sh").lstrip("/"))
    python = [sh, "-c", 'exec python3 "$@"', "python3"]
    env = {"PATH": "/usr/bin:/bin", "HOME": work}
    cached = "import json; print(json.__cached__ or '')"

    # before: no bytecode in the tree, and none written at import
    rc, before = run([*python, "-c", cached], env, work)
    had = (
        rc == 0
        and before.strip()
        and os.path.exists(os.path.join(root, before.strip().lstrip("/")))
    )
    t0 = import_time(python, env, work)
    print(
        f"without bytecode: {MODULES} import in {t0 * 1000:.0f} ms; cached in the tree: {bool(had)}"
    )

    # the zero-code alternative: a cache prefix on the host, written at the first run
    prefix_env = {**env, "PYTHONPYCACHEPREFIX": os.path.join(work, "pycache-runtime")}
    import_time(python, prefix_env, work)  # the first run writes the cache
    t1 = import_time(python, prefix_env, work)
    print(f"with PYTHONPYCACHEPREFIX on the host: {t1 * 1000:.0f} ms")

    # the two-phase pattern: the generator inside, writing to a host staging directory
    staging = os.path.join(work, "staging")
    rc, libdir = run(
        [*python, "-c", "import sysconfig; print(sysconfig.get_paths()['stdlib'])"], env, work
    )
    libdir = libdir.strip()
    if rc or not libdir.startswith("/"):
        sys.exit(f"cannot find the standard library inside the exclave: {libdir[-200:]}")
    rc, out = run(
        [*python, "-m", "compileall", "-q", "-j", "0", libdir],
        {**env, "PYTHONPYCACHEPREFIX": staging},
        work,
    )
    if rc:
        sys.exit(f"compileall inside the exclave failed: {out[-400:]}")
    rc, out = run([*TOOL, "unwrap", ex], env, work)
    if rc:
        sys.exit(f"unwrap: {out[-400:]}")
    # the prefix's tree mirrors the sources' directories without the __pycache__ level, which the
    # tree gets back: the prefix's <dir>/x.pyc is the tree's <dir>/__pycache__/x.pyc
    copied = 0
    src = os.path.join(staging, libdir.lstrip("/"))
    for dirpath, _dirs, files in os.walk(src):
        pycs = [f for f in files if f.endswith(".pyc")]
        if not pycs:
            continue
        dst = os.path.join(root, os.path.relpath(dirpath, staging), "__pycache__")
        os.makedirs(dst, exist_ok=True)
        for f in pycs:
            shutil.copyfile(os.path.join(dirpath, f), os.path.join(dst, f))
            copied += 1
    rc, out = run([*TOOL, "wrap", ex], env, work)
    if rc:
        sys.exit(f"wrap: {out[-400:]}")
    rc, after = run([*python, "-c", cached], env, work)
    has = (
        rc == 0 and after.strip() and os.path.exists(os.path.join(root, after.strip().lstrip("/")))
    )
    t2 = import_time(python, env, work)
    print(
        f"with {copied} bytecode files copied into the tree by the two-phase pattern: "
        f"{t2 * 1000:.0f} ms; cached in the tree: {bool(has)}"
    )
    ok = not had and bool(has)
    print(
        "bytecode: "
        + ("the pattern works" if ok else "FAIL: the bytecode is not in the tree afterwards")
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
