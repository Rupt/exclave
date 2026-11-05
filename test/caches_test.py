"""The caches only a tree's own programs make, made by exclave caches (DESIGN.md 10.1, 13 item 48).

    test/caches_test.py --exclave EXCLAVE [--work DIR]

The exclave holds Python, GLib's schema compiler with schemas to compile and the MIME database's
generator with its packages: scripts/inputs makes caches.exclave, Ubuntu's python3-minimal,
libglib2.0-bin, shared-mime-info and gsettings-desktop-schemas. On a copy, before and after
`exclave caches`: Python imports a module from its source, then from bytecode in __pycache__,
checked by the source's hash; gsettings finds no schemas, then reads a key's default; GIO takes an
HTML file for plain text, then for HTML. The tree hash is recorded again, so exclave check passes;
a second run changes nothing; and the given exclave, whose files the copy shares by hard links, is
left as it was.
"""

import argparse
import os
import shutil
import subprocess
import sys

import tree

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PYC = "lib/python3.12/encodings/__pycache__/aliases.cpython-312.pyc"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--exclave", required=True, help="an exclave holding Python, GLib and shared-mime-info"
    )
    ap.add_argument("--work", default=os.path.join(REPO, "build", "caches-work"))
    args = ap.parse_args()
    work = os.path.abspath(args.work)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    given = os.path.abspath(args.exclave)
    given_hash = tree.records(os.path.join(given, ".exclave", "hashes"))["tree"]
    ex = tree.fresh_exclave(given, os.path.join(work, "caches.exclave"))
    root = os.path.join(ex, "tree")
    sh = os.path.join(root, tree.vbin(root, "sh").lstrip("/"))
    with open(os.path.join(work, "page.html"), "w") as f:
        f.write("<html><body>an exclave</body></html>\n")
    probe = (
        'python3 -v -c "import enum" 2>&1 | grep "code object from .*/enum"; '
        "GSETTINGS_BACKEND=memory gsettings get org.gnome.desktop.interface clock-format 2>&1; "
        "gio info -a standard::content-type page.html | grep content-type"
    )
    env = {"PATH": "/usr/bin:/bin", "HOME": work}

    def state() -> list[str]:
        p = subprocess.run(
            [sh, "-c", probe],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        return [x.strip() for x in p.stdout.strip().split("\n")]

    def caches() -> tuple[int, str]:
        p = subprocess.run(
            [*tree.TOOL, "caches", ex],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        return p.returncode, p.stdout + p.stderr

    fails = 0

    def expect(ok: bool, what: str, got: object) -> None:  # noqa: FBT001  the verdict reads first, as harness.expect
        nonlocal fails
        print(f"{'ok' if ok else 'FAIL'}: {what}{'' if ok else f': {got!r}'}")
        fails += not ok

    before = state()
    expect(
        before
        == [
            "# code object from /usr/lib/python3.12/enum.py",
            "No schemas installed",
            "standard::content-type: text/plain",
        ],
        "before: enum compiled from its source, no schemas, HTML taken for plain text",
        before,
    )
    rc, out = caches()
    expect(
        rc == 0
        and "python3.12 bytecode:" in out
        and "GSettings schemas: gschemas.compiled, new or changed" in out
        and "MIME database:" in out,
        "exclave caches runs the three generators",
        out,
    )
    after = state()
    expect(
        after
        == [
            "# code object from '/usr/lib/python3.12/__pycache__/enum.cpython-312.pyc'",
            "'24h'",
            "standard::content-type: text/html",
        ],
        "after: enum from its bytecode, the schemas' default read, HTML known",
        after,
    )
    with open(os.path.join(root, "usr", PYC), "rb") as f:
        flags = int.from_bytes(f.read(8)[4:8], "little")
    expect(flags == 3, "the bytecode is checked against its source's hash (PEP 552 flags 3)", flags)
    p = subprocess.run([*tree.TOOL, "check", ex], capture_output=True, text=True, check=False)
    expect(p.returncode == 0, "exclave check passes on the tree hash recorded", p.stdout[-300:])
    rc, again = caches()
    expect(
        rc == 0 and "0 new or changed" in again and "unchanged" in again,
        "a second run changes nothing",
        again,
    )
    expect(
        tree.records(os.path.join(given, ".exclave", "hashes"))["tree"] == given_hash
        and not os.path.lexists(os.path.join(given, "tree", "usr", PYC))
        and subprocess.run(
            [*tree.TOOL, "hash", given], capture_output=True, text=True, check=False
        ).stdout.strip()
        == given_hash[0][0],
        "the given exclave is left as it was",
        given_hash,
    )
    print(f"caches: {fails} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
