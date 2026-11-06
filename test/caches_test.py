"""The caches only a tree's own programs make, made by exclave caches (DESIGN.md 10.1, 13 item 48).

    test/caches_test.py --exclave EXCLAVE [--exclave EXCLAVE...] [--work DIR]

Each exclave holds Python, GLib's schema compiler and gsettings and gio, schemas to compile and
the MIME database's generator with its packages: scripts/inputs makes caches.exclave, Ubuntu's
python3-minimal, libglib2.0-bin, shared-mime-info and gsettings-desktop-schemas, and on x86-64
alpine-caches.exclave, Alpine's, whose shell is busybox. On a copy of each, before and after
`exclave caches`: Python imports a module from its source, then from bytecode in __pycache__,
checked by the source's hash; gsettings finds no schemas, then reads a key's default; GIO takes an
HTML file for plain text, then for HTML. exclave check passes on the tree hash recorded; a second
run changes no file and leaves the tree hash as it was; a tree changed since its hash was
recorded is refused; and the given exclave, whose files the copy shares by hard links, is left as
it was. On a second copy, a generator that fails, the MIME generator on a package that is a
directory, leaves the tree, its hash and the exclave's directory as they were.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

import tree

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
fails = 0


def expect(ok: bool, what: str, got: object) -> None:  # noqa: FBT001  the verdict first, as harness.expect
    global fails  # noqa: PLW0603  one count for the run, as the other drivers keep
    print(f"{'ok' if ok else 'FAIL'}: {what}{'' if ok else f': {got!r}'}")
    fails += not ok


def tool(*args: str) -> tuple[int, str]:
    p = subprocess.run(
        [*tree.TOOL, *args], capture_output=True, text=True, check=False, timeout=300
    )
    return p.returncode, p.stdout + p.stderr


def recorded(ex: str) -> str:
    return tree.records(os.path.join(ex, ".exclave", "hashes"))["tree"][0][0]


def one(given: str, work: str) -> None:
    """Every case on copies of the exclave given."""
    name = os.path.basename(given)
    given_hash = recorded(given)
    ex = tree.fresh_exclave(given, os.path.join(work, name))
    root = os.path.join(ex, "tree")
    pys = [
        n
        for n in sorted(os.listdir(os.path.join(root, "usr", "lib")))
        if re.fullmatch(r"python3\.\d+", n)
    ]
    expect(
        bool(pys),
        f"{name}: a Python under /usr/lib",
        sorted(os.listdir(os.path.join(root, "usr", "lib"))),
    )
    if not pys:
        return
    py = pys[0]
    pyc = os.path.join(
        "usr",
        "lib",
        py,
        "__pycache__",
        "enum.cpython-" + py[len("python") :].replace(".", "") + ".pyc",
    )
    sh = os.path.join(root, tree.vbin(root, "sh").lstrip("/"))
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

    before = state()
    expect(
        before
        == [
            f"# code object from /usr/lib/{py}/enum.py",
            "No schemas installed",
            "standard::content-type: text/plain",
        ],
        f"{name}: before, enum compiled from its source, no schemas, HTML taken for plain text",
        before,
    )
    rc, out = tool("caches", ex)
    expect(
        rc == 0
        and f"{py} bytecode:" in out
        and "GSettings schemas: 1 file, 1 new or changed" in out
        and "MIME database:" in out,
        f"{name}: exclave caches runs the three generators",
        out[-600:],
    )
    after = state()
    expect(
        after == [f"# code object from '/{pyc}'", "'24h'", "standard::content-type: text/html"],
        f"{name}: after, enum from its bytecode, the schemas' default read, HTML known",
        after,
    )
    with open(os.path.join(root, pyc), "rb") as f:
        flags = int.from_bytes(f.read(8)[4:8], "little")
    expect(
        flags == 3, f"{name}: the bytecode is checked by its source's hash (PEP 552 flags 3)", flags
    )
    rc, out = tool("check", ex)
    expect(rc == 0, f"{name}: exclave check passes on the tree hash recorded", out[-300:])
    first = recorded(ex)
    rc, again = tool("caches", ex)
    counts = re.findall(r", (\d+) new or changed$", again, re.MULTILINE)
    expect(
        rc == 0 and len(counts) == 3 and set(counts) == {"0"} and recorded(ex) == first,
        f"{name}: a second run changes no file and the same tree hash is recorded",
        again[-400:],
    )
    expect(
        not os.path.exists(os.path.join(ex, ".exclave", "caches")),
        f"{name}: no staging is left",
        ex,
    )
    with open(os.path.join(root, "zz-edited"), "w") as f:
        f.write("an edit the hash has not seen\n")
    rc, out = tool("caches", ex)
    expect(
        rc == 1 and "differs from the hash" in out and recorded(ex) == first,
        f"{name}: a tree changed since its hash was recorded is refused",
        out,
    )
    rc, out = tool("hash", given)
    expect(
        recorded(given) == given_hash
        and out.strip() == given_hash
        and not os.path.lexists(os.path.join(given, "tree", pyc)),
        f"{name}: the given exclave is left as it was",
        out,
    )

    # a generator that fails: nothing reaches the tree
    ex2 = tree.fresh_exclave(given, os.path.join(work, "failing-" + name))
    os.makedirs(os.path.join(ex2, "tree", "usr", "share", "mime", "packages", "zz-a-directory.xml"))
    rc, out = tool("wrap", ex2)
    expect(rc == 0, f"{name}: the altered copy wraps again", out[-300:])
    before_fail = recorded(ex2)
    rc, out = tool("caches", ex2)
    _rc, now = tool("hash", ex2)
    expect(
        rc == 1
        and now.strip() == before_fail
        and recorded(ex2) == before_fail
        and not os.path.lexists(os.path.join(ex2, "tree", pyc))
        and not os.path.exists(os.path.join(ex2, ".exclave", "caches")),
        f"{name}: a generator that fails leaves the tree, its hash and .exclave as they were",
        out[-300:],
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--exclave",
        action="append",
        required=True,
        help="an exclave holding Python, GLib and shared-mime-info; several may be given",
    )
    ap.add_argument("--work", default=os.path.join(REPO, "build", "caches-work"))
    args = ap.parse_args()
    work = os.path.abspath(args.work)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    with open(os.path.join(work, "page.html"), "w") as f:
        f.write("<html><body>an exclave</body></html>\n")
    for ex in args.exclave:
        one(os.path.abspath(ex), work)
    print(f"caches: {fails} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
