"""The caches only a tree's own programs make, made by exclave caches (DESIGN.md 10.1, 13 item 48).

    test/caches_test.py --exclave EXCLAVE [--exclave EXCLAVE...] [--work DIR]

Each exclave holds Python, GLib's schema compiler and gsettings and gio, schemas to compile and
the MIME database's generator with its packages: scripts/inputs makes caches.exclave, Ubuntu's
python3-minimal, libglib2.0-bin, shared-mime-info and gsettings-desktop-schemas with
libgdk-pixbuf2.0-bin, dconf-gsettings-backend, desktop-file-utils, gtk-update-icon-cache,
hicolor-icon-theme, vim-common, fontconfig and fonts-dejavu-core, and on x86-64
alpine-caches.exclave, Alpine's, whose shell is busybox, with gdk-pixbuf, dconf,
desktop-file-utils, gtk-update-icon-cache, hicolor-icon-theme, htop, fontconfig and font-dejavu.
On a copy of each, before and after `exclave caches`: Python imports a module from its source,
then from bytecode in __pycache__, checked by the source's hash; gsettings finds no schemas, then
reads a key's default; GIO takes an HTML file for plain text, then for HTML. Where the tree holds
the generator and something for it to index, and otherwise skipped with the reason: GIO opens
every module in its module directory, then reads giomodule.cache and opens none;
gdk-pixbuf-pixdata cannot read a BMP image, whose loader is a module, then reads it; each icon
theme's cache does not exist, then validates, names every icon of the theme and is no older than
the theme's directory; the desktop database does not exist, then maps each MIME type to the
desktop files that name it; and fc-list writes fontconfig's caches under the home, then lists
the same fonts and writes none. exclave check passes on the tree hash recorded; a second run
changes no file and leaves the tree hash as it was; font directories given new times, as a copy
that loses them gives them, leave the font caches stale until a run remakes them; a tree changed
since its hash was recorded is refused; and the given exclave, whose files the copy shares by
hard links, is left as it was. On a second copy, a generator that fails, the MIME generator on a
package that is a directory, leaves the tree, its hash and the exclave's directory as they were.
"""

import argparse
import glob
import os
import platform
import re
import shutil
import subprocess
import sys
from typing import Any

import tree

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
# a BMP image of one pixel, whose loader is a module in gdk-pixbuf's builds of Ubuntu and Alpine
BMP = bytes.fromhex(
    "424d3a000000000000003600000028000000010000000100000001001800000000000400000013"
    "0b0000130b00000000000000000000ff000000"
)
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


def real(root: str, v: str) -> str | None:
    """The file in the tree a virtual path names, its links followed, or None."""
    p = os.path.join(root, tree.resolve(root, v).lstrip("/"))
    return p if os.path.lexists(p) else None


def first(root: str, *vs: str) -> str | None:
    """The first of the virtual paths the tree holds."""
    return next((v for v in vs if real(root, v)), None)


def desktop_types(apps: str) -> dict[str, set[str]]:
    """The desktop files under apps that name each MIME type, by desktop file ID."""
    types: dict[str, set[str]] = {}
    for d, _dirs, files in os.walk(apps):
        for n in files:
            if not n.endswith(".desktop"):
                continue
            path = os.path.join(d, n)
            ident = os.path.relpath(path, apps).replace("/", "-")
            group = ""
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()  # noqa: PLW2901  the line as the key file parser reads it
                    if line.startswith("["):
                        group = line
                    elif group == "[Desktop Entry]" and line.startswith("MimeType="):
                        for t in line[len("MimeType=") :].split(";"):
                            if t:
                                types.setdefault(t, set()).add(ident)
    return types


def mimeinfo(path: str) -> dict[str, set[str]]:
    types: dict[str, set[str]] = {}
    with open(path, encoding="utf-8") as f:
        for line in f.read().split("\n")[1:]:
            if "=" in line:
                t, ids = line.split("=", 1)
                types[t] = {i for i in ids.split(";") if i}
    return types


class Probe:
    """A shell command run inside the exclave, with a home of its own and a log."""

    def __init__(self, root: str, work: str) -> None:
        self.sh = os.path.join(root, tree.vbin(root, "sh").lstrip("/"))
        self.work = work
        self.n = 0

    def run(self, cmd: str) -> tuple[int, str, str, str]:
        """Return the exit status, the output, the log and the home directory of the run."""
        self.n += 1
        home = os.path.join(self.work, f"home-{self.n}")
        log = os.path.join(self.work, f"log-{self.n}")
        os.makedirs(home)
        p = subprocess.run(
            [self.sh, "-c", cmd],
            cwd=self.work,
            env={"PATH": "/usr/bin:/bin", "HOME": home, "EXCLAVE_LOG": log},
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        logged = ""
        for f in sorted(glob.glob(log + "*")):
            with open(f, encoding="utf-8", errors="replace") as g:
                logged += g.read()
        return p.returncode, p.stdout + p.stderr, logged, home


def opened(log: str, pattern: str) -> list[str]:
    """The paths the log says were opened, matching the pattern."""
    return [
        m.group(1)
        for m in re.finditer(r"^open(?:at)? \d+ (.*)$", log, re.MULTILINE)
        if re.fullmatch(pattern, m.group(1))
    ]


def home_files(home: str) -> list[str]:
    return [os.path.join(d, n) for d, _dirs, files in os.walk(home) for n in files]


class Generators:
    """The generators beyond Python's, GSettings' and the MIME database's.

    What each needs of the tree, the reason it is skipped where the tree lacks it, and its state
    before and after.
    """

    def __init__(self, root: str, probe: Probe, name: str) -> None:
        self.root, self.probe, self.name = root, probe, name
        trip = tree.triplet(root, platform.machine())
        libs = ("/usr/lib", f"/usr/lib/{trip}", "/usr/lib64")
        self.cases: dict[str, str] = {}  # the line exclave caches prints, by case
        self.gio_dirs = [
            d
            for d in (f"{lib}/gio/modules" for lib in libs)
            if (r := real(root, d)) and glob.glob(os.path.join(r, "*.so"))
        ]
        self.gio = first(
            root,
            "/usr/bin/gio-querymodules",
            "/usr/bin/gio-querymodules-64",
            f"/usr/lib/{trip}/glib-2.0/gio-querymodules",
        )
        self.case(
            "gio",
            "GIO module cache",
            self.gio and self.gio_dirs and real(root, tree.vbin(root, "gio")),
            "no gio-querymodules, gio or GIO module",
        )
        query = first(
            root,
            "/usr/bin/gdk-pixbuf-query-loaders",
            "/usr/bin/gdk-pixbuf-query-loaders-64",
            f"/usr/lib/{trip}/gdk-pixbuf-2.0/gdk-pixbuf-query-loaders",
        )
        bmp = first(
            root, *(f"{lib}/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-bmp.so" for lib in libs)
        )
        self.case(
            "pixbuf",
            "gdk-pixbuf loader cache",
            query and bmp and real(root, tree.vbin(root, "gdk-pixbuf-pixdata")),
            "no gdk-pixbuf-query-loaders, gdk-pixbuf-pixdata or BMP loader module",
        )
        self.icon_tool = first(
            root, "/usr/bin/gtk-update-icon-cache", "/usr/bin/gtk4-update-icon-cache"
        )
        icons = real(root, "/usr/share/icons")
        self.themes = sorted(
            {
                tree.resolve(root, f"/usr/share/icons/{n}")
                for n in (os.listdir(icons) if icons and os.path.isdir(icons) else [])
                if real(root, f"/usr/share/icons/{n}/index.theme")
            }
        )
        self.case(
            "icons",
            "icon caches",
            self.icon_tool and self.themes,
            "no gtk-update-icon-cache or icon theme",
        )
        self.apps = real(root, "/usr/share/applications")
        self.case(
            "desktop",
            "desktop database",
            real(root, "/usr/bin/update-desktop-database")
            and self.apps
            and any(f.endswith(".desktop") for _d, _s, fs in os.walk(self.apps) for f in fs),
            "no update-desktop-database or desktop file",
        )
        self.case(
            "fonts",
            "font caches",
            real(root, "/usr/bin/fc-cache")
            and real(root, tree.vbin(root, "fc-list"))
            and real(root, "/etc/fonts/fonts.conf"),
            "no fc-cache, fc-list or /etc/fonts/fonts.conf",
        )

    def case(self, case: str, line: str, applies: object, reason: str) -> None:
        if applies:
            self.cases[case] = line
        else:
            print(f"skip: {self.name}: {case}: the tree has {reason}")

    def state(self) -> dict[str, Any]:
        """What each case's program does now."""
        s: dict[str, Any] = {}
        root, probe = self.root, self.probe
        if "gio" in self.cases:
            _rc, _out, log, _home = probe.run("gio info -a standard::content-type page.html")
            dirs = "|".join(re.escape(d) for d in self.gio_dirs)
            s["gio"] = (
                bool(opened(log, f"({dirs})/[^/]*\\.so")),
                bool(opened(log, f"({dirs})/giomodule\\.cache")),
            )
        if "pixbuf" in self.cases:
            rc, out, _log, _home = probe.run("gdk-pixbuf-pixdata image.bmp image.pixdata")
            s["pixbuf"] = (rc, "recognize" in out)
        if "icons" in self.cases:
            got = []
            for theme in self.themes:
                rc, _out, _log, _home = probe.run(f'"{self.icon_tool}" -v "{theme}"')
                cache = os.path.join(root, theme.lstrip("/"), "icon-theme.cache")
                if not os.path.exists(cache):
                    got.append((theme, rc, None))
                    continue
                with open(cache, "rb") as f:
                    data = f.read()
                d = os.path.join(root, theme.lstrip("/"))
                names = {
                    os.path.splitext(n)[0]
                    for sub, _dirs, files in os.walk(d)
                    if sub != d
                    for n in files
                    if n.endswith((".png", ".svg", ".xpm"))
                }
                missing = sorted(n for n in names if n.encode() + b"\0" not in data)
                fresh = os.stat(cache).st_mtime_ns >= os.stat(d).st_mtime_ns
                got.append((theme, rc, (missing, fresh)))
            s["icons"] = got
        if "desktop" in self.cases:
            cache = os.path.join(str(self.apps), "mimeinfo.cache")
            s["desktop"] = mimeinfo(cache) if os.path.exists(cache) else None
        if "fonts" in self.cases:
            rc, out, _log, home = probe.run("fc-list")
            s["fonts"] = (rc, len(out.strip().split("\n")), len(home_files(home)))
        return s

    def check(self, before: dict[str, Any], after: dict[str, Any]) -> None:
        n = self.name
        if "gio" in self.cases:
            expect(
                before["gio"] == (True, False) and after["gio"] == (False, True),
                f"{n}: before, GIO opens its modules; after, giomodule.cache and no module",
                (before["gio"], after["gio"]),
            )
        if "pixbuf" in self.cases:
            b, a = before["pixbuf"], after["pixbuf"]
            expect(
                b[0] != 0 and b[1] and a == (0, False),
                f"{n}: before, gdk-pixbuf cannot read a BMP image; after, it reads it",
                (b, a),
            )
        if "icons" in self.cases:
            b, a = before["icons"], after["icons"]
            expect(
                all(rc != 0 and made is None for _t, rc, made in b)
                and all(rc == 0 and made == ([], True) for _t, rc, made in a),
                f"{n}: before, no icon cache; after, each theme's validates, names every icon "
                "and is no older than its directory",
                (b, a),
            )
        if "desktop" in self.cases:
            want = desktop_types(str(self.apps))
            expect(
                before["desktop"] is None and after["desktop"] == want,
                f"{n}: before, no desktop database; after, each MIME type's desktop files "
                f"({len(want)} types)",
                (before["desktop"], after["desktop"], want),
            )
        if "fonts" in self.cases:
            b, a = before["fonts"], after["fonts"]
            expect(
                b[0] == 0 and b[1] > 0 and b[2] > 0 and a == (0, b[1], 0),
                f"{n}: before, fc-list writes font caches under the home; after, it lists the "
                "same fonts and writes none",
                (b, a),
            )


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

    runs = os.path.join(work, "runs-" + name)
    os.makedirs(runs)
    shutil.copy(os.path.join(work, "page.html"), runs)
    with open(os.path.join(runs, "image.bmp"), "wb") as f:
        f.write(BMP)
    gens = Generators(root, Probe(root, runs), name)
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
    gens_before = gens.state()
    rc, out = tool("caches", ex)
    made = re.findall(r", \d+ new or changed$", out, re.MULTILINE)
    expect(
        rc == 0
        and f"{py} bytecode:" in out
        and "GSettings schemas: 1 file, 1 new or changed" in out
        and "MIME database:" in out
        and all(f"\n{line}: " in out for line in gens.cases.values()),
        f"{name}: exclave caches runs the generators the tree holds: "
        + ", ".join(["Python", "GSettings", "MIME", *gens.cases]),
        out[-600:],
    )
    after = state()
    expect(
        after == [f"# code object from '/{pyc}'", "'24h'", "standard::content-type: text/html"],
        f"{name}: after, enum from its bytecode, the schemas' default read, HTML known",
        after,
    )
    gens.check(gens_before, gens.state())
    with open(os.path.join(root, pyc), "rb") as f:
        flags = int.from_bytes(f.read(8)[4:8], "little")
    expect(
        flags == 3, f"{name}: the bytecode is checked by its source's hash (PEP 552 flags 3)", flags
    )
    rc, out = tool("check", ex)
    expect(rc == 0, f"{name}: exclave check passes on the tree hash recorded", out[-300:])
    first_hash = recorded(ex)
    rc, again = tool("caches", ex)
    counts = re.findall(r", (\d+) new or changed$", again, re.MULTILINE)
    expect(
        rc == 0
        and len(counts) == len(made)
        and set(counts) == {"0"}
        and recorded(ex) == first_hash,
        f"{name}: a second run changes no file and the same tree hash is recorded",
        again[-400:],
    )
    expect(
        not os.path.exists(os.path.join(ex, ".exclave", "caches")),
        f"{name}: no staging is left",
        ex,
    )
    if "fonts" in gens.cases:
        # a copy that loses the times, as cp -r does: the font directories' change, so their
        # caches are stale and fontconfig writes its own, until exclave caches remakes them
        fonts = real(root, "/usr/share/fonts")
        for d, _dirs, _files in os.walk(fonts) if fonts else []:
            st = os.stat(d)
            os.utime(d, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
        stale = gens.state()["fonts"]
        rc, out = tool("caches", ex)
        remade = gens.state()["fonts"]
        expect(
            stale[2] > 0 and rc == 0 and "font caches:" in out and remade == (0, stale[1], 0),
            f"{name}: font directories with new times leave the caches stale; a run remakes them",
            (stale, remade, out[-300:]),
        )
        first_hash = recorded(ex)
    with open(os.path.join(root, "zz-edited"), "w") as f:
        f.write("an edit the hash has not seen\n")
    rc, out = tool("caches", ex)
    expect(
        rc == 1 and "differs from the hash" in out and recorded(ex) == first_hash,
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
