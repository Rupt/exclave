"""Unpack's rules, asked with hostile package files in each format (DESIGN.md 10.1, 17).

    test/unpack_test.py [--work DIR] [-k NAME|SUBSTRING]

Each test makes the .deb, .apk and .rpm files it needs (test/packages.py) and runs build/exclave
unpack on them as scripts/unpack does. A set unpack refuses must be refused in one line, `unpack: `
and the
reason, with no traceback and nothing left at the output; and whatever it does, nothing outside
the output may change: each test's work directory holds host/, with a file the packages aim at
through `..`, symlinks and hard links. The tests take no exclave; the readers' own tests, which
wrap what they unpack, run build/exclave. Prints one line per test; the exit status is the number
of failures, at most 255.
"""

import argparse
import base64
import dataclasses
import gzip
import hashlib
import io
import os
import shutil
import stat
import sys
import tarfile
import zlib
from typing import TYPE_CHECKING, Any
lazy from collections.abc import Sequence

import tree
from harness import TESTS, expect, read_text, run, run_tests, select, test
from packages import MACHINE, MTIME, Member, compress, cpio, make_apk, make_deb, make_rpm, tar_bytes

if TYPE_CHECKING:
    from harness import Test

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
UNPACK = tree.UNPACK
TOOL = tree.TOOL
FORMATS = ("deb", "apk", "rpm")
# the host's volatile directories (8.1), as unpack strips them; test/tables_test.py holds the
# copies to one
VOLATILE = ("/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run")


@dataclasses.dataclass(frozen=True)
class Ctx:
    """A test's own directories: work, and host/ inside it, which no package may change."""

    work: str
    host: str


def package(
    ctx: Ctx,
    fmt: str,
    name: str,
    members: Sequence[Member],
    *,
    replaces: str = "",
    data: bytes | None = None,
    control_files: Sequence[tuple[str, str]] = (),
) -> str:
    """Write the package name in the format fmt, with a Replaces field; return its path.

    data: the payload as given: a .deb's data member, an .apk's data stream, an .rpm's payload.
    control_files: a .deb's further control members, a postinst or a triggers file, by name.
    """
    d = os.path.join(ctx.work, "pkgs")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{name}.{fmt}")
    if fmt == "deb":
        make_deb(
            path,
            name,
            members,
            f"Replaces: {replaces}\n" if replaces else "",
            data=data,
            control_files=control_files,
        )
    elif fmt == "apk":
        make_apk(path, name, members, f"replaces = {replaces}\n" if replaces else "", data=data)
    else:
        assert not replaces  # rpm spells it Obsoletes, which the reader maps; not built here
        make_rpm(path, name, members, payload=data)
    return path


def host_state(ctx: Ctx) -> list[tuple[str, int, int, int, bytes]]:
    """Every entry under host/: its path, mode, size, link count and contents."""
    out = []
    for dirpath, dirnames, filenames in os.walk(ctx.host):
        for n in sorted(dirnames + filenames):
            p = os.path.join(dirpath, n)
            st = os.lstat(p)
            body = b""
            if stat.S_ISREG(st.st_mode):
                with open(p, "rb") as f:
                    body = f.read()
            out.append((os.path.relpath(p, ctx.host), st.st_mode, st.st_size, st.st_nlink, body))
    return out


def unpack(ctx: Ctx, name: str, pkgs: Sequence[str]) -> tuple[int, str, str, str]:
    """Unpack into WORK/NAME.exclave; host/ must be as it was, whatever the answer."""
    before = host_state(ctx)
    out = os.path.join(ctx.work, name + ".exclave")
    rc, o, e = run([*UNPACK, out, *pkgs])
    expect(host_state(ctx) == before, f"{name}: unpack changed host/: {e[-300:]!r}")
    expect(
        "Traceback" not in e and (rc == 0 or e.startswith("unpack: ")),
        f"{name}: rc={rc}, not one line: {e[-400:]!r}",
    )
    return rc, o, e, out


def refused(ctx: Ctx, name: str, pkgs: Sequence[str], why: str) -> None:
    """The set must be refused, naming why, the reason measured, with nothing left at the output."""
    rc, o, e, out = unpack(ctx, name, pkgs)
    expect(rc == 1 and why in e, f"{name}: wanted a refusal naming {why!r}: rc={rc} {o}{e}")
    expect(not os.path.lexists(out), f"{name}: the refusal left {out} behind")


def accepted(ctx: Ctx, name: str, pkgs: Sequence[str]) -> tuple[str, str]:
    """The set must unpack; return its tree and the standard output."""
    rc, o, e, out = unpack(ctx, name, pkgs)
    expect(rc == 0, f"{name}: refused: {e[-400:]!r}")
    return os.path.join(out, "tree"), o


def landing(root: str, host_path: str) -> str | None:
    """Where in the tree an absolute link to host_path leads, or None if the step strips it.

    The volatile step (8.1) leaves nothing there to read, as when the work directory is under /tmp.
    """
    if any(host_path == v or host_path.startswith(v + "/") for v in VOLATILE):
        return None
    return os.path.join(root, host_path.lstrip("/"))


UNREAD = "the work directory is under a volatile prefix: where an absolute link lands was not read"


# ---------------------------------------------------------------- the readers by format
@test
def rpm_unpack(ctx: Ctx) -> None:
    """10.1: unpack reads .rpm files by the file.

    Lead, headers, cpio payload; Requires and Provides with rpm's flags, so-called provides, file
    dependencies asked of the tree, rpmlib features and rich dependencies skipped; the merged-usr
    links; alternatives --install lines in %post synthesised; one format per exclave.
    """
    d = os.path.join(ctx.work, "rpms")
    os.makedirs(d, exist_ok=True)
    # rpm's RPMSENSE_EQUAL, and RPMSENSE_GREATER | RPMSENSE_EQUAL
    sense_eq, sense_ge = 8, 12
    make_rpm(
        os.path.join(d, "tool-1.0-1.x86_64.rpm"),
        "tool",
        [
            ("usr", "dir", None, 0o755),
            ("usr/bin", "dir", None, 0o755),
            ("usr/bin/tool-2", "file", b"#!/bin/sh\necho tool ok\n", 0o755),
            (
                "usr/bin/tool",
                "file",
                b"#!/bin/sh\necho the shipped file, which %post removes\n",
                0o755,
            ),
        ],
        requires=[
            ("libfoo.so.1()(64bit)", 0, ""),
            ("absent-pkg", sense_ge, "2"),
            ("/bin/sh", 0, ""),
            ("/usr/bin/absent-file", 0, ""),
            ("rpmlib(CompressedFileNames)", (1 << 24) | 10, "3.0.4-1"),
            ("(a or b)", 0, ""),
        ],
        postin="/usr/bin/rm -f /usr/bin/tool\n"
        "/usr/sbin/alternatives --install /usr/bin/tool tool /usr/bin/tool-2 20\n",
    )
    make_rpm(
        os.path.join(d, "libfoo-1.0-1.x86_64.rpm"),
        "libfoo",
        [
            ("usr", "dir", None, 0o755),
            ("usr/lib64", "dir", None, 0o755),
            ("usr/lib64/libfoo.so.1", "file", b"data\n", 0o644),
            ("usr/bin", "dir", None, 0o755),
            ("usr/bin/sh", "file", b"#!/bin/true\n", 0o755),  # /bin/sh through the merged-usr link
            ("usr/share", "dir", None, 0o755),
            ("usr/share/doc", "file", b"doc\n", 0o644),
        ],
        provides=[("libfoo.so.1()(64bit)", 0, ""), ("libfoo", sense_eq, "1.0-1")],
    )
    out = os.path.join(ctx.work, "rpm.exclave")
    rc, o, e = run(
        [
            *UNPACK,
            out,
            os.path.join(d, "tool-1.0-1.x86_64.rpm"),
            os.path.join(d, "libfoo-1.0-1.x86_64.rpm"),
        ]
    )
    expect(rc == 0, "unpack: " + o + e)
    expect(
        "depends: tool needs absent-pkg (>= 2), not in the set" in o,
        "the versioned dependency was not reported: " + o,
    )
    expect(
        "libfoo" not in o.replace("libfoo-1.0", "")
        and "/bin/sh" not in o
        and "rpmlib" not in o
        and "(a or b)" not in o,
        "a provide in the set, a file dependency the tree has, an rpmlib feature or a rich "
        "dependency was reported: " + o,
    )
    expect(
        "depends: tool needs /usr/bin/absent-file, not in the set" in o,
        "a file dependency the tree lacks was not reported: " + o,
    )
    root = os.path.join(out, "tree")
    expect(
        os.readlink(os.path.join(root, "bin")) == "usr/bin"
        and os.readlink(os.path.join(root, "lib64")) == "usr/lib64",
        "the merged-usr links",
    )
    expect(
        os.path.exists(os.path.join(root, "usr", "lib64", "libfoo.so.1"))
        and os.path.exists(os.path.join(root, "usr", "bin", "tool-2")),
        "payload extracted",
    )
    expect(
        os.path.islink(os.path.join(root, "usr", "bin", "tool"))
        and os.readlink(os.path.join(root, "usr", "bin", "tool")) == "/etc/alternatives/tool"
        and os.readlink(os.path.join(root, "etc", "alternatives", "tool")) == "/usr/bin/tool-2",
        "alternatives from %post replace the shipped file at the link path: {!r}".format(
            os.listdir(os.path.join(root, "usr", "bin"))
        ),
    )
    lock = tree.records(os.path.join(out, ".exclave", "hashes"))
    pkgs = lock.get("pkg", [])
    expect(
        [tuple(p[:3]) for p in pkgs] == [("libfoo", "1.0-1", MACHINE), ("tool", "1.0-1", MACHINE)],
        f"pkg records: {pkgs!r}",
    )
    rc, o, e = run([*TOOL, "wrap", out])
    expect(
        rc == 0 and tree.records(os.path.join(out, ".exclave", "hashes")).get("tree"),
        "wrap: " + o + e,
    )
    make_apk(os.path.join(d, "x-1.0-r0.apk"), "x", [("usr", "dir", None, 0o755)])
    rc, o, e = run(
        [
            *UNPACK,
            out + "2",
            os.path.join(d, "x-1.0-r0.apk"),
            os.path.join(d, "tool-1.0-1.x86_64.rpm"),
        ]
    )
    expect(rc != 0 and "one format per exclave" in o + e, "a mixed set must be refused: " + o + e)


@test
def apk_unpack(ctx: Ctx) -> None:
    """10.1: unpack reads .apk files by the file, with .PKGINFO's depend and provides.

    Names and file dependencies are asked of the tree; Alpine's directories are its own, not merged
    /usr; busybox's applet links are synthesised from /etc/busybox-paths.d as relative links; apk's
    database records each package, its licence by name among its fields; one format per exclave.
    """
    d = os.path.join(ctx.work, "apks")
    os.makedirs(d, exist_ok=True)
    make_apk(
        os.path.join(d, "tool-1.0-r0.apk"),
        "tool",
        [
            ("usr", "dir", None, 0o755),
            ("usr/bin", "dir", None, 0o755),
            ("usr/bin/tool", "file", b"#!/bin/sh\necho tool ok\n", 0o755),
        ],
        "depend = so:libfoo.so.1\ndepend = absent-pkg>=2\ndepend = /bin/sh\n"
        "depend = /usr/bin/absent-file\n",
    )
    make_apk(
        os.path.join(d, "libfoo-1.0-r0.apk"),
        "libfoo",
        [
            ("bin", "dir", None, 0o755),
            ("bin/busybox", "file", b"#!/bin/true\n", 0o755),
            ("etc", "dir", None, 0o755),
            ("etc/busybox-paths.d", "dir", None, 0o755),
            ("etc/busybox-paths.d/busybox", "file", b"bin/sh\nusr/bin/tool2\n", 0o644),
            ("usr", "dir", None, 0o755),
            ("usr/lib", "dir", None, 0o755),
            ("usr/lib/libfoo.so.1", "file", b"data\n", 0o644),
        ],
        "provides = so:libfoo.so.1=1\nprovides = cmd:busybox=1.0-r0\n"
        "license = MIT AND Zlib\norigin = foo\npkgdesc = the foo library\n",
    )
    out = os.path.join(ctx.work, "apk.exclave")
    rc, o, e = run(
        [*UNPACK, out, os.path.join(d, "tool-1.0-r0.apk"), os.path.join(d, "libfoo-1.0-r0.apk")]
    )
    expect(rc == 0, "unpack: " + o + e)
    expect(
        "depends: tool needs absent-pkg (>= 2), not in the set" in o,
        "the versioned dependency was not reported: " + o,
    )
    expect(
        "libfoo" not in o.replace("libfoo-1.0", "") and "/bin/sh" not in o,
        "a so: provides in the set or a file dependency the tree has (the applet link) was "
        "reported: " + o,
    )
    expect(
        "depends: tool needs /usr/bin/absent-file, not in the set" in o,
        "a file dependency the tree lacks was not reported: " + o,
    )
    root = os.path.join(out, "tree")
    expect(
        os.path.isdir(os.path.join(root, "bin")) and not os.path.islink(os.path.join(root, "bin")),
        "Alpine's /bin is a directory of its own",
    )
    expect(
        os.readlink(os.path.join(root, "bin", "sh")) == "busybox"
        and os.readlink(os.path.join(root, "usr", "bin", "tool2")) == "../../bin/busybox",
        "applet links relative to their target: {!r}".format(os.listdir(os.path.join(root, "bin"))),
    )
    with open(os.path.join(root, "lib", "apk", "db", "installed")) as f:
        db = f.read()
    with open(os.path.join(d, "libfoo-1.0-r0.apk"), "rb") as f:
        raw = f.read()
    # the control section, the first gzip member here, is what apk's checksum is of
    inflate = zlib.decompressobj(31)
    inflate.decompress(raw)
    control = raw[: len(raw) - len(inflate.unused_data)]
    checksum = "Q1" + base64.b64encode(hashlib.sha1(control).digest()).decode()  # noqa: S324  apk's own
    expect(
        db.startswith(
            f"C:{checksum}\nP:libfoo\nV:1.0-r0\nA:{MACHINE}\nS:{len(raw)}\nI:1\n"
            "T:the foo library\nL:MIT AND Zlib\no:foo\np:so:libfoo.so.1=1 cmd:busybox=1.0-r0\n\n"
            "C:Q1"
        )
        and "\nP:tool\n" in db,
        f"apk's database, the licence by name: {db!r}",
    )
    with open(os.path.join(root, "etc", "apk", "world")) as f:
        world = f.read()
    expect(world == "libfoo\ntool\n", f"apk's world, every package: {world!r}")
    lock = tree.records(os.path.join(out, ".exclave", "hashes"))
    pkgs = lock.get("pkg", [])
    expect(
        [tuple(p[:3]) for p in pkgs]
        == [("libfoo", "1.0-r0", MACHINE), ("tool", "1.0-r0", MACHINE)],
        f"pkg records: {pkgs!r}",
    )
    rc, o, e = run([*TOOL, "wrap", out])
    expect(
        rc == 0 and tree.records(os.path.join(out, ".exclave", "hashes")).get("tree"),
        "wrap: " + o + e,
    )
    make_deb(os.path.join(d, "x.deb"), "x", [("./usr", "dir", None, 0o755)])
    rc, o, e = run(
        [*UNPACK, out + "2", os.path.join(d, "x.deb"), os.path.join(d, "tool-1.0-r0.apk")]
    )
    expect(rc != 0 and "one format per exclave" in o + e, "a mixed set must be refused: " + o + e)


@test
def merged_usr_spellings_conflict(ctx: Ctx) -> None:
    """10.1: two spellings of one path under merged usr are one path, so two files there conflict.

    /usr/lib/libfoo.so.1 in one package and /lib/libfoo.so.1 in another, through the merged-usr
    link, are the same file shipped twice, which extraction refuses.
    """
    d = os.path.join(ctx.work, "debs")
    os.makedirs(d, exist_ok=True)
    make_deb(
        os.path.join(d, "a.deb"),
        "a",
        [
            ("./usr", "dir", None, 0o755),
            ("./usr/lib", "dir", None, 0o755),
            ("./usr/lib/libfoo.so.1", "file", b"A", 0o644),
        ],
    )
    make_deb(
        os.path.join(d, "b.deb"),
        "b",
        [("./lib", "dir", None, 0o755), ("./lib/libfoo.so.1", "file", b"B", 0o644)],
    )
    rc, _o, e, _out = unpack(
        ctx, "root-alias", [os.path.join(d, "a.deb"), os.path.join(d, "b.deb")]
    )
    expect(
        rc != 0 and "both ship" in e,
        "the merged-usr spellings of one file were not seen as a conflict: " + e,
    )


@test
def busybox_links_stay_in_the_tree(ctx: Ctx) -> None:
    """10.1: a path in /etc/busybox-paths.d is a member's path, which stays in the tree.

    `..` is refused, and a symlink the set ships, such as one to /tmp, resolves in the tree: the
    applet link never lands on the host.
    """
    d = os.path.join(ctx.work, "busybox-escape")
    os.makedirs(d, exist_ok=True)
    escape = os.path.join(ctx.work, f"escaped-{os.getpid()}")
    host = f"/tmp/exclave-escaped-{os.getpid()}"
    for case, line in (
        ("dotdot", f"../../{os.path.basename(escape)}"),
        ("link", f"usr/hostdir/{os.path.basename(host)}"),
    ):
        pkg = os.path.join(d, f"{case}-1.0-r0.apk")
        make_apk(
            pkg,
            "busybox",
            [
                ("bin", "dir", None, 0o755),
                ("bin/busybox", "file", b"#!/bin/true\n", 0o755),
                ("etc", "dir", None, 0o755),
                ("etc/busybox-paths.d", "dir", None, 0o755),
                ("etc/busybox-paths.d/busybox", "file", f"{line}\n".encode(), 0o644),
                ("usr", "dir", None, 0o755),
                ("usr/hostdir", "sym", "/tmp", 0o777),
            ],
        )
        out = os.path.join(ctx.work, f"busybox-{case}.exclave")
        rc, o, e = run([*UNPACK, out, pkg])
        expect(
            (rc != 0 and "escapes the tree" in e and not os.path.lexists(out))
            if case == "dotdot"
            else rc == 0,
            f"{case}: rc={rc} {o}{e}",
        )
        expect(
            not os.path.lexists(escape) and not os.path.lexists(host),
            f"{case}: an applet link was made outside the tree",
        )


# ---------------------------------------------------------------- hostile package files
@test
def escapes_stay_in_the_tree(ctx: Ctx) -> str | None:
    """10.1: no member reaches outside the tree, in any format.

    `..` in a member's name or a hard link's, and the reserved name .real, are refused. A symlink
    the set ships resolves with the tree as its root, as dpkg's would in the root it installs into:
    one that climbs out leads back in, and an absolute one starts at the tree's root. A hard link
    to a file through an absolute link to the host names a file the tree does not hold, and is
    refused. A name with a leading slash lands in the tree.
    """
    secret = os.path.join(ctx.host, "secret")
    note = None
    for fmt in FORMATS:
        for name, members, why in (
            ("dotdot", [("usr/../../host/x", "file", b"x", 0o644)], "escapes the tree"),
            ("real", [("usr/bin/.real/x", "file", b"x", 0o755)], "reserved name .real"),
        ):
            refused(ctx, f"{fmt}-{name}", [package(ctx, fmt, f"{fmt}-{name}", members)], why)
        climb: list[Member] = [
            ("usr", "dir", None, 0o755),
            ("usr/share", "dir", None, 0o755),
            ("usr/share/doc", "sym", "../../../../host", 0o777),
            ("usr/share/doc/x", "file", b"x", 0o644),
        ]
        absolute: list[Member] = [("opt", "sym", ctx.host, 0o777), ("opt/x", "file", b"x", 0o644)]
        slash: list[Member] = [("/abs/x", "file", b"x", 0o644)]
        for name, members, lands in (
            ("climb", climb, "/host"),
            ("absolute", absolute, ctx.host),
            ("slash", slash, "/abs"),
        ):
            root, _ = accepted(ctx, f"{fmt}-{name}", [package(ctx, fmt, f"{fmt}-{name}", members)])
            at = landing(root, lands)
            if at is None:
                note = UNREAD
                continue
            expect(read_text(os.path.join(at, "x")) == "x", f"{fmt} {name}: not at {lands}/x")
    for fmt in ("deb", "apk"):  # the rpm builder makes no hard links
        hard_dotdot: list[Member] = [
            ("f", "file", b"f", 0o644),
            ("h", "hard", "../host/secret", 0o644),
        ]
        hard_through: list[Member] = [
            ("usr", "dir", None, 0o755),
            ("usr/out", "sym", ctx.host, 0o777),
            ("usr/copy", "hard", "usr/out/secret", 0o644),
        ]
        for name, members, why in (
            ("hard-dotdot", hard_dotdot, "escapes the tree"),
            ("hard-through", hard_through, "does not hold"),
        ):
            refused(ctx, f"{fmt}-{name}", [package(ctx, fmt, f"{fmt}-{name}", members)], why)
    expect(os.stat(secret).st_nlink == 1, "a hard link to the host's file was made")
    return note


@test
def synthesis_rules_and_notes(ctx: Ctx) -> None:
    """10.1: the rules are a table, named in the log as they apply; --set picks the alternative.

    A loop over literal words is unrolled, as ImageMagick's postinst needs, around a loop it cannot
    unroll; a postinst that builds its update-alternatives lines from other variables is noted,
    since its alternatives are not made, and a trigger interest the tree lacks a cache for is
    noted by name.
    A JDK's tools are linked from its .jinfo file, the highest priority's winning.
    """
    alt = package(
        ctx,
        "deb",
        "alt",
        [
            ("usr/bin/x-1", "file", b"#!/bin/sh\n", 0o755),
            ("usr/bin/x-2", "file", b"#!/bin/sh\n", 0o755),
        ],
        control_files=[
            (
                "postinst",
                (
                    "#!/bin/sh\nupdate-alternatives --install /usr/bin/x x /usr/bin/x-1 10\n"
                    "update-alternatives --install /usr/bin/x x /usr/bin/x-2 20\n"
                    "update-alternatives --set x /usr/bin/x-1\n"
                ),
            )
        ],
    )
    loopy = package(
        ctx,
        "deb",
        "loopy",
        [
            (f"usr/lib/{n}-q{v}", "file", b"#!/bin/sh\n", 0o755)
            for n in ("conv", "ident")
            for v in ("", ".1")
        ],
        control_files=[
            (
                "postinst",
                (
                    "#!/bin/sh\nfor prog in conv ident; do\n"
                    "  if true; then update-alternatives --remove-all $prog; fi\n"
                    "  for v in '' .1; do :; done\n"
                    "  update-alternatives --install /usr/bin/$prog \\\n"
                    "    $prog /usr/lib/${prog}-q 10 \\\n"
                    "    --slave /usr/bin/$prog.1 $prog.1 /usr/lib/$prog-q.1\n"
                    "done\n"
                ),
            )
        ],
    )
    varied = package(
        ctx,
        "deb",
        "varied",
        [("usr/lib/j1", "file", b"#!/bin/sh\n", 0o755)],
        control_files=[
            (
                "postinst",
                "#!/bin/sh\nupdate-alternatives --install /usr/bin/j$1 j$1 /usr/lib/j$1 1\n",
            )
        ],
    )
    py = package(
        ctx,
        "deb",
        "py",
        [("usr/lib/python3.12/os.py", "file", b"pass\n", 0o644)],
        control_files=[("triggers", "interest-noawait /usr/lib/python3.12\n")],
    )
    jdks = [
        package(
            ctx,
            "deb",
            f"jdk{n}",
            [
                (f"usr/lib/jvm/jdk{n}/bin/java", "file", b"#!/bin/sh\n", 0o755),
                (
                    f"usr/lib/jvm/.jdk{n}.jinfo",
                    "file",
                    f"name=jdk{n}\npriority={10 * n}\nsection=main\n\n"
                    f"hl java /usr/lib/jvm/jdk{n}/bin/java\n".encode(),
                    0o644,
                ),
            ],
        )
        for n in (1, 2)
    ]
    root, out = accepted(ctx, "rules", [alt, loopy, varied, py, *jdks])
    expect(
        os.readlink(os.path.join(root, "usr", "bin", "java")) == "/etc/alternatives/java"
        and os.readlink(os.path.join(root, "etc", "alternatives", "java"))
        == "/usr/lib/jvm/jdk2/bin/java",
        "the JDK of the higher priority is not linked: " + out[-400:],
    )
    expect(
        os.readlink(os.path.join(root, "etc", "alternatives", "x")) == "/usr/bin/x-1",
        "--set did not choose the alternative: " + out[-400:],
    )
    expect(
        "synthesis rules applied: alternatives, java-jinfo\n" in out,
        "the applied rules are not named: " + out,
    )
    expect(
        "note: varied's postinst calls update-alternatives in a form the alternatives rule does not"
        in out,
        "a postinst with variables is not noted: " + out,
    )
    expect(
        "note: py triggers on /usr/lib/python3.12: Python bytecode" in out,
        "a trigger interest the tree lacks a cache for is not noted: " + out,
    )
    expect(
        not os.path.lexists(os.path.join(root, "usr", "bin", "j1")),
        "an alternative named by a variable was made",
    )
    for n in ("conv", "ident"):
        for link, name, target in ((n, n, f"{n}-q"), (f"{n}.1", f"{n}.1", f"{n}-q.1")):
            alt_link = os.path.join(root, "etc", "alternatives", name)
            expect(
                os.path.lexists(os.path.join(root, "usr", "bin", link))
                and os.readlink(alt_link) == f"/usr/lib/{target}",
                f"the loop over literal words did not make {link}: " + out[-400:],
            )
    expect("note: loopy's" not in out, "an unrolled loop is noted: " + out)


@test
def shells_from_debianutils(ctx: Ctx) -> None:
    """10.1: /etc/shells is written as update-shells writes it, from the template and shells.d.

    Each listed shell follows the template's lines, with its merged-/usr spelling beside it, as
    update-shells lists them, so a shell two files list comes twice. The interests that need
    nothing, or that the rules and extraction make, are not noted: shells.d, base-files' multilib
    links, ca-certificates' named triggers and man-db's other manual paths.
    """
    du = package(
        ctx,
        "deb",
        "debianutils",
        [
            ("usr/bin/sh", "file", b"#!/bin/sh\n", 0o755),
            ("usr/share/debianutils/shells", "file", b"# valid login shells\n/bin/sh\n", 0o644),
            ("usr/share/debianutils/shells.d/bash", "file", b"/bin/bash\n/bin/rbash\n", 0o644),
            ("usr/share/debianutils/shells.d/dash", "file", b"/usr/bin/dash\n/bin/sh\n", 0o644),
        ],
        control_files=[
            (
                "triggers",
                (
                    "interest-noawait /usr/share/debianutils/shells.d\ninterest-noawait lib32\n"
                    "interest-noawait /usr/local/man\ninterest-noawait update-ca-certificates\n"
                ),
            )
        ],
    )
    root, out = accepted(ctx, "shells", [du])
    want = (
        "# valid login shells\n/bin/sh\n/usr/bin/sh\n/bin/bash\n/usr/bin/bash\n"
        "/bin/rbash\n/usr/bin/rbash\n/usr/bin/dash\n/usr/bin/sh\n"
    )
    got = read_text(os.path.join(root, "etc", "shells"))
    expect(got == want, f"/etc/shells is {got!r}, not {want!r}")
    expect("synthesis rules applied: shells" in out, "the shells rule is not named: " + out)
    expect("note:" not in out, "an interest that needs nothing is noted: " + out)


@test
def synthesis_stays_in_the_tree(ctx: Ctx) -> str | None:
    """10.1, 8.1: synthesis reads and writes the tree as its root, and so does the volatile step.

    A set that ships /etc, /usr/share/base-passwd or /var as absolute links to a host directory
    makes /etc/passwd from the tree's own master, copies nothing of the host's, and removes nothing
    of the host's /var/tmp.
    """
    os.makedirs(os.path.join(ctx.host, "tmp"))
    for name in ("passwd.master", "group.master", "tmp/keep"):
        with open(os.path.join(ctx.host, name), "w") as f:
            f.write("the host's own\n")
    master: list[Member] = [
        ("usr/share/base-passwd/passwd.master", "file", b"root:x:0:0::/root:/bin/sh\n", 0o644),
        ("usr/share/base-passwd/group.master", "file", b"root:x:0:\n", 0o644),
    ]
    etc_out: list[Member] = [("etc", "sym", ctx.host, 0o777)]
    root, _ = accepted(ctx, "write-through", [package(ctx, "deb", "base-passwd", master + etc_out)])
    at = landing(root, ctx.host)
    note = None if at else UNREAD
    if at:
        expect(
            read_text(os.path.join(at, "passwd")).startswith("root:x:0:0"),
            "/etc/passwd is not in the tree",
        )
    shutil.rmtree(os.path.join(ctx.work, "pkgs"))  # the second base-passwd, by the same name
    master_out: list[Member] = [("usr/share/base-passwd", "sym", ctx.host, 0o777)]
    root, _ = accepted(ctx, "read-through", [package(ctx, "deb", "base-passwd", master_out)])
    expect(
        not os.path.lexists(os.path.join(root, "etc", "passwd")),
        "/etc/passwd was copied from the host's master",
    )
    for fmt in FORMATS:
        var_out: list[Member] = [("var", "sym", ctx.host, 0o777), ("usr/x", "file", b"x", 0o644)]
        accepted(ctx, f"{fmt}-volatile", [package(ctx, fmt, f"{fmt}-volatile", var_out)])
    return note


@test
def declared_sizes_are_bounded(ctx: Ctx) -> None:
    """10.1: a member whose size would leave the output's filesystem short of room is refused.

    Before a byte of it is written, by the size its header declares, so that a payload that
    decompresses without end is refused rather than filling the disk.
    """
    huge = tarfile.TarInfo("usr/huge")
    huge.size = 1 << 50
    huge.mtime = MTIME
    raw = huge.tobuf(tarfile.GNU_FORMAT) + b"\0" * 1024
    for fmt in ("deb", "apk"):
        data = compress(raw, ".gz") if fmt == "deb" else gzip.compress(raw, mtime=0)
        refused(ctx, f"{fmt}-huge", [package(ctx, fmt, f"{fmt}-huge", [], data=data)], "free")


@test
def modes_and_types(ctx: Ctx) -> None:
    """10.1: modes from the archive, setuid and setgid dropped, every file readable by its owner.

    A directory stays traversable and writable by its owner; a hard link is to the member it names,
    a symlink included, and an empty file's hard link to it; device files and pipes are skipped
    with a note; times are the archive's.
    """
    common: list[Member] = [
        ("usr", "dir", None, 0o755),
        ("usr/suid", "file", b"s", 0o4755),
        ("usr/sgid", "file", b"g", 0o2711),
        ("usr/none", "file", b"n", 0),
        ("usr/locked", "dir", None, 0o500),
        ("usr/locked/f", "file", b"f", 0o640),
        ("usr/link", "sym", "suid", 0o777),
        ("usr/hard", "hard", "usr/suid", 0o4755),
        ("usr/empty", "file", b"", 0o644),
        ("usr/empty2", "hard", "usr/empty", 0o644),
    ]
    tar_only: list[Member] = [
        ("usr/hard-to-link", "hard", "usr/link", 0o777),
        ("usr/char", "chr", None, 0o644),
        ("usr/pipe", "fifo", None, 0o644),
    ]
    for fmt in FORMATS:
        members = common + (tar_only if fmt != "rpm" else [])
        root, out = accepted(ctx, fmt, [package(ctx, fmt, f"modes-{fmt}", members)])
        u = os.path.join(root, "usr")

        def mode(name: str, u: str = u) -> int:
            return stat.S_IMODE(os.lstat(os.path.join(u, name)).st_mode)

        expect(
            (mode("suid"), mode("sgid"), mode("none"), mode("locked"))
            == (0o755, 0o711, 0o400, 0o700),
            f"{fmt}: modes {mode('suid'):o} {mode('sgid'):o} {mode('none'):o} {mode('locked'):o}",
        )
        expect(read_text(os.path.join(u, "locked", "f")) == "f", f"{fmt}: nothing under a 0500 dir")
        expect(
            int(os.stat(os.path.join(u, "suid")).st_mtime) == MTIME,
            f"{fmt}: not the archive's time",
        )
        same = os.stat(os.path.join(u, "hard")).st_ino == os.stat(os.path.join(u, "suid")).st_ino
        expect(same, f"{fmt}: the hard link is not to its member")
        empty = os.stat(os.path.join(u, "empty")), os.stat(os.path.join(u, "empty2"))
        expect(
            empty[0].st_ino == empty[1].st_ino and empty[0].st_size == 0,
            f"{fmt}: the empty file's hard link is not to it, or it is not empty",
        )
        if fmt == "rpm":
            continue
        to_link = os.lstat(os.path.join(u, "hard-to-link"))
        expect(
            stat.S_ISLNK(to_link.st_mode)
            and to_link.st_ino == os.lstat(os.path.join(u, "link")).st_ino,
            f"{fmt}: a hard link to a symlink followed it",
        )
        for special in ("char", "pipe"):
            expect(
                not os.path.lexists(os.path.join(u, special))
                and f"skipping special file /usr/{special}" in out,
                f"{fmt}: the special file {special} was not skipped with a note: {out!r}",
            )


@test
def unreadable_diversions(ctx: Ctx) -> None:
    """10.1 step 2: a renaming diversion a package makes for itself of a path the rule cannot read.

    vim-runtime's preinst diverts vim-tiny's copies of its help files through a shell function's
    argument. Alone it has nothing to move and is admitted with a note naming it; with a package
    that ships one of its files, the diversion would move that file, and the set is refused.
    """
    preinst = (
        "#!/bin/sh\nset -e\nadd_diversion() {\n"
        '  dpkg-divert --package rt --add --rename --divert "$1.tiny" "$1"\n'
        "}\nadd_diversion /usr/share/rt/help.txt\n"
    )
    rt = package(
        ctx,
        "deb",
        "rt",
        [("usr/share/rt/help.txt", "file", b"full\n", 0o644)],
        control_files=[("preinst", preinst)],
    )
    _root, out = accepted(ctx, "alone", [rt])
    expect(
        "note: rt adds a renaming diversion the rule cannot read" in out,
        "an admitted diversion is not noted: " + out,
    )
    tiny = package(ctx, "deb", "tiny", [("usr/share/rt/help.txt", "file", b"tiny\n", 0o644)])
    refused(ctx, "shared", [rt, tiny], "rt adds a renaming diversion the rule cannot read")
    refused(ctx, "shared-first", [tiny, rt], "rt adds a renaming diversion the rule cannot read")


@test
def literal_diversions(ctx: Ctx) -> None:
    """10.1 step 2: a renaming diversion a package makes for itself of a literal path.

    postgresql-common's preinst diverts libpq-dev's /usr/bin/pg_config to pg_config.libpq-dev and
    ships its own. Alone the package's file stays at the path; with another package that ships
    the path, under its /lib or /usr/lib spelling too, that package's file lands under the
    diverted name whichever comes first, as dpkg would leave it. A diversion for another package,
    or with --local, which diverts the package's own file too, is refused.
    """

    def diverting(name: str, line: str) -> str:
        return package(
            ctx,
            "deb",
            name,
            [("usr/bin/x", "file", b"own\n", 0o755), ("usr/lib/y", "file", b"own\n", 0o644)],
            control_files=[("preinst", f"#!/bin/sh\nset -e\n{line}\n")],
        )

    pg = diverting(
        "pg",
        "dpkg-divert --package pg --add --rename --divert /usr/bin/x.other /usr/bin/x\n"
        "dpkg-divert --package pg --rename --divert=/lib/y.other --add /lib/y",
    )
    root, _out = accepted(ctx, "lit-alone", [pg])

    def content(root: str, rel: str) -> bytes | None:
        p = os.path.join(root, rel)
        if not os.path.exists(p):
            return None
        with open(p, "rb") as f:
            return f.read()

    expect(
        content(root, "usr/bin/x") == b"own\n" and content(root, "usr/bin/x.other") is None,
        "a diversion with nothing to move leaves the package's file at its path",
    )
    other = package(
        ctx,
        "deb",
        "other",
        [("usr/bin/x", "file", b"other\n", 0o755), ("lib/y", "file", b"other\n", 0o644)],
    )
    for case, pkgs in (("lit-after", [pg, other]), ("lit-before", [other, pg])):
        root, out = accepted(ctx, case, pkgs)
        paths = ("usr/bin/x", "usr/bin/x.other", "usr/lib/y", "lib/y.other")
        got = [content(root, r) for r in paths]
        expect(
            got == [b"own\n", b"other\n", b"own\n", b"other\n"],
            f"{case}: the other package's files under the diverted names: {got!r}",
        )
        expect(
            "other's /usr/bin/x diverted to /usr/bin/x.other by pg" in out,
            f"{case}: the diversion is not in the log: {out!r}",
        )
    foreign = diverting(
        "foreign", "dpkg-divert --package else --add --rename --divert /usr/bin/x.o /usr/bin/x"
    )
    refused(ctx, "lit-foreign", [foreign], "foreign adds a renaming diversion in its preinst")
    local = diverting("local", "dpkg-divert --local --rename --divert /usr/bin/x.o /usr/bin/x")
    refused(ctx, "lit-local", [local], "local adds a renaming diversion in its preinst")


@test
def conflicts_and_replaces(ctx: Ctx) -> None:
    """10.1: a path two packages ship is refused unless one replaces the other, which then wins.

    The same symlink from both is no conflict, two different ones are, and a file is never laid
    over a directory symlink.
    """
    a_file, b_file = [("usr/x", "file", b"a", 0o644)], [("usr/x", "file", b"b", 0o644)]
    for fmt in ("deb", "apk"):  # the rpm builder writes no Obsoletes

        def pair(
            case: str,
            a: Sequence[Member],
            b: Sequence[Member],
            *,
            a_replaces: str = "",
            b_replaces: str = "",
            fmt: str = fmt,
        ) -> list[str]:
            return [
                package(ctx, fmt, f"{case}-a", a, replaces=a_replaces),
                package(ctx, fmt, f"{case}-b", b, replaces=b_replaces),
            ]

        refused(
            ctx, f"{fmt}-conflict", pair(f"{fmt}-c", a_file, b_file), "neither declares Replaces"
        )
        for case, ra, rb, want in (
            ("later", "", f"{fmt}-l-a", "b"),
            ("earlier", f"{fmt}-e-b", "", "a"),
        ):
            pkgs = pair(f"{fmt}-{case[0]}", a_file, b_file, a_replaces=ra, b_replaces=rb)
            root, _ = accepted(ctx, f"{fmt}-{case}", pkgs)
            expect(read_text(os.path.join(root, "usr", "x")) == want, f"{fmt}: {case} replaces")
        same = [("usr/l", "sym", "x", 0o777)]
        accepted(ctx, f"{fmt}-same", pair(f"{fmt}-s", same, same))
        other = [("usr/l", "sym", "y", 0o777)]
        refused(ctx, f"{fmt}-other", pair(f"{fmt}-o", same, other), "neither declares Replaces")
        dirlink = [("usr/e", "dir", None, 0o755), ("usr/d", "sym", "e", 0o777)]
        refused(
            ctx,
            f"{fmt}-over-dir-link",
            pair(f"{fmt}-d", dirlink, [("usr/d", "file", b"f", 0o644)]),
            "over a directory symlink",
        )


def payload_forms(members: Sequence[Member]) -> list[tuple[str, str, bytes]]:
    """(format, .deb suffix, the payload whole) for each compression the readers take."""
    tar = tar_bytes(members)
    return [
        ("deb", ".gz", compress(tar, ".gz")),
        ("deb", ".xz", compress(tar, ".xz")),
        ("deb", ".zst", compress(tar, ".zst")),
        ("apk", "", gzip.compress(tar, mtime=0)),
        ("rpm", "", gzip.compress(cpio(members), mtime=0)),
    ]


@test
def damaged_payloads(ctx: Ctx) -> None:
    """10.1: a payload cut short, flipped, empty or not compressed is refused in one line.

    Each compression a reader takes checks its data: gzip's and xz's CRCs, zstd's checksum. The
    reason names the payload and what its decompressor found.
    """
    members: list[Member] = [
        ("usr", "dir", None, 0o755),
        ("usr/share", "dir", None, 0o755),
        ("usr/share/f", "file", bytes(range(256)) * 64, 0o644),
    ]
    os.makedirs(os.path.join(ctx.work, "pkgs"))
    why = {  # by the compression and the case, as each decompressor says it
        ("gz", "cut"): "unexpected EOF",
        ("gz", "flipped"): "gzip: invalid checksum",
        ("gz", "plain"): "gzip: invalid header",
        ("gz", "empty"): "EOF",
        ("xz", "cut"): "unexpected EOF",
        ("xz", "flipped"): "writeMatch: distance out of range",
        ("xz", "plain"): "xz: invalid header magic bytes",
        ("xz", "empty"): "unexpected EOF",
        ("zst", "cut"): "unexpected EOF",
        ("zst", "flipped"): "CRC check failed",
        ("zst", "plain"): "invalid input: magic number mismatch",
        ("zst", "empty"): "unexpected EOF",
    }
    for fmt, suffix, good in payload_forms(members):
        flipped = bytearray(good)
        flipped[len(good) // 2] ^= 0x10
        cases = [("cut", good[: len(good) // 2]), ("flipped", bytes(flipped))]
        cases += [("plain", b"not compressed at all")]
        # an .apk without a data stream is a package without files, as Alpine's virtual ones are
        cases += [("empty", b"")] if fmt != "apk" else []
        for case, data in cases:
            name = f"{fmt}{suffix.replace('.', '-')}-{case}"
            if fmt == "deb":
                pkg = os.path.join(ctx.work, "pkgs", f"{name}.deb")
                make_deb(pkg, name, members, suffix=suffix, data=data)
            else:
                pkg = package(ctx, fmt, name, members, data=data)
            prefix = {"deb": f"corrupt data.tar{suffix}: ", "apk": "not an apk: "}
            reason = why[suffix.lstrip(".") or "gz", case]
            refused(ctx, name, [pkg], prefix.get(fmt, "corrupt gzip payload: ") + reason)
    for fmt, reason in (
        ("deb", "not an ar archive"),
        ("apk", "not an apk: "),  # random bytes begin as gzip once in 65 536 runs
        ("rpm", "not an rpm"),
    ):
        path = os.path.join(ctx.work, "pkgs", f"noise.{fmt}")
        with open(path, "wb") as f:
            f.write(os.urandom(4096))
        refused(ctx, f"noise-{fmt}", [path], reason)


@test
def first_failure_in_order(ctx: Ctx) -> None:
    """10.1: of two damaged packages, the refusal names the one given first, as a serial pass would.

    The payloads are read on several goroutines before anything is written; the first, a large
    payload cut near its end, is found damaged long after the second, whose payload is not
    compressed at all.
    """
    os.makedirs(os.path.join(ctx.work, "pkgs"))
    body = os.urandom(1 << 20) * 8  # 8 MiB that xz cannot shrink much, so the first is slow to read
    members: list[Member] = [("usr", "dir", None, 0o755), ("usr/big", "file", body, 0o644)]
    good = compress(tar_bytes(members), ".xz")
    first = os.path.join(ctx.work, "pkgs", "a-cut.deb")
    make_deb(first, "a-cut", members, suffix=".xz", data=good[:-4096])
    second = os.path.join(ctx.work, "pkgs", "b-plain.deb")
    make_deb(second, "b-plain", members[:1], suffix=".xz", data=b"not compressed at all")
    rc, _, e, out = unpack(ctx, "order", [first, second])
    expect(
        rc == 1 and "a-cut.deb: corrupt data.tar.xz: unexpected EOF" in e and "b-plain" not in e,
        f"the refusal is not the first package's: rc={rc} {e[-300:]!r}",
    )
    expect(not os.path.lexists(out), f"the refusal left {out} behind")


@test
def tar_structure(ctx: Ctx) -> None:
    """10.1: what tar spells long or large is read; an archive with anything after it is refused.

    GNU long names, PAX paths and link paths and base-256 times are read as tar defines them. A
    member whose data runs past the end is refused, and so is any byte but NUL after the archive's
    last member: a corrupt header or a part of one, behind which more members could hide, and a
    header cut short after a GNU long-link header, which ends the archive where the last whole
    member did.
    """
    long = "usr/share/" + "/".join(["d" * 40] * 4) + "/file"
    target = "/" + "t" * 150
    members: list[Member] = [(long, "file", b"long\n", 0o644), ("usr/l", "sym", target, 0o777)]
    early = tarfile.TarInfo("usr/early")
    early.mtime = -1
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:", format=tarfile.GNU_FORMAT) as t:
        t.addfile(early, io.BytesIO(b""))
    base256 = bio.getvalue()
    head = tar_bytes(members, trailer=False)
    for fmt in ("deb", "apk"):

        def pkg(case: str, raw: bytes, fmt: str = fmt) -> str:
            data = compress(raw, ".gz") if fmt == "deb" else gzip.compress(raw, mtime=0)
            return package(ctx, fmt, f"tar-{fmt}-{case}", [], data=data)

        for case, fmt_tar in (("gnu", tarfile.GNU_FORMAT), ("pax", tarfile.PAX_FORMAT)):
            root, _ = accepted(ctx, f"{fmt}-{case}", [pkg(case, tar_bytes(members, fmt=fmt_tar))])
            expect(read_text(os.path.join(root, long)) == "long\n", f"{fmt} {case}: the long name")
            expect(os.readlink(os.path.join(root, "usr", "l")) == target, f"{fmt} {case}: the link")
        root, _ = accepted(ctx, f"{fmt}-base256", [pkg("base256", base256)])
        expect(os.lstat(os.path.join(root, "usr", "early")).st_mtime == -1, f"{fmt}: base-256 time")
        refused(ctx, f"{fmt}-cut-head", [pkg("cut-head", head[: len(head) - 300])], "after")
        big = tar_bytes([("usr/big", "file", b"b" * 5000, 0o644)], trailer=False)
        cut = big[: len(big) - 3000]  # the cut inside the member's data
        refused(ctx, f"{fmt}-cut-data", [pkg("cut-data", cut)], "unexpected EOF")
        after = tar_bytes([("usr/hidden", "file", b"h", 0o644)])
        refused(ctx, f"{fmt}-bad-header", [pkg("bad-header", head + b"x" * 512 + after)], "after")
        refused(
            ctx, f"{fmt}-part-header", [pkg("part-header", head + b"part of a header")], "after"
        )


@test
def cpio_structure(ctx: Ctx) -> None:
    """10.1: an rpm payload must end with cpio's trailer, every entry whole, and nothing after it.

    The trailer is the end cpio defines, so an archive without it was cut short; an entry whose data
    runs past the end is cut short; and any byte but NUL after the trailer is refused.
    """
    members: list[Member] = [("usr", "dir", None, 0o755), ("usr/f", "file", b"x" * 1000, 0o644)]
    whole = cpio(members)
    trailer = whole.index(b"TRAILER!!!") - 110
    for case, raw, why in (
        ("no-trailer", whole[:trailer], "the cpio payload has no trailer: it is cut short"),
        (
            "cut-entry",
            whole[: trailer - 600],
            "cpio entry 'usr/f' runs past the end of the payload",
        ),
        ("after-trailer", whole + b"junk", "data after the archive's end"),
    ):
        data = gzip.compress(raw, mtime=0)
        pkg = package(ctx, "rpm", f"cpio-{case}", members, data=data)
        refused(ctx, f"rpm-{case}", [pkg], "corrupt gzip payload: " + why)
    accepted(
        ctx,
        "rpm-padded",
        [
            package(
                ctx, "rpm", "cpio-padded", members, data=gzip.compress(whole + b"\0" * 512, mtime=0)
            )
        ],
    )


# ---------------------------------------------------------------- the runner
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--work", default=os.path.join(REPO, "build", "unpack-test"))
    ap.add_argument("-k", dest="select", default="")
    args = ap.parse_args()
    work = os.path.abspath(args.work)
    shutil.rmtree(work, ignore_errors=True)
    chosen = select(TESTS, args.select)

    def call(t: Test[Any]) -> str | None:
        d = os.path.join(work, t.__name__)
        host = os.path.join(d, "host")
        os.makedirs(host)
        with open(os.path.join(host, "secret"), "w") as f:
            f.write("the host's own\n")
        return t(Ctx(work=d, host=host))

    failed = run_tests(chosen, call)
    print(f"{len(chosen)} tests, {len(failed)} failures")
    return min(len(failed), 255)


if __name__ == "__main__":
    sys.exit(main())
