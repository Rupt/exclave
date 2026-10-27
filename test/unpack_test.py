"""Unpack's rules, asked with hostile package files in each format (DESIGN.md 10.1, 17).

    test/unpack_test.py [--work DIR] [-k NAME|SUBSTRING]

Each test makes the .deb, .apk and .rpm files it needs (test/packages.py) and runs unpack on them
as scripts/unpack does. A set unpack refuses must be refused in one line, `unpack: ` and the
reason, with no traceback and nothing left at the output; and whatever it does, nothing outside
the output may change: each test's work directory holds host/, with a file the packages aim at
through `..`, symlinks and hard links. The tests take no exclave; the readers' own tests, which
wrap what they unpack, run build/exclave. Prints one line per test; the exit status is the number
of failures, at most 255.
"""

import argparse
import dataclasses
import gzip
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from typing import Protocol
lazy from collections.abc import Sequence

import tree
from packages import MACHINE, MTIME, Member, compress, cpio, make_apk, make_deb, make_rpm, tar_bytes

from unpack import steps

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
UNPACK = (sys.executable, "-m", "unpack")
TOOL = tree.TOOL
FORMATS = ("deb", "apk", "rpm")


@dataclasses.dataclass(frozen=True)
class Ctx:
    """A test's own directories: work, and host/ inside it, which no package may change."""

    work: str
    host: str


class Test(Protocol):
    """A test: given its directories, it raises AssertionError when a rule does not hold."""

    __name__: str

    def __call__(self, ctx: Ctx, /) -> None: ...


TESTS: list[Test] = []


def test(f: Test) -> Test:
    """Register a test."""
    TESTS.append(f)
    return f


def run(cmd: Sequence[str]) -> tuple[int, str, str]:
    p = subprocess.run(cmd, check=False, capture_output=True, timeout=300)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def expect(cond: object, msg: str) -> None:
    """Fail the test with msg unless cond holds."""
    if not cond:
        raise AssertionError(msg)


def read_text(path: str) -> str:
    with open(path) as f:
        return f.read()


def package(
    ctx: Ctx,
    fmt: str,
    name: str,
    members: Sequence[Member],
    *,
    replaces: str = "",
    data: bytes | None = None,
) -> str:
    """Write the package name in the format fmt, with a Replaces field; return its path.

    data: the payload as given: a .deb's data member, an .apk's data stream, an .rpm's payload.
    """
    d = os.path.join(ctx.work, "pkgs")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{name}.{fmt}")
    if fmt == "deb":
        make_deb(path, name, members, f"Replaces: {replaces}\n" if replaces else "", data=data)
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


def refused(ctx: Ctx, name: str, pkgs: Sequence[str], why: str = "") -> None:
    """The set must be refused, naming why, with nothing left at the output."""
    rc, o, e, out = unpack(ctx, name, pkgs)
    expect(rc == 1 and why in e, f"{name}: wanted a refusal naming {why!r}: rc={rc} {o}{e}")
    expect(not os.path.lexists(out), f"{name}: the refusal left {out} behind")


def accepted(ctx: Ctx, name: str, pkgs: Sequence[str]) -> tuple[str, str]:
    """The set must unpack; return its tree and the standard output."""
    rc, o, e, out = unpack(ctx, name, pkgs)
    expect(rc == 0, f"{name}: refused: {e[-400:]!r}")
    return os.path.join(out, "tree"), o


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
    /usr; busybox's applet links are synthesised from /etc/busybox-paths.d as relative links; one
    format per exclave.
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
        "provides = so:libfoo.so.1=1\nprovides = cmd:busybox=1.0-r0\n",
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
def tool_extraction_rules(ctx: Ctx) -> None:
    """10.1: a member reached through a package's own symlink is refused.

    So is a hard link whose target is reached through one, which would put a file from outside the
    tree into it. Two spellings of one path under merged usr conflict. A corrupt package is refused
    in one line, and unpack leaves nothing behind.
    """
    d = os.path.join(ctx.work, "debs")
    os.makedirs(d, exist_ok=True)
    outside = os.path.join(ctx.work, "escaped")
    os.makedirs(outside, exist_ok=True)
    with open(os.path.join(outside, "README"), "w") as f:
        f.write("ORIGINAL\n")
    make_deb(
        os.path.join(d, "evil.deb"),
        "evil",
        [
            ("./usr", "dir", None, 0o755),
            ("./usr/share", "dir", None, 0o755),
            ("./usr/share/doc", "sym", "../../../../escaped", 0o777),
            ("./usr/share/doc/README", "file", b"ESCAPED\n", 0o644),
        ],
    )
    root = os.path.join(ctx.work, "root-evil")
    try:
        steps.extract(
            root, [steps.Package("evil", os.path.join(d, "evil.deb"), {})], log=lambda *_: None
        )
    except steps.UnpackError as e:
        expect("escapes" in str(e), str(e))
    else:
        msg = "a member behind a symlink out of the tree was extracted"
        raise AssertionError(msg)
    expect(
        read_text(os.path.join(outside, "README")) == "ORIGINAL\n",
        "the file outside the tree was written",
    )
    make_deb(
        os.path.join(d, "thief.deb"),
        "thief",
        [
            ("./usr", "dir", None, 0o755),
            ("./usr/out", "sym", outside, 0o777),
            ("./usr/copy", "hard", "./usr/out/README", 0o644),
        ],
    )
    root = os.path.join(ctx.work, "root-thief")
    try:
        steps.extract(root, [steps.Package("thief", os.path.join(d, "thief.deb"), {})])
    except steps.UnpackError as e:
        expect("escapes" in str(e), str(e))
    else:
        msg = "a hard link to a file outside the tree was extracted"
        raise AssertionError(msg)
    with open(os.path.join(d, "thief.deb"), "rb") as f:
        whole = f.read()
    with open(os.path.join(d, "corrupt.deb"), "wb") as f:
        f.write(whole[: len(whole) - 40])  # the data member cut short
    out = os.path.join(ctx.work, f"corrupt-{os.getpid()}.exclave")
    rc, _o, e = run([*UNPACK, out, os.path.join(d, "corrupt.deb")])
    expect(
        rc != 0 and e.startswith("unpack: ") and "Traceback" not in e,
        f"a corrupt package: rc={rc} {e[-300:]!r}",
    )
    expect(not os.path.exists(out), "unpack left a partial exclave behind")
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
    root = os.path.join(ctx.work, "root-alias")
    try:
        steps.extract(
            root,
            [
                steps.Package("a", os.path.join(d, "a.deb"), {}),
                steps.Package("b", os.path.join(d, "b.deb"), {}),
            ],
            log=lambda *_: None,
        )
    except steps.UnpackError as e:
        expect("both ship" in str(e), str(e))
    else:
        msg = "the merged-usr spellings of one file were not seen as a conflict"
        raise AssertionError(msg)


@test
def busybox_links_stay_in_the_tree(ctx: Ctx) -> None:
    """10.1: a path in /etc/busybox-paths.d is a member's path, refused when it leaves the tree.

    By `..`, or through a symlink the set ships, such as one to /tmp: the applet link would land on
    the host.
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
            rc != 0 and "tree" in e,
            f"{case}: a busybox path out of the tree was not refused: {o}{e}",
        )
        expect(
            not os.path.lexists(escape) and not os.path.lexists(host) and not os.path.lexists(out),
            f"{case}: an applet link was made outside the tree, or the output was kept",
        )


# ---------------------------------------------------------------- hostile package files
@test
def escapes_are_refused(ctx: Ctx) -> None:
    """10.1: no member reaches outside the tree, in any format.

    Not by `..` in its name or a hard link's, not through a symlink the set ships, relative or
    absolute, and not by the reserved name .real; a name with a leading slash lands in the tree.
    """
    secret = os.path.join(ctx.host, "secret")
    for fmt in FORMATS:
        for name, members, why in (
            ("dotdot", [("usr/../../host/x", "file", b"x", 0o644)], "escapes the tree"),
            ("real", [("usr/bin/.real/x", "file", b"x", 0o755)], "reserved name .real"),
            (
                "climb",
                [
                    ("usr", "dir", None, 0o755),
                    ("usr/share", "dir", None, 0o755),
                    ("usr/share/doc", "sym", "../../../../host", 0o777),
                    ("usr/share/doc/x", "file", b"x", 0o644),
                ],
                "escapes the tree",
            ),
        ):
            refused(ctx, f"{fmt}-{name}", [package(ctx, fmt, f"{fmt}-{name}", members)], why)
        # an absolute link: never a write on the host, whether refused or kept in the tree
        members = [("opt", "sym", ctx.host, 0o777), ("opt/x", "file", b"x", 0o644)]
        unpack(ctx, f"{fmt}-absolute", [package(ctx, fmt, f"{fmt}-absolute", members)])
        root, _ = accepted(
            ctx,
            f"{fmt}-slash",
            [package(ctx, fmt, f"{fmt}-slash", [("/abs/x", "file", b"a", 0o644)])],
        )
        expect(
            read_text(os.path.join(root, "abs", "x")) == "a", f"{fmt}: /abs/x is not in the tree"
        )
    for fmt in ("deb", "apk"):  # the rpm builder makes no hard links
        for name, members in (
            ("hard-dotdot", [("f", "file", b"f", 0o644), ("h", "hard", "../host/secret", 0o644)]),
            (
                "hard-through",
                [
                    ("usr", "dir", None, 0o755),
                    ("usr/out", "sym", ctx.host, 0o777),
                    ("usr/copy", "hard", "usr/out/secret", 0o644),
                ],
            ),
        ):
            refused(ctx, f"{fmt}-{name}", [package(ctx, fmt, f"{fmt}-{name}", members)], "escapes")
    expect(os.stat(secret).st_nlink == 1, "a hard link to the host's file was made")


@test
def modes_and_types(ctx: Ctx) -> None:
    """10.1: modes from the archive, setuid and setgid dropped, every file readable by its owner.

    A directory stays traversable and writable by its owner; a hard link is to the member it names,
    a symlink included; device files and pipes are skipped with a note; times are the archive's.
    """
    common: list[Member] = [
        ("usr", "dir", None, 0o755),
        ("usr/suid", "file", b"s", 0o4755),
        ("usr/sgid", "file", b"g", 0o2711),
        ("usr/none", "file", b"n", 0),
        ("usr/locked", "dir", None, 0o500),
        ("usr/locked/f", "file", b"f", 0o640),
        ("usr/link", "sym", "suid", 0o777),
    ]
    tar_only: list[Member] = [
        ("usr/hard", "hard", "usr/suid", 0o4755),
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
        if fmt == "rpm":
            continue
        same = os.stat(os.path.join(u, "hard")).st_ino == os.stat(os.path.join(u, "suid")).st_ino
        to_link = os.lstat(os.path.join(u, "hard-to-link"))
        expect(same, f"{fmt}: the hard link is not to its member")
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

    Each compression a reader takes checks its data: gzip's and xz's CRCs, zstd's checksum.
    """
    members: list[Member] = [
        ("usr", "dir", None, 0o755),
        ("usr/share", "dir", None, 0o755),
        ("usr/share/f", "file", bytes(range(256)) * 64, 0o644),
    ]
    os.makedirs(os.path.join(ctx.work, "pkgs"))
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
            refused(ctx, name, [pkg])
    for fmt in FORMATS:
        path = os.path.join(ctx.work, "pkgs", f"noise.{fmt}")
        with open(path, "wb") as f:
            f.write(os.urandom(4096))
        refused(ctx, f"noise-{fmt}", [path])


@test
def tar_structure(ctx: Ctx) -> None:
    """10.1: what tar spells long or large is read; an archive with anything after it is refused.

    GNU long names, PAX paths and link paths and base-256 times are read as tar defines them. A
    member whose data runs past the end is refused, and so is any byte but NUL after the archive's
    last member: a corrupt header or a part of one, behind which more members could hide.
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
        refused(ctx, f"{fmt}-cut-data", [pkg("cut-data", head[: len(head) - 300])])
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
    for case, raw in (
        ("no-trailer", whole[:trailer]),
        ("cut-entry", whole[: trailer - 600]),
        ("after-trailer", whole + b"junk"),
    ):
        data = gzip.compress(raw, mtime=0)
        refused(ctx, f"rpm-{case}", [package(ctx, "rpm", f"cpio-{case}", members, data=data)])
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
    failures = 0
    chosen = [t for t in TESTS if args.select in t.__name__]
    for t in chosen:
        d = os.path.join(work, t.__name__)
        host = os.path.join(d, "host")
        os.makedirs(host)
        with open(os.path.join(host, "secret"), "w") as f:
            f.write("the host's own\n")
        start = time.monotonic()
        try:
            t(Ctx(work=d, host=host))
        except (AssertionError, OSError, steps.UnpackError) as e:
            failures += 1
            print(f"FAIL {t.__name__:<34} {time.monotonic() - start:5.1f}s {str(e)[:600]}")
            continue
        print(f"PASS {t.__name__:<34} {time.monotonic() - start:5.1f}s")
    print(f"{len(chosen)} tests, {failures} failures")
    return min(failures, 255)


if __name__ == "__main__":
    sys.exit(main())
