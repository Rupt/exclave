"""The tool's unpack and wrap: a group of the regression suite (DESIGN.md 17 item 4).

Run by test/run.py, on the fixtures test/suite.py makes.
"""

import os
import platform
import re
import shutil
import sys
from typing import TYPE_CHECKING

import tree
from packages import make_apk, make_deb

if TYPE_CHECKING:
    from collections.abc import Sequence
from harness import expect, read_bytes, read_text, run, test
from suite import REPO, TOOL, Ctx, check, copy_exclave, inside

from unpack import ldcache
from unpack.root import Root

UNPACK = (sys.executable, "-m", "unpack")


# the synthetic packages of the tool tests carry this machine's architecture
MACHINE = platform.machine()


DEB_ARCH = {"x86_64": "amd64", "aarch64": "arm64"}.get(MACHINE, MACHINE)


@test
def tool_version(ctx: Ctx) -> None:
    """The build `version` names is the launcher's and the hashes file's too (7, 10)."""
    rc, out, err = run([*tree.TOOL, "version"], cwd=ctx.work, env=ctx.env)
    name = out.strip()
    expect(
        rc == 0 and name.startswith("exclave ") and name.count(" ") == 1,
        f"version: rc={rc} {out!r} {err!r}",
    )
    expect(name.encode() in read_bytes(ctx.launcher), f"the launcher does not carry {name!r}")
    ex = os.path.join(ctx.work, f"version-{os.getpid()}.exclave")
    os.makedirs(os.path.join(ex, "tree"))
    rc, out, err = run([*tree.TOOL, "wrap", ex], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, f"wrap of an empty tree: rc={rc} {out!r} {err!r}")
    hashes = read_bytes(os.path.join(ex, ".exclave", "hashes")).decode()
    want = f'tool "{name.removeprefix("exclave ")}"\n'
    expect(want in hashes, f"the hashes file lacks {want!r}: {hashes!r}")


@test
def pre_rename_can_refused(ctx: Ctx) -> None:
    """A can, an exclave from before the rename (.can/, root/), is refused by name.

    Every command that takes an exclave refuses it before anything is read or written, rather than
    ending in a traceback; docs/DESIGN.md 13 item 45 says how to convert it.
    """
    old = os.path.join(ctx.work, f"old-{os.getpid()}.can")
    os.makedirs(os.path.join(old, ".can"))
    os.makedirs(os.path.join(old, "root", "usr", "bin"))
    with open(os.path.join(old, ".can", "manifest"), "w") as f:
        f.write("can 1\n")
    log = os.path.join(ctx.work, "old-can.log")
    open(log, "w").close()
    before = sorted(os.walk(old))
    for args in (["wrap"], ["unwrap"], ["check"], ["prune", log], ["hash"], ["relink"]):
        rc, _o, e = run([*TOOL, args[0], old, *args[1:]])
        expect(
            rc != 0 and "is a can, an exclave from before the rename" in e and "Traceback" not in e,
            f"{args[0]} on a can: rc={rc} {e[-300:]!r}",
        )
    expect(sorted(os.walk(old)) == before, "a refused command changed the can")


@test
def exclave_readme(ctx: Ctx) -> None:
    """6.1: every exclave explains itself to whoever finds it.

    Wrap and relink write README at the top where the exclave has none and leave the maker's own,
    or a shortcut by that name, alone, and unpack, the step before the tool, writes none; the files
    it names are there; the launcher run bare names it, and a launcher outside any exclave says so.
    The launcher carries the licence's text, and the README names its copyright line.
    """
    d = os.path.join(ctx.work, "readme-apks")
    os.makedirs(d, exist_ok=True)
    make_apk(
        os.path.join(d, "x-1.0-r0.apk"),
        "x",
        [
            ("usr", "dir", None, 0o755),
            ("usr/share", "dir", None, 0o755),
            ("usr/share/x", "file", b"x\n", 0o644),
        ],
    )
    out = os.path.join(ctx.work, "readme-unpacked.exclave")
    rc, o, e = run([*UNPACK, out, os.path.join(d, "x-1.0-r0.apk")])
    expect(rc == 0, "unpack: " + o + e)
    expect(not os.path.lexists(os.path.join(out, "README")), "unpack wrote a README")
    rc, o, e = run([*TOOL, "wrap", out])
    expect(rc == 0, "wrap: " + o + e)
    readme = read_bytes(os.path.join(out, "README"))
    expect(b"exclave" in readme, "wrap wrote no README")
    # a bare directory holding tree/, made an exclave by wrap alone
    bare = os.path.join(ctx.work, "readme-bare")
    os.makedirs(os.path.join(bare, "tree", "usr", "share"))
    os.makedirs(os.path.join(bare, ".exclave"))
    shutil.copy2(ctx.launcher, os.path.join(bare, ".exclave", "launcher"))
    with open(os.path.join(bare, "tree", "usr", "share", "x"), "w") as f:
        f.write("x\n")
    rc, o, e = run([*TOOL, "wrap", bare])
    expect(rc == 0, "wrap: " + o + e)
    expect(read_bytes(os.path.join(bare, "README")) == readme, "wrap wrote another README")
    here = readme.split(b"\nWhat is here\n")[1].split(b"\nRunning it\n")[0].decode()
    for name in re.findall(r"^  (\S+/\S*)", here, re.MULTILINE):
        expect(
            os.path.lexists(os.path.join(bare, name)),
            f"the README names {name}, which a wrapped exclave lacks",
        )
    with open(os.path.join(REPO, "LICENSE"), "rb") as f:
        licence = f.read()
    with open(os.path.join(bare, ".exclave", "launcher"), "rb") as f:
        expect(licence in f.read(), "the launcher does not carry LICENSE's text")
    notice = next(line for line in licence.decode().splitlines() if line.startswith("Copyright"))
    expect(notice.encode() in readme.replace(b"\n", b" "), f"the README does not name {notice!r}")
    rc, _out, err = run([os.path.join(bare, ".exclave", "launcher")], cwd=ctx.work)
    expect(
        rc == 127 and "exclave's launcher" in err and "README" in err,
        f"the launcher run bare: rc={rc} {err!r}",
    )
    lone = os.path.join(ctx.work, f"readme-lone-{os.getpid()}")
    os.makedirs(lone, exist_ok=True)
    shutil.copy2(ctx.launcher, os.path.join(lone, "launcher"))
    rc, _out, err = run([os.path.join(lone, "launcher"), "true"], cwd=ctx.work)
    expect(
        rc == 127 and "not inside an exclave" in err and ".exclave/manifest" in err,
        f"a launcher outside an exclave: rc={rc} {err!r}",
    )
    with open(os.path.join(bare, "README"), "w") as f:  # the maker's own notes stay
        f.write("notes\n")
    rc, o, e = run([*TOOL, "wrap", bare])
    expect(
        rc == 0 and read_text(os.path.join(bare, "README")) == "notes\n",
        "wrap replaced the maker's README: " + o + e,
    )
    run([*TOOL, "relink", bare, ctx.launcher])
    expect(
        read_text(os.path.join(bare, "README")) == "notes\n", "relink replaced the maker's README"
    )
    os.remove(os.path.join(bare, "README"))
    # a shortcut by that name stays a shortcut
    os.symlink("tree/usr/share/x", os.path.join(bare, "README"))
    run([*TOOL, "relink", bare, ctx.launcher])
    expect(
        os.readlink(os.path.join(bare, "README")) == "tree/usr/share/x",
        "relink replaced a shortcut named README",
    )
    os.remove(os.path.join(bare, "README"))
    run([*TOOL, "relink", bare, ctx.launcher])  # relink writes a README where the exclave has none
    expect(read_bytes(os.path.join(bare, "README")) == readme, "relink wrote no README")


@test
def unpack_and_wrap(ctx: Ctx) -> None:
    """10.1 as files: unpack, wrap, unwrap and check on package files.

    Unpack takes package files and nothing else, records every input by hash, reports what the set's
    own control files say it lacks, strips the volatile directories, refuses two versions of one
    package, and adds no launcher, manifest or placeholder; wrap adds them, wraps the tree and
    records the manifest and tree hashes; unwrap, check and a second wrap keep the hashes file; a
    tree assembled by hand becomes an exclave by wrap alone; the tree hash refuses a directory it
    cannot read, as it does a file.
    """
    d = os.path.join(ctx.work, "updebs")
    os.makedirs(d, exist_ok=True)
    true_bytes = read_bytes(ctx.payload("true"))
    make_deb(
        os.path.join(d, "tool.deb"),
        "tool",
        [
            ("./usr", "dir", None, 0o755),
            ("./usr/bin", "dir", None, 0o755),
            ("./usr/bin/tool", "file", b"#!/bin/sh\necho tool ok\n", 0o755),
        ],
        "Depends: libfoo1 (>= 2), virt | missing-alt\nPre-Depends: absent-pkg\n",
    )
    make_deb(
        os.path.join(d, "libfoo1.deb"),
        "libfoo1",
        [
            ("./usr", "dir", None, 0o755),
            ("./usr/share", "dir", None, 0o755),
            ("./usr/share/foo", "file", b"data\n", 0o644),
            ("./var", "dir", None, 0o755),
            ("./var/tmp", "dir", None, 0o755),
            ("./var/tmp/junk", "file", b"junk\n", 0o644),
        ],
        "Provides: virt\n",
    )
    out = os.path.join(ctx.work, "up.exclave")
    rc, o, e = run([*UNPACK, out, os.path.join(d, "tool.deb"), os.path.join(d, "libfoo1.deb")])
    expect(rc == 0, "unpack: " + o + e)
    expect(
        "depends: tool needs absent-pkg, not in the set" in o,
        "the missing Pre-Depends was not reported: " + o,
    )
    expect(
        "depends: tool needs libfoo1 (>= 2), not in the set" in o,
        "the version constraint was not checked: " + o,
    )
    expect("virt" not in o, "a Provides in the set was reported missing: " + o)
    lock = tree.records(os.path.join(out, ".exclave", "hashes"))
    pkgs = lock.get("pkg", [])
    expect(
        [p[0] for p in pkgs] == ["libfoo1", "tool"]
        and pkgs[1][1] == "1"
        and pkgs[1][2] == DEB_ARCH,
        f"pkg records: {pkgs!r}",
    )
    expect(
        pkgs[1][3] == tree.b2(read_bytes(os.path.join(d, "tool.deb"))),
        "the input hash is the file's",
    )
    expect(not lock.get("tree", []), "an unwrapped exclave has no tree hash yet")
    expect(
        not os.path.lexists(os.path.join(out, "tree", "var", "tmp")),
        "the volatile directories are stripped",
    )
    expect(
        os.listdir(os.path.join(out, ".exclave")) == ["hashes"]
        and not os.path.lexists(os.path.join(out, "tree", "opt")),
        "an unpacked tree: no launcher, manifest or placeholder yet",
    )
    # the exclave is a directory between the two steps: put an ELF in by hand, then wrap it
    with open(os.path.join(out, "tree", "usr", "bin", "t2"), "wb") as f:
        f.write(true_bytes)
    os.chmod(os.path.join(out, "tree", "usr", "bin", "t2"), 0o755)
    rc, o, e = run([*TOOL, "wrap", out])
    expect(
        rc == 1 and "does not resolve" in o,
        f"an ELF whose loader the tree lacks must refuse the wrap: rc={rc} {o[-400:]}",
    )
    os.remove(os.path.join(out, "tree", "usr", "bin", "t2"))
    rc, o, e = run([*TOOL, "wrap", out])
    expect(rc == 0 and f"{out} is wrapped" in o, "wrap: " + o + e)
    lock = tree.records(os.path.join(out, ".exclave", "hashes"))
    expect(
        len(lock.get("pkg", [])) == 2 and lock.get("tree", []) and lock.get("manifest", []),
        f"the wrapped hashes file keeps its inputs and adds the hashes: {list(lock)!r}",
    )
    expect(
        read_bytes(os.path.join(out, ".exclave", "manifest")) == b"exclave 1\n",
        "the default manifest",
    )
    expect(
        os.path.isdir(os.path.join(out, "tree", "var", "tmp"))
        and os.path.exists(os.path.join(out, "tree", "etc", "passwd")),
        "wrap adds the placeholders",
    )
    rc, o, e = run([*TOOL, "hash", out])
    expect(
        o.strip() == lock["tree"][0][0] == tree.tree_hash(os.path.join(out, "tree")),
        "hash agrees with the hashes file and with the tree hash as 6.4 states it",
    )
    expect(
        tree.is_wrapper(os.path.join(out, "tree", "usr", "bin", "tool"), out),
        "the script was wrapped",
    )
    rc, o, e = run(
        [
            *UNPACK,
            os.path.join(ctx.work, "dup.exclave"),
            os.path.join(d, "tool.deb"),
            os.path.join(d, "tool.deb"),
        ]
    )
    expect(
        rc != 0 and "one version of a package" in e,
        f"two files of one package must be refused: {o} {e}",
    )
    # a hand-made tree becomes an exclave by wrap alone: no manifest, no inputs in the hashes file
    hand = os.path.join(ctx.work, "hand.exclave")
    os.makedirs(os.path.join(hand, "tree", "usr", "bin"))
    with open(os.path.join(hand, "tree", "usr", "bin", "hi"), "w") as f:
        f.write("#!/bin/sh\necho hi\n")
    os.chmod(os.path.join(hand, "tree", "usr", "bin", "hi"), 0o755)
    rc, o, e = run([*TOOL, "wrap", hand])
    expect(rc == 0, "wrap of a bare tree: " + o + e)
    lock = tree.records(os.path.join(hand, ".exclave", "hashes"))
    expect(
        not lock.get("pkg", []) and lock.get("tree", []) and lock.get("launcher", []),
        "a hand-made exclave's hashes file has no inputs, a launcher hash and a tree hash",
    )
    errors, _warnings, _out = check(hand)
    expect(not errors, f"static check of a tree with no ELF: {errors!r}")
    expect(
        os.path.exists(os.path.join(hand, "tree", "etc", "passwd"))
        and os.path.isdir(os.path.join(hand, "tree", "opt")),
        "wrap adds the placeholders a hand-made tree lacks",
    )
    # the hashes file through the life of an exclave
    wrapped = read_bytes(os.path.join(out, ".exclave", "hashes"))
    rc, o, e = run([*TOOL, "unwrap", out])
    expect(rc == 0, "unwrap: " + o + e)
    lock = tree.records(os.path.join(out, ".exclave", "hashes"))
    expect(
        len(lock.get("pkg", [])) == 2
        and not lock.get("tree", [])
        and not lock.get("manifest", [])
        and not lock.get("launcher", []),
        f"an unwrapped exclave's hashes file keeps its inputs and has no hashes: {list(lock)!r}",
    )
    rc, o, e = run([*TOOL, "check", out])
    expect(rc == 1 and "an unwrapped exclave" in o, "check names an unwrapped exclave: " + o[-300:])
    rc, o, e = run([*TOOL, "wrap", out])
    expect(
        rc == 0 and read_bytes(os.path.join(out, ".exclave", "hashes")) == wrapped,
        "wrap after unwrap reproduces the hashes file byte for byte",
    )
    os.remove(os.path.join(out, "tree", "usr", "share", "foo"))
    rc, o, e = run([*TOOL, "check", out])
    expect(
        rc == 1 and "differs from the hashes file" in o,
        "a file removed from a wrapped exclave must show against the hashes file: " + o[-300:],
    )
    rc, o, e = run([*TOOL, "hash", os.path.join(ctx.work, "not-an-exclave")])
    expect(rc != 0 and "no tree" in e, "hash of a non-exclave is refused")
    locked = os.path.join(out, "tree", "usr", "share", "locked")
    os.makedirs(locked)
    os.chmod(locked, 0)
    rc, o, e = run([*TOOL, "hash", out])
    os.rmdir(locked)
    expect(
        rc == 1 and f"cannot read {locked}: the tree hash needs every file readable" in e,
        f"an unreadable directory must refuse the hash, as an unreadable file does: {o} {e}",
    )
    lockcopy = os.path.join(ctx.work, "some.hashes.txt")
    shutil.copy2(os.path.join(out, ".exclave", "hashes"), lockcopy)
    rc, o, e = run([*TOOL, "format", "--check", lockcopy])
    expect(rc == 0, "format recognises a hashes file by its first record, not its name: " + o + e)


@test
def tree_by_hand(ctx: Ctx) -> str | None:
    """10.1: a tree made from a package with ar and tar, as the design shows, becomes an exclave.

    The package's data member is extracted by hand into tree/, and wrap alone makes the directory
    an exclave: the tool needs no package reader. Skips where ar is missing.
    """
    if not shutil.which("ar"):
        return "no ar"
    d = os.path.join(ctx.work, "hand-debs")
    os.makedirs(d, exist_ok=True)
    make_deb(
        os.path.join(d, "tool.deb"),
        "tool",
        [
            ("./usr", "dir", None, 0o755),
            ("./usr/bin", "dir", None, 0o755),
            ("./usr/bin/tool", "file", b"#!/bin/sh\necho tool ok\n", 0o755),
        ],
    )
    ex = os.path.join(ctx.work, f"by-hand-{os.getpid()}.exclave")
    os.makedirs(os.path.join(ex, "tree"))
    rc, o, e = run(
        ["sh", "-c", 'ar p "$1" data.tar.gz | tar -xz -C "$2"', "sh", "tool.deb", ex + "/tree"],
        cwd=d,
    )
    expect(rc == 0, "ar and tar: " + o + e)
    rc, o, e = run([*TOOL, "wrap", ex])
    expect(rc == 0 and f"{ex} is wrapped" in o, "wrap of a tree made by hand: " + o + e)
    lock = tree.records(os.path.join(ex, ".exclave", "hashes"))
    expect(
        not lock.get("pkg", []) and lock.get("tree", []),
        f"no inputs and a tree hash: {list(lock)!r}",
    )
    expect(
        tree.is_wrapper(os.path.join(ex, "tree", "usr", "bin", "tool"), ex),
        "the package's script was wrapped",
    )
    return None


@test
def wrap_refusals(ctx: Ctx) -> None:
    """Wrap refuses, and wraps nothing when it refuses.

    It refuses a stale wrapper of another launcher, a file its user cannot execute, an original
    without a wrapper, an ELF whose loader the tree lacks, a manifest or a tree beyond the
    launcher's tables, which the launcher refuses too, and a link naming the exclave's own location,
    with the link that fixes it; executables in a data directory are left alone.
    """

    def hand(
        name: str, files: Sequence[tuple[str, bytes, int]], manifest: bytes | None = None
    ) -> str:
        ex = os.path.join(ctx.work, name)
        shutil.rmtree(ex, ignore_errors=True)
        for v, body, mode in files:
            p = os.path.join(ex, "tree", v.lstrip("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(body)
            os.chmod(p, mode)
        if manifest is not None:
            os.makedirs(os.path.join(ex, ".exclave"), exist_ok=True)
            with open(os.path.join(ex, ".exclave", "manifest"), "wb") as f:
                f.write(manifest)
        return ex

    script = b"#!/bin/sh\necho hi\n"
    true_bytes = read_bytes(ctx.payload("true"))
    # a copy whose launcher differs by a byte, then wrap: the original must survive
    a = hand("st.exclave", [("/usr/bin/hi", script, 0o755)])
    rc, o, e = run([*TOOL, "wrap", a])
    expect(rc == 0, o + e)
    b = os.path.join(ctx.work, "st2.exclave")
    shutil.rmtree(b, ignore_errors=True)
    shutil.copytree(a, b, symlinks=True)  # plain copies: the hard links are broken
    with open(os.path.join(b, ".exclave", "launcher"), "ab") as f:
        f.write(b"\0")
    rc, o, e = run([*TOOL, "wrap", b])
    expect(
        rc != 0 and "stale wrapper" in o + e and "relink" in o + e,
        f"a stale wrapper must be refused: {rc} {o[-300:]} {e[-300:]}",
    )
    expect(
        read_bytes(os.path.join(b, "tree", "usr", "bin", ".real", "hi")) == script,
        "the original was overwritten",
    )
    rc, o, e = run([*TOOL, "relink", b, ctx.launcher_src])
    rc, o, e = run([*TOOL, "wrap", b])
    expect(rc == 0, "after relink the copy is wrapped: " + o + e)
    # an executable its user cannot execute
    c = hand("nx.exclave", [("/usr/bin/gx", script, 0o601)])
    rc, o, e = run([*TOOL, "wrap", c])
    expect(
        rc != 0
        and "cannot execute" in o + e
        and not os.path.exists(os.path.join(c, "tree", "usr", "bin", ".real")),
        f"a 0601 file must not become a 0755 launcher: {o[-300:]} {e[-300:]}",
    )
    # an original without a wrapper
    d = hand("stray.exclave", [("/usr/bin/hi", script, 0o755)])
    rc, o, e = run([*TOOL, "wrap", d])
    expect(rc == 0, o + e)
    h1 = run([*TOOL, "hash", d])[1].strip()
    with open(os.path.join(d, "tree", "usr", "bin", ".real", "stray"), "wb") as f:
        f.write(true_bytes)
    os.chmod(os.path.join(d, "tree", "usr", "bin", ".real", "stray"), 0o755)
    h2 = run([*TOOL, "hash", d])[1].strip()
    expect(h1 != h2, "a stray original must change the tree hash")
    for cmd in ("wrap", "unwrap", "check"):
        rc, o, e = run([*TOOL, cmd, d])
        expect(
            rc != 0 and "original without wrapper" in o + e,
            f"{cmd} must refuse a stray original: {o[-300:]} {e[-300:]}",
        )
    rc, o, e = run([*TOOL, "relink", d, ctx.launcher_src])
    expect(
        rc == 0
        and "left alone" in o
        and not os.path.exists(os.path.join(d, "tree", "usr", "bin", "stray")),
        "relink must not make a wrapper for a stray: " + o,
    )
    # a refused wrap wraps nothing
    e_ = hand(
        "noloader.exclave", [("/usr/bin/hi", script, 0o755), ("/usr/bin/t", true_bytes, 0o755)]
    )
    rc, o, e = run([*TOOL, "wrap", e_])
    expect(
        rc == 1
        and "nothing was wrapped" in o
        and not os.path.exists(os.path.join(e_, "tree", "usr", "bin", ".real")),
        "a refused wrap must leave the tree unwrapped: " + o[-400:],
    )
    # the launcher's tables
    f_ = hand(
        "lim.exclave",
        [("/usr/bin/hi", script, 0o755)],
        b"exclave 1\n\n" + b"".join(b'own "/own%03d"\n' % i for i in range(300)),
    )
    rc, o, e = run([*TOOL, "wrap", f_])
    expect(
        rc != 0 and "line 259 col 1: more than 256 own records" in o + e,
        "300 own records must be refused at the 257th: " + (o + e)[-300:],
    )
    g = hand(
        "lim2.exclave",
        [("/usr/bin/hi", script, 0o755)],
        b"exclave 1\n\n" + b"".join(b'host "/hostpath%03d"\n' % i for i in range(40)),
    )
    rc, o, e = run([*TOOL, "wrap", g])
    expect(
        rc != 0 and "line 35 col 1: more than 32 host records" in o + e,
        "40 host records must be refused at the 33rd: " + (o + e)[-300:],
    )
    t_ = hand(
        "lim3.exclave",
        [("/usr/bin/hi", script, 0o755)] + [(f"/top{i:03}", b"", 0o644) for i in range(300)],
    )
    for i in range(20):
        # placeholders take no slot, as the launcher counts
        os.makedirs(os.path.join(t_, "tree", f"empty{i:02}"))
    rc, o, e = run([*TOOL, "wrap", t_])
    # /usr, /etc with its identity placeholders, the 300
    m = re.search(r"tree/ has (\d+) top-level entries; the launcher holds 256", o + e)
    expect(
        rc != 0 and m and 301 < int(m.group(1)) < 320,
        "300 top-level files must be refused, the placeholders not counted: " + (o + e)[-300:],
    )
    ex2 = os.path.join(ctx.work, "hosts30.exclave")
    copy_exclave(ctx.exclave, ex2)
    with open(os.path.join(ex2, ".exclave", "manifest"), "wb") as f:
        f.write(b"exclave 1\n\n" + b"".join(b'host "/hostpath%03d"\n' % i for i in range(30)))
    rc, out, err = run(
        [os.path.join(ex2, "tree", ctx.vbin("cat").lstrip("/")), "/etc/hosts"],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        rc == 0 and out == read_text("/etc/hosts"),
        f"30 host records leave the identity files the host's: {out[:80]!r} {err!r}",
    )
    # the tree's 256 slots are its own, whatever the manifest owns
    ex3 = os.path.join(ctx.work, "top300.exclave")
    copy_exclave(ctx.exclave, ex3)
    for i in range(300):
        open(os.path.join(ex3, "tree", f"top{i:03}"), "w").close()
    rc, out, err = run(
        [os.path.join(ex3, "tree", ctx.vbin("cat").lstrip("/")), "/etc/hosts"],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        rc != 0 and "more than 256 top-level entries" in err,
        f"300 top-level entries must be refused by the launcher: {err[-300:]!r}",
    )
    # a data directory is neither wrapped nor executed
    dp = os.path.join(ctx.work, "data.exclave")
    copy_exclave(ctx.exclave, dp)
    sys_ = os.path.join(dp, "tree", "opt", "sysroot", "bin")
    os.makedirs(sys_)
    with open(os.path.join(sys_, "true"), "wb") as f:
        f.write(true_bytes)
    os.chmod(os.path.join(sys_, "true"), 0o755)
    with open(os.path.join(dp, ".exclave", "manifest"), "wb") as f:
        f.write(b'exclave 1\n\ndata "/opt/sysroot"\n')
    rc, o, e = run([*TOOL, "wrap", dp])
    expect(
        rc == 0 and not os.path.exists(os.path.join(sys_, ".real")),
        "the data directory was wrapped or the exclave refused: " + (o + e)[-400:],
    )
    rc, o, e = run([*TOOL, "check", dp])
    expect(rc == 0, "check with a data directory: " + o[-300:])
    rc, out, err = run(
        [
            os.path.join(dp, "tree", ctx.vbin("sh").lstrip("/")),
            "-c",
            "/opt/sysroot/bin/true; echo rc=$?",
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        "Permission denied" in out + err and "rc=126" in out,
        f"a data directory is never executed: {out!r} {err!r}",
    )
    # a link whose text is the exclave's real location would break when the exclave moved
    lk = hand("located.exclave", [("/usr/bin/hi", script, 0o755)])
    os.symlink(
        os.path.join(os.path.realpath(lk), "tree", "usr", "bin", "hi"),
        os.path.join(lk, "tree", "usr", "bin", "lk"),
    )
    rc, o, e = run([*TOOL, "wrap", lk])
    expect(
        rc != 0
        and "link naming the exclave's own location: /usr/bin/lk" in o + e
        and "ln -sfn /usr/bin/hi" in o + e
        and not os.path.exists(os.path.join(lk, "tree", "usr", "bin", ".real")),
        f"a link naming the exclave's location must be refused: {rc} {(o + e)[-400:]}",
    )


@test
def ld_so_cache_as_ldconfig_writes_it(ctx: Ctx) -> str | None:
    """10.1: unpack writes ld.so.cache as the tree's own ldconfig would, running nothing of it.

    Two unwrapped copies of the exclave, altered alike: a dangling `.so.` link, a library under a
    new name whose soname link then moves to it, a directory a `ld.so.conf.d` file adds, a
    `glibc-hwcaps` subdirectory, libraries in `lib`, `lib64` and `libx32`, a linker script and a
    truncated file. The tree's ldconfig runs on one, inside the exclave as a program of the tree,
    and unpack's writer on the other; the caches and the directories' links must agree. The
    loader's directories the writer reads from the loader file must be those `--list-diagnostics`
    prints.
    """
    if ctx.musl or not ctx.libc:
        return "musl reads no ld.so.cache"
    copies = []
    for which in ("ldconfig", "writer"):
        ex = os.path.join(ctx.work, f"cache-{which}-{os.getpid()}.exclave")
        shutil.rmtree(ex, ignore_errors=True)
        copy_exclave(ctx.exclave, ex)
        tree.unwrap_tree(ex)
        copies.append(os.path.join(ex, "tree"))
    a, b = copies
    with Root(a) as r:
        ldconfig = ldcache.find_ldconfig(r)
    # a glibc tree carries one; the pruned fixture keeps it, since this run opens it
    expect(ldconfig is not None, "no static ldconfig in the tree")
    assert ldconfig is not None
    family = ldcache.EM_X86_64 if ctx.machine == "x86_64" else ldcache.EM_AARCH64
    libdir = os.path.dirname(ctx.vreal(ctx.libc))
    sample = None  # a library beside libc with a soname, which the alterations copy
    for name in sorted(os.listdir(os.path.join(a, libdir.lstrip("/")))):
        p = os.path.join(a, libdir.lstrip("/"), name)
        if name.startswith("lib") and ".so" in name and name != "libc.so.6" and os.path.isfile(p):
            info = None if os.path.islink(p) else ldcache.shared_object(read_bytes(p), family)
            if info and info[2]:
                sample = name
                break
    if not sample:
        return "no library with a soname beside libc"
    hwcaps = os.path.join(libdir.lstrip("/"), "glibc-hwcaps", "x86-64-v3")
    for root in copies:
        ld = os.path.join(root, libdir.lstrip("/"))
        src = os.path.join(ld, sample)
        os.symlink("libgone.so.1.0.0", os.path.join(ld, "libgone.so.1"))
        shutil.copyfile(src, os.path.join(ld, "libzz.so.9"))
        for d in ("opt/testlib", "usr/lib", "usr/lib64", "usr/libx32", hwcaps):
            os.makedirs(os.path.join(root, d), exist_ok=True)
        shutil.copyfile(src, os.path.join(root, "opt", "testlib", "libopt.so.1.2"))
        shutil.copyfile(src, os.path.join(root, "usr", "lib", "libplain.so.3"))
        shutil.copyfile(src, os.path.join(root, "usr", "lib64", "lib64only.so.2"))
        shutil.copyfile(src, os.path.join(root, "usr", "libx32", "libx.so.1"))
        shutil.copyfile(src, os.path.join(root, hwcaps, "libhw.so.1"))
        with open(os.path.join(ld, "libscript.so"), "w") as f:
            f.write("/* GNU ld script */\nGROUP ( libzz.so.9 )\n")
        with open(os.path.join(ld, "libjunk.so.1"), "wb") as f:
            f.write(b"\x7fELF" + bytes(16))
        os.makedirs(os.path.join(root, "etc", "ld.so.conf.d"), exist_ok=True)
        with open(os.path.join(root, "etc", "ld.so.conf.d", "zz-test.conf"), "w") as f:
            f.write("# a test\n/opt/testlib  \n/missing/dir\n")
    # the tree's ldconfig on the first copy; a relative include, Red Hat's, is spelt from /etc,
    # since -r refuses it
    conf, cf = os.path.join(a, "etc", "ld.so.conf"), "/etc/ld.so.conf"
    if os.path.exists(conf):
        text = read_text(conf)
        spelt = re.sub(r"^(\s*include\s+)([^/\s]\S*)", r"\1/etc/\2", text, flags=re.MULTILINE)
        if spelt != text:
            cf = "/etc/ld.so.conf.exclave"
            with open(os.path.join(a, "etc", "ld.so.conf.exclave"), "w") as f:
                f.write(spelt)
    rc, out, err = inside(ctx, ldconfig, ["-r", a, "-f", cf])
    expect(rc == 0, f"the tree's ldconfig on a copy: {out}{err}")
    if cf != "/etc/ld.so.conf":
        os.remove(os.path.join(a, "etc", "ld.so.conf.exclave"))
    logs: list[str] = []
    with Root(b) as r:
        expect(ldcache.write(r, ldconfig, logs.append), f"the writer wrote no cache: {logs}")
    ca = read_bytes(os.path.join(a, "etc", "ld.so.cache"))
    cb = read_bytes(os.path.join(b, "etc", "ld.so.cache"))
    expect(
        ca == cb, f"the caches differ: ldconfig's {len(ca)} bytes, the writer's {len(cb)}; {logs}"
    )
    dirs = (libdir, "/opt/testlib", "/usr/lib", "/usr/lib64", "/usr/libx32", "/" + hwcaps)

    def listing(root: str) -> list[tuple[str, str, str]]:
        out = []
        for d in dirs:
            p = os.path.join(root, d.lstrip("/"))
            for n in sorted(os.listdir(p)) if os.path.isdir(p) else []:
                q = os.path.join(p, n)
                kind = os.readlink(q) if os.path.islink(q) else "file" if os.path.isfile(q) else "?"
                out.append((d, n, kind))
        return out

    la, lb = listing(a), listing(b)
    expect(la == lb, f"the links differ: {sorted(set(la) ^ set(lb))[:6]!r}")
    rc, out, err = inside(ctx, ctx.interp, ["--list-diagnostics"])
    printed = re.findall(r'^path\.system_dirs\[0x[0-9a-f]+\]="([^"]*)"', out, flags=re.MULTILINE)
    if printed:  # glibc 2.33 and later print them
        got = ldcache.trusted_dirs(read_bytes(ctx.payload(ctx.interp)))
        expect(got == printed, f"the loader's table {got!r} is not what it prints {printed!r}")
    for root in copies:
        shutil.rmtree(os.path.dirname(root), ignore_errors=True)
    return f"{len(ca)} bytes, {len(logs)} links made or removed, table of {len(printed)}"


@test
def wrap_takes_a_launcher(ctx: Ctx) -> str | None:
    """10.1, 10.5: wrap takes a launcher and checks the tree as that launcher's machine.

    A hand-made tree holding a static program of the other machine, that machine's launcher
    built here, and one of this machine is wrapped with the other machine's launcher: the other
    machine's program is checked and wrapped, this machine's is a foreign object, warned about and
    not checked; the hashes file records the launcher given; a second wrap with the same launcher
    passes, one with another launcher is refused naming relink, and check passes.
    """
    other = os.path.join(REPO, "build", "launcher-aarch64")
    if (
        not os.path.exists(other)
        or read_bytes(other, 20)[18:20] == read_bytes(ctx.launcher, 20)[18:20]
    ):
        return "no launcher of another machine built here"
    ex = os.path.join(ctx.work, f"foreign-{os.getpid()}.exclave")
    shutil.rmtree(ex, ignore_errors=True)
    os.makedirs(os.path.join(ex, "tree", "usr", "bin"))
    for name, src in (("theirs", other), ("ours", ctx.launcher)):
        shutil.copyfile(src, os.path.join(ex, "tree", "usr", "bin", name))
        os.chmod(os.path.join(ex, "tree", "usr", "bin", name), 0o755)
    rc, o, e = run([*TOOL, "wrap", ex, other])
    expect(rc == 0 and f"{ex} is wrapped" in o, "wrap with the other machine's launcher: " + o + e)
    expect(
        "/usr/bin/ours: not aarch64: a foreign object, not checked" in o,
        "this machine's program is a foreign object to that launcher: " + o[-500:],
    )
    expect(
        tree.is_wrapper(os.path.join(ex, "tree", "usr", "bin", "theirs"), ex),
        "the other machine's program was not wrapped",
    )
    lock = tree.records(os.path.join(ex, ".exclave", "hashes"))
    expect(
        [[tree.b2(read_bytes(other))]] == lock.get("launcher"),
        f"the launcher given is not the one recorded: {lock.get('launcher')!r}",
    )
    rc, o, e = run([*TOOL, "wrap", ex, other])
    expect(rc == 0, "a second wrap with the same launcher: " + o + e)
    rc, o, e = run([*TOOL, "wrap", ex, ctx.launcher])
    expect(rc != 0 and "relink" in o + e, "a wrap with another launcher must refuse: " + o + e)
    errors, _warnings, _out = check(ex)
    expect(not errors, f"check of the foreign exclave: {errors[:3]!r}")
    shutil.rmtree(ex, ignore_errors=True)
    return None
