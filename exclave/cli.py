"""The exclave command line (DESIGN.md 10).

An exclave is a directory at every stage, and every command takes paths; `format --check` is the
one flag.

    exclave wrap EXCLAVE            Wrap an exclave: add the launcher and the placeholders where
                                    missing, check the manifest (written as `exclave 1` if absent),
                                    the wrappers and every ELF, then wrap every executable and
                                    write the launcher, manifest and tree hashes to .exclave/hashes.
                                    Idempotent; a bare directory holding tree/ becomes an exclave.
    exclave unwrap EXCLAVE          Unwrap it: move every original back over its wrapper.
    exclave check EXCLAVE [LOG...]  Wrappers, originals, the tree against its recorded hash and the
                                    static check; with EXCLAVE_LOG files, the dynamic check of what
                                    a workload opened.
    exclave prune EXCLAVE LOG...    Drop every file no logged workload touched (10.4).
    exclave format FILE...          Parse with the strict grammar and rewrite in canonical form
                                    (--check: only report).
    exclave hash EXCLAVE            The tree hash of 6.4.
    exclave relink EXCLAVE [LAUNCHER]  Replace the launcher and relink every wrapper.

Every command but format takes an exclave, a directory holding tree/. Whatever made the tree is
the step before the tool: the unpack package from package files, debootstrap, a container export
or a person. Wrap and relink also write EXCLAVE/README, which tells whoever finds the exclave
what it is and how to run it, where the exclave has none.

The tool never opens a network connection.
"""

import argparse
import hashlib
import io
import os
import shutil
import stat
import sys
lazy from collections.abc import Iterable, Sequence

from exclave import build, elfcheck, grammar, layout
from exclave.build import BuildError
from exclave.grammar import GrammarError, Record

HERE = os.path.dirname(os.path.abspath(__file__))
# The exclave's README (6.1), for whoever finds the directory without knowing the project.
README_TEXT = b"""\
This directory is an exclave: Linux software packed with the
libraries and files it needs, so that its programs run from here, by
path, with nothing installed. It was made by exclave, a tool that
builds such directories. It runs on Linux 3.10 or later, on the
machine type it was built for ("file .exclave/launcher" names it),
with no root, setup step, daemon or container, and running it changes
nothing in tree/ or .exclave/ and leaves nothing behind. It is not a
sandbox: its programs run as you, with your files and your network.

What is here

  tree/              the software's own /: usually the packages listed
                     in .exclave/hashes, unpacked as if installed.
  .exclave/launcher  a small program that starts the others. Every
                     program in tree/ is a hard link to it, a
                     "wrapper"; the original sits in a hidden .real/
                     directory beside it, and running tree/usr/bin/NAME
                     runs tree/usr/bin/.real/NAME inside the exclave.
  .exclave/manifest  the maker's settings; "exclave 1" alone means none.
  .exclave/hashes    one "pkg" line per package that went in: name,
                     version, architecture and hash of the package
                     file; then hashes of the launcher, the manifest
                     and, on the "tree" line, all of tree/. Not where
                     they came from.
  other names        shortcuts into tree/ that the maker added.

A hashes file with no "tree" line marks an unwrapped, unfinished
exclave: its programs would use this system's libraries.

Running it

With EX the path of this directory, run from your own directory:

  EX/NAME ARGS...                    a shortcut, if the maker made one
  EX/tree/usr/bin/NAME ARGS...       any program in the exclave
  EX/tree/bin/sh                     a shell inside the exclave, if it
                                     has one
  EX/.exclave/launcher PROG ARGS...  PROG run inside the exclave: one of
                                     your own, such as one the
                                     exclave's compiler built, or an
                                     exclave path, /usr/bin/NAME

A symlink to a program in tree/ works too; a copy does not, and a
program run straight from .real/ is likely to fail.

Inside, a program sees the top-level directories that tree/ fills,
/usr, /etc, /lib and the rest, as its own, read-only: writing there
fails as on a read-only disk. Everything else is this system's: /home,
/tmp, /proc, /dev, the working directory, and eight files such as
/etc/passwd and /etc/resolv.conf that say who you are and how network
names are looked up. PATH is the exclave's, so this system's commands
are not found by name. The locale is C.UTF-8 and the time zone UTC by
default, and sudo, su and other setuid programs do not work inside.

EXCLAVE_LOG=/some/file makes every process append one line per call
that names a file: the call, its result and the path. Messages that
begin "launcher:" come from the exclave, not from the program.

Moving, copying, removing

Nothing outside this directory refers to it: move it, copy it with
cp -a, pack it with tar, or remove it with rm -r. A copy that splits
the hard links (cp -r) still runs, larger by the launcher's size per
program. Do not edit a program in tree/ in place: they are all one
file. An exclave does not run from a filesystem mounted noexec.

Checking it

The hashes are BLAKE2b-256, so "b2sum -l 256 .exclave/launcher" prints
the recorded launcher hash, and a package file fetched again its pkg
hash. The exclave tool, which builds these directories, is not part
of this one:

  exclave check DIR   every program wrapped, the libraries each needs
                      found inside, tree/ against its recorded hash
  exclave unwrap DIR  unwrap the exclave for editing; exclave wrap DIR
                      wraps it again
  exclave relink DIR  put in another launcher, relinking every program

Licences

The software in tree/ keeps its packages' licences, and passing this
directory on passes their terms on with it. Their texts are in
tree/usr/share/doc/*/copyright and tree/usr/share/common-licenses/
(Debian, Ubuntu) or tree/usr/share/licenses/ (Fedora and others);
exclave prune keeps them. An Alpine package's licence text comes in
its -doc package, so an Alpine exclave has it only if that went in.
The launcher is part of exclave, Copyright (c) 2026 Rupert Tombs,
under the MIT licence, whose text it carries: "readelf -p
.exclave.license .exclave/launcher" prints it.

This file is the same in every exclave; a maker may replace it.
"""


# -------------------------------------------------------------- the exclave as the launcher sees it
def manifest(ex: str) -> list[Record]:
    """Return the manifest's records, which are `exclave 1` alone when the file is absent."""
    p = layout.manifest_path(ex)
    return grammar.load(p, "exclave") if os.path.exists(p) else [Record("exclave", [("t", b"1")])]


def owned_top(ex: str) -> list[str]:
    """Return the tree's top-level entries that the exclave owns by 8.1 rule 1.

    These are all but the empty directories; a directory that cannot be listed is not empty.
    """
    root = os.path.join(ex, "tree")
    top = []
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        try:
            empty = not os.path.islink(p) and os.path.isdir(p) and not os.listdir(p)
        except PermissionError:
            empty = False
        if not empty:
            top.append("/" + name)
    return top


def owned(ex: str) -> elfcheck.Ownership:
    """Return the exclave's ownership as the launcher computes it at startup (8.1).

    The own prefixes are the manifest's own records and the tree's top-level entries of rule 1;
    the host prefixes are the manifest's host records.
    """
    m = manifest(ex)
    own = {o[0].decode("utf-8", "surrogateescape") for o in grammar.values(m, "own")}
    host = [h[0].decode("utf-8", "surrogateescape") for h in grammar.values(m, "host")]
    return elfcheck.Ownership(tuple(sorted(own | set(owned_top(ex)))), tuple(host))


def check_limits(ex: str) -> None:
    """Refuse, before wrapping, an exclave too large for the launcher's fixed tables (8.1).

    parse counts the manifest's records; this counts the tree's top-level entries.
    """
    manifest(ex)
    top = len(owned_top(ex))  # as the launcher counts them: a placeholder takes no slot
    if top > grammar.LIMITS["top"]:
        msg = f"tree/ has {top} top-level entries; the launcher holds {grammar.LIMITS['top']}"
        raise BuildError(msg)


def data_prefixes(ex: str) -> list[str]:
    """Return the manifest's data directories."""
    return [d[0].decode("utf-8", "surrogateescape") for d in grammar.values(manifest(ex), "data")]


def default_launcher() -> str:
    """Return the launcher to install, this machine's.

    That is build/launcher in a checkout, or the launcher beside this file in the tool's own
    exclave (10.5): an exclave is wrapped on a machine of its architecture (10.1).
    """
    for p in (os.path.join(HERE, "..", "build", "launcher"), os.path.join(HERE, "launcher")):
        if os.path.isfile(p):
            return p
    return os.path.join(HERE, "..", "build", "launcher")


def write_readme(ex: str) -> None:
    """Write EXCLAVE/README (6.1), unless the exclave has a file or link by that name already."""
    p = os.path.join(ex, "README")
    if not os.path.lexists(p):
        with open(p, "wb") as f:
            f.write(README_TEXT)


def install_launcher(ex: str) -> None:
    """Copy this machine's launcher to EXCLAVE/.exclave/launcher, unless one is there already."""
    dst = layout.launcher_path(ex)
    if os.path.exists(dst):
        return
    launcher = default_launcher()
    if not os.path.isfile(launcher):
        msg = f"no launcher at {launcher} (run scripts/build)"
        raise BuildError(msg)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(launcher, dst)
    os.chmod(dst, 0o755)  # noqa: S103 -- the launcher runs as every program, for whoever runs it


# ---------------------------------------------------------------- commands
def wrapper_problems(ex: str, data: Sequence[str] = ()) -> list[str]:
    """Return the problems with the tree's wrappers and originals as it stands (6.1).

    These are a stale wrapper (one of another launcher), a wrapper without an original, an original
    without a wrapper (a stray under the reserved name), and an executable its user cannot run.
    Executables not yet wrapped are not problems here.
    """
    root = os.path.join(ex, "tree")
    launcher = layout.launcher_of(ex)
    problems = []
    for real, v, st in layout.walk_files(root):
        if not stat.S_ISREG(st.st_mode) or layout.under_any(v, data):
            continue
        w = layout.is_wrapper(real, launcher)
        if not w and layout.payload_path(real) != real:
            problems.append(f"stale wrapper (not this exclave's launcher): {v}; run exclave relink")
        elif st.st_mode & 0o111 and not w and not os.access(real, os.X_OK):
            problems.append(
                f"executable file its user cannot execute: {v} (mode {st.st_mode & 0o7777:o}); "
                "a wrapper would run as the launcher's mode"
            )
        if w and layout.payload_path(real) == real:
            problems.append("wrapper without original: " + v)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort(key=os.fsencode)
        filenames.sort(key=os.fsencode)
        if os.path.basename(dirpath) == ".real":
            problems.extend(
                f"original without wrapper: /{os.path.relpath(os.path.join(dirpath, n), root)} "
                "(.real is reserved for originals, 6.1)"
                for n in filenames
                if not os.path.lexists(os.path.join(os.path.dirname(dirpath), n))
            )
    return problems


def wrap_files(ex: str, data: Sequence[str] = (), *, quiet: bool = False) -> int:
    """Wrap every executable file in tree/ outside data directories, and return how many (6.1).

    Each original moves to `.real/` beside it, and a hard link to the launcher takes its place.

    Raises:
        BuildError: When an original is in `.real/` already, the mark of a stale wrapper.
    """
    root = os.path.join(ex, "tree")
    launcher = layout.launcher_of(ex)
    n = 0
    for real, v, st in list(layout.walk_files(root)):
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111 or layout.under_any(v, data):
            continue
        if layout.is_wrapper(real, launcher):
            continue
        d, name = os.path.split(real)
        rd = os.path.join(d, ".real")
        if os.path.lexists(os.path.join(rd, name)):
            msg = f"{v} has an original in .real/ already: a stale wrapper; run exclave relink"
            raise BuildError(msg)
        os.makedirs(rd, exist_ok=True)
        os.rename(real, os.path.join(rd, name))
        layout.link_or_copy(launcher.path, real)
        n += 1
    if not quiet:
        print(f"wrapped {n} executables")
    return n


def located_links(ex: str) -> list[str]:
    """Return the tree's symlinks whose text names the exclave's own location (6.1).

    Packages never make one; one added by hand would break when the exclave is moved or copied,
    which nothing in an exclave may prevent, so wrap and check refuse it, naming the fix.
    """
    root = os.path.join(ex, "tree")
    places = dict.fromkeys((os.path.abspath(ex), os.path.realpath(ex)))
    problems = []
    for real, v, st in layout.walk_files(root):
        if not stat.S_ISLNK(st.st_mode):
            continue
        text = os.readlink(real)
        place = next((p for p in places if layout.under(text, p)), None)
        if place is None:
            continue
        inside = os.path.relpath(text, os.path.join(place, "tree"))
        fix = f"; ln -sfn /{inside} {real}" if not inside.startswith("..") and inside != "." else ""
        problems.append(f"link naming the exclave's own location: {v} -> {text}{fix}")
    return problems


def cmd_wrap(ex: str, *, quiet: bool = False) -> int:
    """Wrap an exclave, and return 0, or 1 when it is refused (10.1).

    The launcher, the placeholders and a manifest are added where missing. Then the wrappers and
    the static check are checked, and any problem refuses the exclave before anything is wrapped.
    Otherwise every executable is wrapped and the hashes file gains the launcher, manifest and tree
    hashes.

    Raises:
        BuildError: When the exclave has no tree, or its manifest is not canonical.
    """
    root = os.path.join(ex, "tree")
    if not os.path.isdir(root):
        msg = f"refusing: {ex} has no tree/ directory"
        raise BuildError(msg)
    install_launcher(ex)
    build.placeholders(root, log=(lambda _: None) if quiet else print)
    mp = layout.manifest_path(ex)
    if not os.path.exists(mp):
        with open(mp, "wb") as f:
            f.write(b"exclave 1\n")
    with open(mp, "rb") as f:
        mdata = f.read()
    recs = grammar.parse(mdata, "exclave")
    if grammar.dump(recs, "exclave") != mdata:
        msg = f"refusing: {mp} is not canonical; run exclave format on it"
        raise BuildError(msg)
    check_limits(ex)
    data = data_prefixes(ex)
    problems = wrapper_problems(ex, data) + located_links(ex)
    for p in problems:
        print("error: " + p)
    rep = static_report(ex, quiet=quiet)
    if problems or rep.errors:
        print("refused: nothing was wrapped")
        return 1
    wrap_files(ex, data, quiet=quiet)
    write_readme(ex)
    manifest_hash = "b2:" + hashlib.blake2b(mdata, digest_size=32).hexdigest()
    build.write_hashes(ex, None, manifest_hash, tree=True)
    if not quiet:
        print(f"{ex} is wrapped")
    return 0


def cmd_unwrap(ex: str) -> None:
    """Unwrap an exclave, moving every original back over its wrapper (10.1).

    The hashes file keeps its inputs and loses the hashes of a wrapped exclave.

    Raises:
        BuildError: For an original without a wrapper, which is not this exclave's.
    """
    strays = [p for p in wrapper_problems(ex) if p.startswith("original without wrapper")]
    if strays:
        raise BuildError("; ".join(strays))
    build.unwrap(ex)
    build.write_hashes(ex, None)


def cmd_relink(ex: str, launcher: str | None = None) -> None:
    """Replace an exclave's launcher and relink every wrapper to it (10.1).

    Wrappers are hard links to the launcher (6.1), so replacing the launcher's file alone would
    leave them running the old one. Each wrapper is replaced in one rename, so an interruption
    leaves no program missing. An original without a wrapper is reported and left alone. A wrapped
    exclave's hashes file records the new launcher and tree hashes.

    Raises:
        BuildError: When the launcher does not exist.
    """
    launcher = launcher or default_launcher()
    if not os.path.isfile(launcher):
        msg = f"no launcher at {launcher}"
        raise BuildError(msg)
    root = os.path.join(ex, "tree")
    new = layout.launcher_path(ex) + ".new"
    shutil.copy2(launcher, new)
    os.chmod(new, 0o755)  # noqa: S103 -- the launcher runs as every program, for whoever runs it
    n, strays = 0, []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort(key=os.fsencode)
        if os.path.basename(dirpath) != ".real":
            continue
        parent = os.path.dirname(dirpath)
        for name in sorted(filenames, key=os.fsencode):
            w = os.path.join(parent, name)
            if not os.path.lexists(w):
                strays.append("/" + os.path.relpath(os.path.join(dirpath, name), root))
                continue
            tmp = os.path.join(parent, f".{name}.exclave-relink")
            layout.link_or_copy(new, tmp)
            os.replace(tmp, w)
            n += 1
    os.replace(new, layout.launcher_path(ex))
    write_readme(ex)
    for s in strays:
        print("original without wrapper, left alone: " + s)
    hashes = layout.hashes_path(ex)
    if os.path.exists(hashes) and grammar.values(grammar.load(hashes, "hashes"), "tree"):
        build.write_hashes(ex, None, keep_hashes=True)
    print(f"relinked {n} wrappers to the new launcher")


def static_report(ex: str, *, quiet: bool = False) -> elfcheck.Report:
    """Run the static check (10.3), print its findings unless quiet, and return them."""
    rep = elfcheck.static_check(ex, owned(ex), data_prefixes(ex))
    if not quiet:
        for w in rep.warnings:
            print("warning: " + w)
        for e in rep.errors:
            print("error: " + e)
        print(
            f"static check: {len(rep.seen)} ELF files, {len(rep.static)} static executables, "
            f"{len(rep.warnings)} warnings, {len(rep.errors)} errors"
        )
    return rep


def cmd_check(ex: str, logs: Sequence[str] = ()) -> int:
    """Check a wrapped exclave, print what is wrong, and return 0, or 1 on any error (10.1).

    Every executable outside data directories must be wrapped by this exclave's launcher, with no
    stray original, and the tree must match its recorded hash. Then the static check runs, and,
    given EXCLAVE_LOG files, the dynamic check.
    """
    root = os.path.join(ex, "tree")
    data = data_prefixes(ex)
    launcher = layout.launcher_of(ex)
    problems = wrapper_problems(ex, data) + located_links(ex)
    for real, v, st in layout.walk_files(root):
        if (
            stat.S_ISREG(st.st_mode)
            and st.st_mode & 0o111
            and not layout.under_any(v, data)
            and not layout.is_wrapper(real, launcher)
            and layout.payload_path(real) == real
        ):
            problems.append("executable not wrapped: " + v)
    hashes = layout.hashes_path(ex)
    if os.path.exists(hashes):
        recorded = grammar.values(grammar.load(hashes, "hashes"), "tree")
        if recorded:
            actual = build.tree_hash(root)
            if recorded[0][0].decode() != actual:
                problems.append(
                    "the tree differs from the hashes file: "
                    f"recorded {recorded[0][0].decode()}, now {actual}"
                )
        else:
            problems.append(
                "an unwrapped exclave: the hashes file has no tree hash; run exclave wrap"
            )
    elif any(layout.is_wrapper(real, launcher) for real, _, _ in layout.walk_files(root)):
        # the third state: wrapped, never finished
        problems.append("wrappers but no hashes file: wrap never finished; run exclave wrap")
    for p in problems:
        print(p)
    print(f"{len(problems)} wrapper problems")
    rep = static_report(ex)
    rc = 1 if problems or rep.errors else 0
    if logs:
        drep = elfcheck.dynamic_check(ex, logs, owned(ex))
        for w in drep.warnings:
            print("warning: " + w)
        for e in drep.errors:
            print("error: " + e)
        print(f"dynamic check: {drep.lines} log lines, {len(drep.errors)} errors")
        rc = rc or (1 if drep.errors else 0)
    return rc


def cmd_prune(ex: str, logs: Sequence[str]) -> int:
    """Prune the exclave to what the logged workloads touched (10.4), then run the static check.

    Returns:
        0, or 1 when the static check finds an error in what is left.
    """
    pruned = build.prune(ex, logs, owned(ex))
    print(
        f"pruned {ex}: kept {pruned.kept} files, removed {pruned.removed}, "
        f"{pruned.freed} bytes freed"
    )
    hashes = layout.hashes_path(ex)
    if os.path.exists(hashes) and grammar.values(grammar.load(hashes, "hashes"), "tree"):
        build.write_hashes(ex, None, keep_hashes=True)
    rep = static_report(ex)
    return 1 if rep.errors else 0


def cmd_format(paths: Iterable[str], *, check: bool) -> int:
    """Rewrite each manifest or hashes file in canonical form, or with check only report (6.5).

    Returns:
        0, or 1 when a file is refused by the grammar or, with check, is not canonical.
    """
    rc = 0
    for p in paths:
        with open(p, "rb") as f:
            data = f.read()
        first = next(
            (line for line in data.split(b"\n") if line and not line.startswith(b"#")), b""
        )
        # which file it is, by its first record rather than its name
        kind = "hashes" if first.startswith(b"hashes ") else "exclave"
        try:
            recs = grammar.parse(data, kind)
        except GrammarError as e:
            print(f"{p}: {e}")
            rc = 1
            continue
        canon = grammar.dump(recs, kind)
        if canon != data:
            if check:
                print(f"{p}: not canonical")
                rc = 1
            else:
                with open(p, "wb") as f:
                    f.write(canon)
                print(f"{p}: rewritten")
    return rc


def require_exclave(ex: str, cmd: str) -> None:
    """Refuse, before reading or writing anything, a directory the command cannot act on.

    A can, an exclave in the layout from before the project's rename, is named as one, since its
    launcher's own refusal sends its user here (DESIGN.md 13 item 45).

    Raises:
        BuildError: With the one-line refusal.
    """
    has_exclave = os.path.isdir(os.path.join(ex, ".exclave"))
    if os.path.isdir(os.path.join(ex, ".can")) and not has_exclave:
        msg = (
            f"refusing: {ex} is a can, an exclave from before the rename, with .can/ and root/; "
            "convert it first (docs/DESIGN.md 13 item 45)"
        )
        raise BuildError(msg)
    if not os.path.isdir(os.path.join(ex, "tree")):
        msg = f"refusing: {ex} has no tree/ directory"
        raise BuildError(msg)
    if cmd != "wrap" and not has_exclave:
        msg = f"refusing: {ex} has no .exclave/ directory; wrap makes one"
        raise BuildError(msg)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exclave",
        description="Wrap a directory holding tree/ as an exclave, and check, prune or relink "
        "one. An exclave is a directory at every stage, and every command takes paths.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    def command(name: str, summary: str) -> argparse.ArgumentParser:
        return sub.add_parser(name, help=summary, description=summary)

    p = command("wrap", "check an exclave and wrap every executable in it")
    p.add_argument("exclave", metavar="EXCLAVE")
    p = command("unwrap", "move every original back over its wrapper")
    p.add_argument("exclave", metavar="EXCLAVE")
    p = command("check", "check a wrapped exclave, and with logs what a workload opened")
    p.add_argument("exclave", metavar="EXCLAVE")
    p.add_argument("logs", nargs="*", metavar="LOG", help="EXCLAVE_LOG files")
    p = command("prune", "remove every file no logged workload touched")
    p.add_argument("exclave", metavar="EXCLAVE")
    p.add_argument("logs", nargs="+", metavar="LOG", help="EXCLAVE_LOG files")
    p = command("format", "rewrite manifests and hashes files in canonical form")
    p.add_argument("files", nargs="+", metavar="FILE")
    p.add_argument("--check", action="store_true", help="report, rewriting nothing")
    p = command("hash", "print the tree hash")
    p.add_argument("exclave", metavar="EXCLAVE")
    p = command("relink", "replace the launcher and relink every wrapper to it")
    p.add_argument("exclave", metavar="EXCLAVE")
    p.add_argument("launcher", nargs="?", metavar="LAUNCHER")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the command line, and return its exit status."""
    # a path that is not UTF-8 is written as its bytes, on standard error as on standard output
    if isinstance(sys.stderr, io.TextIOWrapper):
        sys.stderr.reconfigure(errors="surrogateescape")
    args = _parser().parse_args(argv)
    try:
        if args.cmd != "format":
            require_exclave(args.exclave, args.cmd)
        match args.cmd:
            case "wrap":
                return cmd_wrap(args.exclave)
            case "unwrap":
                cmd_unwrap(args.exclave)
            case "check":
                return cmd_check(args.exclave, args.logs)
            case "prune":
                return cmd_prune(args.exclave, args.logs)
            case "format":
                return cmd_format(args.files, check=args.check)
            case "hash":
                print(build.tree_hash(os.path.join(args.exclave, "tree")))
            case "relink":
                cmd_relink(args.exclave, args.launcher)
    except GrammarError as e:
        sys.exit(f"grammar: {e}")
    except OSError as e:  # the file and the system's word for what went wrong
        sys.exit(f"exclave: {e.filename}: {e.strerror}" if e.filename else f"exclave: {e.strerror}")
    except BuildError as e:
        sys.exit(f"exclave: {e}")
    return 0
