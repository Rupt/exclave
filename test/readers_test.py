"""The command's readers on hostile files (DESIGN.md 10.3, 17).

    test/readers_test.py [--tool PATH] [--work DIR] [-k NAME|SUBSTRING]

The ELF reader, the ld.so.cache reader and the log reader take the files of a tree and the
EXCLAVE_LOG files given, so each case is a small tree made here by hand, its ELF files and cache
written byte by byte, and `exclave check` run on it with build/exclave. The answer must be the
reader's own, by its message, with a check's status, 0 or 1; a Go panic would exit 2 with its
trace. Each tree beside the case holds a loader the
program names and the library it needs, so that a reader that answered nothing would leave a
message missing. Prints one line per test; the exit status is the number of failures.
"""

import argparse
import dataclasses
import os
import platform
import shutil
import struct
import sys
from typing import TYPE_CHECKING, Any

from harness import TESTS, expect, run, run_tests, select, test

if TYPE_CHECKING:
    from harness import Test

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
LAUNCHER = os.path.join(REPO, "build", "launcher")
EM = {"x86_64": 62, "aarch64": 183}[platform.machine()]  # the launcher's machine, the tree's
PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_SONAME = 0, 1, 5, 10, 14


@dataclasses.dataclass(frozen=True)
class Ctx:
    """A test's own work directory and the command under test."""

    work: str
    tool: str


def elf(
    *,
    interp: bytes | None = None,
    needed: tuple[str, ...] = (),
    soname: str | None = None,
    phoff: int = 64,
    phentsize: int = 56,
    phnum: int | None = None,
    strtab_at: int | None = None,
    strsz: int | None = None,
    needed_at: int | None = None,
    interp_cut: bool = False,
) -> bytes:
    """A 64-bit little-endian ET_DYN for the tree's machine, as the arguments break it.

    One PT_LOAD maps the whole file from address 0, then PT_INTERP and PT_DYNAMIC. strtab_at and
    strsz override DT_STRTAB and DT_STRSZ, needed_at every DT_NEEDED's offset; interp_cut puts
    the interpreter last in the file without its NUL, its PT_INTERP running past the end.
    """
    strtab, offsets = b"\0", []
    for n in needed:
        offsets.append(len(strtab))
        strtab += n.encode() + b"\0"
    so_at = len(strtab)
    strtab += (soname or "").encode() + b"\0"
    nph = 2 + (interp is not None)
    start = 64 + 56 * nph
    str_off = start
    body = strtab + b"\0" * (-len(strtab) % 8)
    dyn_off = start + len(body)
    tags = [(DT_NEEDED, o if needed_at is None else needed_at) for o in offsets]
    tags += [(DT_SONAME, so_at)] if soname else []
    tags += [(DT_STRTAB, str_off if strtab_at is None else strtab_at)]
    tags += [(DT_STRSZ, len(strtab) if strsz is None else strsz), (DT_NULL, 0)]
    dyn = b"".join(struct.pack("<qQ", t, v) for t, v in tags)
    body += dyn
    interp_off = start + len(body)
    if interp is not None:
        body += interp if interp_cut else interp + b"\0"
    size = start + len(body)
    ph = struct.pack("<IIQQQQQQ", PT_LOAD, 5, 0, 0, 0, size, size, 0x1000)
    if interp is not None:
        n = len(interp) + (16 if interp_cut else 1)
        ph += struct.pack("<IIQQQQQQ", PT_INTERP, 4, interp_off, interp_off, 0, n, n, 1)
    ph += struct.pack("<IIQQQQQQ", PT_DYNAMIC, 6, dyn_off, dyn_off, 0, len(dyn), len(dyn), 8)
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    head = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        3,
        EM,
        1,
        0,
        phoff,
        0,
        0,
        64,
        phentsize,
        nph if phnum is None else phnum,
        64,
        0,
        0,
    )
    return head + ph + body


def cache(entries: list[tuple[str, str]], *, nlibs: int | None = None, past: bool = False) -> bytes:
    """An ld.so.cache in glibc's glibc-ld.so.cache1.1 format, offsets from its header.

    nlibs overrides the count of entries; past moves every key's offset a megabyte past the end.
    """
    first = 48 + 24 * len(entries)
    strings, rows = b"", b""
    for key, value in entries:
        k = first + len(strings)
        strings += key.encode() + b"\0"
        v = first + len(strings)
        strings += value.encode() + b"\0"
        rows += struct.pack("<iIIIQ", 0x0303, k + (1 << 20 if past else 0), v, 0, 0)
    count = len(entries) if nlibs is None else nlibs
    head = b"glibc-ld.so.cache1.1" + struct.pack("<II", count, len(strings)) + b"\0" * 20
    return head + rows + strings


def put(root: str, vpath: str, data: bytes) -> None:
    """Write data at vpath in the tree, mode 0644: a file the check reads, no executable to wrap."""
    p = os.path.join(root, vpath.lstrip("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)
    os.chmod(p, 0o644)


def exclave(ctx: Ctx, name: str) -> tuple[str, str]:
    """A hand-made exclave: its directory and its tree, which owns /etc, /lib and /opt.

    /lib/ld.so is a loader with no table of directories, and /opt/lib/libfoo.so.1 a library only
    the cache names.
    """
    ex = os.path.join(ctx.work, name)
    os.makedirs(os.path.join(ex, ".exclave"))
    shutil.copy(LAUNCHER, os.path.join(ex, ".exclave", "launcher"))
    with open(os.path.join(ex, ".exclave", "manifest"), "w") as f:
        f.write("exclave 1\n")
    root = os.path.join(ex, "tree")
    put(root, "/etc/ld.so.conf", b"")
    put(root, "/lib/ld.so", elf(soname="ld.so"))
    put(root, "/opt/lib/libfoo.so.1", elf(soname="libfoo.so.1"))
    return ex, root


def check(ctx: Ctx, ex: str, *logs: str) -> tuple[int, list[str], list[str]]:
    """Run the command's check; its status, error lines and warning lines, each without its prefix.

    A status but 0 or 1, or a panic's trace, fails the test.
    """
    rc, out, err = run([ctx.tool, "check", ex, *logs])
    expect(rc in (0, 1) and "panic" not in err, f"check exited {rc}: {err[-1500:]}")
    lines = out.splitlines()
    errors = [x.removeprefix("error: ") for x in lines if x.startswith("error: ")]
    warnings = [x.removeprefix("warning: ") for x in lines if x.startswith("warning: ")]
    return rc, errors, warnings


@test
def elf_headers(ctx: Ctx) -> None:
    """10.3: an ELF file whose headers lie is an error by name.

    A header cut short; program headers placed past the end of the file, or of size 0, so that
    they run past it; a DT_STRTAB outside every PT_LOAD.
    """
    past = "its program headers run past the end of the file"
    for name, data, why in (
        ("short", elf()[:40], "truncated ELF header"),
        ("phoff", elf(phoff=4096)[:64], past),
        ("phentsize", elf(phentsize=0, phnum=1), past),
        (
            "strtab",
            elf(strtab_at=1 << 20, needed=("libfoo.so.1",)),
            "address not in a loaded segment",
        ),
    ):
        ex, root = exclave(ctx, name)
        put(root, "/usr/bin/x", data)
        rc, errors, _ = check(ctx, ex)
        expect(
            rc == 1 and any(e.startswith("/usr/bin/x: ") and e.endswith(why) for e in errors),
            f"{name}: {errors!r}",
        )


@test
def elf_strings(ctx: Ctx) -> None:
    """10.3: a DT_NEEDED past DT_STRSZ, and a PT_INTERP that runs past the end without its NUL.

    The string table is read to DT_STRSZ and no further, so the name is empty and resolves
    nowhere, an error for a program; the interpreter is the bytes up to the end of the file, which
    name the tree's loader.
    """
    ex, root = exclave(ctx, "needed")
    prog = elf(interp=b"/lib/ld.so", needed=("libfoo.so.1",), strsz=4, needed_at=100)
    put(root, "/usr/bin/x", prog)
    rc, errors, _ = check(ctx, ex)
    expect(
        rc == 1 and any(e.startswith("/usr/bin/x needs , which does not resolve") for e in errors),
        f"a DT_NEEDED past DT_STRSZ: {errors!r}",
    )
    ex, root = exclave(ctx, "interp")
    put(root, "/usr/bin/x", elf(interp=b"/lib/ld.so", interp_cut=True))
    rc, errors, _ = check(ctx, ex)
    expect(rc == 0 and not errors, f"a PT_INTERP cut by the end of the file: {errors!r}")


@test
def cache_reader(ctx: Ctx) -> None:
    """10.3: the tree's ld.so.cache is read, and a cache that lies about itself has no entries.

    A program needs libfoo.so.1, which only the cache names: found through a well-formed cache,
    and through none with 0xffffffff entries or with its strings past the end of the file.
    """
    prog = elf(interp=b"/lib/ld.so", needed=("libfoo.so.1",))
    entries = [("libfoo.so.1", "/opt/lib/libfoo.so.1")]
    unfound = "/usr/bin/x needs libfoo.so.1, which no search finds"
    for name, data, found in (
        ("cache-good", cache(entries), True),
        ("cache-nlibs", cache(entries, nlibs=0xFFFFFFFF), False),
        ("cache-past", cache(entries, past=True), False),
    ):
        ex, root = exclave(ctx, name)
        put(root, "/usr/bin/x", prog)
        put(root, "/etc/ld.so.cache", data)
        _rc, errors, warnings = check(ctx, ex)
        said = any(w.startswith(unfound) for w in warnings)
        expect(said != found, f"{name}: libfoo.so.1 {'not ' if found else ''}found: {warnings!r}")
        if found:
            expect(not errors, f"{name}: {errors!r}")


@test
def log_reader(ctx: Ctx) -> None:
    """10.3, 6.2: the log's lines as the launcher writes them, and bytes it never writes.

    A NUL ends its line; a path's escapes are undone; a result past a long's range is still a
    number; a lone backslash ends the file with no final LF. Each library opened at a path the
    host owns is an error by its path.
    """
    ex, root = exclave(ctx, "logged")
    put(root, "/usr/bin/x", elf(interp=b"/lib/ld.so"))
    log = os.path.join(ctx.work, "log")
    with open(log, "wb") as f:
        f.write(
            b"launcher 1 cwd /\n"
            b"open 3 /srv/liba.so\0junk\n"
            b"open 3 /srv/libb\\\\c.so\n"
            b"open 99999999999999999999 /srv/libbig.so\n"
            b"open -2 /srv/libgone.so\n"
            b"open 3 /srv/libz.so\\"
        )
    rc, errors, _ = check(ctx, ex, log)
    opened = sorted(e.removeprefix("library opened on the host: ") for e in errors)
    want = ["/srv/liba.so", "/srv/libb\\c.so", "/srv/libbig.so"]
    expect(rc == 1 and opened == want, f"the log's libraries: {errors!r}")


@test
def log_version(ctx: Ctx) -> None:
    """6.2: a log whose launcher lines name a later format's version is refused by name.

    check reads it for the dynamic check and prune for what to keep; both refuse it rather than
    misread lines a later launcher may spell otherwise, and read formats 1 and 2 alike.
    """
    ex, root = exclave(ctx, "versioned")
    put(root, "/usr/bin/x", elf(interp=b"/lib/ld.so"))
    log = os.path.join(ctx.work, "log2")
    with open(log, "wb") as f:
        f.write(b"launcher 1 border /usr/bin/x\nlauncher 3 inside /usr/bin/x\nexec 0 /usr/bin/x\n")
    for cmd in ("check", "prune"):
        rc, out, err = run([ctx.tool, cmd, ex, log])
        expect(
            rc == 1
            and "a launcher of log format 3 wrote it; this command reads formats 1 to 2" in err,
            f"{cmd} of a format 3 log: rc={rc} {out[-200:]!r} {err[-300:]!r}",
        )


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--tool", default=os.path.join(REPO, "build", "exclave"))
    ap.add_argument("--work", default=os.path.join(REPO, "build", "readers-test"))
    ap.add_argument("-k", dest="select", default="")
    args = ap.parse_args()
    work = os.path.abspath(args.work)
    shutil.rmtree(work, ignore_errors=True)
    chosen = select(TESTS, args.select)

    def call(t: Test[Any]) -> str | None:
        d = os.path.join(work, t.__name__)
        os.makedirs(d)
        return t(Ctx(work=d, tool=args.tool))

    failed = run_tests(chosen, call, budget=30)
    print(f"{len(chosen)} tests, {len(failed)} failures")
    return min(len(failed), 255)


if __name__ == "__main__":
    sys.exit(main())
