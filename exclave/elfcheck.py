"""elfcheck.py — the static and dynamic checks (DESIGN.md 10.3).

Static: every ELF under tree/ outside data directories, originals in place of wrappers, must name
one interpreter between them (through the tree's symlinks), every DT_NEEDED must resolve under tree/
by the loader's own algorithm, every library reached must depend on that loader's libc and nothing
else. Anything that would resolve on the host, and anything that would mix libcs, is reported and
the exclave is refused. Static executables are reported.

Dynamic: given EXCLAVE_LOG files a workload wrote, every library opened must be on an exclave path,
and NSS modules named by the host's nsswitch.conf but absent from the exclave are reported.
"""

import contextlib
import os
import platform
import re
import stat
import struct
import subprocess
from typing import BinaryIO
lazy from collections.abc import Callable, Iterable, Sequence

lazy import build

PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_SONAME, DT_RPATH, DT_RUNPATH = 0, 1, 5, 10, 14, 15, 29
ET_DYN = 3
# the machines the launcher is built for (7.1): ELF e_machine, uname -m, Debian's multiarch triplet
MACHINES = {62: ("x86_64", "x86_64-linux-gnu"), 183: ("aarch64", "aarch64-linux-gnu")}
MACHINE = 62  # the exclave's, set from its launcher by static_check
DEFAULT_DIRS = [
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib64",
    "/usr/lib64",
    "/lib",
    "/usr/lib",
]  # Debian's and Fedora's glibc; the tree's loader is asked when it can answer
MUSL_DIRS = ["/lib", "/usr/local/lib", "/usr/lib"]
HWCAPS = ["glibc-hwcaps/x86-64-v4", "glibc-hwcaps/x86-64-v3", "glibc-hwcaps/x86-64-v2"]
LIBC_SONAME = {"glibc": "libc.so.6", "musl": "libc.musl-x86_64.so.1"}
# what the loader substitutes for $LIB and $PLATFORM; set by set_machine
LIB_DIR, PLATFORM = "lib/x86_64-linux-gnu", "x86_64"


def set_machine(machine: int) -> None:
    """Set the exclave's machine.

    The exclave's machine decides the multiarch directory, the hwcaps subdirectories and musl's
    soname.
    """
    global MACHINE, DEFAULT_DIRS, HWCAPS, LIBC_SONAME, LIB_DIR, PLATFORM  # noqa: PLW0603 -- read by every search below
    MACHINE = machine
    uname, triplet = MACHINES.get(machine, ("unknown", "unknown"))
    LIB_DIR, PLATFORM = "lib/" + triplet, uname
    DEFAULT_DIRS = [
        "/lib/" + triplet,
        "/usr/lib/" + triplet,
        "/lib64",
        "/usr/lib64",
        "/lib",
        "/usr/lib",
    ]
    HWCAPS = (
        ["glibc-hwcaps/x86-64-v4", "glibc-hwcaps/x86-64-v3", "glibc-hwcaps/x86-64-v2"]
        if machine == 62
        else []
    )
    LIBC_SONAME = {"glibc": "libc.so.6", "musl": f"libc.musl-{uname}.so.1"}


def glibc_version(tree: Tree) -> tuple[int, int] | None:
    """(major, minor) of the tree's glibc, from libc.so.6's banner, or None."""
    for d in [*DEFAULT_DIRS, "/lib64", "/usr/lib64"]:
        r = tree.resolve(d + "/libc.so.6")
        if r and os.path.isfile(tree.payload(r)):
            with open(tree.payload(r), "rb") as f:
                m = re.search(
                    rb"GNU C Library \([^)]*\) (?:\w+ )?release version (\d+)\.(\d+)", f.read()
                )
            if m:
                return int(m.group(1)), int(m.group(2))
    return None


def loader_dirs(tree: Tree, interp: str | None) -> list[str]:
    """The default search directories of the loader in the tree.

    glibc prints them with --list-diagnostics (2.33 and later); musl's are fixed; older loaders get
    Debian's list.
    """
    if interp is None:
        return list(DEFAULT_DIRS)
    if "musl" in os.path.basename(interp):
        return list(MUSL_DIRS)
    try:
        out = subprocess.run(
            [tree.payload(interp), "--list-diagnostics"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=20,
            check=False,
        ).stdout.decode(errors="replace")
        dirs = re.findall(r'^path\.system_dirs\[0x[0-9a-f]+\]="([^"]+)"', out, re.MULTILINE)
        if dirs:
            return [d.rstrip("/") for d in dirs]
    except OSError, subprocess.SubprocessError:
        pass
    return list(DEFAULT_DIRS)


class ForeignElfError(ValueError):
    """A well-formed ELF file of another class, byte order or machine.

    Not this exclave's to run, not checked.
    """


class Elf:
    """The parts of an ELF64 file the checks need."""

    path: str
    type: int
    machine: int
    loads: list[tuple[int, int, int]]
    interp: str | None
    debug_only: bool
    needed: list[str]
    rpath: str | None
    runpath: str | None
    soname: str | None

    def __init__(self, path: str) -> None:
        self.path = path
        with open(path, "rb") as f:
            h = f.read(64)
            if len(h) < 16 or h[:4] != b"\x7fELF":
                msg = "not ELF64 LE"
                raise ValueError(msg)
            if h[4] != 2 or h[5] != 1:
                msg = "ELF32 or big-endian: a foreign object, not checked (13)"
                raise ForeignElfError(msg)
            if len(h) < 64:
                msg = "truncated ELF header"
                raise ValueError(msg)
            try:
                self._parse(f, h)
            except struct.error as e:
                msg = f"truncated or malformed ELF: {e}"
                raise ValueError(msg) from e

    def _parse(self, f: BinaryIO, h: bytes) -> None:
        self.type = struct.unpack_from("<H", h, 16)[0]
        self.machine = struct.unpack_from("<H", h, 18)[0]
        phoff, phentsize, phnum = (
            struct.unpack_from("<Q", h, 32)[0],
            struct.unpack_from("<H", h, 54)[0],
            struct.unpack_from("<H", h, 56)[0],
        )
        f.seek(phoff)
        ph = f.read(phentsize * phnum)
        self.loads, self.interp, dyn = [], None, None
        self.debug_only = False
        for i in range(phnum):
            p_type, _, p_offset, p_vaddr, _, p_filesz, _p_memsz, _ = struct.unpack_from(
                "<IIQQQQQQ", ph, i * phentsize
            )
            if p_type == PT_LOAD:
                self.loads.append((p_vaddr, p_offset, p_filesz))
            elif p_type == PT_INTERP and p_filesz < 2:
                # a separate debug file (objcopy --only-keep-debug, /usr/lib/debug) keeps a
                # program's headers but not the bytes they map; its PT_INTERP is empty in the file,
                # which the kernel refuses (ENOEXEC), so it is no program
                self.debug_only = True
            elif p_type == PT_INTERP:
                f.seek(p_offset)
                self.interp = f.read(p_filesz).rstrip(b"\0").decode("utf-8", "surrogateescape")
            elif p_type == PT_DYNAMIC:
                dyn = (p_offset, p_filesz)
        self.needed, self.rpath, self.runpath, self.soname = [], None, None, None
        if dyn:
            f.seek(dyn[0])
            d = f.read(dyn[1])
            tags: list[tuple[int, int]] = []
            for i in range(0, len(d) - 15, 16):
                tag, val = struct.unpack_from("<qQ", d, i)
                if tag == DT_NULL:
                    break
                tags.append((tag, val))
            strtab = dict(tags).get(DT_STRTAB)
            strsz = dict(tags).get(DT_STRSZ, 1 << 20)
            if strtab is not None:
                off = self._v2o(strtab)
                f.seek(off)
                table = f.read(strsz)
                for tag, val in tags:
                    if tag in (DT_NEEDED, DT_RPATH, DT_RUNPATH, DT_SONAME):
                        end = table.find(b"\0", val)
                        sval = table[val : end if end >= 0 else None].decode(
                            "utf-8", "surrogateescape"
                        )
                        if tag == DT_NEEDED:
                            self.needed.append(sval)
                        elif tag == DT_RPATH:
                            self.rpath = sval
                        elif tag == DT_RUNPATH:
                            self.runpath = sval
                        else:
                            self.soname = sval

    def _v2o(self, vaddr: int) -> int:
        for va, off, sz in self.loads:
            if va <= vaddr < va + sz:
                return off + vaddr - va
        msg = "address not in a loaded segment"
        raise ValueError(msg)


class Tree:
    """Virtual-path resolution inside tree/, wrappers redirected to originals."""

    def __init__(self, root: str) -> None:
        self.root = root

    def real(self, vpath: str) -> str:
        return os.path.join(self.root, vpath.lstrip("/"))

    def resolve(self, vpath: str, *, follow_last: bool = True) -> str | None:
        """Canonical virtual path with symlinks resolved as a chroot would.

        None if a component is missing.
        """
        cur, rest, hops = "", [p for p in vpath.split("/") if p], 0
        while rest:
            comp = rest.pop(0)
            if comp == ".":
                continue
            if comp == "..":
                cur = cur.rsplit("/", 1)[0] if "/" in cur else ""
                continue
            cand = cur + "/" + comp
            real = self.real(cand)
            if not os.path.lexists(real):
                return None
            if os.path.islink(real) and (rest or follow_last):
                hops += 1
                if hops > 40:
                    return None
                t = os.readlink(real)
                rest = [p for p in t.split("/") if p] + rest
                if t.startswith("/"):
                    cur = ""
                continue
            cur = cand
        return cur or "/"

    def payload(self, vpath: str) -> str:
        real = self.real(vpath)
        d, n = os.path.split(real)
        p = os.path.join(d, ".real", n)
        return p if os.path.exists(p) else real


class Report:
    lines = 0

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.static: list[str] = []
        self.seen: dict[tuple[str, tuple[str, ...]], bool] = {}

    def ok(self) -> bool:
        return not self.errors


def _expand(s: str, origin: str) -> str:
    """The loader's substitutions in an RPATH, a RUNPATH or a DT_NEEDED that is a path.

    For the exclave's machine (glibc's dl-load.c).
    """
    return (
        s.replace("$ORIGIN", origin)
        .replace("${ORIGIN}", origin)
        .replace("$LIB", LIB_DIR)
        .replace("${LIB}", LIB_DIR)
        .replace("$PLATFORM", PLATFORM)
        .replace("${PLATFORM}", PLATFORM)
    )


def read_cache(tree: Tree) -> dict[str, list[str]] | None:
    """/etc/ld.so.cache in the glibc-ld.so.cache1.1 format: {soname: [paths in file order]}.

    None if absent.
    """
    real = tree.real("/etc/ld.so.cache")
    if not os.path.isfile(real):
        return None
    with open(real, "rb") as f:
        data = f.read()
    off = data.find(b"glibc-ld.so.cache1.1")
    if off < 0:
        return {}
    nlibs, _len_strings = struct.unpack_from("<II", data, off + 20)
    entries = off + 48
    table: dict[str, list[str]] = {}
    # offsets are from the header; fall back to the string table
    for base in (off, entries + 24 * nlibs):
        table = {}
        ok = True
        for i in range(nlibs):
            _flags, key, value = struct.unpack_from("<iII", data, entries + 24 * i)
            hwcap = struct.unpack_from("<Q", data, entries + 24 * i + 16)[0]
            try:
                k = data[base + key : data.index(b"\0", base + key)].decode()
                v = data[base + value : data.index(b"\0", base + value)].decode()
            except ValueError, UnicodeDecodeError:
                ok = False
                break
            if not v.startswith("/"):
                ok = False
                break
            if hwcap == 0:
                table.setdefault(k, []).append(v)
        if ok:
            break
    return table


VOLATILE = ("/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run")  # noqa: S108 -- prefixes, not files


class Owned(list[str]):
    """8.1's ownership as the launcher computes it.

    The own prefixes, the list itself, and the manifest's host records, .host, which take a path
    back from an own prefix no longer than theirs.
    """

    def __init__(self, own: Iterable[str] = (), host: Iterable[str] = ()) -> None:
        list.__init__(self, own)
        self.host = list(host)


def _under(v: str, p: str) -> bool:
    return v == p or v.startswith(p.rstrip("/") + "/")


def host_owned(vdir: str, own: Sequence[str]) -> bool:
    """The launcher's base rule for a path (8.1, vis.c base_is_host).

    Volatile, or its longest host record at least as long as its longest own prefix, which a path
    under neither is.
    """
    if any(_under(vdir, v) for v in VOLATILE):
        return True

    def longest(prefixes: Iterable[str]) -> int:
        return max((len(p) for p in prefixes if _under(vdir, p)), default=-1)

    return longest(getattr(own, "host", ())) >= longest(own)


def find_library(
    tree: Tree,
    name: str,
    elf: Elf,
    vpath: str,
    rpaths: list[str],
    *,
    cache: dict[str, list[str]] | None,
    own: Sequence[str] = (),
    host_hits: list[str] | None = None,
    default_dirs: list[str] | None = None,
    interp: str | None = None,
) -> str | None:
    """The virtual path ld.so would load for DT_NEEDED name from the object at vpath, or None.

    rpaths: the DT_RPATH of every object on the chain that led here (inherited when the object has
    no RUNPATH). A search directory the exclave does not own is the host's at run time: such a
    directory is recorded in host_hits, since the loader would take the host's library from it,
    default directories included. The loader satisfies its own soname without a search.
    """
    if interp and name == os.path.basename(interp) and tree.resolve(interp):
        return tree.resolve(interp)
    # a path, loaded as named: glibc expands $ORIGIN and the other tokens in it first (dl-load.c),
    # musl does not
    if "/" in name:
        if interp and "musl" not in os.path.basename(interp):
            name = os.path.normpath(_expand(name, os.path.dirname(vpath)))
        return tree.resolve(name) if name.startswith("/") else None
    origin = os.path.dirname(vpath)
    search: list[str] = []
    if not elf.runpath:
        for r in ([elf.rpath] if elf.rpath else []) + rpaths:
            search += [_expand(p, origin) for p in r.split(":") if p]
    if elf.runpath:
        search += [_expand(p, origin) for p in elf.runpath.split(":") if p]
    for d in search:
        if own and host_owned(os.path.normpath(d), own) and host_hits is not None:
            host_hits.append(d)
        for sub in [*HWCAPS, ""]:
            cand = tree.resolve(os.path.join(d, sub, name) if sub else os.path.join(d, name))
            if cand and os.path.isfile(tree.payload(cand)):
                return cand
    for p in (cache or {}).get(name, []):
        cand = tree.resolve(p)
        if cand and os.path.isfile(tree.payload(cand)):
            return cand
    for d in default_dirs or DEFAULT_DIRS:
        if own and host_owned(os.path.normpath(d), own) and host_hits is not None:
            host_hits.append(d)
        for sub in [*HWCAPS, ""]:
            cand = tree.resolve(os.path.join(d, sub, name) if sub else os.path.join(d, name))
            if cand and os.path.isfile(tree.payload(cand)):
                return cand
    return None


def _has_musl_loader(tree: Tree) -> bool:
    """Whether the tree has musl's loader for the exclave's machine (set_machine).

    That loader reads no ld.so.cache.
    """
    r = tree.resolve(f"/lib/ld-musl-{PLATFORM}.so.1")
    return bool(r and os.path.isfile(tree.payload(r)))


def static_check(
    ex: str,
    own: Sequence[str],
    data_prefixes: Sequence[str] = (),
    _log: Callable[..., object] = print,
) -> Report:
    """Returns a Report. own: the ownership set of 8.1 as the launcher computes it."""
    tree, rep = Tree(os.path.join(ex, "tree")), Report()
    native = {v[0]: k for k, v in MACHINES.items()}.get(platform.machine())
    try:
        # the exclave's machine is its launcher's
        set_machine(Elf(os.path.join(ex, ".exclave", "launcher")).machine)
    except ValueError, OSError:
        set_machine(native or 62)  # no launcher yet: the machine the check runs on
    # 10.1: an exclave is wrapped on a machine of its architecture, where its loader can be asked
    if native != MACHINE:
        rep.errors.append(
            "the exclave's launcher is for {} and this machine is {}: wrap the exclave on a "
            "machine of its architecture (10.1)".format(
                MACHINES.get(MACHINE, ("?",))[0], platform.machine()
            )
        )
        return rep
    cache = read_cache(tree)
    if host_owned("/etc", own):  # the loader would read the host's cache and preload list
        rep.errors.append(
            "/etc is the host's: the loader would read the host's /etc/ld.so.cache and "
            "/etc/ld.so.preload; the tree must own /etc"
        )
    elif cache is None:
        # musl has no cache; glibc without one searches its defaults only
        if not _has_musl_loader(tree):
            rep.warnings.append(
                "no /etc/ld.so.cache: only the loader's default directories are searched at run "
                "time"
            )
    else:
        for soname, paths in cache.items():  # no cache entry may name the launcher (10.3)
            for p in paths:
                r = tree.resolve(p)
                if r and os.path.isfile(tree.payload(r)):
                    try:
                        e = Elf(tree.payload(r))
                    except ValueError, OSError:
                        continue
                    if e.soname is None and e.type == ET_DYN and not e.needed:
                        rep.errors.append(
                            f"ld.so.cache entry {soname} names {p}, which is not a shared library "
                            "(the launcher?)"
                        )
    seen = rep.seen
    executables: list[tuple[str, Elf]] = []
    libraries: list[tuple[str, Elf]] = []
    interps: dict[str, tuple[str, str]] = {}
    for dirpath, dirnames, filenames in os.walk(tree.root):
        rel = "/" + os.path.relpath(dirpath, tree.root).replace(os.sep, "/")
        rel = "" if rel == "/." else rel
        if any(rel == p or rel.startswith(p + "/") for p in data_prefixes):
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d != ".real"]
        for name in filenames:
            vpath = rel + "/" + name
            real = os.path.join(dirpath, name)
            st = os.lstat(real)
            if stat.S_ISLNK(st.st_mode):
                if tree.resolve(vpath) is None:
                    rep.warnings.append(f"dangling symlink {vpath} -> {os.readlink(real)}")
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            pay = tree.payload(vpath)
            try:
                with open(pay, "rb") as f:
                    head = f.read(4)
            except PermissionError:
                rep.errors.append(
                    f"unreadable file {vpath}: chmod u+r it; no copy of the exclave can carry it "
                    "and the tree hash needs it (10.3)"
                )
                continue
            if head != b"\x7fELF":
                continue
            try:
                e = Elf(pay)
            except ForeignElfError as exc:
                # Fedora's gcc ships 32-bit crt objects beside the 64-bit ones
                rep.warnings.append(f"{vpath}: {exc}")
                continue
            except ValueError as exc:
                rep.errors.append(f"{vpath}: {exc}")
                continue
            if e.machine != MACHINE:
                rep.warnings.append(
                    "{}: not {}: a foreign object, not checked (13)".format(
                        vpath, MACHINES.get(MACHINE, ("?",))[0]
                    )
                )
                continue
            if e.debug_only:  # debug information, which nothing loads or runs
                continue
            if e.interp is None and e.type != ET_DYN:
                rep.static.append(vpath)
            elif e.interp is not None:
                r = tree.resolve(e.interp)
                if r is None:
                    rep.errors.append(
                        f"{vpath} wants interpreter {e.interp}, which does not resolve in the tree"
                    )
                elif any(r == p or r.startswith(p.rstrip("/") + "/") for p in data_prefixes):
                    rep.errors.append(
                        f"{vpath} wants interpreter {e.interp}, which resolves into the data "
                        f"directory {r}: never executed or loaded (6.2)"
                    )
                elif own and host_owned(r, own):
                    rep.errors.append(
                        f"{vpath} wants interpreter {e.interp}, which resolves to {r}, a path the "
                        "exclave does not own: the launcher refuses a host loader (7.4.5)"
                    )
                else:
                    interps.setdefault(r, (e.interp, vpath))
            (executables if e.interp is not None or e.type != ET_DYN else libraries).append(
                (vpath, e)
            )
    # one loader, and so one libc, per exclave (7.3): read from the ELF files, not declared anywhere
    if len(interps) > 1:
        rep.errors.append(
            "the tree mixes loaders {} (one world inside an exclave, 7.3)".format(
                ", ".join(f"{i} ({v})" for r, (i, v) in sorted(interps.items()))
            )
        )
    interp = next(iter(interps.values()))[0] if interps else None
    libc_soname = (
        LIBC_SONAME["musl"]
        if interp and "musl" in os.path.basename(interp)
        else LIBC_SONAME["glibc"]
    )
    default_dirs = loader_dirs(tree, interp)
    # 6.2: the locale inside an exclave is C.UTF-8, built into glibc 2.35 and later and into musl;
    # an older glibc needs the C.utf8 directory or every program runs in the plain C locale, and
    # bash and perl say so
    if interp and "musl" not in os.path.basename(interp):
        ver = glibc_version(tree)
        if (
            ver
            and ver < (2, 35)
            and not any(
                os.path.isdir(tree.real(d))
                for d in ("/usr/lib/locale/C.utf8", "/usr/lib/locale/C.UTF-8")
            )
        ):
            rep.warnings.append(
                f"glibc {ver[0]}.{ver[1]} predates the built-in C.UTF-8 locale and the tree has no "
                "/usr/lib/locale/C.utf8: programs will run in the plain C locale"
            )

    reached: set[str] = set()

    def check(vpath: str, e: Elf, rpaths: list[str], chain: list[str]) -> None:
        key = (vpath, tuple(rpaths))
        if key in seen:
            return
        seen[key] = True
        if chain:
            reached.add(vpath)
        below = rpaths if e.runpath else ([e.rpath] if e.rpath else []) + rpaths
        for n in e.needed:
            host_hits: list[str] = []
            found = find_library(
                tree,
                n,
                e,
                vpath,
                rpaths,
                cache=cache,
                own=own,
                host_hits=host_hits,
                default_dirs=default_dirs,
                interp=interp,
            )
            for d in host_hits:
                rep.errors.append(
                    f"{vpath} searches {d} for {n}, a directory the exclave does not own: the "
                    "host's library would load"
                )
            if not found:
                rep.errors.append(
                    "{} needs {}, which does not resolve in the tree (chain {})".format(
                        vpath, n, " > ".join([*chain, vpath])
                    )
                )
                continue
            if any(found == p or found.startswith(p.rstrip("/") + "/") for p in data_prefixes):
                rep.errors.append(
                    f"{vpath} needs {n}, which resolves into the data directory {found}: never "
                    "loaded (6.2)"
                )
                continue
            if n.startswith("libc.") and n != libc_soname:
                rep.errors.append(
                    f"{vpath} needs {n}: a libc other than the loader's {libc_soname}"
                )
            try:
                fe = Elf(tree.payload(found))
            except (ValueError, OSError) as exc:
                rep.errors.append(f"{found}: {exc}")
                continue
            check(found, fe, below, [*chain, vpath])

    for vpath, e in executables:  # executables first, so that RPATH inheritance is seen
        check(vpath, e, [], [])
    for vpath, e in libraries:  # a library nothing reaches is a dlopen candidate: checked alone
        if vpath not in reached:
            check(vpath, e, [], [])
    return rep


def needed_closure(tree: Tree, vpaths: Sequence[str], own: Sequence[str]) -> set[str]:
    """The virtual paths of every library the given ELF files reach through DT_NEEDED.

    By the loader's search with RPATH inherited down the chain; for pruning (10.4).
    """
    out: set[str] = set()
    seen: set[tuple[str, tuple[str, ...]]] = set()
    cache = read_cache(tree)
    interp: str | None = None
    for v in vpaths:
        with contextlib.suppress(ValueError, OSError):
            interp = interp or Elf(tree.payload(v)).interp
    default_dirs = loader_dirs(tree, interp)

    def visit(vpath: str, e: Elf, rpaths: list[str]) -> None:
        key = (vpath, tuple(rpaths))
        if key in seen:
            return
        seen.add(key)
        if e.interp:
            # the loader is loaded by the launcher, never through a logged syscall
            out.add(e.interp)
        below = rpaths if e.runpath else ([e.rpath] if e.rpath else []) + rpaths
        for n in e.needed:
            found = find_library(
                tree,
                n,
                e,
                vpath,
                rpaths,
                cache=cache,
                own=own,
                host_hits=None,
                default_dirs=default_dirs,
                interp=interp,
            )
            if not found:
                continue
            out.add(found)
            try:
                fe = Elf(tree.payload(found))
            except ValueError, OSError:
                continue
            visit(found, fe, below)

    for v in vpaths:
        try:
            visit(v, Elf(tree.payload(v)), [])
        except ValueError, OSError:
            continue
    return out


def dynamic_check(
    ex: str,
    logs: Iterable[str],
    own: Sequence[str],
    log: Callable[..., object] = print,  # noqa: ARG001 -- the suite passes it by name
) -> Report:
    """Read EXCLAVE_LOG files.

    Report libraries opened outside the exclave and NSS modules the host names that the exclave
    lacks.
    """
    rep = Report()
    libs: set[str] = set()
    cwds: set[str] = set()
    for what, r, path in build.log_lines(logs):
        rep.lines += 1
        # 8.1 rule 4 as the launcher applied it; the plain "cwd" line is a diagnostic and gives
        # nothing
        if what == "launcher" and path.startswith("cwd given to the host "):
            c = path[len("cwd given to the host ") :]
            if c != "/":
                cwds.add(c)
        if what == "launcher" and path.startswith("cwd ") and not path.startswith("cwd given"):
            c = path[len("cwd ") :]
            # a working directory under a volatile prefix is the host's by 8.1 rule 3, with nothing
            # to give: the build's own directory all the same; never /
            if any(c == v or c.startswith(v + "/") for v in VOLATILE):
                cwds.add(c)
        if what == "open" and r >= 0 and re.search(r"\.so(\.\d+)*$", path):
            libs.add(path)
    for lib in sorted(libs):
        # the workload's own build directory: the host's by 8.1 rule 4, whatever prefix it lies
        # under
        if any(lib.startswith(c.rstrip("/") + "/") for c in cwds):
            rep.warnings.append(
                "library opened under the workload's working directory, its own output presumably: "
                + lib
            )
        elif not host_owned(lib, own):
            continue
        else:
            rep.errors.append("library opened on the host: " + lib)
    tree = Tree(os.path.join(ex, "tree"))
    if os.path.exists("/etc/nsswitch.conf"):
        mods: set[str] = set()
        with open("/etc/nsswitch.conf", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.split("#", 1)[0]
                if ":" in line:
                    # a module name, mdns4_minimal included; not [NOTFOUND=return]
                    for w in line.split(":", 1)[1].split():
                        if re.fullmatch(r"[A-Za-z0-9_]+", w) and w not in ("files", "dns"):
                            mods.add(w)
        for m in sorted(mods):
            if not any(tree.resolve(os.path.join(d, f"libnss_{m}.so.2")) for d in DEFAULT_DIRS):
                rep.warnings.append(
                    f"this host's nsswitch.conf names {m}; the exclave has no libnss_{m}.so.2"
                )
    return rep
