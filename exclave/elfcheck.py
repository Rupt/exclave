"""The static and dynamic checks of an exclave's ELF files (DESIGN.md 10.3).

The static check reads every ELF file under tree/ outside data directories, taking originals in
place of wrappers. All of them must name one interpreter, resolved through the tree's symlinks;
every DT_NEEDED must resolve inside the tree by the loader's own search; and every library reached
must depend on that loader's libc and no other. A library that would load from the host, or a mix
of libcs, is an error that refuses the exclave. Static executables are listed.

The dynamic check reads the EXCLAVE_LOG files a workload wrote. Every library opened must lie on a
path the exclave owns, and NSS modules that this host's nsswitch.conf names but the exclave lacks
are reported.
"""

import contextlib
import os
import platform
import re
import stat
import struct
import subprocess
from dataclasses import dataclass, field
from typing import BinaryIO
lazy from collections.abc import Iterable, Sequence

from exclave import layout

PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_SONAME, DT_RPATH, DT_RUNPATH = 0, 1, 5, 10, 14, 15, 29
ET_DYN = 3
MUSL_DIRS = ["/lib", "/usr/local/lib", "/usr/lib"]
GLIBC_SONAME = "libc.so.6"


@dataclass(frozen=True, slots=True)
class Machine:
    """A machine the launcher is built for (7.1), and what its loaders search."""

    e_machine: int  # the ELF header's e_machine
    uname: str  # uname -m, which glibc's loader also substitutes for $PLATFORM
    triplet: str  # Debian's multiarch triplet
    hwcaps: tuple[str, ...]  # the glibc-hwcaps subdirectories searched first, best first

    @property
    def lib_dir(self) -> str:
        """What glibc's loader substitutes for $LIB."""
        return "lib/" + self.triplet

    @property
    def default_dirs(self) -> list[str]:
        """The default search directories of glibc on Debian and Fedora.

        Used where the tree's own loader cannot be asked for its list.
        """
        return [f"/lib/{self.triplet}", f"/usr/lib/{self.triplet}", *_LIB64_DIRS]

    @property
    def musl_soname(self) -> str:
        return f"libc.musl-{self.uname}.so.1"


_LIB64_DIRS = ["/lib64", "/usr/lib64", "/lib", "/usr/lib"]
X86_64 = Machine(
    62,
    "x86_64",
    "x86_64-linux-gnu",
    ("glibc-hwcaps/x86-64-v4", "glibc-hwcaps/x86-64-v3", "glibc-hwcaps/x86-64-v2"),
)
AARCH64 = Machine(183, "aarch64", "aarch64-linux-gnu", ())
MACHINES = {m.e_machine: m for m in (X86_64, AARCH64)}


def native_machine() -> Machine | None:
    """Return this machine, or None where no launcher is built for it."""
    return next((m for m in MACHINES.values() if m.uname == platform.machine()), None)


def launcher_machine(ex: str) -> int | None:
    """Return the e_machine of the exclave's launcher, or None without a readable one."""
    try:
        return Elf(layout.launcher_path(ex)).machine
    except ValueError, OSError:
        return None


def machine_for(ex: str) -> Machine:
    """Return the exclave's machine: its launcher's, or this machine's before it has one."""
    known = MACHINES.get(launcher_machine(ex) or 0)
    return known or native_machine() or X86_64


def glibc_version(tree: Tree, machine: Machine) -> tuple[int, int] | None:
    """Return the (major, minor) version in the tree's libc.so.6 banner, or None."""
    for d in machine.default_dirs:
        r = tree.resolve(d + "/" + GLIBC_SONAME)
        if r and os.path.isfile(tree.payload(r)):
            with open(tree.payload(r), "rb") as f:
                m = re.search(
                    rb"GNU C Library \([^)]*\) (?:\w+ )?release version (\d+)\.(\d+)", f.read()
                )
            if m:
                return int(m.group(1)), int(m.group(2))
    return None


def loader_dirs(tree: Tree, interp: str | None, machine: Machine) -> list[str]:
    """Return the default search directories of the tree's loader.

    glibc 2.33 and later prints them with --list-diagnostics; musl's are fixed; an older glibc is
    taken to search Debian's and Fedora's defaults.
    """
    if interp is None:
        return machine.default_dirs
    if "musl" in os.path.basename(interp):
        return list(MUSL_DIRS)
    try:
        # the tree's own loader, run on this host, as wrapping requires (10.1)
        out = subprocess.run(  # noqa: S603 -- an argument vector, no shell
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
    return machine.default_dirs


class ForeignElfError(ValueError):
    """A well-formed ELF file of another class or byte order, which the checks skip (13)."""


class Elf:
    """The parts of a little-endian ELF64 file that the checks read.

    Raises:
        ForeignElfError: For an ELF32 or big-endian file.
        ValueError: For a file that is not ELF, or is truncated or malformed.
    """

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
        """Return the file offset of a virtual address in a loaded segment."""
        for va, off, sz in self.loads:
            if va <= vaddr < va + sz:
                return off + vaddr - va
        msg = "address not in a loaded segment"
        raise ValueError(msg)


class Tree:
    """Virtual paths resolved inside tree/ as a chroot would, wrappers standing for originals."""

    def __init__(self, root: str) -> None:
        self.root = root

    def real(self, vpath: str) -> str:
        """Return the real path of vpath, its symlinks unresolved."""
        return os.path.join(self.root, vpath.lstrip("/"))

    def resolve(
        self, vpath: str, *, follow_last: bool = True, links: set[str] | None = None
    ) -> str | None:
        """Return vpath's canonical virtual path, every symlink resolved inside the tree.

        Args:
            vpath: The virtual path to resolve.
            follow_last: Whether a symlink in the last component is followed.
            links: If given, every symlink met on the way is added to it, by virtual path.

        Returns:
            The canonical virtual path, or None when a component is missing or the symlinks loop.
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
                if hops > 40:  # the kernel's limit, ELOOP
                    return None
                if links is not None:
                    links.add(cand)
                t = os.readlink(real)
                rest = [p for p in t.split("/") if p] + rest
                if t.startswith("/"):
                    cur = ""
                continue
            cur = cand
        return cur or "/"

    def payload(self, vpath: str) -> str:
        """Return the real path of the file vpath names: a wrapper's original, or the file."""
        return layout.payload_path(self.real(vpath))


@dataclass(slots=True)
class Report:
    """A check's findings. Errors refuse the exclave; warnings and static executables do not."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    static: list[str] = field(default_factory=list)
    # every (ELF file, inherited RPATHs) the static check followed
    seen: set[tuple[str, tuple[str, ...]]] = field(default_factory=set)
    lines: int = 0  # log lines the dynamic check read


def _expand(s: str, origin: str, machine: Machine) -> str:
    """Make glibc's substitutions (dl-load.c) in an RPATH, a RUNPATH or a DT_NEEDED path."""
    return (
        s.replace("$ORIGIN", origin)
        .replace("${ORIGIN}", origin)
        .replace("$LIB", machine.lib_dir)
        .replace("${LIB}", machine.lib_dir)
        .replace("$PLATFORM", machine.uname)
        .replace("${PLATFORM}", machine.uname)
    )


def read_cache(tree: Tree) -> dict[str, list[str]] | None:
    """Read the tree's /etc/ld.so.cache, in the glibc-ld.so.cache1.1 format.

    Returns:
        Each soname's paths in the cache's order, or None when the tree has no cache.
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


@dataclass(frozen=True, slots=True)
class Ownership:
    """The exclave's ownership as the launcher computes it at startup (8.1).

    own holds the exclave's own prefixes. host holds the manifest's host records, each of which
    gives paths under it back to the host when it is at least as long as the longest own prefix
    covering them.
    """

    own: tuple[str, ...]
    host: tuple[str, ...] = ()


def host_owned(vpath: str, own: Ownership) -> bool:
    """Return whether the launcher would resolve vpath on the host (8.1, vis.c base_is_host).

    It does when vpath is under a volatile prefix, or when the longest host record covering it is
    at least as long as the longest own prefix covering it. A path covered by neither is the host's.
    """
    if layout.under_any(vpath, layout.VOLATILE):
        return True

    def longest(prefixes: Iterable[str]) -> int:
        return max((len(p) for p in prefixes if layout.under(vpath, p)), default=-1)

    return longest(own.host) >= longest(own.own)


def find_library(
    tree: Tree,
    name: str,
    elf: Elf,
    vpath: str,
    rpaths: list[str],
    *,
    machine: Machine,
    cache: dict[str, list[str]] | None,
    default_dirs: list[str],
    interp: str | None,
    own: Ownership | None = None,
    host_hits: list[str] | None = None,
) -> str | None:
    """Return the virtual path the loader would load for a DT_NEEDED entry, or None.

    The loader satisfies its own soname without a search. A name with a slash is loaded as a path.
    Otherwise the search is glibc's: RPATH (with those inherited) unless there is a RUNPATH, then
    RUNPATH, the cache and the default directories, each directory's hwcaps subdirectories first.

    Args:
        tree: The exclave's tree.
        name: The DT_NEEDED entry.
        elf: The object that needs it.
        vpath: That object's virtual path, for $ORIGIN.
        rpaths: The DT_RPATHs inherited from the objects that led to this one.
        machine: The exclave's machine.
        cache: The tree's ld.so.cache, as read_cache returns it.
        default_dirs: The loader's default directories, as loader_dirs returns them.
        interp: The loader's virtual path, or None for a static program.
        own: The exclave's ownership, to find search directories that are the host's.
        host_hits: If given, every searched directory that is the host's at run time is appended:
            the loader would take the host's library from it.
    """
    if interp and name == os.path.basename(interp) and tree.resolve(interp):
        return tree.resolve(interp)
    # a path, loaded as named: glibc expands $ORIGIN and the other tokens in it first (dl-load.c),
    # musl does not
    if "/" in name:
        if interp and "musl" not in os.path.basename(interp):
            name = os.path.normpath(_expand(name, os.path.dirname(vpath), machine))
        return tree.resolve(name) if name.startswith("/") else None
    origin = os.path.dirname(vpath)
    search: list[str] = []
    if not elf.runpath:
        for r in ([elf.rpath] if elf.rpath else []) + rpaths:
            search += [_expand(p, origin, machine) for p in r.split(":") if p]
    if elf.runpath:
        search += [_expand(p, origin, machine) for p in elf.runpath.split(":") if p]

    def host_dir(d: str) -> bool:
        return own is not None and host_owned(os.path.normpath(d), own)

    for d in search:
        if host_hits is not None and host_dir(d):
            host_hits.append(d)
        for sub in [*machine.hwcaps, ""]:
            cand = tree.resolve(os.path.join(d, sub, name) if sub else os.path.join(d, name))
            if cand and os.path.isfile(tree.payload(cand)):
                return cand
    for p in (cache or {}).get(name, []):
        cand = tree.resolve(p)
        if cand and os.path.isfile(tree.payload(cand)):
            return cand
    for d in default_dirs:
        if host_hits is not None and host_dir(d):
            host_hits.append(d)
        for sub in [*machine.hwcaps, ""]:
            cand = tree.resolve(os.path.join(d, sub, name) if sub else os.path.join(d, name))
            if cand and os.path.isfile(tree.payload(cand)):
                return cand
    return None


def _has_musl_loader(tree: Tree, machine: Machine) -> bool:
    """Return whether the tree has musl's loader, which reads no ld.so.cache."""
    r = tree.resolve(f"/lib/ld-musl-{machine.uname}.so.1")
    return bool(r and os.path.isfile(tree.payload(r)))


def static_check(ex: str, own: Ownership, data_prefixes: Sequence[str] = ()) -> Report:
    """Run the static check on the exclave as it stands (10.3).

    Args:
        ex: The exclave.
        own: Its ownership, as the launcher would compute it.
        data_prefixes: The manifest's data directories, which are not checked.

    Returns:
        The findings; any error refuses the exclave.
    """
    tree, rep = Tree(os.path.join(ex, "tree")), Report()
    native = native_machine()
    if native is None:
        rep.errors.append(f"no launcher is built for this machine, {platform.machine()} (7.1)")
        return rep
    e_machine = launcher_machine(ex)
    # An exclave is checked on a machine of its own architecture, where its loader can be asked
    # (10.1); one without a launcher yet is taken to be this machine's.
    if e_machine is not None and e_machine != native.e_machine:
        theirs = MACHINES[e_machine].uname if e_machine in MACHINES else f"machine {e_machine}"
        rep.errors.append(
            f"the exclave's launcher is for {theirs} and this machine is {platform.machine()}: "
            "wrap the exclave on a machine of its architecture (10.1)"
        )
        return rep
    machine = native
    cache = read_cache(tree)
    if host_owned("/etc", own):  # the loader would read the host's cache and preload list
        rep.errors.append(
            "/etc is the host's: the loader would read the host's /etc/ld.so.cache and "
            "/etc/ld.so.preload; the tree must own /etc"
        )
    elif cache is None:
        # musl has no cache; glibc without one searches its defaults only
        if not _has_musl_loader(tree, machine):
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
    executables: list[tuple[str, Elf]] = []
    libraries: list[tuple[str, Elf]] = []
    interps: dict[str, tuple[str, str]] = {}
    for dirpath, dirnames, filenames in os.walk(tree.root):
        rel = "/" + os.path.relpath(dirpath, tree.root).replace(os.sep, "/")
        rel = "" if rel == "/." else rel
        if layout.under_any(rel, data_prefixes):
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
            if e.machine != machine.e_machine:
                rep.warnings.append(
                    f"{vpath}: not {machine.uname}: a foreign object, not checked (13)"
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
                elif layout.under_any(r, data_prefixes):
                    rep.errors.append(
                        f"{vpath} wants interpreter {e.interp}, which resolves into the data "
                        f"directory {r}: never executed or loaded (6.2)"
                    )
                elif host_owned(r, own):
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
        mixed = ", ".join(
            f"{i} ({v})" for _, (i, v) in sorted(interps.items(), key=lambda x: os.fsencode(x[0]))
        )
        rep.errors.append(f"the tree mixes loaders {mixed} (one world inside an exclave, 7.3)")
    interp = next(iter(interps.values()))[0] if interps else None
    musl = bool(interp) and "musl" in os.path.basename(interp or "")
    libc_soname = machine.musl_soname if musl else GLIBC_SONAME
    default_dirs = loader_dirs(tree, interp, machine)
    # 6.2: the locale inside an exclave is C.UTF-8, built into glibc 2.35 and later and into musl;
    # an older glibc needs the C.utf8 directory or every program runs in the plain C locale, and
    # bash and perl say so
    if interp and not musl:
        ver = glibc_version(tree, machine)
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
        if key in rep.seen:
            return
        rep.seen.add(key)
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
                machine=machine,
                cache=cache,
                default_dirs=default_dirs,
                interp=interp,
                own=own,
                host_hits=host_hits,
            )
            for d in host_hits:
                rep.errors.append(
                    f"{vpath} searches {d} for {n}, a directory the exclave does not own: the "
                    "host's library would load"
                )
            if not found:
                path = " > ".join([*chain, vpath])
                rep.errors.append(
                    f"{vpath} needs {n}, which does not resolve in the tree (chain {path})"
                )
                continue
            if layout.under_any(found, data_prefixes):
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


def needed_closure(tree: Tree, vpaths: Sequence[str], machine: Machine) -> set[str]:
    """Return the virtual paths of every library the given ELF files reach through DT_NEEDED.

    Each is found by the loader's search, RPATHs inherited down the chain, and each loader the
    files name is included, since the launcher loads it and no logged call does (10.4).
    """
    out: set[str] = set()
    seen: set[tuple[str, tuple[str, ...]]] = set()
    cache = read_cache(tree)
    interp: str | None = None
    for v in vpaths:
        with contextlib.suppress(ValueError, OSError):
            interp = interp or Elf(tree.payload(v)).interp
    default_dirs = loader_dirs(tree, interp, machine)

    def visit(vpath: str, e: Elf, rpaths: list[str]) -> None:
        key = (vpath, tuple(rpaths))
        if key in seen:
            return
        seen.add(key)
        if e.interp:
            out.add(e.interp)
        below = rpaths if e.runpath else ([e.rpath] if e.rpath else []) + rpaths
        for n in e.needed:
            found = find_library(
                tree,
                n,
                e,
                vpath,
                rpaths,
                machine=machine,
                cache=cache,
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


def dynamic_check(ex: str, logs: Iterable[str], own: Ownership) -> Report:
    """Run the dynamic check on EXCLAVE_LOG files a workload wrote (10.3).

    A library opened on a path the host owns is an error; one under the workload's own working
    directory, its build output presumably, is a warning. NSS modules this host's nsswitch.conf
    names that the exclave lacks are warnings too.
    """
    rep = Report()
    libs: set[str] = set()
    cwds: set[str] = set()
    for what, r, path in layout.log_lines(logs):
        rep.lines += 1
        # 8.1 rule 4 as the launcher applied it; the plain "cwd" line is a diagnostic and gives
        # nothing
        if what == "launcher" and path.startswith("cwd given to the host "):
            c = path[len("cwd given to the host ") :]
            if c != "/":
                cwds.add(c)
        if what == "launcher" and path.startswith("cwd ") and not path.startswith("cwd given"):
            c = path[len("cwd ") :]
            # A working directory under a volatile prefix is already the host's (8.1 rule 3), so
            # the launcher logs no "given" line for it; it is the workload's own all the same.
            if layout.under_any(c, layout.VOLATILE):
                cwds.add(c)
        if what == "open" and r >= 0 and re.search(r"\.so(\.\d+)*$", path):
            libs.add(path)
    for lib in sorted(libs, key=os.fsencode):
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
    dirs = machine_for(ex).default_dirs
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
            if not any(tree.resolve(os.path.join(d, f"libnss_{m}.so.2")) for d in dirs):
                rep.warnings.append(
                    f"this host's nsswitch.conf names {m}; the exclave has no libnss_{m}.so.2"
                )
    return rep
