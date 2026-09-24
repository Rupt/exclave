"""elfcheck.py — the static and dynamic checks (PROPOSAL.md 10.3).

Static: every ELF under root/ outside data prefixes, payloads in place of wrappers, must name one
interpreter between them (through the tree's symlinks), every DT_NEEDED must resolve under root/ by the
loader's own algorithm, every library reached must depend on that loader's libc and nothing else. Anything that would resolve on the host, and anything that would mix
libcs, is reported and the can is refused. Static executables are reported.

Dynamic: given CAN_LOG files a workload wrote, every library opened must be can-owned, and NSS modules
named by the host's nsswitch.conf but absent from the can are reported.
"""
import os
import re
import stat
import struct

PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_SONAME, DT_RPATH, DT_RUNPATH = 0, 1, 5, 10, 14, 15, 29
ET_DYN = 3
# the machines the opener is built for (7.1): ELF e_machine, uname -m, Debian's multiarch triplet
MACHINES = {62: ("x86_64", "x86_64-linux-gnu"), 183: ("aarch64", "aarch64-linux-gnu")}
MACHINE = 62                                                 # the can's, set from its opener by static_check
DEFAULT_DIRS = ["/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib64", "/usr/lib64", "/lib", "/usr/lib"]   # Debian's and Fedora's glibc; the tree's loader is asked when it can answer (review F4-13)
MUSL_DIRS = ["/lib", "/usr/local/lib", "/usr/lib"]
HWCAPS = ["glibc-hwcaps/x86-64-v4", "glibc-hwcaps/x86-64-v3", "glibc-hwcaps/x86-64-v2"]
LIBC_SONAME = {"glibc": "libc.so.6", "musl": "libc.musl-x86_64.so.1"}
LIB_DIR, PLATFORM = "lib/x86_64-linux-gnu", "x86_64"          # what the loader substitutes for $LIB and $PLATFORM; set by set_machine


def set_machine(machine):
    """The can's machine decides the multiarch directory, the hwcaps subdirectories and musl's soname."""
    global MACHINE, DEFAULT_DIRS, HWCAPS, LIBC_SONAME, LIB_DIR, PLATFORM
    MACHINE = machine
    uname, triplet = MACHINES.get(machine, ("unknown", "unknown"))
    LIB_DIR, PLATFORM = "lib/" + triplet, uname
    DEFAULT_DIRS = ["/lib/" + triplet, "/usr/lib/" + triplet, "/lib64", "/usr/lib64", "/lib", "/usr/lib"]
    HWCAPS = ["glibc-hwcaps/x86-64-v4", "glibc-hwcaps/x86-64-v3", "glibc-hwcaps/x86-64-v2"] if machine == 62 else []
    LIBC_SONAME = {"glibc": "libc.so.6", "musl": "libc.musl-%s.so.1" % uname}


def glibc_version(tree):
    """(major, minor) of the tree's glibc, from libc.so.6's banner, or None."""
    for d in DEFAULT_DIRS + ["/lib64", "/usr/lib64"]:
        r = tree.resolve(d + "/libc.so.6")
        if r and os.path.isfile(tree.payload(r)):
            with open(tree.payload(r), "rb") as f:
                m = re.search(rb"GNU C Library \([^)]*\) (?:\w+ )?release version (\d+)\.(\d+)", f.read())
            if m:
                return int(m.group(1)), int(m.group(2))
    return None


def loader_dirs(tree, interp):
    """The default search directories of the loader in the tree: glibc prints them with --list-diagnostics
    (2.33 and later); musl's are fixed; older loaders get Debian's list (review F4-13)."""
    if interp is None:
        return list(DEFAULT_DIRS)
    if "musl" in os.path.basename(interp):
        return list(MUSL_DIRS)
    try:
        import subprocess
        out = subprocess.run([tree.payload(interp), "--list-diagnostics"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20).stdout.decode(errors="replace")
        dirs = re.findall(r'^path\.system_dirs\[0x[0-9a-f]+\]="([^"]+)"', out, re.M)
        if dirs:
            return [d.rstrip("/") for d in dirs]
    except (OSError, subprocess.SubprocessError):
        pass
    return list(DEFAULT_DIRS)


class ForeignElf(ValueError):
    """A well-formed ELF file of another class, byte order or machine: not this can's to run, not checked."""


class Elf:
    """The parts of an ELF64 file the checks need."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            h = f.read(64)
            if len(h) < 16 or h[:4] != b"\x7fELF":
                raise ValueError("not ELF64 LE")
            if h[4] != 2 or h[5] != 1:
                raise ForeignElf("ELF32 or big-endian: a foreign object, not checked (13)")
            if len(h) < 64:
                raise ValueError("truncated ELF header")
            try:
                self._parse(f, h)
            except struct.error as e:
                raise ValueError("truncated or malformed ELF: %s" % e)

    def _parse(self, f, h):
        self.type = struct.unpack_from("<H", h, 16)[0]
        self.machine = struct.unpack_from("<H", h, 18)[0]
        phoff, phentsize, phnum = struct.unpack_from("<Q", h, 32)[0], struct.unpack_from("<H", h, 54)[0], struct.unpack_from("<H", h, 56)[0]
        f.seek(phoff)
        ph = f.read(phentsize * phnum)
        self.loads, self.interp, dyn = [], None, None
        for i in range(phnum):
            p_type, _, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from("<IIQQQQQQ", ph, i * phentsize)
            if p_type == PT_LOAD:
                self.loads.append((p_vaddr, p_offset, p_filesz))
            elif p_type == PT_INTERP:
                f.seek(p_offset)
                self.interp = f.read(p_filesz).rstrip(b"\0").decode("utf-8", "surrogateescape")
            elif p_type == PT_DYNAMIC:
                dyn = (p_offset, p_filesz)
        self.needed, self.rpath, self.runpath, self.soname = [], None, None, None
        if dyn:
            f.seek(dyn[0])
            d = f.read(dyn[1])
            tags = []
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
                        sval = table[val:end if end >= 0 else None].decode("utf-8", "surrogateescape")
                        if tag == DT_NEEDED:
                            self.needed.append(sval)
                        elif tag == DT_RPATH:
                            self.rpath = sval
                        elif tag == DT_RUNPATH:
                            self.runpath = sval
                        else:
                            self.soname = sval

    def _v2o(self, vaddr):
        for va, off, sz in self.loads:
            if va <= vaddr < va + sz:
                return off + vaddr - va
        raise ValueError("address not in a loaded segment")


class Tree:
    """Virtual-path resolution inside root/, wrappers redirected to payloads."""

    def __init__(self, root):
        self.root = root

    def real(self, vpath):
        return os.path.join(self.root, vpath.lstrip("/"))

    def resolve(self, vpath, follow_last=True):
        """Canonical virtual path with symlinks resolved as a chroot would; None if a component is missing."""
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

    def payload(self, vpath):
        real = self.real(vpath)
        d, n = os.path.split(real)
        p = os.path.join(d, ".real", n)
        return p if os.path.exists(p) else real


class Report:
    lines = 0

    def __init__(self):
        self.errors, self.warnings, self.static, self.seen = [], [], [], {}

    def ok(self):
        return not self.errors


def _expand(s, origin):
    """The loader's substitutions in an RPATH or RUNPATH, for the can's machine (glibc's dl-load.c)."""
    return s.replace("$ORIGIN", origin).replace("${ORIGIN}", origin).replace("$LIB", LIB_DIR).replace("${LIB}", LIB_DIR).replace("$PLATFORM", PLATFORM).replace("${PLATFORM}", PLATFORM)


def read_cache(tree):
    """/etc/ld.so.cache in the glibc-ld.so.cache1.1 format: {soname: [paths in file order]}. None if absent."""
    real = tree.real("/etc/ld.so.cache")
    if not os.path.isfile(real):
        return None
    data = open(real, "rb").read()
    off = data.find(b"glibc-ld.so.cache1.1")
    if off < 0:
        return {}
    nlibs, len_strings = struct.unpack_from("<II", data, off + 20)
    entries = off + 48
    table = {}
    for base in (off, entries + 24 * nlibs):                     # offsets are from the header; fall back to the string table
        table = {}
        ok = True
        for i in range(nlibs):
            flags, key, value = struct.unpack_from("<iII", data, entries + 24 * i)
            hwcap = struct.unpack_from("<Q", data, entries + 24 * i + 16)[0]
            try:
                k = data[base + key:data.index(b"\0", base + key)].decode()
                v = data[base + value:data.index(b"\0", base + value)].decode()
            except (ValueError, UnicodeDecodeError):
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


VOLATILE = ("/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run")


def host_owned(vdir, own):
    """The opener's ownership rule for a directory: volatile, or under no own prefix (8.1)."""
    if any(vdir == v or vdir.startswith(v + "/") for v in VOLATILE):
        return True
    return not any(vdir == o or vdir.startswith(o.rstrip("/") + "/") for o in own)


def find_library(tree, name, elf, vpath, rpaths, cache, own=(), host_hits=None, default_dirs=None, interp=None):
    """The virtual path ld.so would load for DT_NEEDED name from the object at vpath, or None.
    rpaths: the DT_RPATH of every object on the chain that led here (inherited when the object has no RUNPATH).
    A search directory the can does not own is the host's at run time: such a directory is recorded in
    host_hits, since the loader would take the host's library from it (review F3-17), default directories
    included (F4-9). The loader satisfies its own soname without a search (F4-13)."""
    if interp and name == os.path.basename(interp) and tree.resolve(interp):
        return tree.resolve(interp)
    if "/" in name:
        return tree.resolve(name) if name.startswith("/") else None
    origin = os.path.dirname(vpath)
    search = []
    if not elf.runpath:
        for r in ([elf.rpath] if elf.rpath else []) + rpaths:
            search += [_expand(p, origin) for p in r.split(":") if p]
    if elf.runpath:
        search += [_expand(p, origin) for p in elf.runpath.split(":") if p]
    for d in search:
        if own and host_owned(os.path.normpath(d), own) and host_hits is not None:
            host_hits.append(d)
        for sub in HWCAPS + [""]:
            cand = tree.resolve(os.path.join(d, sub, name) if sub else os.path.join(d, name))
            if cand and os.path.isfile(tree.payload(cand)):
                return cand
    for p in (cache or {}).get(name, []):
        cand = tree.resolve(p)
        if cand and os.path.isfile(tree.payload(cand)):
            return cand
    for d in (default_dirs or DEFAULT_DIRS):
        if own and host_owned(os.path.normpath(d), own) and host_hits is not None:
            host_hits.append(d)
        for sub in HWCAPS + [""]:
            cand = tree.resolve(os.path.join(d, sub, name) if sub else os.path.join(d, name))
            if cand and os.path.isfile(tree.payload(cand)):
                return cand
    return None


def _interps(tree):
    """The PT_INTERP strings of the tree's dynamic executables, from a bounded look at the conventional loaders."""
    out = []
    for cand in ("/lib/ld-musl-x86_64.so.1", "/lib64/ld-linux-x86-64.so.2", "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"):
        r = tree.resolve(cand)
        if r and os.path.isfile(tree.payload(r)):
            out.append(cand)
    return out


def static_check(can, own, data_prefixes=(), log=print):
    """Returns a Report. own: the ownership set of 8.1 as the opener computes it."""
    import platform
    tree, rep = Tree(os.path.join(can, "root")), Report()
    native = {v[0]: k for k, v in MACHINES.items()}.get(platform.machine())
    try:
        set_machine(Elf(os.path.join(can, ".can", "opener")).machine)   # the can's machine is its opener's
    except (ValueError, OSError):
        set_machine(native or 62)                                       # no opener yet: the machine the check runs on
    if native != MACHINE:                                    # 10.1: a can is closed on a machine of its architecture, where its loader can be asked
        rep.errors.append("the can's opener is for %s and this machine is %s: close the can on a machine of its architecture (10.1)"
                          % (MACHINES.get(MACHINE, ("?",))[0], platform.machine()))
        return rep
    cache = read_cache(tree)
    if host_owned("/etc", own):                                # the loader would read the host's cache and preload list (review F4-9)
        rep.errors.append("/etc is the host's: the loader would read the host's /etc/ld.so.cache and /etc/ld.so.preload; the tree must own /etc")
    elif cache is None:
        if not any("musl" in os.path.basename(i) for i in _interps(tree)):   # musl has no cache; glibc without one searches its defaults only
            rep.warnings.append("no /etc/ld.so.cache: only the loader's default directories are searched at run time")
    else:
        for soname, paths in cache.items():                       # no cache entry may name the opener (10.3)
            for p in paths:
                r = tree.resolve(p)
                if r and os.path.isfile(tree.payload(r)):
                    try:
                        e = Elf(tree.payload(r))
                    except (ValueError, OSError):
                        continue
                    if e.soname is None and e.type == ET_DYN and not e.needed:
                        rep.errors.append("ld.so.cache entry %s names %s, which is not a shared library (the opener?)" % (soname, p))
    seen = rep.seen
    executables, libraries, interps = [], [], {}
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
                    rep.warnings.append("dangling symlink %s -> %s" % (vpath, os.readlink(real)))
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            pay = tree.payload(vpath)
            try:
                head = open(pay, "rb").read(4)
            except PermissionError:
                rep.errors.append("unreadable file %s: chmod u+r it; no copy of the can can carry it and the tree hash needs it (10.3)" % vpath)
                continue
            with open(pay, "rb") as f:
                if head != b"\x7fELF":
                    continue
            try:
                e = Elf(pay)
            except ForeignElf as ex:                          # Fedora's gcc ships 32-bit crt objects beside the 64-bit ones
                rep.warnings.append("%s: %s" % (vpath, ex))
                continue
            except ValueError as ex:
                rep.errors.append("%s: %s" % (vpath, ex))
                continue
            if e.machine != MACHINE:
                rep.warnings.append("%s: not %s: a foreign object, not checked (13)" % (vpath, MACHINES.get(MACHINE, ("?",))[0]))
                continue
            if e.interp is None and e.type != ET_DYN:
                rep.static.append(vpath)
            elif e.interp is not None:
                r = tree.resolve(e.interp)
                if r is None:
                    rep.errors.append("%s wants interpreter %s, which does not resolve in the tree" % (vpath, e.interp))
                elif any(r == p or r.startswith(p.rstrip("/") + "/") for p in data_prefixes):
                    rep.errors.append("%s wants interpreter %s, which resolves into the data prefix %s: never executed or loaded (6.2)" % (vpath, e.interp, r))
                else:
                    interps.setdefault(r, (e.interp, vpath))
            (executables if e.interp is not None or e.type != ET_DYN else libraries).append((vpath, e))
    # one loader, and so one libc, per can (7.3): read from the ELF files, not declared anywhere
    if len(interps) > 1:
        rep.errors.append("the tree mixes loaders %s (one world inside a can, 7.3)" % ", ".join("%s (%s)" % (i, v) for r, (i, v) in sorted(interps.items())))
    interp = next(iter(interps.values()))[0] if interps else None
    libc_soname = LIBC_SONAME["musl"] if interp and "musl" in os.path.basename(interp) else LIBC_SONAME["glibc"]
    default_dirs = loader_dirs(tree, interp)
    # 6.2: the locale inside a can is C.UTF-8, built into glibc 2.35 and later and into musl; an older glibc
    # needs the C.utf8 directory or every program runs in the plain C locale, and bash and perl say so
    if interp and "musl" not in os.path.basename(interp):
        ver = glibc_version(tree)
        if ver and ver < (2, 35) and not any(os.path.isdir(tree.real(d)) for d in ("/usr/lib/locale/C.utf8", "/usr/lib/locale/C.UTF-8")):
            rep.warnings.append("glibc %d.%d predates the built-in C.UTF-8 locale and the tree has no /usr/lib/locale/C.utf8: programs will run in the plain C locale" % ver)

    reached = set()

    def check(vpath, e, rpaths, chain):
        key = (vpath, tuple(rpaths))
        if key in seen:
            return
        seen[key] = True
        if chain:
            reached.add(vpath)
        below = rpaths if e.runpath else ([e.rpath] if e.rpath else []) + rpaths
        for n in e.needed:
            host_hits = []
            found = find_library(tree, n, e, vpath, rpaths, cache, own, host_hits, default_dirs, interp)
            for d in host_hits:
                rep.errors.append("%s searches %s for %s, a directory the can does not own: the host's library would load" % (vpath, d, n))
            if not found:
                rep.errors.append("%s needs %s, which does not resolve in the tree (chain %s)" % (vpath, n, " > ".join(chain + [vpath])))
                continue
            if any(found == p or found.startswith(p.rstrip("/") + "/") for p in data_prefixes):
                rep.errors.append("%s needs %s, which resolves into the data prefix %s: never loaded (6.2)" % (vpath, n, found))
                continue
            if n.startswith("libc.") and n != libc_soname:
                rep.errors.append("%s needs %s: a libc other than the loader's %s" % (vpath, n, libc_soname))
            try:
                fe = Elf(tree.payload(found))
            except (ValueError, OSError) as ex:
                rep.errors.append("%s: %s" % (found, ex))
                continue
            check(found, fe, below, chain + [vpath])
    for vpath, e in executables:                                   # executables first, so that RPATH inheritance is seen
        check(vpath, e, [], [])
    for vpath, e in libraries:                                     # a library nothing reaches is a dlopen candidate: checked alone
        if vpath not in reached:
            check(vpath, e, [], [])
    return rep


def needed_closure(tree, vpaths, own):
    """The virtual paths of every library the given ELF files reach through DT_NEEDED, by the loader's
    search with RPATH inherited down the chain; for pruning (10.4)."""
    out, seen, cache = set(), set(), read_cache(tree)
    interp = None
    for v in vpaths:
        try:
            interp = interp or Elf(tree.payload(v)).interp
        except (ValueError, OSError):
            pass
    default_dirs = loader_dirs(tree, interp)

    def visit(vpath, e, rpaths):
        key = (vpath, tuple(rpaths))
        if key in seen:
            return
        seen.add(key)
        if e.interp:
            out.add(e.interp)                                  # the loader is loaded by the opener, never through a logged syscall
        below = rpaths if e.runpath else ([e.rpath] if e.rpath else []) + rpaths
        for n in e.needed:
            found = find_library(tree, n, e, vpath, rpaths, cache, own, None, default_dirs, interp)
            if not found:
                continue
            out.add(found)
            try:
                fe = Elf(tree.payload(found))
            except (ValueError, OSError):
                continue
            visit(found, fe, below)
    for v in vpaths:
        try:
            visit(v, Elf(tree.payload(v)), [])
        except (ValueError, OSError):
            continue
    return out


def dynamic_check(can, logs, own, log=print):
    """Read CAN_LOG files; report libraries opened outside the can and NSS modules the host names that
    the can lacks."""
    import build
    rep = Report()
    libs, cwds = set(), set()
    for what, r, path in build.log_lines(logs):
        rep.lines += 1
        if what == "opener" and path.startswith("cwd claimed for the host "):   # 8.1 rule 4 as the opener applied it; the plain
            c = path[len("cwd claimed for the host "):]                           # "cwd" line is a diagnostic and claims nothing (review O5-4)
            if c != "/":
                cwds.add(c)
        if what == "opener" and path.startswith("cwd ") and not path.startswith("cwd claimed"):
            c = path[len("cwd "):]                                                # a working directory under a volatile prefix is the
            if any(c == v or c.startswith(v + "/") for v in VOLATILE):            # host's by 8.1 rule 3, with nothing to claim: the
                cwds.add(c)                                                       # build's own directory all the same; never /
        if what == "open" and r >= 0 and re.search(r"\.so(\.\d+)*$", path):
            libs.add(path)
    for lib in sorted(libs):
        if any(lib.startswith(c.rstrip("/") + "/") for c in cwds):   # the workload's own build directory (review F4-10): the
            rep.warnings.append("library opened under the workload's working directory, its own output presumably: " + lib)   # host's by 8.1 rule 4, whatever prefix it lies under
        elif any(lib == o or lib.startswith(o.rstrip("/") + "/") for o in own):
            continue
        else:
            rep.errors.append("library opened on the host: " + lib)
    tree = Tree(os.path.join(can, "root"))
    if os.path.exists("/etc/nsswitch.conf"):
        mods = set()
        for line in open("/etc/nsswitch.conf", encoding="utf-8", errors="replace"):
            line = line.split("#", 1)[0]
            if ":" in line:
                for w in line.split(":", 1)[1].split():
                    if w.isalpha() and w not in ("files", "dns", "db", "compat"):
                        mods.add(w)
                    elif w in ("db", "compat"):
                        mods.add(w)
        for m in sorted(mods):
            if not any(tree.resolve(os.path.join(d, "libnss_%s.so.2" % m)) for d in DEFAULT_DIRS):
                rep.warnings.append("this host's nsswitch.conf names %s; the can has no libnss_%s.so.2" % (m, m))
    return rep
