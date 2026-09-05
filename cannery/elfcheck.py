"""elfcheck.py — the static and dynamic checks (PROPOSAL.md 10.3).

Static: every ELF under root/ outside data prefixes, payloads in place of wrappers, must have the
index's interpreter (through the tree's symlinks), every DT_NEEDED must resolve under root/ by the
loader's own algorithm, every library reached must depend on the index's libc and nothing else, no
path component may be `.real`. Anything that would resolve on the host, and anything that would mix
libcs, is reported and the can is refused. Static executables are reported.

Dynamic: a workload runs under CAN_LOG; every library opened must be can-owned, and NSS modules named
by the host's nsswitch.conf but absent from the can are reported.
"""
import os
import re
import stat
import struct
import subprocess
import tempfile

PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_SONAME, DT_RPATH, DT_RUNPATH = 0, 1, 5, 10, 14, 15, 29
ET_DYN = 3
DEFAULT_DIRS = ["/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib", "/usr/lib"]
HWCAPS = ["glibc-hwcaps/x86-64-v4", "glibc-hwcaps/x86-64-v3", "glibc-hwcaps/x86-64-v2"]
LIBC_SONAME = {"glibc": "libc.so.6", "musl": "libc.musl-x86_64.so.1"}


class Elf:
    """The parts of an ELF64 file the checks need."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            h = f.read(64)
            if len(h) < 64 or h[:4] != b"\x7fELF" or h[4] != 2 or h[5] != 1:
                raise ValueError("not ELF64 LE")
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
    def __init__(self):
        self.errors, self.warnings, self.static, self.seen = [], [], [], {}

    def ok(self):
        return not self.errors


def _expand(s, origin):
    return s.replace("$ORIGIN", origin).replace("${ORIGIN}", origin).replace("$LIB", "lib/x86_64-linux-gnu").replace("${LIB}", "lib/x86_64-linux-gnu").replace("$PLATFORM", "x86_64").replace("${PLATFORM}", "x86_64")


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


def find_library(tree, name, elf, vpath, rpaths, cache, own=(), host_hits=None):
    """The virtual path ld.so would load for DT_NEEDED name from the object at vpath, or None.
    rpaths: the DT_RPATH of every object on the chain that led here (inherited when the object has no RUNPATH).
    A search directory the can does not own is the host's at run time: such a directory is recorded in
    host_hits, since the loader would take the host's library from it (review F3-17)."""
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
    for d in DEFAULT_DIRS:
        for sub in HWCAPS + [""]:
            cand = tree.resolve(os.path.join(d, sub, name) if sub else os.path.join(d, name))
            if cand and os.path.isfile(tree.payload(cand)):
                return cand
    return None


def static_check(can, index, data_prefixes=(), log=print):
    """Returns a Report. index: dict with 'interp' and 'libc' from the index records."""
    tree, rep = Tree(os.path.join(can, "root")), Report()
    interp = index.get("interp")
    libc_soname = LIBC_SONAME.get(index.get("libc", ("glibc",))[0], "libc.so.6")
    interp_resolved = tree.resolve(interp) if interp else None
    if interp and not interp_resolved:
        rep.errors.append("interp %s does not resolve in the tree" % interp)
    own = index.get("own", [])
    cache = read_cache(tree)
    if cache is None:
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
    executables, libraries = [], []
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
            with open(pay, "rb") as f:
                if f.read(4) != b"\x7fELF":
                    continue
            try:
                e = Elf(pay)
            except ValueError:
                continue
            if e.machine != 62:
                rep.errors.append("%s: not x86-64" % vpath)
                continue
            if e.interp is None and e.type != ET_DYN:
                rep.static.append(vpath)
            elif e.interp is not None:
                r = tree.resolve(e.interp)
                if not interp:
                    rep.errors.append("%s wants interpreter %s but the index names none" % (vpath, e.interp))
                elif r != interp_resolved:
                    rep.errors.append("%s wants interpreter %s, not the can's %s (one libc per can, 7.3)" % (vpath, e.interp, interp))
            (executables if e.interp is not None or e.type != ET_DYN else libraries).append((vpath, e))

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
            found = find_library(tree, n, e, vpath, rpaths, cache, own, host_hits)
            for d in host_hits:
                rep.errors.append("%s searches %s for %s, a directory the can does not own: the host's library would load" % (vpath, d, n))
            if not found:
                rep.errors.append("%s needs %s, which does not resolve in the tree (chain %s)" % (vpath, n, " > ".join(chain + [vpath])))
                continue
            if n.startswith("libc.") and n != libc_soname:
                rep.errors.append("%s needs %s: a libc other than the index's %s" % (vpath, n, libc_soname))
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


def dynamic_check(can, index, command, own, log=print):
    """Run command under CAN_LOG; report libraries opened outside the can and NSS modules the host names
    that the can lacks. Returns (report, exit status)."""
    rep = Report()
    with tempfile.NamedTemporaryFile(prefix="can-log-", delete=False) as t:
        logpath = t.name
    env = dict(os.environ, CAN_LOG=logpath)
    p = subprocess.run(command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    libs = set()
    for line in open(logpath, encoding="utf-8", errors="replace"):
        parts = line.rstrip("\n").split(" ", 2)
        if len(parts) == 3 and parts[0] == "open" and int(parts[1]) >= 0 and re.search(r"\.so(\.\d+)*$", parts[2]):
            libs.add(parts[2])
    os.remove(logpath)
    for lib in sorted(libs):
        if not any(lib == o or lib.startswith(o.rstrip("/") + "/") for o in own):
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
                rep.warnings.append("host nsswitch.conf names %s; the can has no libnss_%s.so.2" % (m, m))
    return rep, p.returncode
