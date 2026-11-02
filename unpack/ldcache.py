"""glibc's ld.so.cache as the tree's own ldconfig writes it, from the tree's files alone (10.1).

Written from glibc's elf/ldconfig.c, elf/cache.c, elf/stringtable.c and elf/readelflib.c, which
2.39 and 2.41 share, so that a tree of any architecture gets the cache its own ldconfig would have
written, byte for byte, without running it:

- The directories: those /etc/ld.so.conf and its includes name, in order, then the built-in ones.
  The built-in directories are the loader's trusted directories, read from the loader's own table
  (the same table the loader prints with --list-diagnostics); glibc's ldconfig takes the first two
  of them, the slibdir and the libdir, and reads a `lib64` among them as `lib`, `lib64` and
  `libx32` (`libilp32` on aarch64), while Debian's ldconfig takes every one as the table spells
  it, from a copy of the table of its own, which is how it is told apart: its binary carries the
  table twice, once in that copy and once in the static C library it is linked with, where
  glibc's carries it once. A directory named twice, by inode, counts once, and each has its
  glibc-hwcaps subdirectories after it.
- The files: in each directory, the names that look like a shared object (`lib*.so*`, `ld-*.so*`,
  `ld.so.*`, `ld64.so.*`), regular files and symlinks, each read as the readelflib of ldconfig's
  own machine reads it: its class, machine, type and DT_SONAME, and on x86 the ISA level its
  GNU property note needs. A dangling symlink whose name has `.so.` is removed, as ldconfig
  removes it.
- One entry per soname per directory, a file preferred to a link and the later name by
  ldconfig's own version comparison to the earlier; the soname link is made beside a file whose
  name is not its soname, where ldconfig would make it.
- The entries in ldconfig's order, the string table tail-merged in its order, the generator
  string the ldconfig binary carries.

Every path is a virtual path resolved by the Root, so nothing outside the tree is read or changed.
"""

import fnmatch
import itertools
import os
import re
import stat
from typing import NamedTuple
lazy from collections.abc import Callable

lazy from unpack.root import Root

type Log = Callable[[str], object]

EM_386, EM_X86_64, EM_AARCH64 = 3, 62, 183
# ldconfig's flags (sysdeps/generic/ldconfig.h)
FLAG_ELF_LIBC6 = 0x0003
FLAG_X8664_LIB64 = 0x0300
FLAG_X8664_LIBX32 = 0x0800
FLAG_ARM_LIBHF = 0x0900
FLAG_AARCH64_LIB64 = 0x0A00
FLAG_ARM_LIBSF = 0x0B00
EF_ARM_ABI_FLOAT_SOFT, EF_ARM_ABI_FLOAT_HARD = 0x200, 0x400
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_GNU_PROPERTY = 1, 2, 3, 0x6474E553
DT_STRTAB, DT_SONAME = 5, 14
NT_GNU_PROPERTY_TYPE_0 = 5
GNU_PROPERTY_X86_ISA_1_NEEDED = 0xC0008002
# the cache's own constants (sysdeps/generic/dl-cache.h)
MAGIC = b"glibc-ld.so.cache1.1"
ENDIAN_LITTLE = 2
EXTENSION_MAGIC = 0xEAA42174
TAG_GENERATOR, TAG_GLIBC_HWCAPS = 0, 1
HWCAP_EXTENSION = 1 << 62
# the loaders Debian's ldconfig leaves the soname link of alone (its local-ldconfig-ignore-ld.so)
LD_SONAMES = frozenset(
    {
        "ld-kfreebsd-x86-64.so.1",
        "ld-linux-aarch64.so.1",
        "ld-linux-aarch64_be.so.1",
        "ld-linux-armhf.so.3",
        "ld-linux-ia64.so.2",
        "ld-linux-mipsn8.so.1",
        "ld-linux-riscv64-lp64.so.1ld-linux-riscv64-lp64d.so.1",  # two literals, no comma between
        "ld-linux-x32.so.2",
        "ld-linux-x86-64.so.2",
        "ld-linux.so.2",
        "ld-linux.so.3",
        "ld.so.1",
        "ld64.so.1",
        "ld64.so.2",
    }
)
LDCONFIG = (
    "/usr/sbin/ldconfig.real",
    "/sbin/ldconfig.real",
    "/usr/sbin/ldconfig",
    "/sbin/ldconfig",
    "/usr/bin/ldconfig",
)


def _u(data: bytes, at: int, size: int) -> int:
    if at < 0 or at + size > len(data):
        raise _TruncatedError
    return int.from_bytes(data[at : at + size], "little")


class _TruncatedError(Exception):
    """A read past the file's end: ldconfig's check_ptr, which skips the file."""


def version_key(name: bytes) -> list[tuple[int, int]]:
    """A name's order as ldconfig's version comparison has it, as a sort key.

    Byte by byte, except that a run of digits counts as one number, and a digit outranks every
    other byte; a name that ends first comes first. (glibc's _dl_cache_libcmp.)
    """
    key: list[tuple[int, int]] = []
    for digits, run in itertools.groupby(name, lambda c: 48 <= c <= 57):
        if digits:
            key.append((1, int(bytes(run))))
        else:
            key.extend((0, c) for c in run)
    return key


def is_dso(name: str) -> bool:
    """Whether a name looks like a shared object to ldconfig: lib*.so*, ld-*.so*, ld.so.*."""
    return (name.startswith(("lib", "ld-")) and ".so" in name) or name.startswith(
        ("ld.so.", "ld64.so.")
    )


def _skipped_name(name: str) -> bool:
    """Whether ldconfig skips the name: prelink's, rpm's and dpkg's temporary files."""
    return (
        (len(name) >= len(".#prelink#.XXXXXX") and name[-17:-6] == ".#prelink#.")
        or ";" in name
        or name.endswith((".#prelink#", ".dpkg-new", ".dpkg-tmp"))
    )


def _isa_level(data: bytes, offset: int, size: int, addr: int) -> int:
    """The ISA level a PT_GNU_PROPERTY segment needs, as x86's read_gnu_property reads it."""
    note, end, level = offset, offset + size, 0
    while note + 12 - offset < size:
        namesz, descsz, kind = _u(data, note, 4), _u(data, note + 4, 4), _u(data, note + 8, 4)
        gnu = data[note + 12 : note + 16] == b"GNU\0"
        if namesz == 4 and kind == NT_GNU_PROPERTY_TYPE_0 and gnu:
            if descsz < 8 or descsz % addr:
                return level
            ptr, pend, last = note + 16, note + 16 + descsz, 0
            while True:
                ptype, datasz = _u(data, ptr, 4), _u(data, ptr + 4, 4)
                if ptype < last:
                    return level
                ptr += 8
                if ptr + datasz > pend:
                    return level
                last = ptype
                if ptype > GNU_PROPERTY_X86_ISA_1_NEEDED:
                    return level
                if ptype == GNU_PROPERTY_X86_ISA_1_NEEDED and datasz == 4:
                    needed = _u(data, ptr, 4)
                    if needed:
                        level = needed.bit_length() - 1
                ptr += (datasz + addr - 1) // addr * addr
                if pend - ptr < 8:
                    return level
        note += 12 + (namesz + addr - 1) // addr * addr + (descsz + addr - 1) // addr * addr
        if note > end:
            return level
    return level


def shared_object(data: bytes, family: int) -> tuple[int, int, str | None] | None:
    """What ldconfig for the machine family makes of a file: (flags, ISA level, soname).

    None where it would skip the file: not an ELF shared object of a class and machine its
    readelflib takes, or one whose dynamic section it cannot read.
    """
    try:
        return _shared_object(data, family)
    except _TruncatedError:
        return None


def _shared_object(data: bytes, family: int) -> tuple[int, int, str | None] | None:
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[5] != 1:
        return None
    cls = data[4]
    if cls not in (1, 2) or _u(data, 16, 2) != 3:  # ET_DYN alone
        return None
    machine = _u(data, 18, 2)
    if cls == 1:
        phoff, phnum, flags, psize, addr = _u(data, 28, 4), _u(data, 44, 2), _u(data, 36, 4), 32, 4
    else:
        phoff, phnum, flags, psize, addr = _u(data, 32, 8), _u(data, 56, 2), _u(data, 48, 4), 56, 8
    if family == EM_X86_64:
        if machine == EM_X86_64:
            flag = FLAG_ELF_LIBC6 | (FLAG_X8664_LIB64 if cls == 2 else FLAG_X8664_LIBX32)
        elif machine == EM_386 and cls == 1:
            flag = FLAG_ELF_LIBC6
        else:
            return None
    elif cls == 2:  # the arm readelflib: a 64-bit object is aarch64's, whatever its machine
        flag = FLAG_ELF_LIBC6 | FLAG_AARCH64_LIB64
    elif flags & EF_ARM_ABI_FLOAT_HARD:
        flag = FLAG_ELF_LIBC6 | FLAG_ARM_LIBHF
    elif flags & EF_ARM_ABI_FLOAT_SOFT:
        flag = FLAG_ELF_LIBC6 | FLAG_ARM_LIBSF
    else:
        flag = FLAG_ELF_LIBC6
    if phoff > len(data):
        return None
    loads: list[tuple[int, int, int]] = []
    dyn_off = dyn_size = level = 0
    for i in range(phnum):
        o = phoff + i * psize
        if o > len(data):
            return None
        kind = _u(data, o, 4)
        if cls == 1:
            off, vaddr, filesz, align = (_u(data, o + k, 4) for k in (4, 8, 16, 28))
        else:
            off, vaddr, filesz, align = (_u(data, o + k, 8) for k in (8, 16, 32, 48))
        if kind == PT_LOAD:
            loads.append((off, vaddr, filesz))
        elif kind == PT_DYNAMIC:
            dyn_off, dyn_size = off, filesz
        elif kind == PT_GNU_PROPERTY and family == EM_X86_64 and align == addr:
            level = _isa_level(data, off, filesz, addr)
    if not dyn_size or dyn_off > len(data):
        return None
    strtab, dsize = None, 8 if cls == 1 else 16
    d = dyn_off
    while (tag := _u(data, d, dsize // 2)) != 0:
        if tag == DT_STRTAB:
            val = _u(data, d + dsize // 2, dsize // 2)
            loadoff = 0
            for off, vaddr, filesz in loads:
                if vaddr <= val < vaddr + filesz:
                    loadoff = vaddr - off
                    break
            strtab = val - loadoff
            if strtab > len(data):
                return None
            break
        d += dsize
    if strtab is None:
        return None
    d = dyn_off
    while (tag := _u(data, d, dsize // 2)) != 0:
        if tag == DT_SONAME:
            at = strtab + _u(data, d + dsize // 2, dsize // 2)
            if at > len(data):
                return None
            end = data.find(b"\0", at)
            name = data[at : end if end >= 0 else len(data)]
            return flag, level, name.decode("utf-8", "surrogateescape")
        d += dsize
    return flag, level, None


def trusted_dirs(loader: bytes) -> list[str]:
    """The loader's trusted directories, from its own table of them.

    The first run of two or more consecutive strings spelt `/.../`, each ending in a slash as
    glibc's build writes them, in the loader's read-only data: its sections that are allocated,
    not code and not writable, in file order, each split at its NULs, so that a string is one the
    section holds and not the tail of the code before it; a loader without section headers is
    read whole.
    """
    for data in _rodata(loader):
        run: list[str] = []
        for chunk in data.split(b"\0"):
            if len(chunk) >= 2 and chunk[:1] == b"/" and chunk[-1:] == b"/":
                run.append(chunk.decode("utf-8", "surrogateescape"))
            elif len(run) >= 2:
                return run
            else:
                run = []
        if len(run) >= 2:
            return run
    return []


def _rodata(elf: bytes) -> list[bytes]:
    """An ELF file's read-only data sections in file order, or the whole file without headers."""
    try:
        if elf[:4] != b"\x7fELF" or elf[4] not in (1, 2):
            return [elf]
        cls = elf[4]
        if cls == 1:
            shoff, shentsize, shnum = _u(elf, 32, 4), _u(elf, 46, 2), _u(elf, 48, 2)
        else:
            shoff, shentsize, shnum = _u(elf, 40, 8), _u(elf, 58, 2), _u(elf, 60, 2)
        out: list[tuple[int, bytes]] = []
        for i in range(shnum):
            o = shoff + i * shentsize
            kind = _u(elf, o + 4, 4)
            if cls == 1:
                flags, off, size = _u(elf, o + 8, 4), _u(elf, o + 16, 4), _u(elf, o + 20, 4)
            else:
                flags, off, size = _u(elf, o + 8, 8), _u(elf, o + 24, 8), _u(elf, o + 32, 8)
            # SHT_PROGBITS, SHF_ALLOC, neither SHF_EXECINSTR nor SHF_WRITE
            if kind == 1 and flags & 2 and not flags & 5 and off + size <= len(elf):
                out.append((off, elf[off : off + size]))
    except _TruncatedError:
        return [elf]
    return [d for _, d in sorted(out)] if out else [elf]


def generator(ldconfig: bytes) -> str | None:
    """The generator string an ldconfig writes, which it carries as a literal."""
    m = re.search(rb"ldconfig \([^)]*\) [a-z]+ release version [0-9][0-9.]*", ldconfig)
    return m.group(0).decode("utf-8", "surrogateescape") if m else None


class _Dir(NamedTuple):
    path: str
    hwcaps: str | None  # the glibc-hwcaps subdirectory's name


class _Entry(NamedTuple):
    lib: str
    path: str
    flags: int
    isa_level: int
    hwcaps: str | None


class Ldconfig:
    """One run of ldconfig over a tree, as its own binary would make it."""

    def __init__(self, r: Root, ldconfig: str, log: Log) -> None:
        self.r, self.log = r, log
        binary = r.read_bytes(ldconfig)
        self.family = _u(binary, 18, 2)
        self.generator = generator(binary)
        self.dirs: list[_Dir] = []
        self._keys: list[tuple[int, int]] = []
        self.entries: list[_Entry] = []
        self.loader = self._find_loader()
        table = trusted_dirs(r.read_bytes(self.loader)) if self.loader else []
        # Debian's ldconfig carries a copy of the loader's table beside its static C library's
        # and adds its entries as spelt; glibc's takes slibdir and libdir and expands a lib64
        run = b"\0".join(d.encode("utf-8", "surrogateescape") for d in table) + b"\0"
        self.debian = bool(table) and binary.count(run) >= 2
        self.table = table

    # ---------------------------------------------------------------- the directories
    def _find_loader(self) -> str | None:
        """The tree's glibc loader: the first ld-*.so* in a library directory, by name."""
        tops: list[str] = []
        for top in ("/lib", "/lib64", "/usr/lib", "/usr/lib64"):
            tops.append(top)
            tops.extend(f"{top}/{n}" for n in self.r.listdir(top) if "linux" in n)
        for d in sorted(set(tops)):
            for name in self.r.listdir(d):
                if not (name.startswith("ld-") and ".so" in name) and not name.startswith(
                    ("ld.so.", "ld64.so.")
                ):
                    continue
                if not self.r.isfile(f"{d}/{name}"):
                    continue
                data = self.r.read_bytes(f"{d}/{name}")
                if (
                    len(data) > 64
                    and data[:4] == b"\x7fELF"
                    and _u(data, 18, 2) == self.family
                    and trusted_dirs(data)
                ):
                    return f"{d}/{name}"
        return None

    def add_dir(self, line: str) -> None:
        """Add a directory as ldconfig's add_dir_1 does: trailing blanks and slashes off, once."""
        path = line.rstrip(" \t\n\v\f\r").rstrip("/")
        if not path:
            return
        st = self.r.stat(path)
        if st is None:
            return
        if (st.st_dev, st.st_ino) in self._keys:
            return
        self._keys.append((st.st_dev, st.st_ino))
        self.dirs.append(_Dir(path, None))
        for name in self.r.listdir(path + "/glibc-hwcaps"):
            if name.startswith(".") or ":" in name:
                continue
            sub = f"{path}/glibc-hwcaps/{name}"
            lst = self.r.stat(sub, follow=False)
            if lst is None or stat.S_ISREG(lst.st_mode):
                continue
            st = self.r.stat(sub)
            if st is None or not stat.S_ISDIR(st.st_mode):
                continue
            if (st.st_dev, st.st_ino) in self._keys:
                continue
            self._keys.append((st.st_dev, st.st_ino))
            self.dirs.append(_Dir(sub, name))

    def add_system_dir(self, d: str) -> None:
        """Add a built-in directory as glibc's add_system_dir does: lib64 is lib, lib64, libx32."""
        other = "x32" if self.family == EM_X86_64 else "ilp32"
        if d.endswith("/lib64"):
            d = d[:-2]
        elif d.endswith("/lib" + other):
            d = d[: -len(other)]
        self.add_dir(d)
        if d.endswith("/lib"):
            self.add_dir(d + "64")
            self.add_dir(d + other)

    def parse_conf(self, filename: str) -> None:
        try:
            text = self.r.read_bytes(filename)
        except OSError:
            return
        for raw in text.split(b"\n"):
            line = raw.split(b"#", 1)[0].decode("utf-8", "surrogateescape").lstrip(" \t\n\v\f\r")
            if not line:
                continue
            if line.startswith("include") and line[7:8] in (" ", "\t"):
                for pattern in re.split(r"[ \t]", line[8:]):
                    if pattern:
                        self.include(filename, pattern)
            elif line[:5].lower() == "hwcap" and line[5:6] in (" ", "\t"):
                continue
            else:
                self.add_dir(line)

    def include(self, config_file: str, pattern: str) -> None:
        if not pattern.startswith("/") and "/" in config_file:
            pattern = config_file.rsplit("/", 1)[0] + "/" + pattern
        for path in self.glob(pattern):
            self.parse_conf(path)

    def glob(self, pattern: str) -> list[str]:
        """Return the tree's paths matching the pattern, in byte order, as glob64 finds them."""
        paths = [""]  # the tree's root, which no virtual path names
        for comp in pattern.split("/"):
            if not comp:
                continue
            if any(c in comp for c in "*?["):
                paths = [
                    f"{p}/{n}"
                    for p in paths
                    for n in sorted(
                        self.r.listdir(p) if p else os.listdir(self.r.fd), key=os.fsencode
                    )
                    if not n.startswith(".") and fnmatch.fnmatchcase(n, comp)
                ]
            else:
                paths = [f"{p}/{comp}" for p in paths if self.r.lexists(f"{p}/{comp}")]
        return paths

    def builtin_dirs(self) -> None:
        if self.debian:
            for d in self.table:
                self.add_dir(d)
        else:
            for d in self.table[:2]:
                self.add_system_dir(d.rstrip("/"))

    # ---------------------------------------------------------------- the files
    def search_dir(self, entry: _Dir) -> None:
        """Read a directory as ldconfig's search_dir does: one library per soname, and its link."""
        r = self.r
        dlibs: dict[str, list] = {}  # soname -> [name, flag, is_link, isa_level]
        order: list[str] = []
        for name in r.listdir(entry.path):
            full = f"{entry.path}/{name}"
            lst = r.stat(full, follow=False)
            if lst is None:
                continue
            kind = stat.S_IFMT(lst.st_mode)
            if kind not in (stat.S_IFLNK, stat.S_IFREG, stat.S_IFDIR):
                continue
            if not is_dso(name) and (kind == stat.S_IFREG or entry.hwcaps is None):
                continue
            if _skipped_name(name):
                continue
            is_link = kind == stat.S_IFLNK
            if is_link:
                if r.stat(full) is None:
                    if ".so." in name:  # a stale symlink, which ldconfig removes
                        r.remove(full)
                        self.log(f"removed the dangling link {full}, as ldconfig does")
                    continue
            elif kind != stat.S_IFREG:
                continue
            try:
                data = r.read_bytes(full)
            except OSError:
                continue
            info = shared_object(data, self.family)
            if info is None:
                continue
            flag, level, soname = info
            if soname is None:
                soname = name
            if is_link:
                # a link named by the soname, or the .so link a soname extends, stays a link
                if name != soname and not (name.endswith(".so") and soname.startswith(name)):
                    is_link = False
                if is_link:
                    soname = name
            have = dlibs.get(soname)
            if have is not None:
                if (not is_link and have[2]) or (
                    is_link == have[2]
                    and version_key(have[0].encode()) < version_key(name.encode())
                ):
                    have[0], have[2], have[3] = name, is_link, level
                continue
            dlibs[soname] = [name, flag, is_link, level]
            order.append(soname)
        for soname in reversed(order):  # the list ldconfig builds at its head
            name, flag, is_link, level = dlibs[soname]
            if entry.hwcaps is None:
                if not is_link:
                    self.create_links(entry.path, name, soname)
                filename = soname
            else:
                filename = name
            self.entries.append(
                _Entry(soname, f"{entry.path}/{filename}", flag, level, entry.hwcaps)
            )

    def create_links(self, path: str, libname: str, soname: str) -> None:
        """Make the soname link to the library as ldconfig's create_links does, where missing."""
        r = self.r
        full_so, full_lib = f"{path}/{soname}", f"{path}/{libname}"
        do_link = do_remove = True
        st_so = r.stat(full_so)
        if st_so is not None:
            st_lib = r.stat(full_lib)
            if st_lib is None:
                return
            if self.debian and soname in LD_SONAMES:
                do_link = False
            if (st_lib.st_dev, st_lib.st_ino) == (st_so.st_dev, st_so.st_ino):
                do_link = False
            else:
                lst = r.stat(full_so, follow=False)
                if lst is not None and not stat.S_ISLNK(lst.st_mode):
                    do_link = do_remove = False
        else:
            lst = r.stat(full_so, follow=False)
            if lst is None or not stat.S_ISLNK(lst.st_mode):
                do_remove = False
        if do_link:
            if do_remove:
                r.remove(full_so)
            r.symlink(libname, full_so)
            self.log(f"synthesised {full_so} -> {libname}, as ldconfig does")

    # ---------------------------------------------------------------- the cache
    def run(self) -> bytes:
        """The directories, the files and the cache, as `ldconfig` with no option makes them."""
        self.parse_conf("/etc/ld.so.conf")
        self.builtin_dirs()
        for entry in self.dirs:
            self.search_dir(entry)
        return self.cache()

    def cache(self) -> bytes:
        # the entries in cache.c's order: by soname, the later version first, then the higher
        # flags first, then the glibc-hwcaps entries before the plain one, in their names' order;
        # stable sorts, the last key first
        enc = "utf-8", "surrogateescape"
        entries = sorted(self.entries, key=lambda e: (e.hwcaps is None, e.hwcaps or ""))
        entries.sort(key=lambda e: e.flags, reverse=True)
        entries.sort(key=lambda e: version_key(e.lib.encode(*enc)), reverse=True)
        hwcaps = sorted({e.hwcaps for e in entries if e.hwcaps is not None})
        index = {name: i for i, name in enumerate(hwcaps)}
        strings = _StringTable({e.lib for e in entries} | {e.path for e in entries} | set(hwcaps))
        str_offset = 48 + 24 * len(entries)
        body = bytearray()
        for e in entries:
            hwcap = (
                HWCAP_EXTENSION | (e.isa_level << 32) | index[e.hwcaps]
                if e.hwcaps is not None
                else 0
            )
            body += e.flags.to_bytes(4, "little")
            body += (str_offset + strings.offset[e.lib]).to_bytes(4, "little")
            body += (str_offset + strings.offset[e.path]).to_bytes(4, "little")
            body += bytes(4) + hwcap.to_bytes(8, "little")
        ext_offset = (str_offset + len(strings.data) + 3) & ~3
        header = (
            MAGIC
            + len(entries).to_bytes(4, "little")
            + len(strings.data).to_bytes(4, "little")
            + bytes([ENDIAN_LITTLE, 0, 0, 0])
            + ext_offset.to_bytes(4, "little")
            + bytes(12)
        )
        gen = (self.generator or "").encode("utf-8", "surrogateescape")
        # the extension directory is sized for both tags; without hwcaps the generator moves up
        hwcaps_offset = ext_offset + 8 + 2 * 16
        hwcaps_size = 4 * len(hwcaps)
        gen_offset = hwcaps_offset + hwcaps_size if hwcaps else hwcaps_offset - 16
        sections = [(TAG_GENERATOR, 0, gen_offset, len(gen))]
        if hwcaps:
            sections.append((TAG_GLIBC_HWCAPS, 0, hwcaps_offset, hwcaps_size))
        ext = EXTENSION_MAGIC.to_bytes(4, "little") + len(sections).to_bytes(4, "little")
        for sec in sections:
            ext += b"".join(x.to_bytes(4, "little") for x in sec)
        ext += b"".join((str_offset + strings.offset[n]).to_bytes(4, "little") for n in hwcaps)
        out = header + bytes(body) + strings.data
        return out + bytes(ext_offset - len(out)) + ext + gen


class _StringTable:
    """The cache's string table: every string once, tail-merged in stringtable.c's order.

    The strings sorted by their tails, the greater byte first and, of a string and its own tail,
    the longer first, so that each tail follows the string that holds it.
    """

    def __init__(self, strings: set[str]) -> None:
        encoded = {s: s.encode("utf-8", "surrogateescape") for s in strings}
        order = sorted(set(encoded.values()), key=lambda b: b[::-1], reverse=True)
        offsets: dict[bytes, int] = {}
        data = bytearray()
        previous: bytes | None = None
        for s in order:
            if previous is not None and previous.endswith(s):
                offsets[s] = offsets[previous] + len(previous) - len(s)
            else:
                offsets[s] = len(data)
                data += s + b"\0"
            previous = s
        self.data = bytes(data)
        self.offset = {s: offsets[b] for s, b in encoded.items()}


def find_ldconfig(r: Root) -> str | None:
    """The tree's static ldconfig, by the names the distributions give it."""
    for cand in LDCONFIG:
        if r.isfile(cand) and r.read_bytes(cand, 4) == b"\x7fELF":
            return cand
    return None


def write(r: Root, ldconfig: str, log: Log) -> bool:
    """Write /etc/ld.so.cache as the tree's ldconfig would, mode 0644; False when it could not."""
    if not r.isdir("/etc"):
        log("no /etc: ldconfig would write no cache")
        return False
    run = Ldconfig(r, ldconfig, log)
    if run.loader is None:
        log("no glibc loader in the tree: no built-in directories for ld.so.cache")
    data = run.run()
    if r.lexists("/etc/ld.so.cache"):
        r.remove("/etc/ld.so.cache")
    r.write_bytes("/etc/ld.so.cache", data, 0o644)
    r.chmod("/etc/ld.so.cache", 0o644)
    return True
