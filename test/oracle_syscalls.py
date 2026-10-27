"""Compare the kernel's and the launcher's answer to every trapped syscall (DESIGN.md 17 item 7).

This is the differential syscall probe. One program (test/progs/probe.c) issues every trapped path
and descriptor syscall of src/filter.c, and the two chattr ioctls, with every path form of 7.4.4
and every flag that changes resolution, over a random maze. It runs under two projections of the
same tree: the kernel's, a bwrap read-only bind of the unwrapped tree at /, and the launcher's.
Return value, errno and what a buffer holds afterwards must agree case by case, and a difference
fails unless EXPECTED names its reason, so the expectations come from the kernel, not from a test's
author. Like oracle_ns, the probe needs user namespaces and bwrap; without them it says so ("cannot
run") and exits 0, and the gate prints that step as SKIP.

    test/oracle_syscalls.py --exclave EXCLAVE [--work DIR] [--seed S] [--only NAME] [--keep]
        [--show N] [--expected]

Arguments. probe.c reads cases, each a syscall number and encoded arguments, and issues each through
syscall(2), so no libc wrapper stands in between; it prints the return value, the errno and what a
buffer holds afterwards. An argument is one of: a path (s:), or a descriptor opened on a named path
before the call (f:); an integer (i:) or a buffer of a named kind; a string that ends at an unmapped
page (e:), a null pointer (n:) or a pointer into an unmapped page (u:); a string vector or a struct
xattr_args; an inotify descriptor, a unix socket (k:) or a sockaddr_un (A:); a struct open_how.
execve runs in a forked child whose exit status is the answer.

Cases. The table covers the trapped path syscalls and the descriptor-addressed ones (fchmod, fchown,
fsetxattr, fremovexattr, fstatfs, and ioctl with FS_IOC_SETFLAGS and FS_IOC_FSSETXATTR), crossed
with every flag that changes resolution, with the invalid arguments the kernel checks before the
lookup, and with the path forms of class Forms over a random maze:
  - inside the exclave: a file, a directory and a symlink of every kind (loop, chained, dangling,
    absolute, relative), a wrapper, the shell's link, an identity file, a placeholder,
    /proc/self/exe, and an exclave link to a host file and to a host directory;
  - on the host: files, directories and links of every kind, and relative paths from the host side,
    up to the root and back into the tree;
  - spellings: ., .. and / as the last component, a trailing slash, //, empty, overlong, a 256-byte
    component, bytes that are not UTF-8, and a newline;
  - the three fault forms, and a socket file in the tree.
The *at forms add descriptors opened O_PATH or O_RDONLY on exclave and host directories, files and
symlinks, a wrapper, /dev/null, AT_FDCWD, a closed descriptor and a negative one. The two-path forms
take pairs from a shorter list (Forms.few). openat2 covers every descriptor-relative form with seven
flag words and seven resolve words, plus its struct's own rules. Cases that depend on one another
run in one group, in order, such as the relative forms after a chdir into the exclave; each world
runs one process per group, with the host area reset before each world, and the answers are compared
line by line.

The two worlds. The same binary, compiled by the exclave's compiler, runs under bwrap, with the
unwrapped tree read-only at / and the visibility rule of 8.1 spelt in bwrap's terms (the identity
files and the host's top-level directories bound from the host), and under the launcher, with a copy
of the exclave relinked with the build.

openat2 and EAGAIN. A scoped walk (RESOLVE_BENEATH, RESOLVE_IN_ROOT) answers EAGAIN when a rename or
a mount anywhere on the system raced it (handle_dots in fs/namei.c), and openat2(2) tells the caller
to retry; probe.c does, so the kernel's answer is the retry's. Measured natively under 170 000
renames a second, 4 900 of a million such walks answered EAGAIN and every one succeeded on its first
retry; with no renames, none of a million did. RESOLVE_CACHED's EAGAIN is not a race and is not
retried.

Accepted differences. EXPECTED is part of the design (DESIGN.md 17 item 7): each entry names the
rule that makes a difference right, and a difference no entry names fails. The entries are of three
kinds:
  - the oracle's own construction: a host entry bound into bwrap's read-only root answers EROFS
    there; uid 0 is unmapped in bwrap's user namespace; a new top-level name is the host's (8.1),
    whose / answers EACCES where bwrap's root says EROFS; an identity symlink whose host target is
    on a tmpfs gives other xattr answers than the tree copy; RESOLVE_CACHED answers EAGAIN under
    bwrap's cold cache;
  - stated limitations: fanotify_mark's order of checks (13 item 41); ETXTBSY before EROFS when
    another gate step runs the exclave copy's shell while the probe write-opens it (13 item 29);
  - for the kernel matrix (12.1), what an older kernel lacks or decided differently, each with the
    kernel change, the handler answering as the newest kernel does: ENOSYS for a syscall the kernel
    lacks; EISDIR for O_CREAT|O_EXCL on ., .. or / before 5.8; linkat with AT_EMPTY_PATH refused
    with ENOENT before 6.10; RENAME_WHITEOUT's capability check in the initial user namespace;
    O_DIRECTORY|O_CREAT opening or creating before 6.3; RHEL 8's 4.18 openat2 answering EXDEV for a
    create through a symlink under RESOLVE_NO_XDEV; RESOLVE_CACHED unknown before 5.12; utimensat
    refusing AT_EMPTY_PATH and checking the nanoseconds first before 5.9; an exec of a socket
    answered ENXIO before 5.9; truncate checking the mount before the permission on 6.1 and earlier
    (6.14 checks the permission first).
More differences are accepted on older kernels, where more of the kernel entries apply.

Counts. The last line of the output gives the number of cases, of groups (one per syscall, plus
the cases run after a chdir into the exclave) and of path forms, then the differences and those
accepted. Most accepted differences are RESOLVE_CACHED's EAGAIN, whose count moves by a few between
runs. The number of cases depends on the machine and the work directory: a syscall missing from the
machine's table is left out, and so is a host-area socket address longer than sun_path's 107 bytes,
which no program could write whole, so a deeper work directory gives fewer cases.
"""

import argparse
import errno
import os
import platform
import random
import re
import shutil
import subprocess
import sys
lazy from collections.abc import Callable

import tree
from oracle_resolve import make_maze
from syscalls import kernel_table

from exclave import build, layout

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


MACHINE = platform.machine()
# orderings have moved between kernels (8.2)
RELEASE = re.match(r"(\d+)\.(\d+)", os.uname().release)
assert RELEASE
KERNEL = tuple(int(x) for x in RELEASE.groups())
O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_TRUNC = 0, 1, 2, os.O_CREAT, os.O_EXCL, os.O_TRUNC
# this machine's bits
O_DIRECTORY, O_NOFOLLOW, O_PATH, O_TMPFILE = os.O_DIRECTORY, os.O_NOFOLLOW, os.O_PATH, os.O_TMPFILE
AT_FDCWD, AT_SYMLINK_NOFOLLOW, AT_REMOVEDIR, AT_SYMLINK_FOLLOW, AT_EMPTY_PATH, AT_EACCESS = (
    -100,
    0x100,
    0x200,
    0x400,
    0x1000,
    0x200,
)
RENAME_NOREPLACE, RENAME_EXCHANGE, RENAME_WHITEOUT = 1, 2, 4
(
    RESOLVE_NO_XDEV,
    RESOLVE_NO_MAGICLINKS,
    RESOLVE_NO_SYMLINKS,
    RESOLVE_BENEATH,
    RESOLVE_IN_ROOT,
    RESOLVE_CACHED,
) = 1, 2, 4, 8, 0x10, 0x20
UTIME_NOW, UTIME_OMIT = (1 << 30) - 1, (1 << 30) - 2
FS_IOC_SETFLAGS = 0x40086602  # _IOW('f', 2, long), the same on both machines
FS_IOC_FSSETXATTR = 0x401C5820  # _IOW('X', 32, struct fsxattr), the same on both machines
IN_MODIFY = 2
STATX_BASIC_STATS = 0x7FF
# the identity files the launcher answers from the host (8.4)
IDENTITY = build.IDENTITY_FILES


def hx(s: str | bytes) -> str:
    """Return the hex of a path, spelt as the kernel takes it."""
    return s.encode("utf-8", "surrogateescape").hex() if isinstance(s, str) else s.hex()


SOCK_STREAM, SOCK_DGRAM = 1, 2

# Each of the one-letter functions makes an argument token for probe.c, named for the token's
# letter.


def K(type_: int) -> str:  # noqa: N802 -- a token's constructor, named for its token's letter
    """Make a unix socket descriptor of this type."""
    return f"k:{type_}"


def A(path: str) -> str:  # noqa: N802 -- as K
    """Make a sockaddr_un holding path, at most 108 bytes of it.

    At 108 bytes the path is unterminated, as the kernel allows.
    """
    return "A:" + path.encode("utf-8", "surrogateescape")[:108].hex()


def alen(path: str) -> int:
    """Return A(path)'s length argument: the family, the bytes, and a NUL when there is room."""
    n = min(len(path.encode("utf-8", "surrogateescape")), 108)
    return 2 + n + (1 if n < 108 else 0)


def unwritable(host_area: str, path: str) -> bool:
    """Tell whether path is in the host area and past sun_path's 107 bytes.

    No program can write such an address whole. The kernel's answer would be for the cut name,
    outside the area, so the case tests the work directory's depth rather than the translation,
    and is left out.
    """
    return path.startswith(host_area) and len(path.encode("utf-8", "surrogateescape")) > 107


# the relative socket name: one per driver, since a chdir into /tmp binds it in the host's /tmp
REL_SOCK = f"probe-sock-{os.getpid()}"


def raw_of(tok: str) -> str | None:
    """Return the path behind an s: token, or None for the fault forms a sockaddr cannot carry."""
    return (
        bytes.fromhex(tok[2:]).decode("utf-8", "surrogateescape") if tok.startswith("s:") else None
    )


def S(path: str) -> str:  # noqa: N802 -- as K
    """Make a string argument."""
    return "s:" + hx(path)


def I(n: int) -> str:  # noqa: E743, N802 -- as K
    """Make an integer argument."""
    return f"i:{n}"


def F(flags: int, path: str) -> str:  # noqa: N802 -- as K
    """Make a descriptor opened on path with flags before the call."""
    return f"f:{flags}:{hx(path)}"


def B(kind: str, size: int) -> str:  # noqa: N802 -- as K
    """Make a buffer of a named kind."""
    return f"b:{kind}:{size}"


def V(*strings: str) -> str:  # noqa: N802 -- as K
    """Make a string vector."""
    return "v:" + ",".join(hx(s) for s in strings)


def X(value: str, flags: int = 0) -> str:  # noqa: N802 -- as K
    """Make a struct xattr_args."""
    return f"x:{hx(value)}:{flags}"


def H(  # noqa: N802 -- as K
    flags: int, mode: int = 0, resolve: int = 0, size: int = 24, tail: int | None = None
) -> str:
    """Make a struct open_how."""
    return f"h:{flags}:{mode}:{resolve}:{size}" + (f":{tail}" if tail is not None else "")


def decode(tok: str) -> str:
    """A token back to something readable, for the report."""
    k, _, p = tok.partition(":")
    if k == "s":
        return repr(bytes.fromhex(p).decode("utf-8", "replace"))
    if k == "f":
        fl, _, h = p.partition(":")
        return "fd({},{!r})".format(fl, bytes.fromhex(h).decode("utf-8", "replace"))
    if k == "e":
        return "unterminated({!r})".format(bytes.fromhex(p).decode("utf-8", "replace"))
    if k == "v":
        return "[{}]".format(
            ",".join(repr(bytes.fromhex(h).decode("utf-8", "replace")) for h in p.split(",") if h)
        )
    return tok


class Forms:
    """The path forms of 7.4.4 over this maze, this tree and the host area."""

    def __init__(
        self, root: str, host: str, links: list[str], _dirs: list[str], files: list[str]
    ) -> None:
        self.host = host
        by_kind: dict[str, str] = {}
        for link in links:
            t = os.readlink(os.path.join(root, link.lstrip("/")))
            if t == link:
                kind = "loop"
            elif t.startswith("/maze/l"):
                kind = "link"
            elif "missing" in t:
                kind = "dangling"
            elif t.startswith("/"):
                kind = "abs"
            else:
                kind = "rel"
            by_kind.setdefault(kind, link)
        self.link = by_kind
        # a file in a subdirectory, and a directory that has a file child
        self.file = min(files, key=lambda f: -f.count("/"))
        self.dir = os.path.dirname(self.file)
        self.true = tree.vbin(root, "true")
        self.sh = tree.vbin(root, "sh")
        h = host
        ex = [
            ("exclave_file", self.file),
            ("exclave_dir", self.dir),
            ("maze", "/maze"),
            ("root", "/"),
            ("file_slash", self.file + "/"),
            ("dir_slash", self.dir + "/"),
            ("double_slash", "/" + self.file),
            ("dot", os.path.dirname(self.file) + "/./" + os.path.basename(self.file)),
            (
                "dotdot",
                self.dir + "/../" + self.dir.split("/")[-1] + "/" + os.path.basename(self.file),
            ),
            ("above_root", "/.." + self.file),
            ("missing", "/maze/missing"),
            ("missing_slash", "/maze/missing/"),
            ("missing_mid", "/maze/missing/x"),
            ("dot_last", self.dir + "/."),
            ("dotdot_last", self.dir + "/.."),
            ("root_dotdot", "/.."),
            ("notdir_mid", self.file + "/x"),
            ("empty", ""),
            ("wrapper", self.true),
            ("sh_link", self.sh),
            # a file its owner cannot write, and a special file: access(W_OK) has its own order
            ("ro_file", "/maze/ro444"),
            ("sock", "/maze/sock"),
            ("passwd", "/etc/passwd"),
            ("resolv", "/etc/resolv.conf"),
            ("tmp", "/tmp"),
            ("dev_null", "/dev/null"),
            ("proc_exe", "/proc/self/exe"),
            ("proc_cwd", "/proc/self/cwd"),
            ("home", "/home"),
            ("opt", "/opt"),
            ("exclave_to_host", "/maze/lH"),
            ("exclave_to_host_dir", "/maze/lHD"),
            ("overlong", "/maze/" + "a" * 5000),
            ("long_component", "/maze/" + "b" * 256),
            ("long_ok", "/maze/" + "c" * 255),
            ("non_utf8", "/maze/\udcff\udcfe"),
            ("newline", "/maze/a\nb"),
        ]
        for kind, link in sorted(by_kind.items()):
            ex.append(("link_" + kind, link))
        hostf = [
            ("host_file", h + "/hfile"),
            ("host_dir", h + "/hdir"),
            ("host_to_exclave", h + "/hlink"),
            ("host_to_exclave_dir", h + "/hlnkdir"),
            ("host_dangling", h + "/hdang"),
            ("host_loop", h + "/hloop"),
            ("host_rel_link", h + "/hrel"),
            ("host_missing", h + "/missing"),
            ("host_dotdot", h + "/hdir/../hfile"),
            ("host_file_slash", h + "/hfile/"),
            ("host_tmp_new", f"/tmp/exclave-probe-{os.getpid()}/new"),
            ("host_dot_last", h + "/hdir/."),
            ("host_dotdot_last", h + "/hdir/.."),
            ("rel_file", "hfile"),
            ("rel_dot", "."),
            ("rel_dotdot", ".."),
            ("rel_dot_dir", "./hdir"),
            ("rel_up", "../" + os.path.basename(h) + "/hfile"),
            ("rel_via_link", "hdir/../hlink"),
            # up to the root from the host area, and into the tree
            ("rel_root_by_dotdot", "../" * h.count("/") + "."),
            ("rel_etc_by_dotdot", "../" * h.count("/") + "etc/passwd"),
        ]
        self.paths = [(n, S(p)) for n, p in ex + hostf]
        self.paths += [
            ("fault_end", "e:" + hx(self.file)),
            ("fault_null", "n:"),
            ("fault_unmapped", "u:"),
        ]
        # no /tmp here: bwrap's bind makes it another mount, so a link or rename into it is EXDEV
        # there and not natively
        self.few = [
            (n, S(p))
            for n, p in [
                ("exclave_file", self.file),
                ("exclave_dir", self.dir),
                ("missing", "/maze/missing"),
                ("dir_slash", self.dir + "/"),
                ("file_slash", self.file + "/"),
                ("above_root", "/.." + self.file),
                ("empty", ""),
                ("wrapper", self.true),
                ("host_file", h + "/hfile"),
                ("host_dir", h + "/hdir"),
                ("host_missing", h + "/missing"),
                ("host_to_exclave", h + "/hlink"),
                ("rel_file", "hfile"),
            ]
        ] + [("fault_null", "n:")]
        # descriptor-relative forms: (label, dirfd token, path token)
        rel_ex = [
            "",
            ".",
            "..",
            "../" + os.path.basename(self.file),
            os.path.basename(self.file),
            "nonexistent",
            "../../etc/passwd",
            "../../../../tmp",
            self.file,
        ]
        rel_host = ["", ".", "..", "inner", "../hfile", "../hlink", "nonexistent", self.file]
        self.at = [("cwd/" + n, I(AT_FDCWD), p) for n, p in self.paths]
        self.at += [("dfd_exclave/" + r, F(O_PATH | O_DIRECTORY, self.dir), S(r)) for r in rel_ex]
        self.at += [
            ("dfd_exclave_rd/" + r, F(O_RDONLY | O_DIRECTORY, self.dir), S(r))
            for r in ("", "..", os.path.basename(self.file))
        ]
        self.at += [("dfd_host/" + r, F(O_PATH, h + "/hdir"), S(r)) for r in rel_host]
        self.at += [
            ("ffd_exclave/" + r, F(O_RDONLY, self.file), S(r)) for r in ("", "x", ".", self.file)
        ]
        self.at += [("ffd_host/" + r, F(O_RDONLY, h + "/hfile"), S(r)) for r in ("", "x")]
        self.at += [("ffd_host_w/", F(O_WRONLY, h + "/hfile"), S(""))]
        self.at += [("lfd_exclave/", F(O_PATH | O_NOFOLLOW, by_kind.get("abs", self.file)), S(""))]
        self.at += [
            ("lfd_sh/", F(O_PATH | O_NOFOLLOW, self.sh), S("")),
            ("lfd_dang/", F(O_PATH | O_NOFOLLOW, h + "/hdang"), S("")),
        ]
        self.at += [
            ("wfd/", F(O_RDONLY, self.true), S("")),
            ("wfd_path/", F(O_PATH, self.true), S("")),
        ]
        self.at += [
            ("devnull_fd/", F(O_RDONLY, "/dev/null"), S("")),
            ("tmpfd/", F(O_PATH | O_DIRECTORY, "/tmp"), S(f"exclave-probe-{os.getpid()}")),
        ]
        self.at += [
            ("badfd/" + n, I(-1), p)
            for n, p in [("rel", S("x")), ("abs", S(self.file)), ("empty", S(""))]
        ]
        self.at += [
            ("closedfd/" + n, I(999), p) for n, p in [("rel", S("x")), ("abs", S(self.file))]
        ]
        self.at_few = [("cwd/" + n, I(AT_FDCWD), p) for n, p in self.few]
        self.at_few += [
            ("dfd_exclave/" + r, F(O_PATH | O_DIRECTORY, self.dir), S(r))
            for r in ("", os.path.basename(self.file), "nonexistent")
        ]
        self.at_few += [
            ("dfd_host/" + r, F(O_PATH, h + "/hdir"), S(r))
            for r in ("", "inner", "nonexistent", "../hfile")
        ]
        self.at_few += [
            ("ffd_exclave/", F(O_RDONLY, self.file), S("")),
            ("ffd_host/", F(O_RDONLY, h + "/hfile"), S("")),
            ("badfd/rel", I(-1), S("x")),
        ]
        # descriptors for the descriptor-addressed syscalls
        self.fds = [
            ("exclave_file_rd", F(O_RDONLY, self.file)),
            ("exclave_file_path", F(O_PATH, self.file)),
            ("exclave_dir", F(O_RDONLY | O_DIRECTORY, self.dir)),
            ("wrapper", F(O_RDONLY, self.true)),
            ("host_file_rd", F(O_RDONLY, h + "/hfile")),
            ("host_file_wr", F(O_WRONLY, h + "/hfile")),
            ("host_dir", F(O_RDONLY | O_DIRECTORY, h + "/hdir")),
            ("dev_null", F(O_RDONLY, "/dev/null")),
            ("badfd", I(-1)),
        ]


def generate(
    forms: Forms, nr: dict[str, int], uid: int, gid: int
) -> list[tuple[str, str, list[str], str]]:
    """(label, syscall name, [tokens], group) for every case.

    A name absent from this machine's table is skipped.
    """
    out: list[tuple[str, str, list[str], str]] = []
    # cases that depend on one another run in one group, in order; None groups by syscall
    group: str | None = None

    def add(name: str, label: str, *toks: str) -> None:
        if name in nr:
            out.append((label, name, list(toks), group or name))

    open_flags = [
        ("rd", O_RDONLY),
        ("wr", O_WRONLY),
        ("rdwr", O_RDWR),
        ("rd_creat", O_RDONLY | O_CREAT),
        ("wr_creat", O_WRONLY | O_CREAT),
        ("wr_creat_excl", O_WRONLY | O_CREAT | O_EXCL),
        ("rd_trunc", O_RDONLY | O_TRUNC),
        ("wr_trunc", O_WRONLY | O_TRUNC),
        ("path", O_PATH),
        ("path_nofollow", O_PATH | O_NOFOLLOW),
        ("rd_nofollow", O_RDONLY | O_NOFOLLOW),
        ("rd_dir", O_RDONLY | O_DIRECTORY),
        ("tmpfile", O_RDWR | O_TMPFILE),
    ]
    stat_flags = [
        ("follow", 0),
        ("nofollow", AT_SYMLINK_NOFOLLOW),
        ("empty", AT_EMPTY_PATH),
        ("nofollow_empty", AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH),
    ]
    for n, p in forms.paths:
        for fn, fl in open_flags:
            if n == "proc_exe" and fl & O_TRUNC:
                # would truncate the running probe: the kernel says ETXTBSY,
                # the launcher does not (13)
                continue
            add("open", f"{n}/{fn}", p, I(fl), I(0o644))
        if n != "proc_exe":
            add("creat", n, p, I(0o644))
        add("stat", n, p, B("stat", 256))
        add("lstat", n, p, B("stat", 256))
        for mn, m in (("F_OK", 0), ("R_OK", 4), ("W_OK", 2), ("X_OK", 1)):
            add("access", f"{n}/{mn}", p, I(m))
        add("readlink", n, p, B("link", 4096), I(4096))
        add("readlink", n + "/short", p, B("link", 4), I(4))
        add("readlink", n + "/zero", p, B("link", 4), I(0))
        # an int argument with bits above the word: the kernel sees 0
        add("readlink", n + "/hi_zero", p, B("link", 4), I(1 << 32))
        add("readlink", n + "/hi_minus", p, B("link", 4), I((1 << 32) | 0xFFFFFFFF))  # and -1
        if n != "proc_exe":
            add("truncate", n, p, I(0))
        add("mkdir", n, p, I(0o755))
        add("rmdir", n, p)
        add("unlink", n, p)
        add("symlink", n, S("/maze/f0"), p)
        add("chmod", n, p, I(0o644))
        add("chown", n, p, I(uid), I(gid))
        add("chown", n + "/to_root", p, I(0), I(0))
        add("lchown", n, p, I(uid), I(gid))
        add("utime", n, p, "U:1000,2000")
        add("utime", n + "/null", p, "n:")
        add("utimes", n, p, "T:1000,0,2000,0")
        add("utimes", n + "/bad_usec", p, "T:1000,1000000,2000,0")
        add("mknod", n + "/fifo", p, I(0o10644), I(0))
        add("mknod", n + "/reg", p, I(0o100644), I(0))
        add("statfs", n, p, B("raw", 256))
        add("setxattr", n, p, S("user.probe"), S("v"), I(1), I(0))
        add("lsetxattr", n, p, S("user.probe"), S("v"), I(1), I(0))
        add("getxattr", n, p, S("user.probe"), B("xattr", 64), I(64))
        add("lgetxattr", n, p, S("user.probe"), B("xattr", 64), I(64))
        add("listxattr", n, p, B("xattr", 512), I(512))
        add("llistxattr", n, p, B("xattr", 512), I(512))
        add("removexattr", n, p, S("user.probe"))
        add("lremovexattr", n, p, S("user.probe"))
        add("inotify_add_watch", n, "I:", p, I(IN_MODIFY))
        add("fanotify_mark", n, I(-1), I(0), I(0), I(AT_FDCWD), p)
        # the arguments the kernel checks before the lookup (13 item 11)
        if n != "proc_exe":
            add("truncate", n + "/negative", p, I(-1))
        add("mknod", n + "/dir_type", p, I(0o40755), I(0))
        add("mknod", n + "/bad_type", p, I(0o170644), I(0))
        add("symlink", n + "/empty_target", S(""), p)
        add("symlink", n + "/null_target", "n:", p)
        add("setxattr", n + "/empty_name", p, S(""), S("v"), I(1), I(0))
        add("setxattr", n + "/bad_flags", p, S("user.probe"), S("v"), I(1), I(0x10))
        add("setxattr", n + "/too_big", p, S("user.probe"), S("v"), I(65537), I(0))
        add("getxattr", n + "/empty_name", p, S(""), B("xattr", 64), I(64))
        add("removexattr", n + "/empty_name", p, S(""))
        add("inotify_add_watch", n + "/bad_fd", I(-1), p, I(IN_MODIFY))
        add("inotify_add_watch", n + "/no_events", "I:", p, I(0))
        add("inotify_add_watch", n + "/not_inotify", F(O_RDONLY, forms.file), p, I(IN_MODIFY))
        add("execve", n, p, V("x"), V())
        raw = raw_of(p)
        if raw is not None and not unwritable(
            forms.host, raw
        ):  # a sockaddr_un path is a path (13 item 31)
            add("bind", n, K(SOCK_STREAM), A(raw), I(alen(raw)))
            add("connect", n, K(SOCK_STREAM), A(raw), I(alen(raw)))
        group = "chdir"
        add("chdir", n, p)
        add("getcwd", n + "/after_chdir", B("cwd", 4096), I(4096))
        add("stat", n + "/after_chdir_dot", S("."), B("stat", 256))
        add("stat", n + "/after_chdir_dotdot", S(".."), B("stat", 256))
        # a relative bind from that directory
        add("bind", n + "/after_chdir_rel", K(SOCK_STREAM), A(REL_SOCK), I(alen(REL_SOCK)))
        add("connect", n + "/after_chdir_rel", K(SOCK_STREAM), A(REL_SOCK), I(alen(REL_SOCK)))
        add("chdir", n + "/back", S(forms.host))
        group = None
    add("getcwd", "short", B("cwd", 4), I(4))
    add("getcwd", "all_ones", B("cwd", 4096), I(-1))
    for name in ("bind", "connect"):  # the structure's own rules, and a socket file in the tree
        add(name, "exclave_sock", K(SOCK_STREAM), A("/maze/sock"), I(alen("/maze/sock")))
        add(name, "exclave_sock_dgram", K(SOCK_DGRAM), A("/maze/sock"), I(alen("/maze/sock")))
        # one name per process
        add(
            name,
            "abstract",
            K(SOCK_STREAM),
            A(f"\0probe-abstract-{os.getpid()}"),
            I(alen(f"\0probe-abstract-{os.getpid()}")),
        )
        add(name, "unnamed", K(SOCK_STREAM), A(""), I(2))
        add(name, "len_too_long", K(SOCK_STREAM), A(forms.file), I(200))
        add(name, "len_too_short", K(SOCK_STREAM), A(forms.file), I(1))
        add(name, "len_hi", K(SOCK_STREAM), A("/maze/sock"), I((1 << 32) | alen("/maze/sock")))
        add(name, "null_addr", K(SOCK_STREAM), "n:", I(20))
        add(name, "fault_addr", K(SOCK_STREAM), "u:", I(20))
        if not unwritable(forms.host, forms.host + "/hfile"):
            add(
                name,
                "not_a_socket",
                F(O_RDONLY, forms.file),
                A(forms.host + "/hfile"),
                I(alen(forms.host + "/hfile")),
            )
    add("stat", "exclave_sock", S("/maze/sock"), B("stat", 256))
    add("execve", "true", S(forms.true), V("true"), V())
    add("execve", "sh_exit3", S(forms.sh), V("sh", "-c", "exit 3"), V("PATH=/usr/bin:/bin"))
    add("execve", "argv_null", S(forms.true), "n:", V())
    add("execve", "rel_true", S("hlink"), V("x"), V())
    for n, d, p in forms.at:
        for fn, fl in open_flags:
            add("openat", f"{n}/{fn}", d, p, I(fl), I(0o644))
        add("mkdirat", n, d, p, I(0o755))
        add("mknodat", n, d, p, I(0o10644), I(0))
        for fn, fl in (("follow", 0), ("nofollow", AT_SYMLINK_NOFOLLOW), ("empty", AT_EMPTY_PATH)):
            add("fchownat", f"{n}/{fn}", d, p, I(uid), I(gid), I(fl))
        add("futimesat", n, d, p, "T:1000,0,2000,0")
        for fn, fl in stat_flags:
            add("newfstatat", f"{n}/{fn}", d, p, B("stat", 256), I(fl))
            add("statx", f"{n}/{fn}", d, p, I(fl), I(STATX_BASIC_STATS), B("statx", 256))
        add("unlinkat", n, d, p, I(0))
        add("unlinkat", n + "/rmdir", d, p, I(AT_REMOVEDIR))
        # the arguments the kernel checks before the lookup (13 item 11)
        add("unlinkat", n + "/bad_flags", d, p, I(1))
        add("mknodat", n + "/dir_type", d, p, I(0o40755), I(0))
        add("fchownat", n + "/bad_flags", d, p, I(uid), I(gid), I(1))
        add("newfstatat", n + "/bad_flags", d, p, B("stat", 256), I(1))
        add("statx", n + "/reserved_mask", d, p, I(0), I(0x80000000), B("statx", 256))
        add("statx", n + "/both_syncs", d, p, I(0x6000), I(STATX_BASIC_STATS), B("statx", 256))
        add("statx", n + "/bad_flags", d, p, I(1), I(STATX_BASIC_STATS), B("statx", 256))
        add("faccessat", n + "/bad_mode", d, p, I(8))
        add("faccessat2", n + "/bad_flags", d, p, I(4), I(1))
        add("fchmodat2", n + "/bad_flags", d, p, I(0o644), I(1))
        add("symlinkat", n + "/empty_target", S(""), d, p)
        add("symlinkat", n, S("/maze/f0"), d, p)
        add("readlinkat", n, d, p, B("link", 4096), I(4096))
        add("readlinkat", n + "/zero", d, p, B("link", 4), I(0))
        add("readlinkat", n + "/hi_two", d, p, B("link", 4), I((1 << 32) | 2))
        add("fchmodat", n, d, p, I(0o644))
        add("faccessat", n, d, p, I(4))
        add("faccessat", n + "/W", d, p, I(2))
        add("faccessat2", n, d, p, I(4), I(0))
        add("faccessat2", n + "/eaccess", d, p, I(2), I(AT_EACCESS))
        add("fchmodat2", n, d, p, I(0o644), I(0))
        add("fchmodat2", n + "/nofollow", d, p, I(0o644), I(AT_SYMLINK_NOFOLLOW))
        add("utimensat", n, d, p, "t:1000,0,2000,0", I(0))
        add("utimensat", n + "/nofollow", d, p, "t:1000,0,2000,0", I(AT_SYMLINK_NOFOLLOW))
        add("utimensat", n + "/now", d, p, f"t:0,{UTIME_NOW},0,{UTIME_NOW}", I(0))
        add("utimensat", n + "/omit", d, p, f"t:0,{UTIME_OMIT},0,{UTIME_OMIT}", I(0))
        add("utimensat", n + "/null_times", d, p, "n:", I(0))
        add("utimensat", n + "/bad_nsec", d, p, "t:0,1000000000,0,0", I(0))
        add("utimensat", n + "/bad_flags", d, p, "t:1000,0,2000,0", I(0x8000))
        add("utimensat", n + "/hi_flags", d, p, "t:1000,0,2000,0", I(1 << 32))
        add("utimensat", n + "/empty", d, p, "t:1000,0,2000,0", I(AT_EMPTY_PATH))
        add("futimesat", n + "/bad_usec", d, p, "T:1000,0,2000,-1")
        add("execveat", n, d, p, V("x"), V(), I(0))
        add("execveat", n + "/empty", d, p, V("x"), V(), I(AT_EMPTY_PATH))
        add("setxattrat", n, d, p, I(0), S("user.probe"), X("v"), I(16))
        add(
            "setxattrat",
            n + "/nofollow",
            d,
            p,
            I(AT_SYMLINK_NOFOLLOW),
            S("user.probe"),
            X("v"),
            I(16),
        )
        add("getxattrat", n, d, p, I(0), S("user.probe"), X("\0" * 64), I(16))
        add("listxattrat", n, d, p, I(0), B("xattr", 512), I(512))
        add("removexattrat", n, d, p, I(0), S("user.probe"))
        add("file_getattr", n, d, p, B("raw", 32), I(32), I(0))
        add("file_setattr", n, d, p, B("raw", 32), I(32), I(0))
    # openat2: the resolve flags over every descriptor-relative form, and the struct's own rules
    how_flags = [
        ("rd", O_RDONLY),
        ("wr", O_WRONLY),
        ("wr_creat", O_WRONLY | O_CREAT),
        ("path", O_PATH),
        ("path_nofollow", O_PATH | O_NOFOLLOW),
        ("rd_dir", O_RDONLY | O_DIRECTORY),
        ("tmpfile", O_RDWR | O_TMPFILE),
    ]
    resolves = [
        ("plain", 0),
        ("no_xdev", RESOLVE_NO_XDEV),
        ("no_magic", RESOLVE_NO_MAGICLINKS),
        ("no_symlinks", RESOLVE_NO_SYMLINKS),
        ("beneath", RESOLVE_BENEATH),
        ("in_root", RESOLVE_IN_ROOT),
        ("cached", RESOLVE_CACHED),
    ]
    for n, d, p in forms.at:
        for fn, fl in how_flags:
            for rn, rs in resolves:
                add(
                    "openat2",
                    f"{n}/{fn}/{rn}",
                    d,
                    p,
                    H(fl, 0o644 if fl & O_CREAT else 0, rs),
                    I(24),
                )
    for n, d, p in forms.at_few:
        add(
            "openat2",
            n + "/both_scopes",
            d,
            p,
            H(O_RDONLY, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT),
            I(24),
        )
        add("openat2", n + "/bad_resolve", d, p, H(O_RDONLY, 0, 0x100), I(24))
        add("openat2", n + "/bad_flag", d, p, H(O_RDONLY | (1 << 25)), I(24))
        add("openat2", n + "/mode_without_creat", d, p, H(O_RDONLY, 0o644), I(24))
        add("openat2", n + "/creat_bad_mode", d, p, H(O_WRONLY | O_CREAT, 0o10644), I(24))
        add("openat2", n + "/path_rdwr", d, p, H(O_PATH | O_RDWR), I(24))
        add("openat2", n + "/dir_creat", d, p, H(O_DIRECTORY | O_CREAT, 0o644), I(24))
        add("openat2", n + "/tmpfile_rd", d, p, H(O_RDONLY | O_TMPFILE), I(24))
        add("openat2", n + "/short_struct", d, p, H(O_RDONLY, size=16), I(16))
        add("openat2", n + "/long_struct_zero", d, p, H(O_RDONLY, size=32), I(32))
        add("openat2", n + "/long_struct_tail", d, p, H(O_RDONLY, size=32, tail=1), I(32))
        add("openat2", n + "/null_how", d, p, "n:", I(24))
        add("openat2", n + "/huge_struct", d, p, H(O_RDONLY, size=24), I(8192))
    add("utimensat", "fd_null_path", F(O_RDONLY, forms.file), "n:", "t:1000,0,2000,0", I(0))
    add(
        "utimensat",
        "fd_null_path_nofollow",
        F(O_RDONLY, forms.file),
        "n:",
        "t:1000,0,2000,0",
        I(AT_SYMLINK_NOFOLLOW),
    )
    add("utimensat", "fd_null_path_bad_nsec", F(O_RDONLY, forms.file), "n:", "t:0,-5,0,0", I(0))
    add("utimensat", "cwd_null_path", I(AT_FDCWD), "n:", "t:1000,0,2000,0", I(0))
    add(
        "utimensat",
        "hostfd_null_path",
        F(O_WRONLY, forms.host + "/hfile"),
        "n:",
        "t:1000,0,2000,0",
        I(0),
    )
    add(
        "newfstatat",
        "fd_null_empty",
        F(O_RDONLY, forms.file),
        "n:",
        B("stat", 256),
        I(AT_EMPTY_PATH),
    )
    add("newfstatat", "fd_null", F(O_RDONLY, forms.file), "n:", B("stat", 256), I(0))
    # AT_EMPTY_PATH with an empty or a NULL path: the *xattrat and file_*attr calls name the
    # descriptor either way (getname_maybe_null)
    for fn, d in (
        ("fd", F(O_RDONLY, forms.file)),
        ("hostfd", F(O_RDONLY, forms.host + "/hfile")),
        ("cwd", I(AT_FDCWD)),
    ):
        for pn, p in (("empty", S("")), ("null", "n:")):
            lab = f"{fn}_{pn}/empty"
            add("setxattrat", lab, d, p, I(AT_EMPTY_PATH), S("user.probe"), X("v"), I(16))
            add("getxattrat", lab, d, p, I(AT_EMPTY_PATH), S("user.probe"), X("\0" * 64), I(16))
            add("listxattrat", lab, d, p, I(AT_EMPTY_PATH), B("xattr", 512), I(512))
            add("removexattrat", lab, d, p, I(AT_EMPTY_PATH), S("user.probe"))
            add("file_getattr", lab, d, p, B("raw", 32), I(32), I(AT_EMPTY_PATH))
            add("file_setattr", lab, d, p, B("raw", 32), I(32), I(AT_EMPTY_PATH))
    # faccessat2 and fchmodat2 with AT_EMPTY_PATH name the descriptor's own file
    for fn, d in (
        ("fd", F(O_RDONLY, forms.file)),
        ("pathfd", F(O_PATH, forms.file)),
        ("hostfd", F(O_RDONLY, forms.host + "/hfile")),
    ):
        add("faccessat2", f"{fn}_empty/read", d, S(""), I(4), I(AT_EMPTY_PATH))
        add("faccessat2", f"{fn}_empty/write", d, S(""), I(2), I(AT_EMPTY_PATH))
        add("fchmodat2", f"{fn}_empty", d, S(""), I(0o644), I(AT_EMPTY_PATH))
    add("readlinkat", "proc_fd", I(AT_FDCWD), S("/proc/self/fd/0"), B("link", 4096), I(4096))
    add("execveat", "true_fd", F(O_RDONLY, forms.true), S(""), V("true"), V(), I(AT_EMPTY_PATH))
    add("execveat", "true_pathfd", F(O_PATH, forms.true), S(""), V("true"), V(), I(AT_EMPTY_PATH))
    add(
        "execveat",
        "sh_fd",
        F(O_RDONLY, forms.sh),
        S(""),
        V("sh", "-c", "exit 3"),
        V(),
        I(AT_EMPTY_PATH),
    )
    two = forms.few
    for n1, p1 in two:
        for n2, p2 in two:
            lab = f"{n1}->{n2}"
            add("rename", lab, p1, p2)
            add("link", lab, p1, p2)
            add("renameat", lab, I(AT_FDCWD), p1, I(AT_FDCWD), p2)
            for fn, fl in (
                ("plain", 0),
                ("noreplace", RENAME_NOREPLACE),
                ("exchange", RENAME_EXCHANGE),
                ("whiteout", RENAME_WHITEOUT),
            ):
                add("renameat2", f"{lab}/{fn}", I(AT_FDCWD), p1, I(AT_FDCWD), p2, I(fl))
            for fn, fl in (
                ("plain", 0),
                ("follow", AT_SYMLINK_FOLLOW),
                ("empty", AT_EMPTY_PATH),
                ("bad_flags", 1),
            ):
                add("linkat", f"{lab}/{fn}", I(AT_FDCWD), p1, I(AT_FDCWD), p2, I(fl))
            for fn, fl in (
                ("bad_flags", 0x100),
                ("exchange_noreplace", RENAME_EXCHANGE | RENAME_NOREPLACE),
            ):
                add("renameat2", f"{lab}/{fn}", I(AT_FDCWD), p1, I(AT_FDCWD), p2, I(fl))
    # a last component that is ".", ".." or the root, either side: do_renameat2 answers EBUSY
    # before the write check
    dots = [
        ("dot_last", S(forms.dir + "/.")),
        ("dotdot_last", S(forms.dir + "/..")),
        ("root", S("/")),
        ("host_dot_last", S(forms.host + "/hdir/.")),
        ("host_dotdot_last", S(forms.host + "/hdir/..")),
    ]
    for n1, p1 in dots:
        for n2, p2 in [
            (n, p) for n, p in two if n in ("exclave_file", "host_file", "host_missing")
        ]:
            for lab, x, y in ((f"{n1}->{n2}", p1, p2), (f"{n2}->{n1}", p2, p1)):
                add("rename", lab, x, y)
                for fn, fl in (
                    ("plain", 0),
                    ("noreplace", RENAME_NOREPLACE),
                    ("exchange", RENAME_EXCHANGE),
                ):
                    add("renameat2", f"{lab}/{fn}", I(AT_FDCWD), x, I(AT_FDCWD), y, I(fl))
    for n1, d1, p1 in forms.at_few:
        for n2, d2, p2 in forms.at_few:
            lab = f"{n1}->{n2}"
            add("renameat", lab, d1, p1, d2, p2)
            add("linkat", lab, d1, p1, d2, p2, I(0))
    add(
        "linkat",
        "fd_empty",
        F(O_RDONLY, forms.file),
        S(""),
        I(AT_FDCWD),
        S(forms.host + "/hlinked"),
        I(AT_EMPTY_PATH),
    )
    add(
        "linkat",
        "hostfd_empty",
        F(O_RDONLY, forms.host + "/hfile"),
        S(""),
        I(AT_FDCWD),
        S(forms.host + "/hlinked2"),
        I(AT_EMPTY_PATH),
    )
    add(
        "linkat",
        "hostfd_empty_to_exclave",
        F(O_RDONLY, forms.host + "/hfile"),
        S(""),
        I(AT_FDCWD),
        S("/maze/hnew"),
        I(AT_EMPTY_PATH),
    )
    for n, f in forms.fds:
        add("fchmod", n, f, I(0o644))
        add("fchown", n, f, I(uid), I(gid))
        add("fsetxattr", n, f, S("user.probe"), S("v"), I(1), I(0))
        add("fremovexattr", n, f, S("user.probe"))
        add("fsetxattr", n + "/empty_name", f, S(""), S("v"), I(1), I(0))
        add("fremovexattr", n + "/empty_name", f, S(""))
        add("fstatfs", n, f, B("raw", 256))
        # not on a host file: ext4 on 5.10 to 6.1 refuses to clear the extent flag of a file
        # recreated moments after its predecessor was deleted (13), which the reset does
        if not n.startswith("host"):
            add("ioctl", n + "/setflags", f, I(FS_IOC_SETFLAGS), B("raw", 8))
            add("ioctl", n + "/fssetxattr", f, I(FS_IOC_FSSETXATTR), B("raw", 28))
            add("ioctl", n + "/setflags_null", f, I(FS_IOC_SETFLAGS), "n:")
            add("ioctl", n + "/fssetxattr_null", f, I(FS_IOC_FSSETXATTR), "n:")
    # relative paths from a working directory the exclave owns
    rel = [
        "",
        ".",
        "..",
        os.path.basename(forms.file),
        "../" + os.path.basename(forms.file),
        "nonexistent",
        "../../..",
        "../../../../etc/passwd",
        "../../home",
        "./",
    ]
    group = "cwd_in_exclave"
    add("chdir", "into_exclave", S(forms.dir))
    add("getcwd", "in_exclave", B("cwd", 4096), I(4096))
    for r in rel:
        add("stat", "in_exclave/" + r, S(r), B("stat", 256))
        add("open", "in_exclave/" + r, S(r), I(O_RDONLY), I(0))
        add("readlink", "in_exclave/" + r, S(r), B("link", 4096), I(4096))
        add("mkdir", "in_exclave/" + r, S(r), I(0o755))
        add("access", "in_exclave/" + r, S(r), I(2))
    add("utimensat", "in_exclave/null_path", I(AT_FDCWD), "n:", "t:1000,0,2000,0", I(0))
    add("chdir", "up_from_exclave", S(".."))
    add("getcwd", "up_from_exclave", B("cwd", 4096), I(4096))
    add("chdir", "above_root_from_exclave", S("../../../.."))
    add("getcwd", "above_root_from_exclave", B("cwd", 4096), I(4096))
    add("chdir", "back", S(forms.host))
    add("getcwd", "back", B("cwd", 4096), I(4096))
    group = None
    return out


def rmtree(d: str) -> None:
    """Rmtree after a chmod case may have taken the directories' permissions away."""
    if not os.path.isdir(d):
        return
    os.chmod(d, 0o755)
    for top, dirs, _files in os.walk(d):
        for x in dirs:
            if not os.path.islink(os.path.join(top, x)):
                os.chmod(os.path.join(top, x), 0o755)
    shutil.rmtree(d)


def host_reset(host: str, _ex_tree: str, probe: str) -> None:
    """The host area both worlds see at the same path, identical before every run."""
    # a chmod of /proc/self/exe takes the probe's own x bit, and an xattr case leaves an attribute
    # on it: the probe written again as a new file has neither, on any Python (a musl build has no
    # os.listxattr), and the default label
    with open(probe, "rb") as f:
        data = f.read()
    with open(probe + ".reset", "wb") as f:
        f.write(data)
    os.chmod(probe + ".reset", 0o755)
    os.replace(probe + ".reset", probe)
    rmtree(os.path.dirname(host))
    rmtree(f"/tmp/exclave-probe-{os.getpid()}")
    if os.path.lexists("/tmp/" + REL_SOCK):  # a relative bind after a chdir into /tmp
        os.remove("/tmp/" + REL_SOCK)
    os.makedirs(host + "/hdir")
    with open(host + "/hfile", "w") as f:
        f.write("hello\n")
    with open(host + "/hdir/inner", "w") as f:
        f.write("inner\n")
    for name, target in (
        ("hlink", "/maze/f0"),
        ("hlnkdir", "/maze/d0"),
        ("hdang", "missing"),
        ("hloop", "hloop"),
        ("hrel", "hdir/inner"),
    ):
        os.symlink(target, os.path.join(host, name))
    os.makedirs(f"/tmp/exclave-probe-{os.getpid()}")


def run_bwrap(root: str, host: str, _bindir: str, probe: str, cases: str) -> tuple[int, str, str]:
    """The kernel's projection of the tree.

    The unwrapped tree read-only at /, and the visibility rule of 8.1 spelt in bwrap's terms: every
    placeholder of the tree is the host's directory, the kernel's volatile directories are the
    host's, and the identity files are the host's files with the host's permissions.
    """
    args = ["bwrap", "--ro-bind", root, "/", "--proc", "/proc", "--dev-bind", "/dev", "/dev"]
    for top in sorted(os.listdir(root)):
        p = "/" + top
        r = os.path.join(root, top)
        if (
            os.path.isdir(r)
            and not os.path.islink(r)
            and not os.listdir(r)
            and os.path.isdir(p)
            and p not in ("/proc", "/dev")
        ):
            args += ["--bind", p, p]
    for p in ("/var/tmp",):
        if os.path.isdir(os.path.join(root, p.lstrip("/"))) and os.path.isdir(p):
            args += ["--bind", p, p]
    for f in IDENTITY:
        if os.path.exists(f) and os.path.lexists(os.path.join(root, f.lstrip("/"))):
            t = os.path.realpath(f) if os.path.islink(f) else f
            # a target under a volatile directory comes with that directory's bind
            if not any(t.startswith(b + "/") for b in ("/run", "/tmp", "/dev", "/proc")):
                args += ["--bind", t, t]
    work = os.path.dirname(os.path.dirname(host))
    if not work.startswith("/home/"):
        args += ["--bind", work, work]
    args += [
        "--chdir",
        host,
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        host,
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "TZ",
        "UTC0",
        "--setenv",
        "SHELL",
        "/bin/sh",
    ]
    with open(cases, "rb") as inp:
        p = subprocess.run([*args, probe], env={}, stdin=inp, capture_output=True, check=False)
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


def run_launcher(ex: str, host: str, probe: str, cases: str) -> tuple[int, str, str]:
    with open(cases, "rb") as inp:
        p = subprocess.run(
            [os.path.join(ex, ".exclave", "launcher"), probe],
            cwd=host,
            stdin=inp,
            env={"PATH": "/usr/bin:/bin", "HOME": host},
            capture_output=True,
            check=False,
        )
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


def forms_in(label: str) -> set[str]:
    return set(label.replace("->", "/").split("/"))


def errnos(b: str, o: str) -> tuple[int, int]:
    return int(b.split("errno=")[1].split(maxsplit=1)[0]), int(
        o.split("errno=")[1].split(maxsplit=1)[0]
    )


# differences with a reason: (syscall name or None, predicate on (label, bwrap answer, launcher
# answer), reason). The list is part of the design (17): each entry names the rule that makes the
# difference right.
# bound from the host into the read-only root under bwrap
BOUND = {"passwd", "resolv", "tmp", "home", "opt", "dev_null", "rel_etc_by_dotdot"}
EXPECTED: list[tuple[str | None, Callable[[str, str, str], object], str]] = [
    # the kernel matrix (12): what this kernel lacks or decided differently, each entry naming the
    # kernel change
    (
        None,
        lambda _, b, o: errnos(b, o)[0] == 38,
        (
            "a syscall this kernel lacks (ENOSYS): the handler answers what it can from its own "
            "rule and re-issues the rest, so only the error cases differ"
        ),
    ),
    (
        None,
        lambda label, b, o: KERNEL < (5, 8) and "creat_excl" in label and errnos(b, o) == (21, 17),
        (
            "O_CREAT|O_EXCL on '.', '..' or '/': EISDIR before the lookup rework of 5.8, EEXIST "
            "since; the handler answers as the newer kernels do"
        ),
    ),
    (
        "linkat",
        lambda label, b, o: KERNEL < (6, 10) and "empty" in label and errnos(b, o)[0] == 2,
        (
            "linkat with AT_EMPTY_PATH needed CAP_DAC_READ_SEARCH (ENOENT without it) until 6.10 "
            "allowed it for files with a link; the handler answers as the newer kernels do"
        ),
    ),
    (
        "openat2",
        lambda label, b, o: "cached" in label and errnos(b, o)[0] == 11,
        (
            "RESOLVE_CACHED: the kernel answers EAGAIN where the lookup would need I/O, and "
            "bwrap's fresh mount namespace has a cold cache; the handler drops the flag, as "
            "openat2(2) permits, and resolves"
        ),
    ),
    (
        "openat2",
        lambda label, b, o: KERNEL < (6, 3) and "dir_creat" in label and errnos(b, o)[1] == 22,
        (
            "O_DIRECTORY|O_CREAT is EINVAL since 6.3 (open.c); this kernel opens or creates "
            "instead; the handler answers as the newer kernels do"
        ),
    ),
    (
        "openat2",
        lambda label, b, o: (
            KERNEL < (5, 6) and "no_xdev" in label and "creat" in label and errnos(b, o)[0] == 18
        ),
        (
            "RHEL 8's 4.18 backport of openat2 answers EXDEV for a create through a symlink under "
            "RESOLVE_NO_XDEV; 5.6 and later resolve it"
        ),
    ),
    (
        "openat2",
        lambda label, b, o: KERNEL < (5, 12) and "cached" in label and errnos(b, o)[0] == 22,
        (
            "RESOLVE_CACHED is 5.12+: EINVAL before; the handler drops it, as openat2(2) permits, "
            "and answers from the walk"
        ),
    ),
    (
        None,
        lambda label, b, o: "whiteout" in label and errnos(b, o)[0] == 1,
        (
            "RENAME_WHITEOUT: this kernel checks a capability in the initial user namespace "
            "before any lookup (EPERM); later kernels check the caller's, which bwrap's namespace "
            "grants"
        ),
    ),
    (
        None,
        lambda label, b, o: "resolv" in forms_in(label) and errnos(b, o) == (61, 95),
        (
            "the host's identity symlink resolves to a file on another filesystem (a tmpfs under "
            "/run) whose xattr answers differ from the tree copy's symlink"
        ),
    ),
    (
        None,
        lambda label, b, o: (
            forms_in(label) & BOUND and errnos(b, o)[0] == 30 and errnos(b, o)[1] in (1, 13)
        ),
        (
            "a host entry bound into bwrap's read-only root: its parent directory, or the "
            "identity symlink itself, is read-only there (EROFS); the launcher answers with the "
            "host's permissions (8.1, 8.4)"
        ),
    ),
    (
        None,
        lambda label, b, o: "to_root" in forms_in(label) and errnos(b, o) == (22, 1),
        "uid 0 is not mapped in bwrap's user namespace (EINVAL); the launcher runs in none (EPERM)",
    ),
    (
        "bind",
        lambda label, b, o: (
            label.startswith(("root/", "root_dotdot/", "rel_root_by_dotdot/"))
            and "after_chdir_rel" in label
            and errnos(b, o) == (30, 13)
        ),
        (
            "a new top-level name is the host's (8.1 rule 2): the host's / answers EACCES for a "
            "create there, where the read-only root under bwrap says EROFS"
        ),
    ),
    (
        "fanotify_mark",
        lambda _, b, o: errnos(b, o)[0] == 22,
        (
            "fanotify_mark checks its flags and descriptor before its path; the launcher resolves "
            "the path first, and fanotify needs CAP_SYS_ADMIN, which no process in an exclave has "
            "(13)"
        ),
    ),
    (
        None,
        lambda label, b, o: (
            KERNEL < (6, 14) and "ro_file" in forms_in(label) and errnos(b, o) == (30, 13)
        ),
        (
            "a truncate of a file its owner cannot write on a read-only mount: this kernel wants "
            "the mount before the permission (EROFS); vfs_truncate checks the permission first by "
            "6.14 (it did not at 6.1), and the handler answers as it does"
        ),
    ),
    (
        "utimensat",
        lambda label, b, o: (
            KERNEL < (5, 9) and ("empty" in label or "bad_nsec" in label) and errnos(b, o)[0] == 22
        ),
        (
            "utimensat before 5.9 refused AT_EMPTY_PATH and checked the nanoseconds before the "
            "lookup (EINVAL); since 5.9 (vfs_utimes) it takes the flag and the lookup's answer "
            "comes first, as the handler answers"
        ),
    ),
    (
        "execve",
        lambda label, b, o: (
            KERNEL < (5, 9)
            and "sock" in forms_in(label)
            and b.startswith("ret=27136")
            and o.startswith("ret=28928")
        ),
        (
            "an exec of a socket: ENXIO from its open before 5.9, EACCES from may_open since "
            "(fs/namei.c); the handler answers as the newer kernels do"
        ),
    ),
    (
        "execveat",
        lambda label, b, o: (
            KERNEL < (5, 9)
            and "sock" in forms_in(label)
            and b.startswith("ret=27136")
            and o.startswith("ret=28928")
        ),
        (
            "an exec of a socket: ENXIO from its open before 5.9, EACCES from may_open since "
            "(fs/namei.c); the handler answers as the newer kernels do"
        ),
    ),
    (
        None,
        lambda _, b, o: errnos(b, o) == (26, 30),
        (
            "a write-open of an executable another process is running: the kernel says ETXTBSY "
            "before EROFS, the launcher EROFS (13); seen when the gate runs the same exclave "
            "copy's shell beside the probe"
        ),
    ),
]

# Before 6.13 the xattr calls looked the path up, or took a descriptor's mount for writing, before
# they read the name, the flags and the size; the handler answers as the newer kernels do.
EXPECTED.extend(
    (
        call,
        lambda label, b, o: (
            KERNEL < (6, 13)
            and label.endswith(("/empty_name", "/bad_flags", "/too_big"))
            and errnos(b, o)[1] in (errno.E2BIG, errno.EINVAL, errno.ERANGE)
        ),
        (
            "an xattr call's name, flags and size: read after the lookup until 6.13, before it "
            "since; the handler answers as the newer kernels do"
        ),
    )
    for call in ("setxattr", "getxattr", "removexattr", "fsetxattr", "fremovexattr")
)


def expected(name: str, label: str, b: str, o: str) -> str | None:
    for n, pred, reason in EXPECTED:
        if (n is None or n == name) and pred(label, b, o):
            return reason
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--exclave", required=True)
    ap.add_argument("--work", default=os.path.join(REPO, "build", "syscalls-work"))
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--only", help="only this syscall")
    ap.add_argument("--show", type=int, default=40, help="differences to print")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument(
        "--expected", action="store_true", help="print the differences accepted under a reason too"
    )
    args = ap.parse_args()
    if not shutil.which("bwrap"):
        print("no bwrap; the syscall probe cannot run here")
        return 0
    if subprocess.run(
        ["bwrap", "--ro-bind", "/", "/", "true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode:
        print(
            "bwrap cannot create namespaces here (user namespaces denied); "
            "the syscall probe cannot run"
        )
        return 0
    given, work = os.path.abspath(args.exclave), os.path.abspath(args.work)
    rmtree(work)
    os.makedirs(work)
    # an earlier run that died left its area behind; a running one (the gate runs several) keeps
    # its own
    for d in os.listdir("/tmp"):
        if d.startswith("exclave-probe-"):
            try:
                os.kill(int(d[11:]), 0)
            except ValueError, ProcessLookupError:
                rmtree(os.path.join("/tmp", d))
            except PermissionError:
                pass
    rng = random.Random(args.seed)
    # the kernel's world: an unwrapped copy of the tree; the launcher's: a copy of the exclave; the
    # same maze in both
    root = os.path.join(work, "bare", "tree")
    shutil.copytree(
        os.path.join(given, "tree"), root, symlinks=True, copy_function=layout.link_or_copy
    )
    build.unwrap(os.path.join(work, "bare"), log=lambda *_: None)
    # the launcher's world: a copy relinked with the build (17)
    ex = tree.fresh_exclave(given, os.path.join(work, "exclave"))
    dirs, files, links = make_maze(root, rng)
    # ".." from the host area is a directory the reset owns
    host = os.path.join(work, "area", "host")
    # an exclave link to a host file, and to a host directory
    os.symlink(host + "/hfile", os.path.join(root, "maze", "lH"))
    os.symlink(host + "/hdir", os.path.join(root, "maze", "lHD"))
    shutil.copytree(os.path.join(root, "maze"), os.path.join(ex, "tree", "maze"), symlinks=True)
    # a socket file in the tree, for bind and connect (copytree cannot carry one)
    for r in (root, os.path.join(ex, "tree")):
        tree.socket_file(os.path.join(r, "maze", "sock"))
        # a file its owner cannot write: access(W_OK) is EACCES before EROFS
        with open(os.path.join(r, "maze", "ro444"), "w") as f:
            f.write("ro\n")
        os.chmod(os.path.join(r, "maze", "ro444"), 0o444)
    for f in IDENTITY:  # as oracle_ns: the host's link text in the copy, its target bound
        p_ = os.path.join(root, f.lstrip("/"))
        if os.path.islink(f) and os.path.lexists(p_):
            os.remove(p_)
            os.symlink(os.readlink(f), p_)
            t = os.path.realpath(f)
            tp = os.path.join(root, t.lstrip("/"))
            if not os.path.lexists(tp) and not t.startswith(("/run/", "/tmp/", "/dev/", "/proc/")):
                os.makedirs(os.path.dirname(tp), exist_ok=True)
                with open(tp, "wb"):
                    pass
    forms = Forms(root, host, links, dirs, files)
    bindir = os.path.join(work, "bin")
    os.makedirs(bindir)
    cc = tree.compiler(root, MACHINE)
    if not cc:
        sys.exit("no C compiler in the exclave")
    # the probe compiled through the build's launcher
    gcc = os.path.join(ex, "tree", tree.vbin(root, cc).lstrip("/"))
    probe = os.path.join(bindir, "probe")
    r = subprocess.run(
        [gcc, "-O1", "-o", probe, os.path.join(HERE, "progs", "probe.c")],
        cwd=work,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        check=False,
    )
    if r.returncode:
        sys.exit(
            "cannot compile probe.c with the exclave's compiler: "
            + r.stderr.decode(errors="replace")
        )
    nr = kernel_table(roots=(root, "/"))
    cases = generate(forms, nr, os.getuid(), os.getgid())
    if args.only:
        cases = [c for c in cases if args.only in (c[1], c[3])]
    names = []
    for c in cases:
        if c[3] not in names:
            names.append(c[3])
    total = differ = accepted = 0
    shown = 0
    for name in names:  # one run per group, the host area reset before each world
        mine = [c for c in cases if c[3] == name]
        path = os.path.join(bindir, "cases-" + name)
        with open(path, "w") as f:
            f.writelines(
                f"{i} {nr[n]} {' '.join(toks)}\n" for i, (label, n, toks, _) in enumerate(mine)
            )
        host_reset(host, os.path.join(ex, "tree"), probe)
        bw = run_bwrap(root, host, bindir, probe, path)
        host_reset(host, os.path.join(ex, "tree"), probe)
        op = run_launcher(ex, host, probe, path)
        bl, ol = bw[1].splitlines(), op[1].splitlines()
        if len(bl) != len(mine) or len(ol) != len(mine):
            stopped = mine[min(len(bl), len(ol))][0]
            print(
                f"FAIL {name}: {len(mine)} cases, "
                f"bwrap answered {len(bl)} (rc {bw[0]}: {bw[2].strip()[-200:]}), "
                f"the launcher {len(ol)} (rc {op[0]}: {op[2].strip()[-200:]}); "
                f"the first unanswered case is {stopped}"
            )
            differ += 1
            continue
        d = 0
        for (label, n, toks, _), bline, oline in zip(mine, bl, ol, strict=False):
            total += 1
            b, o = bline.split(" ", 1)[1], oline.split(" ", 1)[1]
            if b == o:
                continue
            why = expected(n, label, b, o)
            if why:
                accepted += 1
                if args.expected:
                    print(
                        "EXPECTED {} {}({}): {}\n     kernel: {}\n     launcher: {}".format(
                            n, label, ", ".join(decode(t) for t in toks), why, b, o
                        )
                    )
                continue
            differ += 1
            d += 1
            if shown < args.show:
                shown += 1
                print(
                    "DIFF {} {}({})\n     kernel: {}\n     launcher: {}".format(
                        n, label, ", ".join(decode(t) for t in toks), b, o
                    )
                )
        print(f"{name:<18} {len(mine):5d} cases, {d} differ")
    print(
        f"{total} cases over {len(names)} groups and {len(forms.paths)} path forms: "
        f"{differ} differ, {accepted} differences expected"
    )
    rmtree(f"/tmp/exclave-probe-{os.getpid()}")
    if not args.keep and not differ:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
