#!/usr/bin/env python3
"""oracle_syscalls.py — the differential syscall probe (PROPOSAL.md 17, item 3).

Every trapped syscall of src/filter.c is issued with every path form of 7.4.4, and every flag that changes
resolution, over a random maze, by one program (test/progs/probe.c) under two projections of the same tree:
the kernel's, a bwrap read-only bind of the unwrapped tree at /, and the opener's. Return value, errno and
what a buffer holds afterwards must agree case by case; a difference fails unless EXPECTED names its reason.
The expectations therefore come from the kernel, not from a test's author. Needs user namespaces and bwrap,
like oracle_ns; says so and exits 0 when it cannot run.

    test/oracle_syscalls.py --can CAN [--work DIR] [--seed S] [--only NAME] [--keep] [--show N]
"""
import argparse
import os
import platform
import random
import re
import shutil
import socket
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "cannery"))
sys.path.insert(0, HERE)
import build  # noqa: E402
import cannery  # noqa: E402
import tree  # noqa: E402
from oracle_resolve import make_maze  # noqa: E402
from syscalls import kernel_table  # noqa: E402

MACHINE = platform.machine()
KERNEL = tuple(int(x) for x in re.match(r"(\d+)\.(\d+)", os.uname().release).groups())   # orderings have moved between kernels (8.2)
O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_TRUNC = 0, 1, 2, os.O_CREAT, os.O_EXCL, os.O_TRUNC
O_DIRECTORY, O_NOFOLLOW, O_PATH, O_TMPFILE = os.O_DIRECTORY, os.O_NOFOLLOW, os.O_PATH, os.O_TMPFILE   # this machine's bits
AT_FDCWD, AT_SYMLINK_NOFOLLOW, AT_REMOVEDIR, AT_SYMLINK_FOLLOW, AT_EMPTY_PATH, AT_EACCESS = -100, 0x100, 0x200, 0x400, 0x1000, 0x200
RENAME_NOREPLACE, RENAME_EXCHANGE, RENAME_WHITEOUT = 1, 2, 4
RESOLVE_NO_XDEV, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS, RESOLVE_BENEATH, RESOLVE_IN_ROOT, RESOLVE_CACHED = 1, 2, 4, 8, 0x10, 0x20
UTIME_NOW, UTIME_OMIT = (1 << 30) - 1, (1 << 30) - 2
FS_IOC_SETFLAGS = 0x40086602 if MACHINE == "x86_64" else 0x40086602
IN_MODIFY = 2
STATX_BASIC_STATS = 0x7ff
IDENTITY = ["/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/host.conf", "/etc/resolv.conf", "/etc/hosts",
            "/etc/ssl/certs/ca-certificates.crt"]


def hx(s):
    return s.encode("utf-8", "surrogateescape").hex() if isinstance(s, str) else s.hex()


SOCK_STREAM, SOCK_DGRAM = 1, 2

def K(type_):                     # a unix socket descriptor of this type
    return "k:%d" % type_
def A(path):                      # a sockaddr_un holding this path, 108 bytes of it at most (unterminated at 108, as the kernel allows)
    return "A:" + path.encode("utf-8", "surrogateescape")[:108].hex()
def alen(path):                   # its length argument: the family, the bytes, and a NUL when there is room
    n = min(len(path.encode("utf-8", "surrogateescape")), 108)
    return 2 + n + (1 if n < 108 else 0)
REL_SOCK = "probe-sock-%d" % os.getpid()     # the relative socket name: one per driver, since a chdir into /tmp binds it in the host's /tmp


def raw_of(tok):                  # the path behind an s: token; None for the fault forms, which a sockaddr cannot carry
    return bytes.fromhex(tok[2:]).decode("utf-8", "surrogateescape") if tok.startswith("s:") else None
def S(path):                      # a string argument
    return "s:" + hx(path)


def I(n):                         # an integer argument
    return "i:%d" % n


def F(flags, path):               # a descriptor opened on path before the call
    return "f:%d:%s" % (flags, hx(path))


def B(kind, size):                # a buffer
    return "b:%s:%d" % (kind, size)


def V(*strings):                  # a string vector
    return "v:" + ",".join(hx(s) for s in strings)


def X(value, flags=0):            # struct xattr_args
    return "x:%s:%d" % (hx(value), flags)


def H(flags, mode=0, resolve=0, size=24, tail=None):   # struct open_how
    return "h:%d:%d:%d:%d%s" % (flags, mode, resolve, size, ":%d" % tail if tail is not None else "")


def decode(tok):
    """A token back to something readable, for the report."""
    k, _, p = tok.partition(":")
    if k == "s":
        return repr(bytes.fromhex(p).decode("utf-8", "replace"))
    if k == "f":
        fl, _, h = p.partition(":")
        return "fd(%s,%r)" % (fl, bytes.fromhex(h).decode("utf-8", "replace"))
    if k == "e":
        return "unterminated(%r)" % bytes.fromhex(p).decode("utf-8", "replace")
    if k == "v":
        return "[%s]" % ",".join(repr(bytes.fromhex(h).decode("utf-8", "replace")) for h in p.split(",") if h)
    return tok


class Forms:
    """The path forms of 7.4.4 over this maze, this tree and the host area."""

    def __init__(self, root, host, links, dirs, files):
        self.host = host
        by_kind = {}
        for l in links:
            t = os.readlink(os.path.join(root, l.lstrip("/")))
            if t == l:
                kind = "loop"
            elif t.startswith("/maze/l"):
                kind = "link"
            elif "missing" in t:
                kind = "dangling"
            elif t.startswith("/"):
                kind = "abs"
            else:
                kind = "rel"
            by_kind.setdefault(kind, l)
        self.link = by_kind
        # a file in a subdirectory, and a directory that has a file child
        self.file = sorted(files, key=lambda f: -f.count("/"))[0]
        self.dir = os.path.dirname(self.file)
        self.true = tree.vbin(root, "true")
        self.sh = tree.vbin(root, "sh")
        h = host
        can = [("can_file", self.file), ("can_dir", self.dir), ("maze", "/maze"), ("root", "/"),
               ("file_slash", self.file + "/"), ("dir_slash", self.dir + "/"), ("double_slash", "/" + self.file),
               ("dot", os.path.dirname(self.file) + "/./" + os.path.basename(self.file)),
               ("dotdot", self.dir + "/../" + self.dir.split("/")[-1] + "/" + os.path.basename(self.file)),
               ("above_root", "/.." + self.file), ("missing", "/maze/missing"), ("missing_slash", "/maze/missing/"), ("missing_mid", "/maze/missing/x"),
               ("dot_last", self.dir + "/."), ("dotdot_last", self.dir + "/.."), ("root_dotdot", "/.."),
               ("notdir_mid", self.file + "/x"), ("empty", ""), ("wrapper", self.true), ("sh_link", self.sh),
               ("ro_file", "/maze/ro444"), ("sock", "/maze/sock"),                   # a file its owner cannot write, and a special file: access(W_OK) has its own order
               ("passwd", "/etc/passwd"), ("resolv", "/etc/resolv.conf"), ("tmp", "/tmp"), ("dev_null", "/dev/null"),
               ("proc_exe", "/proc/self/exe"), ("proc_cwd", "/proc/self/cwd"), ("home", "/home"), ("opt", "/opt"),
               ("can_to_host", "/maze/lH"), ("can_to_host_dir", "/maze/lHD"),
               ("overlong", "/maze/" + "a" * 5000), ("long_component", "/maze/" + "b" * 256), ("long_ok", "/maze/" + "c" * 255),
               ("non_utf8", "/maze/\udcff\udcfe"), ("newline", "/maze/a\nb")]
        for kind, l in sorted(by_kind.items()):
            can.append(("link_" + kind, l))
        hostf = [("host_file", h + "/hfile"), ("host_dir", h + "/hdir"), ("host_to_can", h + "/hlink"), ("host_to_can_dir", h + "/hlnkdir"),
                 ("host_dangling", h + "/hdang"), ("host_loop", h + "/hloop"), ("host_rel_link", h + "/hrel"), ("host_missing", h + "/missing"),
                 ("host_dotdot", h + "/hdir/../hfile"), ("host_file_slash", h + "/hfile/"), ("host_tmp_new", "/tmp/cont-probe-%d/new" % os.getpid()),
                 ("host_dot_last", h + "/hdir/."), ("host_dotdot_last", h + "/hdir/.."),
                 ("rel_file", "hfile"), ("rel_dot", "."), ("rel_dotdot", ".."), ("rel_dot_dir", "./hdir"), ("rel_up", "../" + os.path.basename(h) + "/hfile"), ("rel_via_link", "hdir/../hlink"),
                 ("rel_root_by_dotdot", "../" * h.count("/") + "."), ("rel_etc_by_dotdot", "../" * h.count("/") + "etc/passwd")]   # up to the root from the host area, and into the tree
        self.paths = [(n, S(p)) for n, p in can + hostf]
        self.paths += [("fault_end", "e:" + hx(self.file)), ("fault_null", "n:"), ("fault_unmapped", "u:")]
        self.few = [(n, S(p)) for n, p in [("can_file", self.file), ("can_dir", self.dir), ("missing", "/maze/missing"), ("dir_slash", self.dir + "/"), ("file_slash", self.file + "/"),
                                          ("above_root", "/.." + self.file), ("empty", ""), ("wrapper", self.true), ("host_file", h + "/hfile"),
                                          ("host_dir", h + "/hdir"), ("host_missing", h + "/missing"), ("host_to_can", h + "/hlink"),
                                          ("rel_file", "hfile")]] + [("fault_null", "n:")]   # no /tmp here: bwrap's bind makes it another mount, so a link or rename into it is EXDEV there and not natively
        # descriptor-relative forms: (label, dirfd token, path token)
        rel_can = ["", ".", "..", "../" + os.path.basename(self.file), os.path.basename(self.file), "nonexistent", "../../etc/passwd", "../../../../tmp", self.file]
        rel_host = ["", ".", "..", "inner", "../hfile", "../hlink", "nonexistent", self.file]
        self.at = [("cwd/" + n, I(AT_FDCWD), p) for n, p in self.paths]
        self.at += [("dfd_can/" + r, F(O_PATH | O_DIRECTORY, self.dir), S(r)) for r in rel_can]
        self.at += [("dfd_can_rd/" + r, F(O_RDONLY | O_DIRECTORY, self.dir), S(r)) for r in ("", "..", os.path.basename(self.file))]
        self.at += [("dfd_host/" + r, F(O_PATH, h + "/hdir"), S(r)) for r in rel_host]
        self.at += [("ffd_can/" + r, F(O_RDONLY, self.file), S(r)) for r in ("", "x", ".", self.file)]
        self.at += [("ffd_host/" + r, F(O_RDONLY, h + "/hfile"), S(r)) for r in ("", "x")]
        self.at += [("ffd_host_w/", F(O_WRONLY, h + "/hfile"), S(""))]
        self.at += [("lfd_can/", F(O_PATH | O_NOFOLLOW, by_kind.get("abs", self.file)), S(""))]
        self.at += [("lfd_sh/", F(O_PATH | O_NOFOLLOW, self.sh), S("")), ("lfd_dang/", F(O_PATH | O_NOFOLLOW, h + "/hdang"), S(""))]
        self.at += [("wfd/", F(O_RDONLY, self.true), S("")), ("wfd_path/", F(O_PATH, self.true), S(""))]
        self.at += [("devnull_fd/", F(O_RDONLY, "/dev/null"), S("")), ("tmpfd/", F(O_PATH | O_DIRECTORY, "/tmp"), S("cont-probe-%d" % os.getpid()))]
        self.at += [("badfd/" + n, I(-1), p) for n, p in [("rel", S("x")), ("abs", S(self.file)), ("empty", S(""))]]
        self.at += [("closedfd/" + n, I(999), p) for n, p in [("rel", S("x")), ("abs", S(self.file))]]
        self.at_few = [("cwd/" + n, I(AT_FDCWD), p) for n, p in self.few]
        self.at_few += [("dfd_can/" + r, F(O_PATH | O_DIRECTORY, self.dir), S(r)) for r in ("", os.path.basename(self.file), "nonexistent")]
        self.at_few += [("dfd_host/" + r, F(O_PATH, h + "/hdir"), S(r)) for r in ("", "inner", "nonexistent", "../hfile")]
        self.at_few += [("ffd_can/", F(O_RDONLY, self.file), S("")), ("ffd_host/", F(O_RDONLY, h + "/hfile"), S("")), ("badfd/rel", I(-1), S("x"))]
        # descriptors for the descriptor-addressed syscalls
        self.fds = [("can_file_rd", F(O_RDONLY, self.file)), ("can_file_path", F(O_PATH, self.file)), ("can_dir", F(O_RDONLY | O_DIRECTORY, self.dir)),
                    ("wrapper", F(O_RDONLY, self.true)), ("host_file_rd", F(O_RDONLY, h + "/hfile")), ("host_file_wr", F(O_WRONLY, h + "/hfile")),
                    ("host_dir", F(O_RDONLY | O_DIRECTORY, h + "/hdir")), ("dev_null", F(O_RDONLY, "/dev/null")), ("badfd", I(-1))]


def generate(forms, nr, uid, gid):
    """(label, syscall name, [tokens]) for every case; a name absent from this machine's table is skipped."""
    out = []
    group = [None]                                                    # cases that depend on one another run in one group, in order

    def add(name, label, *toks):
        if name in nr:
            out.append((label, name, list(toks), group[0] or name))
    open_flags = [("rd", O_RDONLY), ("wr", O_WRONLY), ("rdwr", O_RDWR), ("rd_creat", O_RDONLY | O_CREAT), ("wr_creat", O_WRONLY | O_CREAT),
                  ("wr_creat_excl", O_WRONLY | O_CREAT | O_EXCL), ("rd_trunc", O_RDONLY | O_TRUNC), ("wr_trunc", O_WRONLY | O_TRUNC),
                  ("path", O_PATH), ("path_nofollow", O_PATH | O_NOFOLLOW), ("rd_nofollow", O_RDONLY | O_NOFOLLOW),
                  ("rd_dir", O_RDONLY | O_DIRECTORY), ("tmpfile", O_RDWR | O_TMPFILE)]
    stat_flags = [("follow", 0), ("nofollow", AT_SYMLINK_NOFOLLOW), ("empty", AT_EMPTY_PATH), ("nofollow_empty", AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)]
    for n, p in forms.paths:
        for fn, fl in open_flags:
            if n == "proc_exe" and fl & O_TRUNC:
                continue                                          # would truncate the running probe: the kernel says ETXTBSY, the opener does not (13)
            add("open", "%s/%s" % (n, fn), p, I(fl), I(0o644))
        if n != "proc_exe":
            add("creat", n, p, I(0o644))
        add("stat", n, p, B("stat", 256))
        add("lstat", n, p, B("stat", 256))
        for mn, m in (("F_OK", 0), ("R_OK", 4), ("W_OK", 2), ("X_OK", 1)):
            add("access", "%s/%s" % (n, mn), p, I(m))
        add("readlink", n, p, B("link", 4096), I(4096))
        add("readlink", n + "/short", p, B("link", 4), I(4))
        add("readlink", n + "/zero", p, B("link", 4), I(0))
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
        add("execve", n, p, V("x"), V())
        if raw_of(p) is not None:                                          # a sockaddr_un path is a path (13 item 31)
            add("bind", n, K(SOCK_STREAM), A(raw_of(p)), I(alen(raw_of(p))))
            add("connect", n, K(SOCK_STREAM), A(raw_of(p)), I(alen(raw_of(p))))
        group[0] = "chdir"
        add("chdir", n, p)
        add("getcwd", n + "/after_chdir", B("cwd", 4096), I(4096))
        add("stat", n + "/after_chdir_dot", S("."), B("stat", 256))
        add("stat", n + "/after_chdir_dotdot", S(".."), B("stat", 256))
        add("bind", n + "/after_chdir_rel", K(SOCK_STREAM), A(REL_SOCK), I(alen(REL_SOCK)))   # a relative bind from that directory
        add("connect", n + "/after_chdir_rel", K(SOCK_STREAM), A(REL_SOCK), I(alen(REL_SOCK)))
        add("chdir", n + "/back", S(forms.host))
        group[0] = None
    add("getcwd", "short", B("cwd", 4), I(4))
    for name in ("bind", "connect"):                                      # the structure's own rules, and a socket file in the tree
        add(name, "can_sock", K(SOCK_STREAM), A("/maze/sock"), I(alen("/maze/sock")))
        add(name, "can_sock_dgram", K(SOCK_DGRAM), A("/maze/sock"), I(alen("/maze/sock")))
        add(name, "abstract", K(SOCK_STREAM), A("\0probe-abstract-%d" % os.getpid()), I(alen("\0probe-abstract-%d" % os.getpid())))   # one name per process
        add(name, "unnamed", K(SOCK_STREAM), A(""), I(2))
        add(name, "len_too_long", K(SOCK_STREAM), A(forms.file), I(200))
        add(name, "len_too_short", K(SOCK_STREAM), A(forms.file), I(1))
        add(name, "null_addr", K(SOCK_STREAM), "n:", I(20))
        add(name, "fault_addr", K(SOCK_STREAM), "u:", I(20))
        add(name, "not_a_socket", F(O_RDONLY, forms.file), A(forms.host + "/hfile"), I(alen(forms.host + "/hfile")))
    add("stat", "can_sock", S("/maze/sock"), B("stat", 256))
    add("execve", "true", S(forms.true), V("true"), V())
    add("execve", "sh_exit3", S(forms.sh), V("sh", "-c", "exit 3"), V("PATH=/usr/bin:/bin"))
    add("execve", "argv_null", S(forms.true), "n:", V())
    add("execve", "rel_true", S("hlink"), V("x"), V())
    for n, d, p in forms.at:
        for fn, fl in open_flags:
            add("openat", "%s/%s" % (n, fn), d, p, I(fl), I(0o644))
        add("mkdirat", n, d, p, I(0o755))
        add("mknodat", n, d, p, I(0o10644), I(0))
        for fn, fl in (("follow", 0), ("nofollow", AT_SYMLINK_NOFOLLOW), ("empty", AT_EMPTY_PATH)):
            add("fchownat", "%s/%s" % (n, fn), d, p, I(uid), I(gid), I(fl))
        add("futimesat", n, d, p, "T:1000,0,2000,0")
        for fn, fl in stat_flags:
            add("newfstatat", "%s/%s" % (n, fn), d, p, B("stat", 256), I(fl))
            add("statx", "%s/%s" % (n, fn), d, p, I(fl), I(STATX_BASIC_STATS), B("statx", 256))
        add("unlinkat", n, d, p, I(0))
        add("unlinkat", n + "/rmdir", d, p, I(AT_REMOVEDIR))
        add("symlinkat", n, S("/maze/f0"), d, p)
        add("readlinkat", n, d, p, B("link", 4096), I(4096))
        add("readlinkat", n + "/zero", d, p, B("link", 4), I(0))
        add("fchmodat", n, d, p, I(0o644))
        add("faccessat", n, d, p, I(4))
        add("faccessat", n + "/W", d, p, I(2))
        add("faccessat2", n, d, p, I(4), I(0))
        add("faccessat2", n + "/eaccess", d, p, I(2), I(AT_EACCESS))
        add("fchmodat2", n, d, p, I(0o644), I(0))
        add("fchmodat2", n + "/nofollow", d, p, I(0o644), I(AT_SYMLINK_NOFOLLOW))
        add("utimensat", n, d, p, "t:1000,0,2000,0", I(0))
        add("utimensat", n + "/nofollow", d, p, "t:1000,0,2000,0", I(AT_SYMLINK_NOFOLLOW))
        add("utimensat", n + "/now", d, p, "t:0,%d,0,%d" % (UTIME_NOW, UTIME_NOW), I(0))
        add("utimensat", n + "/omit", d, p, "t:0,%d,0,%d" % (UTIME_OMIT, UTIME_OMIT), I(0))
        add("utimensat", n + "/null_times", d, p, "n:", I(0))
        add("utimensat", n + "/bad_nsec", d, p, "t:0,1000000000,0,0", I(0))
        add("utimensat", n + "/bad_flags", d, p, "t:1000,0,2000,0", I(0x8000))
        add("utimensat", n + "/empty", d, p, "t:1000,0,2000,0", I(AT_EMPTY_PATH))
        add("futimesat", n + "/bad_usec", d, p, "T:1000,0,2000,-1")
        add("execveat", n, d, p, V("x"), V(), I(0))
        add("execveat", n + "/empty", d, p, V("x"), V(), I(AT_EMPTY_PATH))
        add("setxattrat", n, d, p, I(0), S("user.probe"), X("v"), I(16))
        add("setxattrat", n + "/nofollow", d, p, I(AT_SYMLINK_NOFOLLOW), S("user.probe"), X("v"), I(16))
        add("getxattrat", n, d, p, I(0), S("user.probe"), X("\0" * 64), I(16))
        add("listxattrat", n, d, p, I(0), B("xattr", 512), I(512))
        add("removexattrat", n, d, p, I(0), S("user.probe"))
        add("file_getattr", n, d, p, B("raw", 32), I(32), I(0))
        add("file_setattr", n, d, p, B("raw", 32), I(32), I(0))
    # openat2: the resolve flags over every descriptor-relative form, and the struct's own rules
    how_flags = [("rd", O_RDONLY), ("wr", O_WRONLY), ("wr_creat", O_WRONLY | O_CREAT), ("path", O_PATH), ("path_nofollow", O_PATH | O_NOFOLLOW),
                 ("rd_dir", O_RDONLY | O_DIRECTORY), ("tmpfile", O_RDWR | O_TMPFILE)]
    resolves = [("plain", 0), ("no_xdev", RESOLVE_NO_XDEV), ("no_magic", RESOLVE_NO_MAGICLINKS), ("no_symlinks", RESOLVE_NO_SYMLINKS),
                ("beneath", RESOLVE_BENEATH), ("in_root", RESOLVE_IN_ROOT), ("cached", RESOLVE_CACHED)]
    for n, d, p in forms.at:
        for fn, fl in how_flags:
            for rn, rs in resolves:
                add("openat2", "%s/%s/%s" % (n, fn, rn), d, p, H(fl, 0o644 if fl & O_CREAT else 0, rs), I(24))
    for n, d, p in forms.at_few:
        add("openat2", n + "/both_scopes", d, p, H(O_RDONLY, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT), I(24))
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
    add("utimensat", "fd_null_path_nofollow", F(O_RDONLY, forms.file), "n:", "t:1000,0,2000,0", I(AT_SYMLINK_NOFOLLOW))
    add("utimensat", "fd_null_path_bad_nsec", F(O_RDONLY, forms.file), "n:", "t:0,-5,0,0", I(0))
    add("utimensat", "cwd_null_path", I(AT_FDCWD), "n:", "t:1000,0,2000,0", I(0))
    add("utimensat", "hostfd_null_path", F(O_WRONLY, forms.host + "/hfile"), "n:", "t:1000,0,2000,0", I(0))
    add("newfstatat", "fd_null_empty", F(O_RDONLY, forms.file), "n:", B("stat", 256), I(AT_EMPTY_PATH))
    add("newfstatat", "fd_null", F(O_RDONLY, forms.file), "n:", B("stat", 256), I(0))
    add("readlinkat", "proc_fd", I(AT_FDCWD), S("/proc/self/fd/0"), B("link", 4096), I(4096))
    add("execveat", "true_fd", F(O_RDONLY, forms.true), S(""), V("true"), V(), I(AT_EMPTY_PATH))
    add("execveat", "true_pathfd", F(O_PATH, forms.true), S(""), V("true"), V(), I(AT_EMPTY_PATH))
    add("execveat", "sh_fd", F(O_RDONLY, forms.sh), S(""), V("sh", "-c", "exit 3"), V(), I(AT_EMPTY_PATH))
    two = forms.few
    for n1, p1 in two:
        for n2, p2 in two:
            lab = "%s->%s" % (n1, n2)
            add("rename", lab, p1, p2)
            add("link", lab, p1, p2)
            add("renameat", lab, I(AT_FDCWD), p1, I(AT_FDCWD), p2)
            for fn, fl in (("plain", 0), ("noreplace", RENAME_NOREPLACE), ("exchange", RENAME_EXCHANGE), ("whiteout", RENAME_WHITEOUT)):
                add("renameat2", "%s/%s" % (lab, fn), I(AT_FDCWD), p1, I(AT_FDCWD), p2, I(fl))
            for fn, fl in (("plain", 0), ("follow", AT_SYMLINK_FOLLOW), ("empty", AT_EMPTY_PATH)):
                add("linkat", "%s/%s" % (lab, fn), I(AT_FDCWD), p1, I(AT_FDCWD), p2, I(fl))
    for n1, d1, p1 in forms.at_few:
        for n2, d2, p2 in forms.at_few:
            lab = "%s->%s" % (n1, n2)
            add("renameat", lab, d1, p1, d2, p2)
            add("linkat", lab, d1, p1, d2, p2, I(0))
    add("linkat", "fd_empty", F(O_RDONLY, forms.file), S(""), I(AT_FDCWD), S(forms.host + "/hlinked"), I(AT_EMPTY_PATH))
    add("linkat", "hostfd_empty", F(O_RDONLY, forms.host + "/hfile"), S(""), I(AT_FDCWD), S(forms.host + "/hlinked2"), I(AT_EMPTY_PATH))
    add("linkat", "hostfd_empty_to_can", F(O_RDONLY, forms.host + "/hfile"), S(""), I(AT_FDCWD), S("/maze/hnew"), I(AT_EMPTY_PATH))
    for n, f in forms.fds:
        add("fchmod", n, f, I(0o644))
        add("fchown", n, f, I(uid), I(gid))
        add("fsetxattr", n, f, S("user.probe"), S("v"), I(1), I(0))
        add("fremovexattr", n, f, S("user.probe"))
        add("fstatfs", n, f, B("raw", 256))
        if not n.startswith("host"):                                   # not on a host file: ext4 on 5.10 to 6.1 refuses to clear the extent flag of
            add("ioctl", n + "/setflags", f, I(FS_IOC_SETFLAGS), B("raw", 8))   # a file recreated moments after its predecessor was deleted (13), which the reset does
    # relative paths from a can-owned working directory
    rel = ["", ".", "..", os.path.basename(forms.file), "../" + os.path.basename(forms.file), "nonexistent", "../../..", "../../../../etc/passwd", "../../home", "./"]
    group[0] = "cwd_in_can"
    add("chdir", "into_can", S(forms.dir))
    add("getcwd", "in_can", B("cwd", 4096), I(4096))
    for r in rel:
        add("stat", "in_can/" + r, S(r), B("stat", 256))
        add("open", "in_can/" + r, S(r), I(O_RDONLY), I(0))
        add("readlink", "in_can/" + r, S(r), B("link", 4096), I(4096))
        add("mkdir", "in_can/" + r, S(r), I(0o755))
        add("access", "in_can/" + r, S(r), I(2))
    add("utimensat", "in_can/null_path", I(AT_FDCWD), "n:", "t:1000,0,2000,0", I(0))
    add("chdir", "up_from_can", S(".."))
    add("getcwd", "up_from_can", B("cwd", 4096), I(4096))
    add("chdir", "above_root_from_can", S("../../../.."))
    add("getcwd", "above_root_from_can", B("cwd", 4096), I(4096))
    add("chdir", "back", S(forms.host))
    add("getcwd", "back", B("cwd", 4096), I(4096))
    group[0] = None
    return out


def rmtree(d):
    """rmtree after a chmod case may have taken the directories' permissions away."""
    if not os.path.isdir(d):
        return
    os.chmod(d, 0o755)
    for top, dirs, files in os.walk(d):
        for x in dirs:
            if not os.path.islink(os.path.join(top, x)):
                os.chmod(os.path.join(top, x), 0o755)
    shutil.rmtree(d)


def host_reset(host, root_can, probe):
    """The host area both worlds see at the same path, identical before every run."""
    os.chmod(probe, 0o755)                                              # a chmod of /proc/self/exe takes the probe's own x bit
    for x in os.listxattr(probe):                                       # and an xattr case leaves an attribute on it
        if x.startswith("user."):                                       # (an SELinux label is not ours to remove)
            os.removexattr(probe, x)
    rmtree(os.path.dirname(host))
    rmtree("/tmp/cont-probe-%d" % os.getpid())
    if os.path.lexists("/tmp/" + REL_SOCK):                              # a relative bind after a chdir into /tmp
        os.remove("/tmp/" + REL_SOCK)
    os.makedirs(host + "/hdir")
    with open(host + "/hfile", "w") as f:
        f.write("hello\n")
    with open(host + "/hdir/inner", "w") as f:
        f.write("inner\n")
    for name, target in (("hlink", "/maze/f0"), ("hlnkdir", "/maze/d0"), ("hdang", "missing"), ("hloop", "hloop"), ("hrel", "hdir/inner")):
        os.symlink(target, os.path.join(host, name))
    os.makedirs("/tmp/cont-probe-%d" % os.getpid())


def run_bwrap(root, host, bindir, probe, cases):
    """The kernel's projection of the tree: the unwrapped tree read-only at /, and the visibility rule of 8.1
    spelt in bwrap's terms: every placeholder of the tree is the host's directory, the kernel's volatile
    directories are the host's, and the identity files are the host's files with the host's permissions."""
    args = ["bwrap", "--ro-bind", root, "/", "--proc", "/proc", "--dev-bind", "/dev", "/dev"]
    for top in sorted(os.listdir(root)):
        p = "/" + top
        r = os.path.join(root, top)
        if os.path.isdir(r) and not os.path.islink(r) and not os.listdir(r) and os.path.isdir(p) and p not in ("/proc", "/dev"):
            args += ["--bind", p, p]
    for p in ("/var/tmp",):
        if os.path.isdir(os.path.join(root, p.lstrip("/"))) and os.path.isdir(p):
            args += ["--bind", p, p]
    for f in IDENTITY:
        if os.path.exists(f) and os.path.lexists(os.path.join(root, f.lstrip("/"))):
            t = os.path.realpath(f) if os.path.islink(f) else f
            if not any(t.startswith(b + "/") for b in ("/run", "/tmp", "/dev", "/proc")):   # the volatile ones are bound above
                args += ["--bind", t, t]
    work = os.path.dirname(os.path.dirname(host))
    if not work.startswith("/home/"):
        args += ["--bind", work, work]
    args += ["--chdir", host, "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", host,
             "--setenv", "LANG", "C.UTF-8", "--setenv", "TZ", "UTC0", "--setenv", "SHELL", "/bin/sh"]
    with open(cases, "rb") as inp:
        p = subprocess.run(args + [probe], env={}, stdin=inp, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


def run_opener(can, host, probe, cases):
    with open(cases, "rb") as inp:
        p = subprocess.run([os.path.join(can, ".can", "opener"), probe], cwd=host, stdin=inp, env={"PATH": "/usr/bin:/bin", "HOME": host},
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


def forms_in(label):
    return set(label.replace("->", "/").split("/"))


def errnos(b, o):
    return int(b.split("errno=")[1].split()[0]), int(o.split("errno=")[1].split()[0])


# differences with a reason: (syscall name or None, predicate on (label, bwrap answer, opener answer), reason).
# The list is part of the design (17): each entry names the rule that makes the difference right.
BOUND = {"passwd", "resolv", "tmp", "home", "opt", "dev_null", "rel_etc_by_dotdot"}   # bound from the host into the read-only root under bwrap
EXPECTED = [
    # the kernel matrix (12): what this kernel lacks or decided differently, each entry naming the kernel change
    (None, lambda l, b, o: errnos(b, o)[0] == 38,
     "a syscall this kernel lacks (ENOSYS): the handler answers what it can from its own rule and re-issues the rest, so only the error cases differ"),
    (None, lambda l, b, o: KERNEL < (5, 8) and "creat_excl" in l and errnos(b, o) == (21, 17),
     "O_CREAT|O_EXCL on '.', '..' or '/': EISDIR before the lookup rework of 5.8, EEXIST since; the handler answers as the newer kernels do"),
    ("linkat", lambda l, b, o: KERNEL < (6, 10) and "empty" in l and errnos(b, o)[0] == 2,
     "linkat with AT_EMPTY_PATH needed CAP_DAC_READ_SEARCH (ENOENT without it) until 6.10 allowed it for files with a link; the handler answers as the newer kernels do"),
    ("openat2", lambda l, b, o: "cached" in l and errnos(b, o)[0] == 11,
     "RESOLVE_CACHED: the kernel answers EAGAIN where the lookup would need I/O, and bwrap's fresh mount namespace has a cold cache; the handler drops the flag, as openat2(2) permits, and resolves"),
    ("openat2", lambda l, b, o: KERNEL < (6, 3) and "dir_creat" in l and errnos(b, o)[1] == 22,
     "O_DIRECTORY|O_CREAT is EINVAL since 6.3 (open.c); this kernel opens or creates instead; the handler answers as the newer kernels do"),
    ("openat2", lambda l, b, o: KERNEL < (5, 6) and "no_xdev" in l and "creat" in l and errnos(b, o)[0] == 18,
     "RHEL 8's 4.18 backport of openat2 answers EXDEV for a create through a symlink under RESOLVE_NO_XDEV; 5.6 and later resolve it"),
    ("openat2", lambda l, b, o: KERNEL < (5, 12) and "cached" in l and errnos(b, o)[0] == 22,
     "RESOLVE_CACHED is 5.12+: EINVAL before; the handler drops it, as openat2(2) permits, and answers from the walk"),
    (None, lambda l, b, o: "whiteout" in l and errnos(b, o)[0] == 1,
     "RENAME_WHITEOUT: this kernel checks a capability in the initial user namespace before any lookup (EPERM); later kernels check the caller's, which bwrap's namespace grants"),
    (None, lambda l, b, o: "resolv" in forms_in(l) and errnos(b, o) == (61, 95),
     "the host's identity symlink resolves to a file on another filesystem (a tmpfs under /run) whose xattr answers differ from the tree copy's symlink"),
    (None, lambda l, b, o: forms_in(l) & BOUND and errnos(b, o)[0] == 30 and errnos(b, o)[1] in (1, 13),
     "a host entry bound into bwrap's read-only root: its parent directory, or the identity symlink itself, is read-only there (EROFS); the opener answers with the host's permissions (8.1, 8.4)"),
    (None, lambda l, b, o: "to_root" in forms_in(l) and errnos(b, o) == (22, 1),
     "uid 0 is not mapped in bwrap's user namespace (EINVAL); the opener runs in none (EPERM)"),
    ("bind", lambda l, b, o: l.startswith(("root/", "root_dotdot/", "rel_root_by_dotdot/")) and "after_chdir_rel" in l and errnos(b, o) == (30, 13),
     "a new top-level name is the host's (8.1 rule 2): the host's / answers EACCES for a create there, where the read-only root under bwrap says EROFS"),
    ("fanotify_mark", lambda l, b, o: errnos(b, o)[0] == 22,
     "fanotify_mark checks its flags and descriptor before its path; the opener resolves the path first, and fanotify needs CAP_SYS_ADMIN, which no can process has (13)"),
    (None, lambda l, b, o: KERNEL < (6, 14) and "ro_file" in forms_in(l) and errnos(b, o) == (30, 13),
     "a truncate of a file its owner cannot write on a read-only mount: this kernel wants the mount before the permission (EROFS); vfs_truncate checks the permission first by 6.14 (it did not at 6.1), and the handler answers as it does"),
    ("utimensat", lambda l, b, o: KERNEL < (5, 9) and ("empty" in l or "bad_nsec" in l) and errnos(b, o)[0] == 22,
     "utimensat before 5.9 refused AT_EMPTY_PATH and checked the nanoseconds before the lookup (EINVAL); since 5.9 (vfs_utimes) it takes the flag and the lookup's answer comes first, as the handler answers"),
    ("execve", lambda l, b, o: KERNEL < (5, 9) and "sock" in forms_in(l) and b.startswith("ret=27136") and o.startswith("ret=28928"),
     "an exec of a socket: ENXIO from its open before 5.9, EACCES from may_open since (fs/namei.c); the handler answers as the newer kernels do"),
    ("execveat", lambda l, b, o: KERNEL < (5, 9) and "sock" in forms_in(l) and b.startswith("ret=27136") and o.startswith("ret=28928"),
     "an exec of a socket: ENXIO from its open before 5.9, EACCES from may_open since (fs/namei.c); the handler answers as the newer kernels do"),
    (None, lambda l, b, o: errnos(b, o) == (26, 30),
     "a write-open of an executable another process is running: the kernel says ETXTBSY before EROFS, the opener EROFS (13); seen when the gate runs the same can copy's shell beside the probe"),
]


def expected(name, label, b, o):
    for n, pred, reason in EXPECTED:
        if (n is None or n == name) and pred(label, b, o):
            return reason
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--can", required=True)
    ap.add_argument("--work", default=os.path.join(REPO, "build", "syscalls-work"))
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--only", help="only this syscall")
    ap.add_argument("--show", type=int, default=40, help="differences to print")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--expected", action="store_true", help="print the differences accepted under a reason too")
    a = ap.parse_args()
    if not shutil.which("bwrap"):
        print("no bwrap; the syscall probe cannot run here")
        return 0
    if subprocess.run(["bwrap", "--ro-bind", "/", "/", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        print("bwrap cannot create namespaces here (user namespaces denied); the syscall probe cannot run")
        return 0
    given, work = os.path.abspath(a.can), os.path.abspath(a.work)
    rmtree(work)
    os.makedirs(work)
    for d in os.listdir("/tmp"):                                            # an earlier run that died left its area behind; a
        if d.startswith("cont-probe-"):                                     # running one (the gate runs several) keeps its own
            try:
                os.kill(int(d[11:]), 0)
            except (ValueError, ProcessLookupError):
                rmtree(os.path.join("/tmp", d))
            except PermissionError:
                pass
    rng = random.Random(a.seed)
    # the kernel's world: an unwrapped copy of the tree; the opener's: a copy of the can; the same maze in both
    root = os.path.join(work, "tree", "root")
    shutil.copytree(os.path.join(given, "root"), root, symlinks=True, copy_function=cannery.link_or_copy)
    build.unwrap(os.path.join(work, "tree"), log=lambda *x: None)
    can = os.path.join(work, "can")
    os.makedirs(os.path.join(can, ".can"))
    for f in ("opener", "manifest"):
        shutil.copy2(os.path.join(given, ".can", f), os.path.join(can, ".can", f))
    shutil.copytree(os.path.join(given, "root"), os.path.join(can, "root"), symlinks=True, copy_function=cannery.link_or_copy)
    dirs, files, links = make_maze(root, rng)
    host = os.path.join(work, "area", "host")                              # ".." from the host area is a directory the reset owns
    os.symlink(host + "/hfile", os.path.join(root, "maze", "lH"))          # a can link to a host file, and to a host directory
    os.symlink(host + "/hdir", os.path.join(root, "maze", "lHD"))
    shutil.copytree(os.path.join(root, "maze"), os.path.join(can, "root", "maze"), symlinks=True)
    for r in (root, os.path.join(can, "root")):                            # a socket file in the tree, for bind and connect (copytree cannot carry one)
        sk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sk.bind(os.path.join(r, "maze", "sock"))
        sk.close()
        with open(os.path.join(r, "maze", "ro444"), "w") as f:              # a file its owner cannot write: access(W_OK) is EACCES before EROFS
            f.write("ro\n")
        os.chmod(os.path.join(r, "maze", "ro444"), 0o444)
    for f in IDENTITY:                                                      # as oracle_ns: the host's link text in the copy, its target bound
        p_ = os.path.join(root, f.lstrip("/"))
        if os.path.islink(f) and os.path.lexists(p_):
            os.remove(p_)
            os.symlink(os.readlink(f), p_)
            t = os.path.realpath(f)
            tp = os.path.join(root, t.lstrip("/"))
            if not os.path.lexists(tp) and not t.startswith(("/run/", "/tmp/", "/dev/", "/proc/")):
                os.makedirs(os.path.dirname(tp), exist_ok=True)
                open(tp, "wb").close()
    forms = Forms(root, host, links, dirs, files)
    bindir = os.path.join(work, "bin")
    os.makedirs(bindir)
    cc = tree.compiler(root, MACHINE)
    if not cc:
        sys.exit("no C compiler in the can")
    gcc = os.path.join(given, "root", tree.vbin(root, cc).lstrip("/"))
    probe = os.path.join(bindir, "probe")
    r = subprocess.run([gcc, "-O1", "-o", probe, os.path.join(HERE, "progs", "probe.c")], cwd=work, env={"PATH": "/usr/bin:/bin"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode:
        sys.exit("cannot compile probe.c with the can's compiler: " + r.stderr.decode(errors="replace"))
    nr = kernel_table(roots=(root, "/"))
    cases = generate(forms, nr, os.getuid(), os.getgid())
    if a.only:
        cases = [c for c in cases if a.only in (c[1], c[3])]
    names = []
    for c in cases:
        if c[3] not in names:
            names.append(c[3])
    total = differ = accepted = 0
    shown = 0
    for name in names:                                                      # one run per group, the host area reset before each world
        mine = [c for c in cases if c[3] == name]
        path = os.path.join(bindir, "cases-" + name)
        with open(path, "w") as f:
            for i, (label, n, toks, _) in enumerate(mine):
                f.write("%d %d %s\n" % (i, nr[n], " ".join(toks)))
        host_reset(host, os.path.join(can, "root"), probe)
        bw = run_bwrap(root, host, bindir, probe, path)
        host_reset(host, os.path.join(can, "root"), probe)
        op = run_opener(can, host, probe, path)
        bl, ol = bw[1].splitlines(), op[1].splitlines()
        if len(bl) != len(mine) or len(ol) != len(mine):
            stopped = mine[min(len(bl), len(ol))][0]
            print("FAIL %s: %d cases, bwrap answered %d (rc %d: %s), the opener %d (rc %d: %s); the first unanswered case is %s" % (name, len(mine), len(bl), bw[0], bw[2].strip()[-200:], len(ol), op[0], op[2].strip()[-200:], stopped))
            differ += 1
            continue
        d = 0
        for (label, n, toks, _), b, o in zip(mine, bl, ol):
            total += 1
            b, o = b.split(" ", 1)[1], o.split(" ", 1)[1]
            if b == o:
                continue
            why = expected(n, label, b, o)
            if why:
                accepted += 1
                if a.expected:
                    print("EXPECTED %s %s(%s): %s\n     kernel: %s\n     opener: %s" % (n, label, ", ".join(decode(t) for t in toks), why, b, o))
                continue
            differ += 1
            d += 1
            if shown < a.show:
                shown += 1
                print("DIFF %s %s(%s)\n     kernel: %s\n     opener: %s" % (n, label, ", ".join(decode(t) for t in toks), b, o))
        print("%-18s %5d cases, %d differ" % (name, len(mine), d))
    print("%d cases over %d syscalls: %d differ, %d differences expected" % (total, len(names), differ, accepted))
    rmtree("/tmp/cont-probe-%d" % os.getpid())
    if not a.keep and not differ:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
