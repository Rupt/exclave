"""Compare the kernel's and the launcher's answer to every trapped syscall (DESIGN.md 17 item 7).

This is the differential syscall probe. One program (test/progs/probe.c) issues every trapped path
and descriptor syscall of src/filter.c, and the two chattr ioctls, with every path form of 7.4.4
and every flag that changes resolution, over a fixed maze. It runs under two projections of the
same tree: the kernel's, a bwrap read-only bind of the unwrapped tree at /, and the launcher's.
Return value, errno, what a buffer holds afterwards and the path an opened descriptor names must
agree case by case; every file of the maze and the host area has a size and a user.probe value of
its own and the process keeps one inotify descriptor, so a stat's size, an attribute's value and a
watch descriptor also tell which object a path reached. A difference fails unless EXPECTED names
its reason, so the expectations come from the kernel, not from a test's author. Like oracle_ns, the
probe needs user namespaces and bwrap; without them it says so ("cannot run") and exits 0, and the
gate prints that step as SKIP.

    test/oracle_syscalls.py --exclave EXCLAVE [--work DIR] [--only NAME] [--keep]
        [--show N] [--expected]

Arguments. probe.c reads cases, each a syscall number and encoded arguments, and issues each through
syscall(2), so no libc wrapper stands in between; it prints the return value, the errno, what a
buffer holds afterwards, the path an opened descriptor names and what an exec'd program wrote. An
argument is one of: a path (s:), or a descriptor opened on a named path before the call (f:); an
integer (i:) or a buffer of a named kind; a string that ends at an unmapped page (e:), a null
pointer (n:) or a pointer into an unmapped page (u:); a string vector or a struct xattr_args; the
process's inotify descriptor, a fanotify descriptor (N:), a unix socket (k:) or a sockaddr_un (A:);
a struct open_how. execve runs in a forked child whose exit status and output are the answer.

Cases. The table covers the trapped path syscalls and the descriptor-addressed ones (fchmod, fchown,
fsetxattr, fremovexattr, fstatfs, and ioctl with FS_IOC_SETFLAGS and FS_IOC_FSSETXATTR), crossed
with every flag that changes resolution, with the invalid arguments the kernel checks before the
lookup, and with the path forms of class Forms over the maze of make_maze, the same in every run:
  - inside the exclave: a file, a directory and a symlink of every kind (loop, chained, dangling,
    absolute, relative), a wrapper, the shell's link, an identity file, also with a trailing
    slash and as a directory on the way, one the host lacks and the directory on the way to it,
    /proc/self/exe, and an exclave link to a host file and to a host directory, the latter also
    crossed in the middle of a path and followed by ..;
  - on the host: files, directories (an empty one among them, for an rmdir that succeeds) and
    links of every kind, links into the exclave's file, its directory and its wrapper, the
    directory link also crossed in the middle of a path and followed by .., and relative paths
    from the host side, up to the root and back into the tree;
  - spellings: ., .. and / as the last component, a trailing slash, also after . and .., after a
    link on either side and on either name of a rename or a link, and a component after a host
    link to a file, //, empty, overlong, a 256-byte component, bytes that are not UTF-8, and a
    newline;
  - the symlink limit: 40 links in one walk and 41, in a chain inside the tree, in one that crosses
    between the tree and the host area at every link, and as 20 links walked as directories before
    a chain of 20 at the end, since the kernel counts over the whole walk;
  - the three fault forms, and a socket file in the tree.
The *at forms add descriptors opened O_PATH or O_RDONLY on exclave and host directories, files and
symlinks, a wrapper, /dev/null, AT_FDCWD, a closed descriptor and a negative one. The two-path forms
take pairs from a shorter list (Forms.few). openat2 covers every descriptor-relative form with seven
flag words and seven resolve words, plus its struct's own rules. Cases that depend on one another
run in one group, in order, such as the relative forms after a chdir into the exclave; each world
runs one process per group, with the host area reset before each world, and the answers are compared
line by line.

Effects. After each world's run of a group, what the calls left is compared too: the host area, the
probe's /tmp directory and the launcher's maze, entry by entry (type and permissions, a file's size
and link count, a link's text, user.probe and the mtime, "now" unless a case set it), the two
worlds' alike and the launcher's maze as the kernel's read-only root keeps its own. A call that
answers 0 and does nothing, a symlink that stores the translated text, and a write that escaped the
read-only refusal fail there even when the answer is right.

The two worlds. The same binary, compiled by the exclave's compiler, runs under bwrap, with the
unwrapped tree read-only at / and the visibility rule of 8.1 spelt in bwrap's terms (the identity
files and the host's top-level directories bound from the host), and under the launcher, with a copy
of the exclave relinked with the build.

openat2 and EAGAIN. A scoped walk (RESOLVE_BENEATH, RESOLVE_IN_ROOT) answers EAGAIN when a rename or
a mount anywhere on the system raced it (handle_dots in fs/namei.c), and openat2(2) tells the caller
to retry; probe.c does, so the kernel's answer is the retry's. Measured natively under 170 000
renames a second, 4 900 of a million such walks answered EAGAIN and every one succeeded on its first
retry; with no renames, none of a million did. RESOLVE_CACHED's EAGAIN says the lookup needs more
than the cache, and openat2(2) tells the caller to retry without the flag; probe.c does, once, and
appends " cached_retry" to the answer. The kernel answers EAGAIN there for a create, a truncate and
a temporary file before any lookup (build_open_flags), and otherwise where its cache is cold, as in
bwrap's fresh mount namespace; the handler answers the first as the kernel does and drops the flag
for the rest, so its answer is the retry's.

The host's own answers. Where the kernel's world cannot be the oracle, on a host entry bound into
bwrap's read-only root and for a chown to root, the host is: a third run, the probe on the host
itself through the tree's loader (run_native), answers the cases of each group that name such a
path and nothing in the tree, a descriptor on a maze directory with a path that climbs out of the
tree spelt as the host names it, and the launcher must answer as it does.

Accepted differences. EXPECTED is part of the design (DESIGN.md 17 item 7): each entry names the
rule that makes a difference right, and a difference no entry names fails. The entries are of two
kinds, and each names the syscalls, the cases by their flag and form, and the answers its reason
covers:
  - the oracle's own construction: a host entry bound into bwrap's read-only root answers EROFS
    there, where the launcher answers as the native run; uid 0 is unmapped in bwrap's user
    namespace; a new top-level name is the host's (8.1),
    whose / answers EACCES where bwrap's root says EROFS; RESOLVE_CACHED answers EAGAIN under
    bwrap's cold cache where the handler answers the retry's answer itself;
  - for the kernel matrix (12.1), what an older kernel lacks or decided differently, each with the
    kernel change, the handler answering as the newest kernel does: ENOSYS for a syscall added after
    3.10, named with its release; EISDIR for O_CREAT|O_EXCL on ., .. or / before 5.8; linkat with
    AT_EMPTY_PATH refused with ENOENT before 6.10; RENAME_WHITEOUT's capability check in the initial
    user namespace; O_DIRECTORY|O_CREAT opening or creating before 6.3; RHEL 8's 4.18 openat2
    answering EXDEV for a create through a symlink under RESOLVE_NO_XDEV and RESOLVE_CACHED unknown
    before 5.12, where the launcher must answer what the kernel answers without the flag;
    utimensat refusing AT_EMPTY_PATH and checking the nanoseconds first before 5.9; an
    exec of a socket answered ENXIO before 5.9; truncate checking the mount before the permission on
    6.1 and earlier (6.14 checks the permission first).
More differences are accepted on older kernels, where more of the kernel entries apply.

Open defects. DEFECTS lists the differences that are the launcher's defects, found and not yet
fixed, each entry by what the kernel does and the cases and exact answers it covers. Every run
prints each entry with its count of cases (--expected prints the cases), and on the kernel they
were measured on, a whole run in which an entry covers no case fails until the entry is removed.

Counts. The last line of the output gives the number of cases, of groups (one per syscall, plus
the cases run after a chdir into the exclave) and of path forms, then the differences and those
accepted. Most accepted differences are RESOLVE_CACHED's retries, whose count moves by a few between
runs. The number of cases depends on the machine and the work directory: a syscall missing from the
machine's table is left out, and so is a host-area socket address longer than sun_path's 107 bytes,
which no program could write whole, so a deeper work directory gives fewer cases.
"""

import argparse
import errno
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from typing import NamedTuple
lazy from collections.abc import Callable

import tree
from harness import run
from syscalls import kernel_table

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
O_NOATIME = os.O_NOATIME
AT_FDCWD, AT_SYMLINK_NOFOLLOW, AT_REMOVEDIR, AT_SYMLINK_FOLLOW, AT_EMPTY_PATH, AT_EACCESS = (
    -100,
    0x100,
    0x200,
    0x400,
    0x1000,
    0x200,
)
RENAME_NOREPLACE, RENAME_EXCHANGE, RENAME_WHITEOUT = 1, 2, 4
AT_EXECVE_CHECK = 0x10000  # execveat's check that runs nothing, 6.14
AT_NO_AUTOMOUNT = 0x800
FAN_MARK_ADD, FAN_MARK_DONT_FOLLOW, FAN_OPEN = 1, 4, 0x20
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
IN_ONLYDIR, IN_DONT_FOLLOW = 0x01000000, 0x02000000
STATX_BASIC_STATS = 0x7FF
# the identity files the launcher answers from the host (8.4)
IDENTITY = tree.IDENTITY_FILES
# a new top-level name: the host's (8.1 rule 2), where bwrap's read-only root refuses it
NEW_TOP = "/exclave-probe-top"
# seconds one world's run of one group may take, many times the slowest group's
TIMEOUT = 60


def hx(s: str | bytes) -> str:
    """Return the hex of a path, spelt as the kernel takes it."""
    return s.encode("utf-8", "surrogateescape").hex() if isinstance(s, str) else s.hex()


SOCK_STREAM, SOCK_DGRAM = 1, 2

# Each of the one-letter functions makes an argument token for probe.c, named for the token's
# letter.


def K(type_: int) -> str:  # noqa: N802 -- a token's constructor, named for its token's letter
    """Make a unix socket descriptor of this type."""
    return f"k:{type_}"


def O(dir_: str) -> str:  # noqa: E743, N802 -- as K
    """Make a descriptor on an O_TMPFILE file in dir_: a file with no path."""
    return "o:" + hx(dir_)


def D(dir_: str) -> str:  # noqa: N802 -- as K
    """Make an O_PATH descriptor on a directory made under dir_ and removed: one with no path."""
    return "d:" + hx(dir_)


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


# The probe's maze, the same in every run (make_maze): a file two directories down and the directory
# that holds it, and a symlink of every kind
MAZE_FILE, MAZE_DIR = "/maze/d0/d1/f0", "/maze/d0/d1"
MAZE_LINKS = {
    "abs": ("/maze/labs", MAZE_FILE),
    "rel": ("/maze/d0/d1/lrel", "../f1"),  # up a directory, to /maze/d0/f1
    "link": ("/maze/lchain", "/maze/labs"),  # a link to a link
    "dangling": ("/maze/d0/ldang", "/maze/d0/missing"),
    "loop": ("/maze/d0/lloop", "/maze/d0/lloop"),
}


# the kernel follows at most 40 links in one walk (MAXSYMLINKS), counted over the whole of it
MAXSYMLINKS = 40
PATH_MAX = 4096


def padded(head: str, tail: str, length: int) -> str:
    """head, then "./" components, then tail: a path of exactly length bytes naming head + tail.

    An odd remainder is made even by a doubled slash after head.
    """
    rest = length - len(head) - len(tail)
    if rest % 2:
        head += "/"
        rest -= 1
    return head + "./" * (rest // 2) + tail


def chain_links(host: str) -> list[tuple[str, str]]:
    """The links of the chains at the symlink limit: (link, absolute target), a file at the end.

    /maze/chain/c0 to c40 lie in the tree; n0 to n40 alternate between the tree (/maze/xchain, the
    even ones) and the host area (hchain, the odd ones); /maze/dl/a is a link to its own directory,
    to be walked through as often as a path names it, and /maze/dl/e0 to e19 a chain at the end.
    """

    def node(i: int) -> str:
        return f"/maze/xchain/n{i}" if i % 2 == 0 else f"{host}/hchain/n{i}"

    links = [
        (f"/maze/chain/c{i}", f"/maze/chain/c{i + 1}" if i < MAXSYMLINKS else "/maze/f2")
        for i in range(MAXSYMLINKS + 1)
    ]
    links += [
        (node(i), node(i + 1) if i < MAXSYMLINKS else "/maze/d0/f1") for i in range(MAXSYMLINKS + 1)
    ]
    half = MAXSYMLINKS // 2
    links.append(("/maze/dl/a", "/maze/dl"))
    links += [
        (f"/maze/dl/e{i}", f"/maze/dl/e{i + 1}" if i < half - 1 else "/maze/f2")
        for i in range(half)
    ]
    return links


def set_probe_xattrs(top: str, values: tuple[tuple[str, str], ...]) -> None:
    """Give files under top a user.probe attribute of their own.

    Then a get or a remove of it succeeds somewhere and says which file it reached. A filesystem
    without user attributes, or a Python without os.setxattr (a musl build), leaves them out in
    both worlds alike.
    """
    setxattr = getattr(os, "setxattr", None)
    for path, value in values:
        try:
            if setxattr:
                setxattr(top + path, "user.probe", value.encode())
        except OSError:
            pass


def make_maze(root: str, host: str) -> None:
    """Make the probe's maze under root's /maze, every form's target named explicitly.

    The forms are fixed, so that no run can lose one; the resolution oracle's maze is the random
    one (17 item 2).
    """
    maze = os.path.join(root, "maze")
    rmtree(maze)
    os.makedirs(os.path.join(root, MAZE_DIR.lstrip("/")))
    # every file a size of its own, as the host area's (host_reset), so that a stat tells which
    # file a path reached
    for f, size in ((MAZE_FILE, 7), ("/maze/d0/f1", 8), ("/maze/f2", 9)):
        with open(os.path.join(root, f.lstrip("/")), "w") as fh:
            fh.write("x" * size)
    links = [
        *MAZE_LINKS.values(),
        # an exclave link to a host file, and to a host directory
        ("/maze/lH", host + "/hfile"),
        ("/maze/lHD", host + "/hdir"),
        # a link whose text ends in a slash, to a missing name and to a file: the kernel walks the
        # text as the rest of the path, so the slash is the path's trailing slash (8.1)
        ("/maze/lS", "/maze/absent/"),
        ("/maze/lFS", "/maze/ro444/"),
        # links to the forms' directory and file, for a trailing slash after a link
        ("/maze/lD", MAZE_DIR),
        ("/maze/lF", MAZE_FILE),
        # a relative link that climbs above the root, which stays at the root; a link to its own
        # directory and one to the root; a link whose text is as long as a text can be
        ("/maze/lup", "../../.."),
        ("/maze/ldot", "."),
        ("/maze/lroot", "/"),
        ("/maze/llong", padded("/maze/", "f2", PATH_MAX - 1)),
    ]
    for link, target in links:
        try:
            os.symlink(target, os.path.join(root, link.lstrip("/")))
        except OSError as e:
            # a text as long as a text can be is more than some filesystems keep (XFS 1024
            # bytes, ext4 a block less one): the link is left out, and its cases answer alike in
            # both worlds
            if e.errno != errno.ENAMETOOLONG or link != "/maze/llong":
                raise
            print(
                f"{link} is not made: this filesystem refuses {len(target)} bytes of link text "
                f"({os.strerror(e.errno)}), and the cases naming it see no link"
            )
    for link, target in chain_links(host):
        if link.startswith("/maze/"):
            os.makedirs(os.path.dirname(os.path.join(root, link.lstrip("/"))), exist_ok=True)
            os.symlink(target, os.path.join(root, link.lstrip("/")))
    set_probe_xattrs(
        root, ((MAZE_FILE, "f0"), ("/maze/d0/f1", "f1"), ("/maze/f2", "f2"), (MAZE_DIR, "d1"))
    )
    # a socket file in the tree, for bind and connect
    tree.socket_file(os.path.join(maze, "sock"))
    # a file its owner cannot write: access(W_OK) is EACCES before EROFS
    with open(os.path.join(maze, "ro444"), "w") as f:
        f.write("ro\n")
    os.chmod(os.path.join(maze, "ro444"), 0o444)


class Forms:
    """The path forms of 7.4.4 over this maze, this tree and the host area."""

    def __init__(self, root: str, host: str) -> None:
        self.host = host
        self.link = {kind: link for kind, (link, _target) in MAZE_LINKS.items()}
        by_kind = self.link
        self.file, self.dir = MAZE_FILE, MAZE_DIR
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
            # a slash after them: the same last component (filename_parentat's type)
            ("dot_slash", self.dir + "/./"),
            ("dotdot_slash", self.dir + "/../"),
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
            # an identity file with a trailing slash, and a path through one: the kernel follows
            # the link and wants a directory (ENOTDIR)
            ("passwd_slash", "/etc/passwd/"),
            ("resolv_slash", "/etc/resolv.conf/"),
            ("resolv_dotdot", "/etc/resolv.conf/../hosts"),
            # an identity file most hosts lack, the exclave's placeholder then (8.1 rule 5), and
            # the directory on the way to it, which the host need not have
            ("ca_bundle", "/etc/pki/tls/certs/ca-bundle.crt"),
            ("ca_bundle_dir", "/etc/pki/tls/certs"),
            ("tmp", "/tmp"),
            ("dev_null", "/dev/null"),
            ("proc_exe", "/proc/self/exe"),
            ("proc_cwd", "/proc/self/cwd"),
            ("home", "/home"),
            ("opt", "/opt"),
            ("exclave_to_host", "/maze/lH"),
            ("exclave_to_host_dir", "/maze/lHD"),
            # through an exclave link to a host directory, then into it or back out of it: .. after
            # a link is the parent of its target, not of the link
            ("exclave_link_mid", "/maze/lHD/inner"),
            ("exclave_link_dotdot", "/maze/lHD/../hfile"),
            # a trailing slash after a link follows it, even for lstat and the no-follow calls
            ("link_dir_slash", "/maze/lD/"),
            ("link_file_slash", "/maze/lF/"),
            ("link_slash_absent", "/maze/lS"),
            ("link_slash_file", "/maze/lFS"),
            ("overlong", "/maze/" + "a" * 5000),
            ("long_component", "/maze/" + "b" * 256),
            ("long_ok", "/maze/" + "c" * 255),
            ("non_utf8", "/maze/\udcff\udcfe"),
            ("newline", "/maze/a\nb"),
            # at the symlink limit and one past it: a chain in the tree, one that crosses between
            # the tree and the host area at every link, and links walked as directories first
            ("chain_40", "/maze/chain/c1"),
            ("chain_41", "/maze/chain/c0"),
            ("cross_chain_40", h + "/hchain/n1"),
            ("cross_chain_41", "/maze/xchain/n0"),
            ("dir_links_40", "/maze/dl/" + "a/" * (MAXSYMLINKS // 2) + "e0"),
            ("dir_links_41", "/maze/dl/" + "a/" * (MAXSYMLINKS // 2 + 1) + "e0"),
            # spellings the walk must normalise: doubled slashes, "." runs, ".." above the root
            ("double_slash_mid", "/maze//d0//d1//f0"),
            ("double_slash_end", self.file + "//"),
            ("dot_runs", "/./maze/./d0/./d1/./f0"),
            ("root_dotdot_runs", "/../../maze/d0/d1/f0"),
            # a new top-level name: the host's (8.1 rule 2)
            ("new_top", NEW_TOP),
            # the process's root, a magic link to /, and a climb out of it
            ("proc_root", "/proc/self/root/maze/d0/d1/f0"),
            ("proc_root_dotdot", "/proc/self/root/../maze/f2"),
            ("proc_root_slash", "/proc/self/root/"),
            # links that climb above the root, name their own directory, the root, or 4095 bytes
            ("link_climb", "/maze/lup/maze/f2"),
            ("link_dot", "/maze/ldot/f2"),
            ("link_root", "/maze/lroot/maze/f2"),
            ("link_text_4095", "/maze/llong"),
            # a path of PATH_MAX - 1 bytes, the longest the kernel reads, and one of PATH_MAX
            ("path_4095", padded("/maze/d0/d1/", "f0", PATH_MAX - 1)),
            ("path_4096", padded("/maze/d0/d1/", "f0", PATH_MAX)),
        ]
        for kind, link in sorted(by_kind.items()):
            ex.append(("link_" + kind, link))
        hostf = [
            ("host_file", h + "/hfile"),
            ("host_dir", h + "/hdir"),
            ("host_empty_dir", h + "/hempty"),
            ("host_to_exclave", h + "/hlink"),
            ("host_to_exclave_dir", h + "/hlnkdir"),
            ("host_dangling", h + "/hdang"),
            ("host_link_mid", h + "/hlnkdir/" + os.path.basename(self.file)),
            (
                "host_link_dotdot",
                h + "/hlnkdir/../" + os.path.basename(self.dir) + "/" + os.path.basename(self.file),
            ),
            ("host_link_slash", h + "/hlink/"),
            ("host_link_dir_slash", h + "/hlnkdir/"),
            ("host_dangling_slash", h + "/hdang/"),
            # through a host link to an exclave file, then on: ENOTDIR from the walk
            ("host_link_notdir_mid", h + "/hlink/x"),
            ("host_missing_slash", h + "/missing/"),
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
                ("host_to_exclave_dir", h + "/hlnkdir"),
                ("host_dangling", h + "/hdang"),
                ("exclave_to_host", "/maze/lH"),
                ("link_dangling", by_kind["dangling"]),
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
            "../../../etc/passwd",  # up to the root, and an identity file
            "../../../../tmp",  # above the root
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
        self.at += [
            ("lfd_exclave/" + r, F(O_PATH | O_NOFOLLOW, by_kind.get("abs", self.file)), S(r))
            for r in ("", "x", "..")
        ]
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
        # the root, and the process's own directory under /proc, whose magic links lead to the
        # host's mounts
        self.at += [
            ("dfd_root/" + r, F(O_PATH | O_DIRECTORY, "/"), S(r))
            for r in ("maze/d0/d1/f0", "..", "etc/passwd", NEW_TOP[1:])
        ]
        self.at += [
            ("dfd_proc/" + r, F(O_PATH, "/proc/self"), S(r))
            for r in ("cwd", "cwd/hfile", "cwd/missing", "root/maze/f2")
        ]
        # descriptors whose file has no path: a socket, a pipe, a memfd, an O_TMPFILE file and a
        # directory removed after it was opened
        self.pathless = [
            ("sockfd", K(SOCK_STREAM)),
            ("pipefd", "p:"),
            ("memfd", "m:"),
            ("tmpfilefd", O(h)),
            ("gonefd", D(h)),
        ]
        self.at += [
            (f"{n}/{r}", d, S(r))
            for n, d in self.pathless
            for r in (("", ".", "..", "x", "../hfile") if n == "gonefd" else ("", ".", "x"))
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
    forms: Forms, nr: dict[str, int], uid: int, gid: int, mutable: set[str]
) -> list[tuple[str, str, list[str], str]]:
    """(label, syscall name, [tokens], group) for every case.

    A name absent from this machine's table is skipped. mutable names the bound host directories
    the kernel's world can write to (writable_in_bwrap), which no case changes.
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
        ("wr_dir", O_WRONLY | O_DIRECTORY),
        ("rd_dir_nofollow", O_RDONLY | O_DIRECTORY | O_NOFOLLOW),
        ("tmpfile", O_RDWR | O_TMPFILE),
        # the flag word's own rules, before any lookup (build_open_flags): O_TMPFILE wants write
        # access and O_DIRECTORY beside it, and refuses O_CREAT; open's O_PATH drops O_CREAT
        ("tmpfile_rd", O_RDONLY | O_TMPFILE),
        ("tmpfile_creat", O_RDWR | O_TMPFILE | O_CREAT),
        ("tmpfile_bare", O_RDWR | (O_TMPFILE & ~O_DIRECTORY)),
        ("path_dir_creat", O_PATH | O_DIRECTORY | O_CREAT),
        # may_open's other answers: an access mode of 3 is checked as a read-write open and
        # opened as neither, so it succeeds on a read-only mount; O_NOATIME is the owner's;
        # O_EXCL without O_CREAT follows symlinks
        ("acc3", 3),
        ("rd_noatime", O_RDONLY | O_NOATIME),
        ("rd_excl", O_RDONLY | O_EXCL),
    ]
    stat_flags = [
        ("follow", 0),
        ("nofollow", AT_SYMLINK_NOFOLLOW),
        ("empty_path", AT_EMPTY_PATH),
        ("nofollow_empty_path", AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH),
        # coreutils' stat and ls pass it; nothing in an exclave is an automount point
        ("no_automount", AT_NO_AUTOMOUNT),
    ]
    # a bound host directory the kernel's world can write to, /tmp aside, is left as it is: the
    # two worlds would share what one of them changed there (an xattr set, a socket bound), and
    # the host is not the probe's to change. /tmp is sticky, so an xattr there is refused and a
    # relative bind there is cleaned up between the worlds.
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
        if n not in mutable:
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
        if n not in mutable:
            add("setxattr", n, p, S("user.probe"), S("v"), I(1), I(0))
            add("lsetxattr", n, p, S("user.probe"), S("v"), I(1), I(0))
        add("getxattr", n, p, S("user.probe"), B("xattr", 64), I(64))
        add("lgetxattr", n, p, S("user.probe"), B("xattr", 64), I(64))
        add("listxattr", n, p, B("xattr", 512), I(512))
        add("llistxattr", n, p, B("xattr", 512), I(512))
        if n not in mutable:
            add("removexattr", n, p, S("user.probe"))
            add("lremovexattr", n, p, S("user.probe"))
        # an identity file's watches in a group of their own: a watch descriptor names an inode
        # within one process, so a watch on the link and one on its target are told apart by the
        # follow and no-follow answers side by side, and the numbering of the others stays
        group = "inotify_identity" if n in ("passwd", "resolv") else None
        add("inotify_add_watch", n, "I:", p, I(IN_MODIFY))
        add("inotify_add_watch", n + "/dont_follow", "I:", p, I(IN_MODIFY | IN_DONT_FOLLOW))
        add("inotify_add_watch", n + "/onlydir", "I:", p, I(IN_MODIFY | IN_ONLYDIR))
        group = None
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
        if n not in mutable:
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
    add("execve", "rel_true", S("htrue"), V("true"), V())
    for n, d, p in forms.at:
        changes = n.partition("/")[2] not in mutable  # cwd/NAME: the path form's own name
        for fn, fl in open_flags:
            add("openat", f"{n}/{fn}", d, p, I(fl), I(0o644))
        add("mkdirat", n, d, p, I(0o755))
        add("mknodat", n, d, p, I(0o10644), I(0))
        for fn, fl in (
            ("follow", 0),
            ("nofollow", AT_SYMLINK_NOFOLLOW),
            ("empty_path", AT_EMPTY_PATH),
        ):
            if changes:
                add("fchownat", f"{n}/{fn}", d, p, I(uid), I(gid), I(fl))
        if changes:
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
        add("statx", n + "/force_sync", d, p, I(0x2000), I(STATX_BASIC_STATS), B("statx", 256))
        add("statx", n + "/dont_sync", d, p, I(0x4000), I(STATX_BASIC_STATS), B("statx", 256))
        # a mark through a real fanotify descriptor, which an unprivileged one reports by file id
        add("fanotify_mark", n, "N:", I(FAN_MARK_ADD), I(FAN_OPEN), d, p)
        add(
            "fanotify_mark",
            n + "/dont_follow",
            "N:",
            I(FAN_MARK_ADD | FAN_MARK_DONT_FOLLOW),
            I(FAN_OPEN),
            d,
            p,
        )
        add("statx", n + "/bad_flags", d, p, I(1), I(STATX_BASIC_STATS), B("statx", 256))
        add("faccessat", n + "/bad_mode", d, p, I(8))
        add("faccessat2", n + "/bad_flags", d, p, I(4), I(1))
        add("fchmodat2", n + "/bad_flags", d, p, I(0o644), I(1))
        add("symlinkat", n + "/empty_target", S(""), d, p)
        add("symlinkat", n, S("/maze/f0"), d, p)
        add("readlinkat", n, d, p, B("link", 4096), I(4096))
        add("readlinkat", n + "/zero", d, p, B("link", 4), I(0))
        add("readlinkat", n + "/hi_two", d, p, B("link", 4), I((1 << 32) | 2))
        if changes:
            add("fchmodat", n, d, p, I(0o644))
        add("faccessat", n, d, p, I(4))
        add("faccessat", n + "/W", d, p, I(2))
        add("faccessat2", n, d, p, I(4), I(0))
        add("faccessat2", n + "/eaccess", d, p, I(2), I(AT_EACCESS))
        if changes:
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
        add("utimensat", n + "/empty_path", d, p, "t:1000,0,2000,0", I(AT_EMPTY_PATH))
        add("futimesat", n + "/bad_usec", d, p, "T:1000,0,2000,-1")
        add("execveat", n, d, p, V("x"), V(), I(0))
        add("execveat", n + "/empty_path", d, p, V("x"), V(), I(AT_EMPTY_PATH))
        # a check that runs nothing (6.14), and a flag no kernel knows
        add("execveat", n + "/check", d, p, V("x"), V(), I(AT_EXECVE_CHECK))
        add("execveat", n + "/bad_flag", d, p, V("x"), V(), I(0x40000))
        if changes:
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
        if changes:
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
        "true_fd/check",
        F(O_RDONLY, forms.true),
        S(""),
        V("true"),
        V(),
        I(AT_EMPTY_PATH | AT_EXECVE_CHECK),
    )
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
                ("empty_path", AT_EMPTY_PATH),
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
    # and across the host's own mounts: /tmp is one of its own under bwrap and, as a rule, natively
    tmp_new = ("tmp_new", S(f"/tmp/exclave-probe-{os.getpid()}/new"))
    for n1, p1 in dots:
        for n2, p2 in [
            (n, p) for n, p in two if n in ("exclave_file", "host_file", "host_missing")
        ] + [tmp_new]:
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
    # a trailing slash on either name of a rename or a link: the last name is looked up in its
    # parent, a symlink included, and the slash is the call's to judge (filename_renameat2: ENOTDIR
    # unless the source is a directory, EEXIST under RENAME_NOREPLACE first; filename_create for
    # link's new name: EEXIST or ENOENT; a lookup for its old name, which follows)
    slashed = [
        ("host_link_slash", S(forms.host + "/hlink/")),
        ("host_link_dir_slash", S(forms.host + "/hlnkdir/")),
        ("host_dangling_slash", S(forms.host + "/hdang/")),
        ("host_file_slash", S(forms.host + "/hfile/")),
        ("host_dir_slash", S(forms.host + "/hdir/")),
        ("host_missing_slash", S(forms.host + "/missing/")),
        ("link_dir_slash", S("/maze/lD/")),
        ("link_file_slash", S("/maze/lF/")),
    ]
    partners = [
        ("host_file", S(forms.host + "/hfile")),
        ("host_dir", S(forms.host + "/hdir")),
        ("host_missing", S(forms.host + "/missing")),
        ("exclave_file", S(forms.file)),
    ]
    for n1, p1 in slashed:
        for n2, p2 in partners:
            for lab, x, y in ((f"{n1}->{n2}", p1, p2), (f"{n2}->{n1}", p2, p1)):
                add("rename", lab, x, y)
                add("link", lab, x, y)
                add("linkat", lab, I(AT_FDCWD), x, I(AT_FDCWD), y, I(0))
                for fn, fl in (
                    ("plain", 0),
                    ("noreplace", RENAME_NOREPLACE),
                    ("exchange", RENAME_EXCHANGE),
                ):
                    add("renameat2", f"{lab}/{fn}", I(AT_FDCWD), x, I(AT_FDCWD), y, I(fl))
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
    # AT_EMPTY_PATH on a descriptor whose file has no path: the kernel's own answer through the
    # descriptor (EXDEV, EPERM, or the link itself since 6.10)
    for n, d in forms.pathless:
        new = S(f"{forms.host}/hlinked_{n}")
        add("linkat", n + "_empty", d, S(""), I(AT_FDCWD), new, I(AT_EMPTY_PATH))
        new = S(f"/maze/hnew_{n}")
        add("linkat", n + "_empty_to_exclave", d, S(""), I(AT_FDCWD), new, I(AT_EMPTY_PATH))
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
        "../../../home",
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
    # O_DIRECTORY|O_CREAT, EINVAL since 6.3, last in its groups: before 6.3 it creates a file, which
    # the cases after it would see in one world only
    for n, p in forms.paths:
        add("open", n + "/dir_creat", p, I(O_DIRECTORY | O_CREAT), I(0o644))
    for n, d, p in forms.at:
        add("openat", n + "/dir_creat", d, p, I(O_DIRECTORY | O_CREAT), I(0o644))
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


def host_reset(host: str, forms: Forms, probe: str) -> None:
    """The host area both worlds see at the same path, identical before every run.

    Its links into the exclave name the forms' file, directory and wrapper, so that the forms that
    cross from the host into the tree reach something in both worlds.
    """
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
    os.makedirs(host + "/hempty")  # for an rmdir that succeeds
    with open(host + "/hfile", "w") as f:
        f.write("hello\n")
    with open(host + "/hdir/inner", "w") as f:
        f.write("inner text\n")
    set_probe_xattrs(host, (("/hfile", "hfile"), ("/hdir", "hdir"), ("/hdir/inner", "inner")))
    for name, target in (
        ("hlink", forms.file),
        ("hlnkdir", forms.dir),
        ("htrue", forms.true),
        ("hdang", "missing"),
        ("hloop", "hloop"),
        ("hrel", "hdir/inner"),
    ):
        os.symlink(target, os.path.join(host, name))
    os.makedirs(host + "/hchain")
    for link, target in chain_links(host):
        if link.startswith(host + "/"):
            os.symlink(target, link)
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
    with open(cases, "rb") as f:
        return run([*args, probe], env={}, stdin=f, timeout=TIMEOUT)


def snapshot(top: str) -> dict[str, str]:
    """What a tree holds, by path relative to top.

    Each entry's type and permissions, a file's size and link count, a link's text, its user.probe
    attribute and its mtime, "now" for any time past 10 000 s, which no case sets.
    """
    getxattr = getattr(os, "getxattr", None)
    out: dict[str, str] = {}
    if not os.path.lexists(top):
        return out
    todo = [""]
    while todo:
        rel = todo.pop()
        full = os.path.join(top, rel) if rel else top
        try:
            st = os.lstat(full)
        except PermissionError:  # under a directory a chmod case took the search bit from
            out[rel] = "unreachable"
            continue
        desc = [f"{st.st_mode:o}"]
        if stat.S_ISREG(st.st_mode):
            desc.append(f"size={st.st_size},nlink={st.st_nlink}")
        elif stat.S_ISLNK(st.st_mode):
            desc.append("link=" + hx(os.readlink(full)))
        try:
            if getxattr:
                desc.append("user.probe=" + hx(getxattr(full, "user.probe", follow_symlinks=False)))
        except OSError:
            pass
        desc.append("mtime=" + ("now" if st.st_mtime_ns > 10**13 else str(st.st_mtime_ns)))
        out[rel or "."] = " ".join(desc)
        if stat.S_ISDIR(st.st_mode):
            try:
                todo += [os.path.join(rel, n) for n in os.listdir(full)]
            except PermissionError:
                out[rel or "."] += " unreadable"
    return out


def prefixed(prefix: str, snap: dict[str, str]) -> dict[str, str]:
    return {f"{prefix}/{k}": v for k, v in snap.items()}


def effects(host: str) -> dict[str, str]:
    """What a world's run of a group left behind.

    The host area, /tmp/exclave-probe-PID and, for a relative bind after a chdir into /tmp,
    /tmp/probe-sock-PID.
    """
    rel_sock = "/tmp/" + REL_SOCK
    return (
        prefixed("area", snapshot(os.path.dirname(host)))
        | prefixed("tmp", snapshot(f"/tmp/exclave-probe-{os.getpid()}"))
        | ({REL_SOCK: snapshot(rel_sock)["."]} if os.path.lexists(rel_sock) else {})
    )


def run_native(root: str, host: str, probe: str, cases: str) -> tuple[int, str, str]:
    """The host's own answers: the probe run on the host, neither under bwrap nor the launcher.

    It runs through the unwrapped tree's loader and libc, which the host need not have, so the
    same binary answers in all three worlds.
    """
    interp = tree.interp(probe)
    cmd = [probe]
    if interp:
        loader = os.path.join(root, tree.resolve(root, interp).lstrip("/"))
        libc = os.path.join(root, tree.resolve(root, tree.libc(root, MACHINE)).lstrip("/"))
        cmd = [loader, "--library-path", os.path.dirname(libc), probe]
    with open(cases, "rb") as f:
        return run(
            cmd, cwd=host, env={"PATH": "/usr/bin:/bin", "HOME": host}, stdin=f, timeout=TIMEOUT
        )


def as_the_host_sees(toks: list[str]) -> list[str]:
    """A case's arguments as the host names them.

    A descriptor on a directory of the maze, with a relative path that climbs out of the tree, is
    AT_FDCWD with the path's lexical form: the host has no /maze, and the walk out of it crosses no
    link.
    """
    out = []
    base: str | None = None
    for t in toks:
        if t.startswith("f:"):
            fp = bytes.fromhex(t[2:].partition(":")[2]).decode("utf-8", "surrogateescape")
            if fp.startswith("/maze"):
                base = fp
                out.append(I(AT_FDCWD))
                continue
        r = raw_of(t)
        climbs = base is not None and r is not None and not r.startswith("/")
        out.append(S(lexical(f"{base}/{r}")) if climbs else t)
        base = None
    return out


def native_cases(
    mine: list[tuple[str, str, list[str], str]], host: str, unsafe: set[str]
) -> list[tuple[int, list[str]]]:
    """A group's cases the native run answers, as the host names them (as_the_host_sees).

    Those whose truth is the host's: a case that names a bound host path, or a chown to root, and no
    path of the tree's, nor one of unsafe, the bound paths whose directory this user can write:
    there a call the other worlds refuse could succeed, which the host is not the probe's to change.
    """
    out = []
    for i, (label, n, toks, group) in enumerate(mine):
        if group != n:
            continue  # a group of cases that depend on one another runs whole or not at all
        host_toks = as_the_host_sees(toks)
        paths = {lexical(r) for r in named_paths(n, host_toks, host)}
        if paths & unsafe or any(p == "/maze" or p.startswith("/maze/") for p in paths):
            continue
        if paths & BOUND_PATHS or label.endswith("/to_root"):
            out.append((i, host_toks))
    return out


def writable_in_bwrap(forms: Forms, root: str, host: str, bindir: str) -> set[str]:
    """The names of the bound host directories (BOUND) the kernel's world can write to.

    Asked in that world rather than here: an unprivileged bwrap gives its user the capabilities of
    its own user namespace, so a directory this user owns but cannot write to is writable there.
    """
    dirs = [
        (n, d)
        for n, p in forms.paths
        if n in BOUND and (d := raw_of(p)) is not None and os.path.isdir(d)
    ]
    script = os.path.join(bindir, "writable.sh")
    os.makedirs(host, exist_ok=True)  # bwrap starts in the host area, which the reset remakes
    with open(script, "w") as f:
        f.write("".join(f'[ -w "{p}" ] && echo "{p}"\n' for _n, p in dirs) + "exit 0\n")
    _rc, out, _err = run_bwrap(root, host, bindir, forms.sh, script)
    found = set(out.split())
    return {n for n, p in dirs if p in found}


def run_launcher(ex: str, host: str, probe: str, cases: str) -> tuple[int, str, str]:
    with open(cases, "rb") as f:
        return run(
            [os.path.join(ex, ".exclave", "launcher"), probe],
            cwd=host,
            env={"PATH": "/usr/bin:/bin", "HOME": host},
            stdin=f,
            timeout=TIMEOUT,
        )


def errnos(b: str, o: str) -> tuple[int, int]:
    return int(b.split("errno=")[1].split(maxsplit=1)[0]), int(
        o.split("errno=")[1].split(maxsplit=1)[0]
    )


def watch_numbers(
    mine: list[tuple[str, str, list[str], str]], bl: list[str], ol: list[str]
) -> tuple[list[str], list[str]]:
    """The inotify_add_watch answers with their watch descriptors numbered by first appearance.

    The probe keeps one inotify instance, so that a watch descriptor names an inode (probe.c), but
    the instance numbers its watches in order: one case the worlds answer differently under a
    rule (the kernel's ELOOP at exactly MAXSYMLINKS links, which its retried walk may give) adds
    a watch in one world and shifts every later number there. Each world's numbers are replaced
    by the order of their first appearance among the cases both worlds answered with a
    descriptor, which keeps what a descriptor says, two cases that reach one inode answer the
    same, and drops the count.
    """
    numbers: tuple[dict[str, int], dict[str, int]] = ({}, {})

    def wd(answer: str) -> str | None:
        ret, _, rest = answer.partition(" ")
        return ret if rest.startswith("errno=0") and not ret.startswith("ret=-") else None

    for (_label, n, _toks, _group), b, o in zip(mine, bl, ol, strict=True):
        if n != "inotify_add_watch":
            continue
        pair = wd(b.split(" ", 1)[1]), wd(o.split(" ", 1)[1])
        if None in pair:
            continue
        for seen, w in zip(numbers, pair, strict=True):
            if w is not None and w not in seen:
                seen[w] = len(seen)
    out = []
    for lines, seen in zip((bl, ol), numbers, strict=True):
        new = []
        for (_label, n, _toks, _group), line in zip(mine, lines, strict=True):
            i, _, answer = line.partition(" ")
            w = wd(answer) if n == "inotify_add_watch" else None
            if w is not None and w in seen:
                answer = f"ret=w{seen[w]}" + answer[len(w) :]
            new.append(f"{i} {answer}")
        out.append(new)
    return out[0], out[1]


def exec_errnos(b: str, o: str) -> tuple[int, int]:
    """An exec's errnos: the probe runs it in a child whose wait status is 100 + errno (probe.c)."""

    def one(a: str) -> int:
        status = int(a.split("ret=")[1].split(maxsplit=1)[0])
        return (status >> 8) - 100

    return one(b), one(o)


# The bound host paths, the host's entries bound into bwrap's read-only root: there the host's own
# answer is the expectation (8.1, 8.4)
BOUND = {
    "passwd": "/etc/passwd",
    "resolv": "/etc/resolv.conf",
    "passwd_slash": "/etc/passwd",
    "resolv_slash": "/etc/resolv.conf",
    "resolv_dotdot": "/etc/resolv.conf",
    "ca_bundle": "/etc/pki/tls/certs/ca-bundle.crt",
    "tmp": "/tmp",
    "home": "/home",
    "opt": "/opt",
    "dev_null": "/dev/null",
    "rel_etc_by_dotdot": "/etc/passwd",
}
BOUND_PATHS = frozenset(BOUND.values())
# openat2's flag words (generate) that create: RESOLVE_CACHED refuses them before any lookup
CREATING = ("wr_creat", "tmpfile")


class Ctx(NamedTuple):
    """What a rule may ask of a case beyond its two answers."""

    raw: tuple[str, ...]  # the paths it names, from its directory as given (named_paths)
    paths: tuple[str, ...]  # the same, made absolute and normal lexically (lexical)
    kernel: dict[str, str]  # the kernel's answers in its group, by label
    native: dict[str, str]  # the native run's answers in its group, by label (run_native)


def named_paths(name: str, toks: list[str], host: str) -> tuple[str, ...]:
    """The paths a case names, and every descriptor's path.

    Each path argument is joined to its directory descriptor's path, or to the host area, the
    working directory. A symlink's target is text, not a path the call names.
    """
    base: str | None = host
    out = []
    for i, t in enumerate(toks):
        if t.startswith("i:"):
            base = host if t == I(AT_FDCWD) else None
        elif t.startswith("f:"):
            base = bytes.fromhex(t[2:].partition(":")[2]).decode("utf-8", "surrogateescape")
            out.append(base)
        elif (r := raw_of(t)) and not (i == 0 and name in ("symlink", "symlinkat")):
            if r.startswith("/"):
                out.append(r)
            elif base is not None:
                out.append(base + "/" + r)
    return tuple(out)


def lexical(path: str) -> str:
    """A path made absolute and normal by its text alone.

    The kernel's walk gives the same where no component is a link, as on the probe's way out of
    the tree through its directories.
    """
    return os.path.normpath("/" + path.lstrip("/"))


def failed(answer: str) -> bool:
    return answer.startswith("ret=-1 ")


# differences with a reason: (syscall name or None, predicate on (label, bwrap answer, launcher
# answer, Ctx), reason). The list is part of the design (17): each entry names the rule that makes
# the difference right, the cases it covers by their flag and form, and the launcher's answer it
# allows.
EXPECTED: list[tuple[str | None, Callable[[str, str, str, Ctx], object], str]] = [
    # the kernel matrix (12): what this kernel lacks or decided differently, each entry naming the
    # kernel change
    (
        None,
        lambda label, b, o, c: (
            KERNEL < (5, 8)
            and label.endswith("/wr_creat_excl")
            and any(r == "/" or r.endswith(("/.", "/..")) for r in c.raw)
            and errnos(b, o) == (errno.EISDIR, errno.EEXIST)
        ),
        (
            "O_CREAT|O_EXCL on '.', '..' or '/': EISDIR before the lookup rework of 5.8, EEXIST "
            "since; the handler answers as the newer kernels do"
        ),
    ),
    (
        "linkat",
        lambda label, b, o, _c: (
            KERNEL < (6, 10)
            and (
                label.endswith(("/empty_path", "_empty", "_empty_to_exclave"))
                or label in ("fd_empty", "hostfd_empty", "hostfd_empty_to_exclave")
            )
            and errnos(b, o)[0] == errno.ENOENT
            and failed(o)
        ),
        (
            "linkat with AT_EMPTY_PATH needed CAP_DAC_READ_SEARCH (ENOENT without it) until 6.10 "
            "allowed it under the opener's own credentials; the handler answers the exclave's "
            "rules (EXDEV, EROFS) before that check, which the kernel makes first, and a host "
            "descriptor's call is re-issued through it as given, which this kernel refuses alike"
        ),
    ),
    (
        "openat2",
        lambda label, b, o, _c: (
            label.endswith("/cached")
            and label.split("/")[-2] not in CREATING
            and b.endswith(" cached_retry")
            and b.removesuffix(" cached_retry") == o
        ),
        (
            "RESOLVE_CACHED: the kernel answers EAGAIN where the lookup would need I/O, as in "
            "bwrap's fresh mount namespace with its cold cache, and the probe retries without the "
            "flag as openat2(2) tells it to; the handler drops the flag, as openat2(2) permits, "
            "so it answers what the retry does. A create or a temporary file is EAGAIN before "
            "any lookup, in both worlds"
        ),
    ),
    *(
        (
            call,
            lambda label, b, o, _c: (
                KERNEL < (5, 8)
                and label.endswith(("dot_slash/wr_creat_excl", "dotdot_slash/wr_creat_excl"))
                and errnos(b, o) == (errno.EISDIR, errno.EEXIST)
            ),
            (
                "O_CREAT|O_EXCL of dir/./ or dir/../: do_last took a last name of . or .. straight "
                "to finish_open, where O_CREAT on a directory is EISDIR, until 5.8's do_open put "
                "O_EXCL's EEXIST before it; the handler answers as the newer kernels do"
            ),
        )
        for call in ("open", "openat")
    ),
    *(
        (
            call,
            lambda label, b, o, _c: (
                KERNEL < (6, 3) and label.endswith("/dir_creat") and errnos(b, o)[1] == errno.EINVAL
            ),
            (
                "O_DIRECTORY|O_CREAT is EINVAL since 6.3 (open.c); this kernel opens or creates "
                "instead; the handler answers as the newer kernels do"
            ),
        )
        for call in ("open", "openat", "openat2")
    ),
    (
        "openat2",
        lambda label, b, o, c: (
            KERNEL < (5, 6)
            and label.endswith("_creat/no_xdev")
            and errnos(b, o)[0] == errno.EXDEV
            and o == c.kernel.get(label.removesuffix("no_xdev") + "plain")
        ),
        (
            "RHEL 8's 4.18 backport of openat2 answers EXDEV for a create through a symlink under "
            "RESOLVE_NO_XDEV; 5.6 and later resolve it, as the handler does, so it answers what "
            "the call without the flag does"
        ),
    ),
    (
        "openat2",
        lambda label, b, o, c: (
            KERNEL < (5, 12)
            and label.endswith("/cached")
            and errnos(b, o)[0] == errno.EINVAL
            and o.removesuffix(" cached_retry")
            == c.kernel.get(label.removesuffix("cached") + "plain")
        ),
        (
            "RESOLVE_CACHED is 5.12+: EINVAL before; the handler answers as 5.12 does, EAGAIN for "
            "a create, a truncate or a temporary file, retried without it, and otherwise drops "
            "it, as openat2(2) permits, so it answers what the call without the flag does"
        ),
    ),
    (
        "renameat2",
        lambda label, b, o, _c: (
            KERNEL < (5, 8)
            and label.endswith("/whiteout")
            and errnos(b, o)[0] == errno.EPERM
            and failed(o)
        ),
        (
            "RENAME_WHITEOUT: this kernel wants CAP_MKNOD in the initial user namespace before any "
            "lookup (EPERM), which bwrap's namespace cannot grant; 5.8 dropped the check (vfs: "
            "allow unprivileged whiteout creation). The handler answers as 5.8 does, and what it "
            "re-issues this kernel refuses, so it renames nothing"
        ),
    ),
    (
        None,
        lambda label, b, o, _c: (
            ("chain_40" in label or "dir_links_40" in label)
            and errnos(b, o)[0] == errno.ELOOP
            and errnos(b, o)[1] != errno.ELOOP
        ),
        (
            "a walk of exactly MAXSYMLINKS links: filename_lookup retries a walk whose RCU attempt "
            "failed (ECHILD) with the same nameidata, and total_link_count carries on from where "
            "that attempt stopped, so the links it followed count twice and the retry may answer "
            "ELOOP, as the dentry cache decides; the launcher's own walk counts each link once"
        ),
    ),
    (
        None,
        lambda label, b, o, c: (
            "dot_last" in label
            and "tmp_new" in label
            and errnos(b, o)[0] == errno.EXDEV
            and errnos(b, o)[1] in (errno.EBUSY, errno.EEXIST)
            and len({tree.mount_of(p) for p in c.paths}) == 1
        ),
        (
            "a rename of . or .. between the host area and /tmp: under bwrap /tmp is a bind mount "
            "of its own, so the kernel compares the mounts first (EXDEV); a host that keeps the "
            "two on one mount, as GitHub's aarch64 runner does, judges the name instead (EBUSY, "
            "or EEXIST under RENAME_NOREPLACE), and the launcher re-issues the name to that kernel"
        ),
    ),
    (
        None,
        lambda label, b, o, c: (
            BOUND_PATHS & set(c.paths)
            and errnos(b, o)[0] == errno.EROFS
            and o == c.native.get(label)
        ),
        (
            "a host entry bound into bwrap's read-only root: its parent directory, or the "
            "identity symlink itself, is read-only there (EROFS); the launcher answers with the "
            "host's permissions (8.1, 8.4), as the probe does run natively"
        ),
    ),
    (
        "chown",
        lambda label, b, o, c: (
            label.endswith("/to_root")
            and errnos(b, o) == (errno.EINVAL, errno.EPERM)
            and c.native.get(label, o) == o
        ),
        (
            "uid 0 is not mapped in bwrap's user namespace (EINVAL); the launcher runs in none, "
            "and answers as the probe does run natively (EPERM) wherever the host names the path"
        ),
    ),
    (
        "bind",
        lambda label, b, o, _c: (
            label
            in (
                "new_top",
                "root/after_chdir_rel",
                "root_dotdot/after_chdir_rel",
                "rel_root_by_dotdot/after_chdir_rel",
                "proc_root_slash/after_chdir_rel",
            )
            and errnos(b, o) == (errno.EROFS, errno.EACCES)
        ),
        (
            "a new top-level name is the host's (8.1 rule 2): the host's / answers EACCES for a "
            "create there, where the read-only root under bwrap says EROFS"
        ),
    ),
    (
        None,
        lambda _label, b, o, c: (
            NEW_TOP in c.paths
            and errnos(b, o)[0] == errno.EROFS
            and errnos(b, o)[1] in (errno.EACCES, errno.ENOENT, errno.EXDEV)
        ),
        (
            "a new top-level name is the host's (8.1 rule 2): the host's / answers EACCES for a "
            "create there, ENOENT for a delete of what it lacks and EXDEV for a link from another "
            "filesystem, where the read-only root under bwrap says EROFS before any lookup"
        ),
    ),
    (
        "openat2",
        lambda label, b, o, c: (
            NEW_TOP in c.paths
            and label.endswith("/no_xdev")
            and errnos(b, o) == (errno.ENOENT, errno.EXDEV)
        ),
        (
            "RESOLVE_NO_XDEV on a new top-level name, which is the host's (8.1 rule 2): the walk "
            "crosses at the root from the exclave's domain into the host's (13 item 22), where the "
            "kernel's one root mount sees no crossing and answers the lookup's ENOENT"
        ),
    ),
    (
        "openat2",
        lambda label, b, o, c: (
            label.startswith("dfd_proc/cwd")
            and label.endswith("/no_xdev")
            and errnos(b, o)[0] == errno.EXDEV
            and o == c.kernel.get(label.removesuffix("no_xdev") + "plain")
        ),
        (
            "RESOLVE_NO_XDEV through /proc/self/cwd from a descriptor on /proc/self: the kernel "
            "crosses from procfs to the working directory's mount (EXDEV); the handler sees the "
            "exclave's boundary and not the host's own mounts (13 item 22), and answers what the "
            "walk without the flag does"
        ),
    ),
    (
        "truncate",
        lambda _label, b, o, c: (
            KERNEL < (6, 14)
            and "/maze/ro444" in c.paths
            and errnos(b, o) == (errno.EROFS, errno.EACCES)
        ),
        (
            "a truncate of a file its owner cannot write on a read-only mount: this kernel wants "
            "the mount before the permission (EROFS); vfs_truncate checks the permission first by "
            "6.14 (it did not at 6.1), and the handler answers as it does"
        ),
    ),
    (
        "utimensat",
        lambda label, b, o, _c: (
            KERNEL < (5, 9)
            and label.endswith(("/empty_path", "/bad_nsec"))
            and errnos(b, o)[0] == errno.EINVAL
            and failed(o)
        ),
        (
            "utimensat before 5.9 refused AT_EMPTY_PATH and checked the nanoseconds before the "
            "lookup (EINVAL); since 5.9 (vfs_utimes) it takes the flag and the lookup's answer "
            "comes first, as the handler answers, and what it re-issues this kernel refuses"
        ),
    ),
    *(
        (
            call,
            lambda _label, b, o, c: (
                KERNEL < (5, 9)
                and "/maze/sock" in c.paths
                and b.startswith("ret=27136")
                and o.startswith("ret=28928")
            ),
            (
                "an exec of a socket: ENXIO from its open before 5.9, EACCES from may_open since "
                "(fs/namei.c); the handler answers as the newer kernels do"
            ),
        )
        for call in ("execve", "execveat")
    ),
]

# The syscalls the probe issues that came after the matrix's oldest kernel, 3.10, with the release
# that added each: a kernel before it answers ENOSYS, and the handler answers what it can from its
# own rule and re-issues the rest, so only the error cases differ.
ADDED = {
    "renameat2": (3, 15),
    "execveat": (3, 19),
    "statx": (4, 11),
    "openat2": (5, 6),
    "faccessat2": (5, 8),
    "fchmodat2": (6, 6),
    "setxattrat": (6, 13),
    "getxattrat": (6, 13),
    "listxattrat": (6, 13),
    "removexattrat": (6, 13),
    "file_getattr": (6, 17),
    "file_setattr": (6, 17),
}
EXPECTED.extend(
    (
        call,
        lambda _label, b, o, _c, since=since: since > KERNEL and errnos(b, o)[0] == errno.ENOSYS,
        (
            f"{call} is {since[0]}.{since[1]}+: this kernel lacks it (ENOSYS); the handler "
            "answers what it can from its own rule and re-issues the rest"
        ),
    )
    for call, since in ADDED.items()
)

# execveat's flags: AT_EXECVE_CHECK is 6.14+, an unknown flag before it, and the handler looks the
# name up before it re-issues the check; and a kernel before the one measured, 7.0, may read the
# name before it refuses a flag it does not know. The handler answers as 7.0 does.
EXPECTED.extend(
    [
        (
            "execveat",
            lambda label, b, o, _c: (
                label.startswith("memfd/")
                and exec_errnos(b, o) == (errno.EACCES, errno.ENOEXEC)
                and tree.memfd_exec_under_bwrap() == errno.EACCES
            ),
            (
                "exec of a memfd under bwrap on a host whose AppArmor confines bwrap's child "
                "(Ubuntu 26.10's bwrap-userns-restrict: unpriv_bwrap, whose exec rule names paths "
                "under / and so refuses a file with none, EACCES); natively the kernel reads the "
                "empty memfd (ENOEXEC), as the launcher does"
            ),
        ),
        (
            "execveat",
            lambda label, b, o, _c: (
                KERNEL < (6, 14)
                and label.endswith("/check")
                and exec_errnos(b, o)[0] == errno.EINVAL
            ),
            (
                "AT_EXECVE_CHECK is 6.14+: this kernel refuses it as unknown before the lookup "
                "(EINVAL); the handler looks the name up first and re-issues, so the lookup's own "
                "error comes first"
            ),
        ),
        (
            "execveat",
            lambda label, b, o, _c: (
                KERNEL < (7, 0)
                and label.endswith("/bad_flag")
                and exec_errnos(b, o)[1] == errno.EINVAL
            ),
            (
                "an unknown execveat flag: this kernel reads the name first (EFAULT, "
                "ENAMETOOLONG, ENOENT); 7.0 refuses the flag before the name, as the handler does"
            ),
        ),
    ]
)

# Before 6.13 the xattr calls looked the path up, or took a descriptor's mount for writing, before
# they read the name, the flags and the size; the handler answers as the newer kernels do.
EXPECTED.extend(
    (
        call,
        lambda label, b, o, _c: (
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


# Launcher defects the probe has found and the handler has yet to fix: differences no rule makes
# right. Each entry is (what the kernel does, a predicate on (syscall, label, bwrap answer, launcher
# answer, Ctx)) naming the cases and the exact answers it covers, and whether this host can show
# it at all. Every run prints each entry with its count of cases, and on the kernel they were
# measured on, 7.0 and later, a whole run in which an entry the host can show matches no case
# fails, so that the fix removes the entry.
DEFECTS_MEASURED = (7, 0)
DEFECTS: list[tuple[str, Callable[[str, str, str, str, Ctx], object], Callable[[], bool]]] = []


def expected(name: str, label: str, b: str, o: str, ctx: Ctx) -> str | None:
    """The reason EXPECTED gives for a difference, or None."""
    for n, pred, reason in EXPECTED:
        if (n is None or n == name) and pred(label, b, o, ctx):
            return reason
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--exclave", required=True)
    ap.add_argument("--work", default=os.path.join(REPO, "build", "syscalls-work"))
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
                os.kill(int(d.removeprefix("exclave-probe-")), 0)
            except ValueError, ProcessLookupError:
                rmtree(os.path.join("/tmp", d))
            except PermissionError:
                pass
    # the launcher's world, a copy of the exclave relinked with the build (17), and the kernel's,
    # an unwrapped copy of the tree, kept between runs; the same maze, made anew, in both
    ex, root = tree.kept_worlds(given, "syscalls")
    # ".." from the host area is a directory the reset owns
    host = os.path.join(work, "area", "host")
    for r in (root, os.path.join(ex, "tree")):
        make_maze(r, host)
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
    forms = Forms(root, host)
    # a tree file the probe names has a copy of its own in the kernel's world, not a hard link to
    # the given exclave's: another gate step may be running that program, and a write-open of it
    # would be ETXTBSY there, an answer about the gate rather than the rule
    for v in (forms.file, forms.true, forms.sh, *forms.link.values()):
        real = os.path.join(root, tree.resolve(root, v).lstrip("/"))
        if os.path.isfile(real) and not os.path.islink(real) and os.lstat(real).st_nlink > 1:
            shutil.copy2(real, real + ".copy")
            os.replace(real + ".copy", real)
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
    writable = writable_in_bwrap(forms, root, host, bindir)
    mutable = writable - {"tmp"}  # /tmp is sticky: the cases there are safe (generate)
    # the bound host paths as this host has them: a difference on one is often the host's doing
    for n, p in forms.paths:
        d = raw_of(p)
        if n in BOUND and d is not None and os.path.lexists(d):
            st = os.stat(d)
            print(
                f"bound host path {d}: uid {st.st_uid} mode {st.st_mode & 0o7777:o}, writable here "
                f"{'yes' if os.access(d, os.W_OK) else 'no'}, in the kernel's world "
                f"{'yes' if n in writable else 'no'}"
                + ("; the cases that change it are left out" if n in mutable else "")
            )
    cases = generate(forms, nr, os.getuid(), os.getgid(), mutable)
    if args.only:
        cases = [c for c in cases if args.only in (c[1], c[3])]
    names = []
    for c in cases:
        if c[3] not in names:
            names.append(c[3])
    # the kernel's maze, which its read-only root keeps as made: the launcher's must stay the same
    maze = prefixed("maze", snapshot(os.path.join(root, "maze")))
    # the native run: never as root, whom nothing refuses, and never on a bound path whose
    # directory this user can write
    native_off = os.geteuid() == 0
    unsafe = {p for p in BOUND_PATHS if os.access(os.path.dirname(p) or "/", os.W_OK)}
    if native_off or unsafe:
        print(
            "the native run "
            + ("is off as root" if native_off else f"leaves out {', '.join(sorted(unsafe))}")
            + "; a difference there that only the host can answer fails"
        )
    total = differ = accepted = 0
    known = [0] * len(DEFECTS)
    shown = 0
    for name in names:  # one run per group, the host area reset before each world
        mine = [c for c in cases if c[3] == name]
        path = os.path.join(bindir, "cases-" + name)
        with open(path, "w") as f:
            f.writelines(
                f"{i} {nr[n]} {' '.join(toks)}\n" for i, (label, n, toks, _) in enumerate(mine)
            )
        here = [] if native_off else native_cases(mine, host, unsafe)
        with open(path + ".native", "w") as f:
            f.writelines(f"{i} {nr[mine[i][1]]} {' '.join(t)}\n" for i, t in here)
        world = "bwrap"
        nat: tuple[int, str, str] = (0, "", "")
        try:
            host_reset(host, forms, probe)
            bw = run_bwrap(root, host, bindir, probe, path)
            bw_effects = effects(host)
            world = "the launcher"
            host_reset(host, forms, probe)
            op = run_launcher(ex, host, probe, path)
            op_effects = effects(host) | prefixed(
                "maze", snapshot(os.path.join(ex, "tree", "maze"))
            )
            if here:
                world = "the native run"
                host_reset(host, forms, probe)
                nat = run_native(root, host, probe, path + ".native")
        except subprocess.TimeoutExpired:
            print(f"FAIL {name}: {len(mine)} cases, {world} killed after {TIMEOUT} s")
            differ += 1
            continue
        # the probe answers every case on stdout and exits 0 with nothing on stderr, in every world
        if bw[0] or bw[2] or op[0] or op[2] or nat[0] or nat[2]:
            print(
                f"FAIL {name}: bwrap rc {bw[0]} stderr {bw[2].strip()[-200:]!r}, "
                f"the launcher rc {op[0]} stderr {op[2].strip()[-200:]!r}, "
                f"the native run rc {nat[0]} stderr {nat[2].strip()[-200:]!r}"
            )
            differ += 1
        # what the calls left behind: the same in both worlds, and the tree's maze untouched
        for where in sorted(set(bw_effects) | set(op_effects)):
            k_, l_ = (
                bw_effects.get(where, maze.get(where, "absent")),
                op_effects.get(where, "absent"),
            )
            if k_ != l_:
                differ += 1
                print(f"EFFECT {name} {where}\n     kernel: {k_}\n     launcher: {l_}")
        native = {
            mine[int(i)][0]: a for i, _, a in (line.partition(" ") for line in nat[1].splitlines())
        }
        if len(native) != len(here):
            print(f"FAIL {name}: the native run answered {len(native)} of {len(here)} cases")
            differ += 1
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
        bl, ol = watch_numbers(mine, bl, ol)
        d = 0
        kernel = {c[0]: bline.split(" ", 1)[1] for c, bline in zip(mine, bl, strict=True)}
        for (label, n, toks, _), bline, oline in zip(mine, bl, ol, strict=True):
            total += 1
            b, o = bline.split(" ", 1)[1], oline.split(" ", 1)[1]
            if b == o:
                continue
            raw = named_paths(n, toks, host)
            ctx = Ctx(raw, tuple(lexical(r) for r in raw), kernel, native)
            which = [i for i, (_why, pred, _s) in enumerate(DEFECTS) if pred(n, label, b, o, ctx)]
            if which:
                known[which[0]] += 1
                if args.expected:
                    print(f"DEFECT {n} {label}\n     kernel: {b}\n     launcher: {o}")
                continue
            why = expected(n, label, b, o, ctx)
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
                    + (f"\n     native: {native[label]}" if label in native else "")
                )
        print(f"{name:<18} {len(mine):5d} cases, {d} differ")
    for (why, _pred, shown), count in zip(DEFECTS, known, strict=True):
        print(f"DEFECT {count} cases: {why}")
        if not count and not args.only and KERNEL >= DEFECTS_MEASURED:
            if shown():
                print("FAIL no case shows this defect any more: remove its DEFECTS entry")
                differ += 1
            else:
                print("(this host cannot show it)")
    print(
        f"{total} cases over {len(names)} groups and {len(forms.paths)} path forms: "
        f"{differ} differ, {accepted} differences expected"
        + (f", {sum(known)} open launcher defects" if sum(known) else "")
    )
    rmtree(f"/tmp/exclave-probe-{os.getpid()}")
    if not args.keep and not differ:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
