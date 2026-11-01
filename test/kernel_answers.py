"""The kernel's answers to the path programs of test/progs that print rather than judge.

The suite asserts them of the launcher (test/regress_paths.py) and the namespace oracle asserts
them of the kernel itself, on a read-only bind of the same tree (test/oracle_ns.py), so that an
expectation written by hand is checked against the kernel at every run (DESIGN.md 17 items 1
and 4).
"""

import errno
import itertools
import os
import platform
lazy import ctypes

# creat_slash HOSTDIR: one line per case, the case and the errno text
CREAT_SLASH = (
    "creat through a link to a missing name with a slash: Is a directory",
    "creat for writing through the same link: Is a directory",
    "creat through a link to a directory with a slash: Is a directory",
    "creat through a link whose text has .. and a slash: Is a directory",
    "open through a link to a missing name with a slash: No such file or directory",
    "creat with O_EXCL through the link: File exists",
    "creat with O_EXCL of a directory's dot with a slash: File exists",
    "creat of a directory's dot with a slash: Is a directory",
    "creat with O_EXCL of a directory's dotdot with a slash: File exists",
)

# unix_socket HOSTDIR /usr/share EXFILE /usr/share/exclave-test.sock CWDDIR: the case and its answer
UNIX_SOCKET = {
    "bind host dir": "ret=0 errno=0",
    "bind /tmp": "ret=0 errno=0",
    "bind exclave dir": "ret=-1 errno=30",
    "bind existing exclave file": "ret=-1 errno=98",
    "bind existing exclave socket": "ret=-1 errno=98",
    "bind missing exclave parent": "ret=-1 errno=2",
    "bind under an exclave file": "ret=-1 errno=20",
    "bind exclave dir itself": "ret=-1 errno=98",
    "bind exclave dir trailing slash name": "ret=-1 errno=2",
    "bind abstract": "ret=0 errno=0",
    "bind relative in host cwd": "ret=0 errno=0",
    "bind relative in exclave cwd": "ret=-1 errno=30",
    "connect host listener": "ret=0 errno=0",
    "connect host socket no listener": "ret=-1 errno=111",
    "connect exclave file": "ret=-1 errno=111",
    "connect exclave socket": "ret=-1 errno=111",
    "connect missing exclave path": "ret=-1 errno=2",
    "connect exclave dir": "ret=-1 errno=111",
    "connect under an exclave file": "ret=-1 errno=20",
    "connect missing host path": "ret=-1 errno=2",
    "sendto host dgram": "ret=1 errno=0",
    "bind through /proc/self/cwd": "ret=0 errno=0",
    "connect through /proc/self/cwd": "ret=0 errno=0",
    "bind addrlen too long": "ret=-1 errno=22",
    "bind addrlen too short": "ret=-1 errno=22",
    "bind wrong family": "ret=-1 errno=22",
    "bind exclave path of 107 bytes": "ret=-1 errno=30",
    "connect exclave path of 107 bytes": "ret=-1 errno=2",
}


def unix_socket_wrong(out: str) -> list[str]:
    """The cases of unix_socket's output that differ from the kernel's answers."""
    got = dict(line.split(": ", 1) for line in out.splitlines() if ": " in line)
    return [
        f"{k}: got {got.get(k)}, the kernel says {v}"
        for k, v in UNIX_SOCKET.items()
        if got.get(k) != v
    ]


# open_flags HOSTDIR: one line per case, the case and the errno text
OPEN_FLAGS = (
    "O_DIRECTORY|O_CREAT on a directory: Invalid argument",
    "O_DIRECTORY|O_CREAT on a file: Invalid argument",
    "O_DIRECTORY|O_CREAT on a missing name: Invalid argument",
    "O_DIRECTORY|O_CREAT with a trailing slash: Invalid argument",
    "O_DIRECTORY|O_CREAT on a bad pointer: Invalid argument",
    "openat O_DIRECTORY|O_CREAT on a missing name: Invalid argument",
    "the missing name afterwards: No such file or directory",
    "O_TMPFILE without write access: Invalid argument",
    "O_TMPFILE with O_CREAT: Invalid argument",
    "O_TMPFILE without O_DIRECTORY: Invalid argument",
    "O_TMPFILE on a missing name: No such file or directory",
    "O_TMPFILE on a file: Not a directory",
    "O_TMPFILE on a directory: Read-only file system",
    "O_PATH|O_DIRECTORY|O_CREAT on a directory: ok",
    "O_PATH|O_DIRECTORY|O_CREAT on a file: Not a directory",
    "O_PATH|O_DIRECTORY|O_CREAT on a missing name: No such file or directory",
    "O_WRONLY|O_DIRECTORY on a file: Not a directory",
    "O_RDWR|O_DIRECTORY on a file: Not a directory",
    "O_WRONLY|O_TRUNC|O_DIRECTORY on a file: Not a directory",
    "O_RDONLY|O_DIRECTORY on a file: Not a directory",
    "O_PATH|O_DIRECTORY on a file: Not a directory",
    "O_WRONLY|O_DIRECTORY on the running program: Not a directory",
    "O_WRONLY|O_DIRECTORY on a link to a file: Not a directory",
    "O_WRONLY|O_DIRECTORY|O_NOFOLLOW on a link: Not a directory",
    "O_RDONLY|O_DIRECTORY|O_NOFOLLOW on a link: Not a directory",
    "O_PATH|O_DIRECTORY|O_NOFOLLOW on a link: Not a directory",
    "O_RDONLY|O_DIRECTORY|O_NOFOLLOW on an identity file: Not a directory",
    "O_WRONLY|O_DIRECTORY on a missing name: No such file or directory",
    "O_RDONLY|O_DIRECTORY on a missing name: No such file or directory",
    "O_WRONLY|O_DIRECTORY on a dangling link: No such file or directory",
    "O_WRONLY|O_DIRECTORY on a directory: Is a directory",
    "O_RDONLY|O_TRUNC|O_DIRECTORY on a directory: Is a directory",
    "O_RDONLY|O_DIRECTORY on a directory: ok",
    "access mode 3 on a file: ok",
    "access mode 3 on a directory: Is a directory",
    "O_RDONLY|O_EXCL without O_CREAT on a link: ok",
    "O_RDONLY|O_EXCL without O_CREAT on a directory: ok",
    "O_WRONLY|O_APPEND on a directory: Is a directory",
    "the mode of an existing file after O_CREAT with mode 0: kept",
)
# the cases a kernel before 6.3 answers otherwise: open and openat opened or created with
# O_DIRECTORY|O_CREAT until build_open_flags refused the pair (fs/open.c); the launcher answers as
# the newer kernels do
OPEN_FLAGS_SINCE_6_3 = "O_DIRECTORY|O_CREAT on "


def kernel() -> tuple[int, int]:
    """The running kernel's major and minor version."""
    major, minor = os.uname().release.split(".")[:2]
    return int(major), int(minor.split("-")[0])


def open_flags_wrong(out: str, *, by_the_kernel: bool = False) -> list[str]:
    """The lines of open_flags's output that differ from the kernel's answers.

    by_the_kernel: the kernel itself answered, so a kernel before 6.3 may answer the cases of
    OPEN_FLAGS_SINCE_6_3 as it did then.
    """
    got = out.splitlines()
    old = by_the_kernel and kernel() < (6, 3)
    wrong = [
        f"got {g!r}, the kernel says {w!r}"
        for g, w in zip(got, OPEN_FLAGS, strict=False)
        if g != w and not (old and OPEN_FLAGS_SINCE_6_3 in w)
    ]
    if len(got) != len(OPEN_FLAGS):
        wrong.append(f"{len(got)} lines, the kernel gives {len(OPEN_FLAGS)}")
    return wrong


def creat_slash_wrong(out: str) -> list[str]:
    """The lines of creat_slash's output that differ from the kernel's answers."""
    got = out.splitlines()
    return (
        [] if got == list(CREAT_SLASH) else [f"got {got!r}, the kernel says {list(CREAT_SLASH)!r}"]
    )


# slash_links HOSTDIR EXFILE EXDIR EXLINK: the case and its answer, measured under bwrap on 7.0; the
# exlink lines are left out where the tree has no symlink to a directory ("exlink: skipped")
SLASH_LINKS = (
    "hdang mkdir: ret=-1 errno=17",
    "hdang mkdirat: ret=-1 errno=17",
    "hdang rmdir: ret=-1 errno=20",
    "hdang unlink: ret=-1 errno=20",
    "hdang symlink: ret=-1 errno=17",
    "hdang symlinkat: ret=-1 errno=17",
    "hdang mknod fifo: ret=-1 errno=17",
    "hdang mknod reg: ret=-1 errno=17",
    "hdang mknodat fifo: ret=-1 errno=17",
    "hdang bind: ret=-1 errno=98",
    "hdang open creat: ret=-1 errno=21",
    "hdang open creat excl: ret=-1 errno=21",
    "hdang open rdonly: ret=-1 errno=2",
    "hdang openat2 creat no_symlinks: ret=-1 errno=21",
    "hdang openat2 creat excl no_symlinks: ret=-1 errno=21",
    "hdang link to it: ret=-1 errno=17",
    "hdang renameat2 noreplace onto it: ret=-1 errno=17",
    "hdang rename onto it: ret=-1 errno=20",
    "hdang renameat2 exchange with it: ret=-1 errno=20",
    "hdang rename it: ret=-1 errno=20",
    "hlink mkdir: ret=-1 errno=17",
    "hlink mkdirat: ret=-1 errno=17",
    "hlink rmdir: ret=-1 errno=20",
    "hlink unlink: ret=-1 errno=20",
    "hlink symlink: ret=-1 errno=17",
    "hlink symlinkat: ret=-1 errno=17",
    "hlink mknod fifo: ret=-1 errno=17",
    "hlink mknod reg: ret=-1 errno=17",
    "hlink mknodat fifo: ret=-1 errno=17",
    "hlink bind: ret=-1 errno=98",
    "hlink open creat: ret=-1 errno=21",
    "hlink open creat excl: ret=-1 errno=21",
    "hlink open rdonly: ret=-1 errno=20",
    "hlink openat2 creat no_symlinks: ret=-1 errno=21",
    "hlink openat2 creat excl no_symlinks: ret=-1 errno=21",
    "hlink link to it: ret=-1 errno=17",
    "hlink renameat2 noreplace onto it: ret=-1 errno=17",
    "hlink rename onto it: ret=-1 errno=20",
    "hlink renameat2 exchange with it: ret=-1 errno=20",
    "hlink rename it: ret=-1 errno=20",
    "hlnkdir mkdir: ret=-1 errno=17",
    "hlnkdir mkdirat: ret=-1 errno=17",
    "hlnkdir rmdir: ret=-1 errno=20",
    "hlnkdir unlink: ret=-1 errno=20",
    "hlnkdir symlink: ret=-1 errno=17",
    "hlnkdir symlinkat: ret=-1 errno=17",
    "hlnkdir mknod fifo: ret=-1 errno=17",
    "hlnkdir mknod reg: ret=-1 errno=17",
    "hlnkdir mknodat fifo: ret=-1 errno=17",
    "hlnkdir bind: ret=-1 errno=98",
    "hlnkdir open creat: ret=-1 errno=21",
    "hlnkdir open creat excl: ret=-1 errno=21",
    "hlnkdir open rdonly: ok",
    "hlnkdir openat2 creat no_symlinks: ret=-1 errno=21",
    "hlnkdir openat2 creat excl no_symlinks: ret=-1 errno=21",
    "hlnkdir link to it: ret=-1 errno=17",
    "hlnkdir renameat2 noreplace onto it: ret=-1 errno=17",
    "hlnkdir rename onto it: ret=-1 errno=20",
    "hlnkdir renameat2 exchange with it: ret=-1 errno=20",
    "hlnkdir rename it: ret=-1 errno=20",
    "hdir mkdir: ret=-1 errno=17",
    "hdir mkdirat: ret=-1 errno=17",
    "hdir rmdir: ok",
    "hdir unlink: ret=-1 errno=2",
    "hdir symlink: ret=-1 errno=2",
    "hdir symlinkat: ret=-1 errno=2",
    "hdir mknod fifo: ret=-1 errno=2",
    "hdir mknod reg: ret=-1 errno=2",
    "hdir mknodat fifo: ret=-1 errno=2",
    "hdir bind: ret=-1 errno=2",
    "hdir open creat: ret=-1 errno=21",
    "hdir open creat excl: ret=-1 errno=21",
    "hdir open rdonly: ret=-1 errno=2",
    "hdir openat2 creat no_symlinks: ret=-1 errno=21",
    "hdir openat2 creat excl no_symlinks: ret=-1 errno=21",
    "hdir link to it: ret=-1 errno=2",
    "hdir renameat2 noreplace onto it: ret=-1 errno=20",
    "hdir rename onto it: ret=-1 errno=20",
    "hdir renameat2 exchange with it: ret=-1 errno=2",
    "hdir rename it: ret=-1 errno=2",
    "hfile mkdir: ret=-1 errno=17",
    "hfile mkdirat: ret=-1 errno=17",
    "hfile rmdir: ret=-1 errno=20",
    "hfile unlink: ret=-1 errno=20",
    "hfile symlink: ret=-1 errno=17",
    "hfile symlinkat: ret=-1 errno=17",
    "hfile mknod fifo: ret=-1 errno=17",
    "hfile mknod reg: ret=-1 errno=17",
    "hfile mknodat fifo: ret=-1 errno=17",
    "hfile bind: ret=-1 errno=98",
    "hfile open creat: ret=-1 errno=21",
    "hfile open creat excl: ret=-1 errno=21",
    "hfile open rdonly: ret=-1 errno=20",
    "hfile openat2 creat no_symlinks: ret=-1 errno=21",
    "hfile openat2 creat excl no_symlinks: ret=-1 errno=21",
    "hfile link to it: ret=-1 errno=17",
    "hfile renameat2 noreplace onto it: ret=-1 errno=17",
    "hfile rename onto it: ret=-1 errno=20",
    "hfile renameat2 exchange with it: ret=-1 errno=20",
    "hfile rename it: ret=-1 errno=20",
    "absent mkdir: ok",
    "absent mkdirat: ret=-1 errno=17",
    "absent rmdir: ok",
    "absent unlink: ret=-1 errno=2",
    "absent symlink: ret=-1 errno=2",
    "absent symlinkat: ret=-1 errno=2",
    "absent mknod fifo: ret=-1 errno=2",
    "absent mknod reg: ret=-1 errno=2",
    "absent mknodat fifo: ret=-1 errno=2",
    "absent bind: ret=-1 errno=2",
    "absent open creat: ret=-1 errno=21",
    "absent open creat excl: ret=-1 errno=21",
    "absent open rdonly: ret=-1 errno=2",
    "absent openat2 creat no_symlinks: ret=-1 errno=21",
    "absent openat2 creat excl no_symlinks: ret=-1 errno=21",
    "absent link to it: ret=-1 errno=2",
    "absent renameat2 noreplace onto it: ret=-1 errno=20",
    "absent rename onto it: ret=-1 errno=20",
    "absent renameat2 exchange with it: ret=-1 errno=2",
    "absent rename it: ret=-1 errno=2",
    "exlink mkdir: ret=-1 errno=17",
    "exlink rmdir: ret=-1 errno=30",
    "exlink unlink: ret=-1 errno=30",
    "exlink symlink: ret=-1 errno=17",
    "exlink mknod fifo: ret=-1 errno=17",
    "exlink mknod reg: ret=-1 errno=17",
    "exlink bind: ret=-1 errno=98",
    "exlink open creat: ret=-1 errno=21",
    "exlink open creat excl: ret=-1 errno=21",
    "exlink open rdonly: ok",
    "exlink openat2 creat no_symlinks: ret=-1 errno=21",
    "exlink openat2 creat excl no_symlinks: ret=-1 errno=21",
    "exlink link to it: ret=-1 errno=17",
    "exlink renameat2 noreplace onto it: ret=-1 errno=18",
    "exlink rename onto it: ret=-1 errno=18",
    "exlink renameat2 exchange with it: ret=-1 errno=18",
    "exlink rename it: ret=-1 errno=18",
    "effect missing: absent",
    "effect hdang: link",
    "effect hlink: link",
    "effect hlnkdir: link",
    "effect hdir: absent",
    "effect hfile: file",
    "effect hfile2: file",
    "effect renamed: absent",
    "effect absent: absent",
)


def slash_links_wrong(out: str) -> list[str]:
    """The lines of slash_links's output that differ from the kernel's answers."""
    got = out.splitlines()
    skipped = "exlink: skipped" in got
    got = [x for x in got if x != "exlink: skipped"]
    want = [x for x in SLASH_LINKS if not (skipped and x.startswith("exlink "))]
    return [
        f"got {g!r}, the kernel says {w!r}" for g, w in itertools.zip_longest(got, want) if g != w
    ]


# magic_links pathless: the descriptors it checks, and the syscalls it makes that a kernel may lack
MAGIC_LINKS_FDS = ("stdin", "pipe", "memfd", "inotify", "unlinked")
SYS_STATX = {"x86_64": 332, "aarch64": 291}
SYS_FACCESSAT2 = 439
AT_FDCWD = -100


def magic_links_missing(hostdir: str) -> set[str]:
    """The failure lines of magic_links pathless DIR that this kernel answers natively.

    Each call the program makes that can be missing is asked of the kernel here, outside any
    exclave: a memfd, an O_TMPFILE file in hostdir, statx and faccessat2. A line for a call it
    answers with an error is the kernel's own answer, and the only failure the program may print.
    """
    lines = set()
    try:
        os.close(os.memfd_create("magic"))
    except OSError as e:
        lines.add(f"memfd errno {e.errno}")
    try:
        os.close(os.open(hostdir, os.O_TMPFILE | os.O_WRONLY, 0o644))
    except OSError as e:
        lines.add(f"tmpfile errno {e.errno}")
    libc = ctypes.CDLL(None, use_errno=True)
    buf = ctypes.create_string_buffer(256)
    for call, args in (
        ("statx", (SYS_STATX[platform.machine()], AT_FDCWD, b"/proc/self/fd/0", 0, 0x100, buf)),
        ("faccessat2", (SYS_FACCESSAT2, AT_FDCWD, b"/proc/self/fd/0", os.F_OK, 0)),
    ):
        if libc.syscall(*args) < 0 and ctypes.get_errno() == errno.ENOSYS:
            lines |= {f"{fd} {call} errno {errno.ENOSYS}" for fd in MAGIC_LINKS_FDS}
    return lines


def magic_links_wrong(out: str, missing: set[str]) -> list[str]:
    """The lines of magic_links pathless that do not find the object.

    Each line ends ok, or is the failure of a call the kernel lacks natively (magic_links_missing).
    """
    return [line for line in out.splitlines() if not line.endswith(" ok") and line not in missing]
