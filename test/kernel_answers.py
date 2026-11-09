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
import re
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
# O_EXCL's EEXIST before a directory's EISDIR since 5.8's do_open (fs/namei.c); do_last said EISDIR
CREAT_SLASH_SINCE_5_8 = "creat with O_EXCL of a directory's dot"

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
# every O_DIRECTORY|O_CREAT line but O_PATH's, which drops O_CREAT on every kernel
OPEN_FLAGS_SINCE_6_3 = ("O_DIRECTORY|O_CREAT ", "openat O_DIRECTORY|O_CREAT ")


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
        if g != w and not (old and w.startswith(OPEN_FLAGS_SINCE_6_3))
    ]
    if len(got) != len(OPEN_FLAGS):
        wrong.append(f"{len(got)} lines, the kernel gives {len(OPEN_FLAGS)}")
    return wrong


# openat2 pathless HOSTDIR: one line per case, the case and the errno's name; the kernel walks a
# scoped openat2 from the descriptor itself (path_init), so a removed directory is its own "." and
# ".." in root, EXDEV beyond it beneath, EISDIR for a write and ENOENT for a name in it, and what
# is no directory at all is ENOTDIR
OPENAT2_PATHLESS = (
    "removed directory, . beneath: ok",
    "removed directory, . in root: ok",
    "removed directory, . with O_DIRECTORY beneath: ok",
    "removed directory, . with O_PATH in root: ok",
    "removed directory, .. beneath: EXDEV",
    "removed directory, .. in root: ok",
    "removed directory, ../x beneath: EXDEV",
    "removed directory, ../x in root: ENOENT",
    "removed directory, x beneath: ENOENT",
    "removed directory, x in root: ENOENT",
    "removed directory, x created beneath: ENOENT",
    "removed directory, / beneath: EXDEV",
    "removed directory, / in root: ok",
    "removed directory, /etc/passwd in root: ENOENT",
    "removed directory, empty path beneath: ENOENT",
    "removed directory, . written beneath: EISDIR",
    "removed directory, .. written in root: EISDIR",
    "removed directory, . created in root: EISDIR",
    "memfd, . beneath: ENOTDIR",
    "memfd, . in root: ENOTDIR",
    "memfd, x beneath: ENOTDIR",
    "memfd, x in root: ENOTDIR",
    "memfd, x created beneath: ENOTDIR",
    "memfd, empty path beneath: ENOENT",
    "memfd, / in root: ENOTDIR",
    "O_TMPFILE file, . beneath: ENOTDIR",
    "O_TMPFILE file, . in root: ENOTDIR",
    "O_TMPFILE file, x beneath: ENOTDIR",
    "O_TMPFILE file, x in root: ENOTDIR",
    "O_TMPFILE file, . with O_PATH beneath: ENOTDIR",
    "pipe, . beneath: ENOTDIR",
    "pipe, x in root: ENOTDIR",
)


def openat2_pathless_wrong(out: str) -> list[str]:
    """The lines of openat2 pathless's output that differ from the kernel's answers.

    Other lines in out, the plain mode's when the two ran together, are left alone.
    """
    got = dict(x.split(": ", 1) for x in out.splitlines() if ": " in x)
    return [
        f"{k}: got {got.get(k)!r}, the kernel says {v!r}"
        for k, v in (x.split(": ", 1) for x in OPENAT2_PATHLESS)
        if got.get(k) != v
    ]


# rename_dots HOSTDIR OTHERDIR: one line per case, the case and the errno's name, in do_renameat2's
# order: the parents looked up, the two mounts compared (EXDEV), a last name of "." or ".." refused
# (EBUSY, or EEXIST for the new name under RENAME_NOREPLACE), the mount wanted writable (EROFS). A
# case against OTHERDIR has a second answer, the one where OTHERDIR shares HOSTDIR's mount.
RENAME_DOTS = (
    ("hdir/. to other", "EXDEV", "EBUSY"),
    ("other to hdir/.", "EXDEV", "EBUSY"),
    ("hdir/.. to other", "EXDEV", "EBUSY"),
    ("other to hdir/..", "EXDEV", "EBUSY"),
    ("other to hdir/. noreplace", "EXDEV", "EEXIST"),
    ("hdir/. to other exchange", "EXDEV", "EBUSY"),
    ("hlink/.. to other", "EXDEV", "EBUSY"),
    ("hdir/. to hnew", "EBUSY"),
    ("hnew to hdir/.", "EBUSY"),
    ("hdir/.. to hnew", "EBUSY"),
    ("hnew to hdir/.. noreplace", "EEXIST"),
    ("hdir/. to hnew noreplace", "EBUSY"),
    ("hdir/. to hnew exchange", "EBUSY"),
    ("hlink/.. to hnew", "EBUSY"),
    ("hfile/. to hnew", "ENOTDIR"),
    ("hnew to hfile/.", "ENOTDIR"),
    ("missing/. to other", "ENOENT"),
    ("/usr/share/. to other", "EXDEV"),
    ("other to /usr/share/..", "EXDEV"),
    ("/usr/share/. to hnew", "EXDEV"),
    ("/usr/share/. to /usr/x", "EBUSY"),
    ("/usr/x to /usr/share/.", "EBUSY"),
    ("/usr/x to /usr/share/.. noreplace", "EEXIST"),
    ("/usr/share/x to /usr/y", "EROFS"),
    ("/ to other", "EXDEV"),
    ("/ to /usr/x", "EBUSY"),
    ("/proc/.. to /usr/x", "EXDEV"),
    ("/proc/.. to hnew", "EXDEV"),
    ("hnew to /proc/..", "EXDEV"),
    ("hdir/.. from a descriptor to other", "EXDEV", "EBUSY"),
    ("hdir/. from a descriptor to hnew", "EBUSY"),
    ("hdir/. from the working directory to other", "EXDEV", "EBUSY"),
    ("hdir/.. from the working directory to hnew", "EBUSY"),
    (".. from the working directory to other", "EXDEV", "EBUSY"),
    ("hdir/./ from the working directory to hnew", "EBUSY"),
    ("hnew afterwards", "ENOENT"),
    ("other afterwards", "ENOENT"),
)


def rename_dots_wrong(out: str, *, across: bool) -> list[str]:
    """The lines of rename_dots's output that differ from the kernel's answers.

    across: OTHERDIR lies on a different mount from HOSTDIR.
    """
    want = [f"{c}: {a[0] if across or len(a) == 1 else a[1]}" for c, *a in RENAME_DOTS]
    got = out.splitlines()
    wrong = [f"got {g!r}, the kernel says {w!r}" for g, w in zip(got, want, strict=False) if g != w]
    if len(got) != len(want):
        wrong.append(f"{len(got)} lines, the kernel gives {len(want)}")
    return wrong


# program_perm: one line per case, the case and the errno text; the running program's own file on a
# host path, writable and then made unwritable (chmod 0555): may_open's permission check comes
# before do_dentry_open's and handle_truncate's ETXTBSY, with O_TRUNC asking for write access
# under any access mode (build_open_flags), and vfs_truncate's before its own
PROGRAM_PERM = (
    "O_WRONLY on the writable program: Text file busy",
    "O_WRONLY|O_TRUNC on the writable program: Text file busy",
    "O_RDONLY|O_TRUNC on the writable program: Text file busy",
    "O_RDWR on the writable program: Text file busy",
    "truncate of the writable program: Text file busy",
    "chmod 0555: ok",
    "O_WRONLY on the unwritable program: Permission denied",
    "O_WRONLY|O_TRUNC on the unwritable program: Permission denied",
    "O_RDONLY|O_TRUNC on the unwritable program: Permission denied",
    "O_RDWR on the unwritable program: Permission denied",
    "O_RDONLY on the unwritable program: ok",
    "truncate of the unwritable program: Permission denied",
    "chmod 0755: ok",
)


# exe_link: one line per case; a forked child reads, stats, opens and runs its parent's exe link, by
# the parent's pid and through a descriptor on the parent's /proc/self, and finds the program
EXE_LINK = (
    "readlink parent exe: the program",
    "readlinkat procself exe: the program",
    "stat parent exe: the program",
    "open parent exe: the program",
    "exec parent exe: ran",
    "exec procself exe: ran",
)

# sigcalls: the trapped signal syscalls in the kernel's order, one line per case
SIGCALLS = (
    "rt_sigaction setsize 4: Invalid argument",
    "rt_sigaction setsize 4, act bad: Invalid argument",
    "rt_sigaction sig 0: Invalid argument",
    "rt_sigaction sig 65: Invalid argument",
    "rt_sigaction sig 64 install: ok",
    "rt_sigaction sig 0 query: Invalid argument",
    "rt_sigaction sig 0, act bad: Bad address",
    "rt_sigaction SIGKILL query: ok",
    "rt_sigaction SIGKILL install: Invalid argument",
    "rt_sigaction SIGSTOP install: Invalid argument",
    "rt_sigaction SIGKILL, act bad: Bad address",
    "rt_sigaction act bad: Bad address",
    "rt_sigaction act bad, oact bad: Bad address",
    "rt_sigaction act ok, oact bad: Bad address",
    "after oact bad, the handler: installed",
    "rt_sigaction act NULL, oact bad: Bad address",
    "own restorer: ran, hits 1",
    "own restorer reported: yes, flags 0x4000000",
    "rt_sigaction act and oact the same: ok",
    "the same struct holds: the old handler",
    "rt_sigaction unknown flag bit: ok",
    "unknown flag bit reported: dropped",
    "SA_RESETHAND: hits 1, then SIG_DFL",
    "SA_NODEFER nesting: 3 deep, 3 runs",
    "deferred nesting: 1 deep, 3 runs",
    "sa_mask reported: USR2 yes, ALRM yes, HUP no",
    "rt_sigaction SIGSYS setsize 4: Invalid argument",
    "rt_sigaction SIGSYS act bad: Bad address",
    "rt_sigaction SIGSYS act ok, oact bad: Bad address",
    "rt_sigaction SIGSYS act NULL, oact bad: Bad address",
    "handler without SA_RESTORER: killed by Segmentation fault",
    "rt_sigprocmask setsize 4: Invalid argument",
    "rt_sigprocmask setsize 4, set bad: Invalid argument",
    "rt_sigprocmask how 99, set NULL: ok",
    "rt_sigprocmask how 99, set NULL, oset NULL: ok",
    "rt_sigprocmask how 99: Invalid argument",
    "rt_sigprocmask how 99, set bad: Bad address",
    "rt_sigprocmask set bad: Bad address",
    "rt_sigprocmask set bad, oset bad: Bad address",
    "rt_sigprocmask set NULL, oset bad: Bad address",
    "rt_sigprocmask set ok, oset bad: Bad address",
    "after oset bad, USR1: blocked",
    "rt_sigprocmask set and oset the same: ok",
    "the same set holds: USR1 yes, USR2 no",
    "blocked after it: USR1 yes, USR2 yes",
    "rt_sigprocmask block KILL, STOP, HUP: ok",
    "blocked: KILL no, STOP no, HUP yes",
    "rt_sigsuspend setsize 4: Invalid argument",
    "rt_sigsuspend setsize 4, set bad: Invalid argument",
    "rt_sigsuspend set bad: Bad address",
    "rt_sigsuspend set NULL: Bad address",
    "ppoll mask NULL, setsize 4: ok",
    "ppoll setsize 4: Invalid argument",
    "ppoll setsize 4, mask bad: Invalid argument",
    "ppoll mask bad: Bad address",
    "ppoll timeout bad: Bad address",
    "ppoll timeout bad, mask bad: Bad address",
    "ppoll timeout bad, setsize 4: Bad address",
    "ppoll timeout invalid: Invalid argument",
    "ppoll timeout invalid, mask bad: Invalid argument",
    "ppoll timeout invalid, setsize 4: Invalid argument",
    "ppoll fds bad: Bad address",
    "ppoll fds bad, mask bad: Bad address",
    "ppoll nfds huge: Invalid argument",
    "ppoll nfds huge, mask bad: Bad address",
    "ppoll nfds huge, setsize 4: Invalid argument",
    "pselect6 pack bad: Bad address",
    "pselect6 pack bad, timeout bad: Bad address",
    "pselect6 pack bad, n -1: Bad address",
    "pselect6 mask NULL, size 4: ok",
    "pselect6 size 4: Invalid argument",
    "pselect6 size 4, mask bad: Invalid argument",
    "pselect6 mask bad: Bad address",
    "pselect6 timeout bad: Bad address",
    "pselect6 timeout bad, mask bad: Bad address",
    "pselect6 timeout bad, size 4: Bad address",
    "pselect6 timeout invalid: Invalid argument",
    "pselect6 timeout invalid, mask bad: Invalid argument",
    "pselect6 timeout invalid, size 4: Invalid argument",
    "pselect6 n -1: Invalid argument",
    "pselect6 n -1, mask bad: Bad address",
    "pselect6 n -1, size 4: Invalid argument",
    "pselect6 fds bad: Bad address",
    "pselect6 fds bad, mask bad: Bad address",
    "epoll_pwait mask NULL, setsize 4, epfd -1: Bad file descriptor",
    "epoll_pwait setsize 4, epfd -1: Invalid argument",
    "epoll_pwait mask bad, epfd -1: Bad address",
    "epoll_pwait mask bad, maxevents 0: Bad address",
    "epoll_pwait maxevents 0: Invalid argument",
    "epoll_pwait events bad: ok",
    "epoll_pwait events bad, epfd -1: Bad file descriptor",
    "epoll_pwait epfd -1: Bad file descriptor",
    "epoll_pwait epfd not epoll: Invalid argument",
    "epoll_pwait ok, no events: ok",
    "epoll_pwait2 timeout bad: Bad address",
    "epoll_pwait2 timeout bad, mask bad: Bad address",
    "epoll_pwait2 timeout bad, setsize 4: Bad address",
    "epoll_pwait2 timeout invalid: Invalid argument",
    "epoll_pwait2 timeout invalid, mask bad: Invalid argument",
    "epoll_pwait2 timeout invalid, setsize 4: Invalid argument",
    "epoll_pwait2 mask NULL, setsize 4, epfd -1: Bad file descriptor",
    "epoll_pwait2 mask bad, epfd -1: Bad address",
    "epoll_pwait2 ok, no events: ok",
    "io_pgetevents pack bad: Bad address",
    "io_pgetevents pack bad, timeout bad: Bad address",
    "io_pgetevents mask NULL, size 4, ctx 0: Invalid argument",
    "io_pgetevents size 4, ctx 0: Invalid argument",
    "io_pgetevents mask bad, ctx 0: Bad address",
    "io_pgetevents timeout bad, mask bad: Bad address",
    "io_pgetevents timeout bad, size 4: Bad address",
    "io_pgetevents timeout invalid, mask bad: Bad address",
    "io_pgetevents timeout invalid, ctx 0: Invalid argument",
    "io_pgetevents ctx 0: Invalid argument",
)


def sigcalls_wrong(out: str) -> list[str]:
    """The lines of sigcalls's output that differ from the kernel's answers.

    aarch64 delivers a handler installed without SA_RESTORER through the vdso's, where x86-64 kills
    with SIGSEGV; a kernel before 5.11 keeps unknown sa_flags bits and has no epoll_pwait2, one
    before 4.18 no io_pgetevents.
    """
    want = list(SIGCALLS)
    if platform.machine() == "aarch64":
        want = [
            w.replace("SA_RESTORER: killed by Segmentation fault", "SA_RESTORER: exit 1")
            for w in want
        ]
    k = kernel()
    if k < (5, 11):
        want = [w.replace("flag bit reported: dropped", "flag bit reported: kept") for w in want]
    # a syscall this kernel lacks: ENOSYS from the kernel, where the launcher's own checks of the
    # arguments before the re-issue answer as the newer kernels do
    lacking = ("epoll_pwait2 ",) * (k < (5, 11)) + ("io_pgetevents ",) * (k < (4, 18))
    also = {
        w: w.split(": ")[0] + ": Function not implemented" for w in want if w.startswith(lacking)
    }
    got = out.splitlines()
    wrong = [
        f"got {g!r}, the kernel says {w!r}"
        for g, w in zip(got, want, strict=False)
        if g != w and g != also.get(w)
    ]
    if len(got) != len(want):
        wrong.append(f"{len(got)} lines, the kernel gives {len(want)}")
    return wrong


# sigrain HOSTDIR: signals in flight during trapped calls, one line per case
SIGRAIN = (
    "stat under SIGALRM rain, handler: ok, 0 EINTR, 0 other",
    "stat under SIGALRM rain, SA_RESTART: ok, 0 EINTR, 0 other",
    "stat under SIGALRM rain, handler that traps: ok, 0 EINTR, 0 other",
    "open under SIGALRM rain, handler: ok, 0 EINTR, 0 other",
    "open under SIGALRM rain, SA_RESTART: ok, 0 EINTR, 0 other",
    "open under SIGALRM rain, handler that traps: ok, 0 EINTR, 0 other",
    "readlink under SIGALRM rain, handler: ok, 0 EINTR, 0 other",
    "readlink under SIGALRM rain, SA_RESTART: ok, 0 EINTR, 0 other",
    "readlink under SIGALRM rain, handler that traps: ok, 0 EINTR, 0 other",
    "execve of a missing file under SIGALRM rain, handler: ok, 0 EINTR, 0 other",
    "execve of a missing file under SIGALRM rain, SA_RESTART: ok, 0 EINTR, 0 other",
    "execve of a missing file under SIGALRM rain, handler that traps: ok, 0 EINTR, 0 other",
    "the trapping handler's own traps: 0 failed",
    "stat under SIGALRM rain, blocked: ok, 0 EINTR, 0 other",
    "blocked throughout: 0 delivered, then 1 on unblocking",
    "stat under SIGALRM rain, ignored: ok, 0 EINTR, 0 other",
    "siglongjmp out of the handler: 20 of 20 rounds jumped, stat after ok",
    "traps under kill from a child: ok, 0 wrong, handler traps 0 failed, signals landed",
    "traps under tgkill from a thread: ok, 0 wrong, handler traps 0 failed, signals landed",
    "pause under SA_RESTART: EINTR",
    "sigsuspend under SA_RESTART: EINTR",
    "ppoll under SA_RESTART: EINTR",
    "pselect under SA_RESTART: EINTR",
    "open of a FIFO under SA_RESTART: ok",
    "open of a FIFO without SA_RESTART: Interrupted system call",
    "mask inside the handler after its traps: USR1 yes, USR2 yes, HUP yes",
    "mask after the handler: USR1 no, USR2 no, HUP no",
    "stat with a path in a file mapping past its end: Bad address",
    "stat with a path running off its mapping: Bad address",
)


def sigrain_wrong(out: str) -> list[str]:
    """The lines of sigrain's output that differ from the kernel's answers."""
    return same_lines_wrong(out, SIGRAIN)


def same_lines_wrong(out: str, want: tuple[str, ...]) -> list[str]:
    """The lines of out that differ from want, line by line, and a count that differs."""
    got = out.splitlines()
    wrong = [f"got {g!r}, the kernel says {w!r}" for g, w in zip(got, want, strict=False) if g != w]
    if len(got) != len(want):
        wrong.append(f"{len(got)} lines, the kernel gives {len(want)}")
    return wrong


# sigstack: the alternate signal stack, one line per case; the first line is the machine's
# MINSIGSTKSZ and is compared by its prefix
SIGSTACK = (
    "MINSIGSTKSZ: 3376 bytes",
    "alternate stack of MINSIGSTKSZ, handler does nothing: exit 1",
    "alternate stack of 4 KB, handler does nothing: exit 1",
    "alternate stack of 5 KB, handler does nothing: exit 1",
    "alternate stack of 6 KB, handler does nothing: exit 1",
    "alternate stack of 8 KB, handler does nothing: exit 1",
    "alternate stack of 16 KB, handler does nothing: exit 1",
    "alternate stack of MINSIGSTKSZ, handler traps: exit 1",
    "alternate stack of 4 KB, handler traps: exit 1",
    "alternate stack of 5 KB, handler traps: exit 1",
    "alternate stack of 6 KB, handler traps: exit 1",
    "alternate stack of 8 KB, handler traps: exit 1",
    "alternate stack of 16 KB, handler traps: exit 1",
    "5 KB handler without SA_ONSTACK during traps, 8 KB alternate stack: exit 0",
    (
        "plain alternate stack: inside flags SS_ONSTACK, stat ok, rearm Operation not permitted, "
        "stat ok; after flags 0"
    ),
    # inside the handler the stack is disarmed (__save_altstack), and its return restores it, flag
    # and all (restore_altstack), over the stack armed inside
    "SS_AUTODISARM: inside flags SS_DISABLE, stat ok, rearm ok, stat ok; after flags SS_AUTODISARM",
    "nested handlers on the alternate stack: both trapped",
    "handler on the main stack beside an armed alternate stack: both trapped",
    "sigaltstack outside any handler: flags 0",
)
# the sizes whose answer the handler's own frame decides (13 item 30)
SIGSTACK_SMALL = ("MINSIGSTKSZ", "4 KB", "5 KB", "6 KB")
# the least alternate stack sigaltstack accepts (MINSIGSTKSZ, uapi signal.h), under which the
# exerciser's child exits 3 in both worlds
MINSIGSTKSZ_LEAST = {"x86_64": 2048, "aarch64": 5120}
SIGSTACK_SIZES = {"4 KB": 4096, "5 KB": 5120, "6 KB": 6144}


def minsigstksz() -> int:
    """The kernel's signal frame size on this machine, AT_MINSIGSTKSZ from the auxiliary vector."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.getauxval.restype = ctypes.c_ulong
    return int(libc.getauxval(51))


def sigstack_wrong(out: str, *, by_the_kernel: bool = False) -> list[str]:
    """The lines of sigstack's output that differ from the kernel's answers.

    by_the_kernel: the kernel itself answered. Otherwise the launcher did, and a handler that traps
    on an alternate stack smaller than 8 KB is its stated limitation (13 item 30), 8 KB too where
    the kernel's frame passes 3.5 KB; and a 5 KB handler without SA_ONSTACK landing during a trap
    exits 9 from the SIGSEGV handler, since it runs on the 8 KB alternate stack (13 item 51), or
    is killed where that handler has no room either, as on aarch64.
    """
    got = out.splitlines()
    wrong = []
    least = MINSIGSTKSZ_LEAST.get(platform.machine(), 0)
    for g, w in zip(got, SIGSTACK, strict=False):
        if g == w or (w.startswith("MINSIGSTKSZ: ") and g.startswith("MINSIGSTKSZ: ")):
            continue
        if (
            w.startswith("SS_AUTODISARM: ")
            and kernel() < (4, 7)
            and g == "SS_AUTODISARM: sigaltstack Invalid argument"
        ):
            continue  # the flag is 4.7's
        if g == w.replace("exit 1", "exit 3") and any(
            f"of {name}," in w and size < least for name, size in SIGSTACK_SIZES.items()
        ):
            continue  # a stack the kernel refuses on this machine
        if not by_the_kernel:
            case = w.split(": ")[0]
            if case.endswith("handler traps") and (
                any(f"of {size}," in case for size in SIGSTACK_SMALL)
                or ("of 8 KB," in case and minsigstksz() > 3500)
            ):
                continue
            if case.startswith("5 KB handler") and (
                g == w.replace("exit 0", "exit 9")
                or (
                    platform.machine() == "aarch64"
                    and g == w.replace("exit 0", "killed by Segmentation fault")
                )
            ):
                continue
        wrong.append(f"got {g!r}, the kernel says {w!r}")
    if len(got) != len(SIGSTACK):
        wrong.append(f"{len(got)} lines, the kernel gives {len(SIGSTACK)}")
    return wrong


# clones HOSTDIR: threads and clones trapping, one line per case
CLONES = (
    "vfork child's traps: stat ok, open ok, readlink ok, access ok, exit 0",
    "clone(CLONE_VM) child on a 64 KB stack: stat ok, open ok, readlink ok, access ok, exit 0",
    "clone(CLONE_VM) child trapping on a 8 KB stack: exit 0",
    "clone(CLONE_VM) child trapping on a 4 KB stack: exit 0",
    "clone(CLONE_VM) child trapping on a 2 KB stack: exit 0",
    "clone(CLONE_VM|CLONE_VFORK) child's traps: stat ok, open ok, readlink ok, access ok, exit 0",
    "thread with a 16 KB stack, 100 traps: ok",
    "thread with the least stack, 100 traps: ok",
    "64 threads trapping under tgkill: 0 wrong, handler traps 0 failed, signals landed",
    "pthread_cancel in a blocking trapped open: cancelled",
    "asynchronous pthread_cancel in a trap loop: cancelled",
    "stat after the cancels: ok",
    "sibling exit during a blocking trap: open completed",
    "exit_group from a handler inside a blocking trap: exit 7",
    "pthread_exit from a handler inside a blocking trap: joined",
    "stat after it: ok",
)


def clones_wrong(out: str, *, by_the_kernel: bool = False) -> list[str]:
    """The lines of clones's output that differ from the kernel's answers.

    by_the_kernel: the kernel itself answered. Otherwise the launcher did, and a clone(CLONE_VM)
    child trapping on a 4 KB or 2 KB stack is its stated limitation (13 item 30), 8 KB too where
    the kernel's frame passes 3.5 KB; so is a thread on the least stack its libc allows where that
    is as small, musl's 2 KB, a death reported with the stack's size. A deferred cancellation of a
    thread blocked in a trapped open is acted on, the trampoline presenting the trap site's frame
    to the libc's cancellation handler (7.5.7).
    """
    got = out.splitlines()
    wrong = []
    for g, w in zip(got, CLONES, strict=False):
        if g == w:
            continue
        case = w.split(": ")[0]
        if (
            not by_the_kernel
            and case.startswith("clone(CLONE_VM) child trapping on a ")
            and ("4 KB" in case or "2 KB" in case or minsigstksz() > 3500)
        ):
            continue
        least = re.fullmatch(
            r"thread with the least stack, 100 traps: killed by .* on (\d+) bytes", g
        )
        if not by_the_kernel and least:
            size = int(least[1])
            if size <= 4096 or (size <= 8192 and minsigstksz() > 3500):
                continue
        wrong.append(f"got {g!r}, the kernel says {w!r}")
    if len(got) != len(CLONES):
        wrong.append(f"{len(got)} lines, the kernel gives {len(CLONES)}")
    return wrong


# sigframe HOSTDIR: what a program's handler finds in its frame and decides there (7.5.7); a line
# that differs by architecture gives its answers by machine
SIGFRAME: tuple[str | dict[str, str] | None, ...] = (
    "blocking open, SA_RESTART: counter at the syscall instruction",
    {
        "x86_64": "blocking open, SA_RESTART: result register the syscall number",
        "aarch64": "blocking open, SA_RESTART: result register the first argument",
    },
    "blocking open, SA_RESTART: stack pointer the program's",
    "blocking open, SA_RESTART: marked register the value set",
    "blocking open, SA_RESTART: signal mask the program's",
    "blocking open, SA_RESTART: floating-point state present, the vector register as set",
    "blocking open, SA_RESTART: the open returned a descriptor",
    "blocking open, no SA_RESTART: counter after the syscall instruction",
    "blocking open, no SA_RESTART: result register -EINTR",
    "blocking open, no SA_RESTART: stack pointer the program's",
    "blocking open, no SA_RESTART: marked register the value set",
    "blocking open, no SA_RESTART: signal mask the program's",
    "blocking open, no SA_RESTART: floating-point state present, the vector register as set",
    "blocking open, no SA_RESTART: the open failed with EINTR",
    "outside a trap: counter in the loop",
    None,  # the result register in the loop: whatever the compiler left there
    "outside a trap: stack pointer the program's",
    "outside a trap: marked register the value set",
    "outside a trap: signal mask the program's",
    "outside a trap: floating-point state present, the vector register as set",
    "stats of a long path under a rain: every stat answered",
    "stats of a long path under a rain: landings outside the program and its libraries none",
    (
        "stats of a long path under a rain: at the syscall instruction or after it, the program's "
        "registers and the stat's result"
    ),
    "stats of a long path under a rain: signal mask the program's at every landing",
    "query of an installed action: handler the program's, mask as written, flags as written",
    "the action an install replaces: handler the program's, mask as written",
    "a handler called by another through the action a query returned: ran with the arguments given",
    "a handler whose sibling call reaches the action a query returned: ran",
    "query of an ignored signal: ignored",
    "query of a signal never installed: default",
    "a handler that moves the counter: the thread went where it was sent",
    "a handler that blocks SIGUSR2 in its frame: open EINTR, SIGUSR2 blocked",
    "a handler that blocks every signal in its frame, then a trap: open EINTR, stat ok",
    "a handler that siglongjmps out: back, stat ok",
    "installs from two threads at once: the last installed",
    "an install in a vfork child: the parent's action unchanged",
    "SA_RESETHAND: the handler ran, then default",
    "a bad oldact: EFAULT, the new action in force",
    "an ignored signal queried after execve: ignored",
)


# under the launcher a query, which passes to the kernel, reports what the launcher installed: the
# stub as the handler and the mask without SIGSYS (13 item 20)
SIGFRAME_QUERY = (
    "query of an installed action: handler another, mask without SIGSYS, flags as written"
)


def sigframe_wrong(out: str, *, by_the_kernel: bool = False) -> list[str]:
    """The lines of sigframe's output that differ from the kernel's answers."""
    got = out.splitlines()
    wrong = []
    for g, w in zip(got, SIGFRAME, strict=False):
        if w is None:
            continue
        want = w[platform.machine()] if isinstance(w, dict) else w
        if not by_the_kernel and g == SIGFRAME_QUERY and want.startswith("query of an installed"):
            continue
        if g != want:
            wrong.append(f"got {g!r}, the kernel says {want!r}")
    if len(got) != len(SIGFRAME):
        wrong.append(f"{len(got)} lines, the kernel gives {len(SIGFRAME)}")
    return wrong


# unwind_frame HOSTDIR, built with -fexceptions: an unwind from a handler during a trapped call
# walks into the program's frames (7.5.7)
UNWIND_FRAME = (
    "pthread_cancel in a blocking trapped open: cancelled, the cleanup handler ran",
    "a forced unwind from a handler during a trapped open: cleanup end",
)
# on musl natively too: libgcc steps through its restorer, whose bytes it knows, but stops at
# __syscall_cp_asm, which carries no unwind information
UNWIND_FRAME_MUSL = "a forced unwind from a handler during a trapped open: end"


def unwind_frame_wrong(out: str, *, musl: bool = False) -> list[str]:
    """The lines of unwind_frame's output that differ from the kernel's answers."""
    got = out.splitlines()
    want = (UNWIND_FRAME[0], UNWIND_FRAME_MUSL) if musl else UNWIND_FRAME
    wrong = [f"got {g!r}, the kernel says {w!r}" for g, w in zip(got, want, strict=False) if g != w]
    if len(got) != len(UNWIND_FRAME):
        wrong.append(f"{len(got)} lines, the kernel gives {len(UNWIND_FRAME)}")
    return wrong


# memfd_exec: exec of a memfd, the kernel's exec permission before its reading of the header. The
# flags MFD_EXEC and MFD_NOEXEC_SEAL are 6.3's, EINVAL before; a memfd made with no flag is sealed
# against exec where vm.memfd_noexec is 1, which the program's last line, the host's facts, shows
# in its seals (F_SEAL_EXEC); and under a bwrap whose child an AppArmor profile confines, every
# exec of a memfd is EACCES (tree.memfd_exec_under_bwrap)
OLD_MEMFD = kernel() < (6, 3)
F_SEAL_EXEC = 0x20


def memfd_exec_table(
    out: str, *, exec_denied: bool
) -> tuple[tuple[str, str | tuple[str, ...] | None], ...]:
    """The answers memfd_exec's cases take on this kernel, read with the host's facts in out."""
    m = re.search(r"seals=(0x[0-9a-f]+|0)", out)
    sealed = bool(int(m.group(1), 16) & F_SEAL_EXEC) if m else False
    flagged = "memfd_create EINVAL" if OLD_MEMFD else None
    ran = "EACCES" if exec_denied else "ran"
    empty = "EACCES" if exec_denied else "ENOEXEC"
    return (
        ("executable memfd with the program", flagged or ran),
        ("executable memfd, empty", flagged or empty),
        ("sealed memfd with the program", flagged or "EACCES"),
        ("sealed memfd, empty", flagged or "EACCES"),
        ("plain memfd with the program", "EACCES" if sealed else ran),
        ("plain memfd, empty", "EACCES" if sealed else empty),
        ("facts", None),
    )


def memfd_exec_wrong(out: str, *, exec_denied: bool = False) -> list[str]:
    """The lines of memfd_exec's output that differ from the kernel's answers.

    exec_denied: the run was under a bwrap whose child is refused the exec of a memfd.
    """
    return lines_wrong(out, memfd_exec_table(out, exec_denied=exec_denied), {}, by_the_kernel=True)


def exe_link_wrong(out: str) -> list[str]:
    """The lines of exe_link's output that differ from the kernel's answers."""
    got = out.splitlines()
    wrong = [
        f"got {g!r}, the kernel says {w!r}" for g, w in zip(got, EXE_LINK, strict=False) if g != w
    ]
    if len(got) != len(EXE_LINK):
        wrong.append(f"{len(got)} lines, the kernel gives {len(EXE_LINK)}")
    return wrong


def program_perm_wrong(out: str) -> list[str]:
    """The lines of program_perm's output that differ from the kernel's answers.

    Root overrides the mode (CAP_DAC_OVERRIDE), and then the unwritable program answers as the
    writable one does.
    """
    want = list(PROGRAM_PERM)
    if os.geteuid() == 0:
        want = [w.replace("Permission denied", "Text file busy") for w in want]
    got = out.splitlines()
    wrong = [f"got {g!r}, the kernel says {w!r}" for g, w in zip(got, want, strict=False) if g != w]
    if len(got) != len(want):
        wrong.append(f"{len(got)} lines, the kernel gives {len(want)}")
    return wrong


def creat_slash_wrong(out: str, *, by_the_kernel: bool = False) -> list[str]:
    """The lines of creat_slash's output that differ from the kernel's answers.

    by_the_kernel: the kernel itself answered, so a kernel before 5.8 may answer the cases of
    CREAT_SLASH_SINCE_5_8 as it did then, EISDIR.
    """
    got = out.splitlines()
    want = list(CREAT_SLASH)
    if by_the_kernel and kernel() < (5, 8):
        want = [
            w.replace("File exists", "Is a directory") if w.startswith(CREAT_SLASH_SINCE_5_8) else w
            for w in want
        ]
    return [] if got == want else [f"got {got!r}, the kernel says {want!r}"]


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
    """The lines of slash_links's output that differ from the kernel's answers.

    A kernel without openat2 (before 5.6) answers its lines "skipped" in both worlds, since the
    launcher re-issues the call as itself.
    """
    got = out.splitlines()
    skipped = "exlink: skipped" in got
    got = [x for x in got if x != "exlink: skipped"]
    want = [x for x in SLASH_LINKS if not (skipped and x.startswith("exlink "))]
    no_openat2 = kernel() < (5, 6)
    return [
        f"got {g!r}, the kernel says {w!r}"
        for g, w in itertools.zip_longest(got, want)
        if g != w
        and not (no_openat2 and w and " openat2 " in w and g == w.split(": ")[0] + ": skipped")
    ]


# magic_links pathless: the descriptors it checks, and the syscalls it makes that a kernel may lack
MAGIC_LINKS_FDS = ("stdin", "pipe", "memfd", "inotify", "unlinked")
SYS_STATX = {"x86_64": 332, "aarch64": 291}
SYS_LINKAT = {"x86_64": 265, "aarch64": 37}
SYS_FACCESSAT2 = 439
AT_FDCWD = -100
AT_EMPTY_PATH = 0x1000

# magic_links link-empty DIR: linkat with AT_EMPTY_PATH on a descriptor whose file has no path,
# the kernel's answer for each, from do_linkat and vfs_link in fs/namei.c: the link made for an
# O_TMPFILE file (6.10 and later), ENOENT for an unlinked file, whose link count is zero, EXDEV
# for an object with no mount in common, EPERM for a directory, and EROFS for a new name in the
# tree
LINK_EMPTY = {
    "tmpfile": "ok",
    "unlinked": "errno 2",
    "memfd": "errno 18",
    "pipe": "errno 18",
    "socket": "errno 18",
    "gone": "errno 1",
    "tmpfile into tree": "errno 30",
}


def link_empty_allowed(hostdir: str) -> set[str]:
    """The lines magic_links link-empty DIR may print on this kernel.

    Before 6.10 linkat with AT_EMPTY_PATH wanted CAP_DAC_READ_SEARCH and answered ENOENT without
    it before any lookup; the kernel is asked natively, with an O_TMPFILE file in hostdir, and
    then every case may answer ENOENT too, the launcher's own EROFS for a name in the tree aside.
    """
    allowed = {f"link-empty {k} {v}" for k, v in LINK_EMPTY.items()}
    try:
        fd = os.open(hostdir, os.O_TMPFILE | os.O_RDWR, 0o644)
    except OSError:
        return allowed
    libc = ctypes.CDLL(None, use_errno=True)
    dst = os.path.join(hostdir, f"link-empty-probe-{os.getpid()}").encode()
    r = libc.syscall(SYS_LINKAT[platform.machine()], fd, b"", AT_FDCWD, dst, AT_EMPTY_PATH)
    old = r < 0 and ctypes.get_errno() == errno.ENOENT
    os.close(fd)
    if r == 0:
        os.unlink(dst)
    if old:
        allowed |= {f"link-empty {k} errno 2" for k in LINK_EMPTY}
    return allowed


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
    """The lines of magic_links pathless and link-empty that do not give the kernel's answer.

    Each line ends ok, or is the failure of a call the kernel lacks natively (magic_links_missing),
    or a link-empty answer the kernel gives (link_empty_allowed).
    """
    return [line for line in out.splitlines() if not line.endswith(" ok") and line not in missing]


# ---------- exec: the four exercisers of test/regress_exec.py, one line per case, "<case>:
# <answer>" ---------- the machine's name where a line answers it
MACHINE = "MACHINE"


def lines_wrong(
    out: str,
    want: tuple[tuple[str, str | tuple[str, ...] | None], ...],
    launcher: dict[str, str],
    *,
    by_the_kernel: bool,
) -> list[str]:
    """The lines of out that differ from want, the kernel's answers in order.

    An answer of None is any (a value the kernel decides for the machine), a tuple any of its
    members, MACHINE the machine's name. The launcher's answers that a stated rule makes differ
    from the kernel's are in launcher and replace the kernel's unless by_the_kernel.
    """
    got = dict(line.split(": ", 1) for line in out.splitlines() if ": " in line)
    wrong = []
    for case, answer in want:
        if case not in got:
            wrong.append(f"{case}: missing")
            continue
        g = got[case]
        if not by_the_kernel and case in launcher:
            ok = g == launcher[case]
            w: object = launcher[case]
        elif answer is None:
            continue
        elif answer == MACHINE:
            ok = g == platform.machine()
            w = platform.machine()
        elif isinstance(answer, tuple):
            ok = g in answer
            w = " or ".join(answer)
        else:
            ok = g == answer
            w = answer
        if not ok:
            wrong.append(
                f"{case}: got {g!r}, the {'kernel' if by_the_kernel else 'rule'} says {w!r}"
            )
    if len(got) != len(want):
        wrong.append(f"{len(got)} lines, the kernel gives {len(want)}")
    return wrong


# exec_script run HOSTDIR (test/progs/exec_script.c), measured under bwrap on 7.0; an unreadable
# script's status is its interpreter's, dash's 2 or bash's 126
# the #! buffer of 128 bytes until 5.1, which cut the interpreter's argument sooner; a distribution
# kernel may carry the change (RHEL 8's 4.18 does), so before 5.1 either answer is the kernel's
OLD_BUF = kernel() < (5, 1)


def shebang_line(case: str, new: str, old: str) -> tuple[str, str | tuple[str, ...]]:
    """A #! line case's answer: its argument cut as since 5.1 (new), or either way before (old)."""

    def answer(cut: str) -> str:
        return f"status=0 out=argv=[$E|interp a*{cut}|$H/{case}|x]"

    return case, (answer(old), answer(new)) if OLD_BUF else answer(new)


# before 5.9 exec opened the file before checking that it was regular, and a socket's open answers
# ENXIO; a distribution kernel may carry the change (Ubuntu's 4.15 does), so either answer is the
# kernel's, and the launcher answers as the newer kernels do
OLD_EXEC_OPEN = kernel() < (5, 9)
EXEC_SCRIPT: tuple[tuple[str, str | tuple[str, ...] | None], ...] = (
    ("line127", "status=0 out=argv=[$E|interp a*full|$H/line127|x]"),
    ("line127-nonl", "status=0 out=argv=[$E|interp a*full|$H/line127-nonl|x]"),
    # a kernel before 5.1 read a 128-byte #! line and cut the argument 128 bytes sooner (OLD_BUF);
    # the launcher reads 256 bytes on every kernel
    *(
        shebang_line(case + nonl, new, old)
        for case, new, old in (
            ("line128", "full", "cut1"),
            ("line255", "full", "cut128"),
            ("line256", "cut1", "cut129"),
        )
        for nonl in ("", "-nonl")
    ),
    ("trailing blanks", "status=0 out=argv=[$E|interp|$H/trailing blanks|x]"),
    (
        "argument with spaces",
        "status=0 out=argv=[$E|interp one two  three|$H/argument with spaces|x]",
    ),
    ("leading blanks", "status=0 out=argv=[$E|interp|$H/leading blanks|x]"),
    ("nul in line", "status=0 out=argv=[$E|$H/nul|x]"),
    ("empty interpreter", "ENOEXEC"),
    ("blank interpreter", "ENOEXEC"),
    # a bare "#!" without a newline: ENOEXEC until binfmt_script's truncation rework in 5.5
    # (allow interpreter argument truncation); EACCES since (measured: 5.4 and 5.10); the
    # launcher answers EACCES on every kernel
    ("only #! no newline", "ENOEXEC" if kernel() < (5, 5) else "EACCES"),
    ("only # no newline", "ENOEXEC"),
    ("empty file", "ENOEXEC"),
    ("one newline", "ENOEXEC"),
    ("text file", "ENOEXEC"),
    ("chain of 3", "status=0 out=argv=[$E|interp|$H/c3-3|$H/c3-2|$H/c3-1|x]"),
    ("chain of 4", "status=0 out=argv=[$E|interp|$H/c4-4|$H/c4-3|$H/c4-2|$H/c4-1|x]"),
    ("chain of 5", "status=0 out=argv=[$E|interp|$H/c5-5|$H/c5-4|$H/c5-3|$H/c5-2|$H/c5-1|x]"),
    ("chain of 6", "ELOOP"),
    ("sh interpreter", "status=0 out=sh $H/sh interpreter x"),
    ("sh -e interpreter", "status=0 out=she $H/sh -e interpreter x"),
    ("symlink interpreter", "status=0 out=argv=[$H/interp-link|interp|$H/symlink interpreter|x]"),
    ("directory interpreter", "EACCES"),
    ("fifo interpreter", "EACCES"),
    ("absent interpreter", "ENOENT"),
    ("empty-file interpreter", "ENOEXEC"),
    ("text-file interpreter", "ENOEXEC"),
    (
        "unreadable interpreter",
        "status=0 out=argv=[$H/interp-0111|interp|$H/unreadable interpreter|x]",
    ),
    ("unreadable elf", "status=0 out=argv=[renamed|x]"),
    ("unreadable script", ("status=2 out=", "status=126 out=")),
    ("unreadable script, elf interpreter", "status=0 out=argv=[$E|interp|$H/script-0111-interp|x]"),
    ("script without x", "EACCES"),
    ("elf without x", "EACCES"),
    ("interpreter without x", "EACCES"),
    ("script by O_PATH fd", "status=0 out=argv=[$E|interp|/dev/fd/N|x]"),
    ("script by O_RDONLY fd", "status=0 out=argv=[$E|interp|/dev/fd/N|x]"),
    ("script by O_CLOEXEC fd", "ENOENT"),
    ("script relative to dirfd", "status=0 out=argv=[$E|interp|/dev/fd/N/fdscript|x]"),
    ("script by dirfd O_PATH", "status=0 out=argv=[$E|interp|/dev/fd/N/fdscript|x]"),
    ("script relative to O_PATH dirfd", "status=0 out=argv=[$E|interp|/dev/fd/N/fdscript|x]"),
    ("script symlink", "status=0 out=argv=[$E|interp|$H/fdscript-link|x]"),
    ("script symlink nofollow", "ELOOP"),
    ("script with trailing slash", "ENOTDIR"),
    ("bad flag", "EINVAL"),
    ("empty path without flag", "ENOENT"),
    ("elf by O_PATH fd", "status=0 out=argv=[renamed|interp]"),
    ("elf by O_RDONLY fd", "status=0 out=argv=[renamed|interp]"),
    ("directory", "EACCES"),
    ("fifo", "EACCES"),
    ("socket", ("EACCES", "ENXIO") if OLD_EXEC_OPEN else "EACCES"),
    ("/dev/null", "EACCES"),
    ("absent", "ENOENT"),
    ("under a file", "ENOTDIR"),
)
# where the launcher answers otherwise by a stated rule: an executable but unreadable file cannot
# run, the EACCES the kernel's own answer to the read (13 item 12)
EXEC_SCRIPT_LAUNCHER: dict[str, str] = {
    "unreadable interpreter": "EACCES",
    "unreadable elf": "EACCES",
    "unreadable script": "EACCES",
    "unreadable script, elf interpreter": "EACCES",
    # the launcher answers as the newer kernels do, whatever this kernel's buffer or rule
    **({"only #! no newline": "EACCES"} if kernel() < (5, 5) else {}),
    **({"socket": "EACCES"} if OLD_EXEC_OPEN else {}),
    **(
        {
            "line128": "status=0 out=argv=[$E|interp a*full|$H/line128|x]",
            "line128-nonl": "status=0 out=argv=[$E|interp a*full|$H/line128-nonl|x]",
            "line255": "status=0 out=argv=[$E|interp a*full|$H/line255|x]",
            "line255-nonl": "status=0 out=argv=[$E|interp a*full|$H/line255-nonl|x]",
            "line256": "status=0 out=argv=[$E|interp a*cut1|$H/line256|x]",
            "line256-nonl": "status=0 out=argv=[$E|interp a*cut1|$H/line256-nonl|x]",
        }
        if OLD_BUF
        else {}
    ),
}
# exec_elf HOSTDIR (test/progs/exec_elf.c), measured under bwrap on 7.0: the image's entry runs on
# the stack on x86-64, so the two stack cases die there, and exits in place on aarch64 (STACK),
# as do the two images whose second PT_LOAD covers the first, measured alike in both worlds on
# each machine; the terabyte of bss depends on the host's overcommit rule
STACK = "signal=11" if platform.machine() == "x86_64" else "status=42"
# until 5.8 a 64-bit image without PT_GNU_STACK got READ_IMPLIES_EXEC, every mapping executable
# (x86/elf: Disable automatic READ_IMPLIES_EXEC for 64-bit address spaces), so the kernel ran the
# three images whose entry runs on the stack or on a page mapped twice; the launcher answers as the
# newer kernels do
# a distribution kernel before 5.8 may carry the change (RHEL 8's 4.18 does), so the kernel's
# own answer is either
OLD_RIE = kernel() < (5, 8)
OLD_RIE_ANSWER: str | tuple[str, ...] = ("status=42", STACK) if OLD_RIE else STACK
# a PT_INTERP naming an ET_EXEC image already at its own address: until 6.7 the interpreter's
# mapping failed and the exec was killed; elf_load() took the interpreter's mapping in 6.7 and the
# image runs (measured: 6.6 kills, 6.8 runs); the launcher answers by 7.3's own rule either way
OLD_INTERP = "signal=11" if kernel() < (6, 7) else "status=42"


# a host that registered a binfmt_misc handler for other machines, as Fedora's cloud image does,
# runs a foreign image through it: ENOEXEC or the handler's death
def binfmt_misc_handlers() -> bool:
    """Whether this host registered a binfmt_misc handler, for any machine."""
    d = "/proc/sys/fs/binfmt_misc"
    return os.path.isdir(d) and any(e not in ("register", "status") for e in os.listdir(d))


FOREIGN: str | tuple[str, ...] = ("ENOEXEC", "signal=11") if binfmt_misc_handlers() else "ENOEXEC"
EXEC_ELF: tuple[tuple[str, str | tuple[str, ...] | None], ...] = (
    ("base", "status=42"),
    ("no PT_GNU_STACK", OLD_RIE_ANSWER),
    ("PT_GNU_STACK without PF_X", STACK),
    ("no PT_LOAD", "signal=11"),
    ("two identical PT_LOADs", OLD_RIE_ANSWER),
    ("PT_LOAD page overlapping the first", OLD_RIE_ANSWER),
    ("PT_LOADs out of address order", "status=42"),
    ("bss segment whose offset is unaligned", "status=42"),
    ("p_memsz below p_filesz", "signal=11"),
    ("a terabyte of bss", None),
    ("p_vaddr off p_offset within the page", "signal=11"),
    ("segment at address zero", "signal=11"),
    ("segment at 0x10000", "status=42"),
    ("segment past the end of the file", "status=42"),
    ("segment whose offset is past the file", "signal=7"),
    ("code segment without PF_X", ("status=42", "signal=11") if OLD_RIE else "signal=11"),
    ("segment without permissions", "signal=11"),
    ("p_align 3", "status=42"),
    ("entry outside every segment", "signal=11"),
    ("entry zero", "signal=11"),
    ("PT_INTERP a text file", "EIO"),
    ("PT_INTERP a script", "EIO"),
    ("PT_INTERP the base image", OLD_INTERP),
    ("PT_INTERP itself", OLD_INTERP),
    ("PT_INTERP absent", "ENOENT"),
    ("PT_INTERP a directory", "EACCES"),
    ("PT_INTERP a text file of 100 bytes", "ELIBBAD"),
    ("PT_INTERP without NUL", "ENOEXEC"),
    ("PT_INTERP empty", "ENOEXEC"),
    ("PT_INTERP of zero size", "ENOEXEC"),
    ("PT_INTERP of a megabyte", "ENOEXEC"),
    ("two PT_INTERPs, the first absent", "ENOENT"),
    ("EI_CLASS 32 on a 64-bit image", "status=42"),
    ("EI_DATA big-endian", "status=42"),
    ("EI_VERSION 0", "status=42"),
    ("e_version 0", "status=42"),
    ("EI_OSABI FreeBSD", "status=42"),
    ("another machine", FOREIGN),
    ("ET_REL", "ENOEXEC"),
    ("ET_CORE", "ENOEXEC"),
    ("e_phnum 0", "ENOEXEC"),
    ("e_phnum PN_XNUM", "ENOEXEC"),
    ("e_phnum 1171", "ENOEXEC"),
    ("e_phnum 1170", "ENOEXEC"),
    ("e_phentsize 64", "ENOEXEC"),
    ("e_phoff past the file", "ENOEXEC"),
    ("e_phoff in the last bytes", "ENOEXEC"),
    ("e_ehsize 0", "status=42"),
    ("sections past the file", "status=42"),
    ("header cut at 48 bytes", "ENOEXEC"),
    ("program headers cut", "ENOEXEC"),
    ("ET_DYN at 0x400000", "status=42"),
    ("ET_DYN at zero", "status=42"),
    ("ET_DYN p_vaddr off p_offset", "signal=11"),
    ("ET_DYN with PT_INTERP the base image", OLD_INTERP),
    ("ET_DYN without PT_LOAD", "signal=11"),
    ("static", ("status=42", "compile failed")),
    ("static-pie", ("status=42", "compile failed")),
    ("pie at 0x400000", ("status=42", "compile failed")),
    ("no-pie at 0x10000", ("status=42", "compile failed")),
    ("dynamic pie", ("status=42", "compile failed")),
    ("dynamic pie execstack", ("status=42", "compile failed")),
)
# where the launcher answers otherwise by a stated rule: a loader that is not the exclave's own file
# is refused by name by the child launcher, where the kernel loads it (7.3)
EXEC_ELF_LAUNCHER: dict[str, str] = {
    "PT_INTERP the base image": "status=127",
    "PT_INTERP itself": "status=127",
    "ET_DYN with PT_INTERP the base image": "status=127",
    # the loader refuses a segment at an address already in use on every machine (7.3), as
    # x86-64's kernel does; aarch64's maps the identical segment over the first and runs it
    **({"two identical PT_LOADs": "signal=11"} if platform.machine() == "aarch64" else {}),
    **(
        {
            "no PT_GNU_STACK": STACK,
            "two identical PT_LOADs": STACK,
            "PT_LOAD page overlapping the first": STACK,
            "code segment without PF_X": "signal=11",
        }
        if OLD_RIE
        else {}
    ),
}
# exec_auxv HOSTDIR (test/progs/exec_auxv.c), measured under bwrap on 7.0; a value the kernel copies
# as its own, the vector's entries, the page size, the hardware capabilities and the loader's name,
# is any (None), and AT_PLATFORM is the machine's name (MACHINE)
EXEC_AUXV: tuple[tuple[str, str | tuple[str, ...] | None], ...] = (
    ("own sp aligned 16", "yes"),
    ("own argc at sp", "yes"),
    ("own argv at sp+8", "yes"),
    ("own envp after argv's NULL", "yes"),
    ("own auxv after envp's NULL", "yes"),
    ("own auxv types", None),
    ("own auxv entries", None),
    ("own AT_PHDR own", "yes"),
    ("own AT_PHENT", "56"),
    ("own AT_PHNUM own", "yes"),
    ("own AT_PAGESZ", None),
    ("own AT_ENTRY own", "yes"),
    ("own AT_BASE maps", None),
    ("own AT_BASE page aligned", "yes"),
    ("own AT_FLAGS", "0"),
    ("own AT_UID/EUID/GID/EGID own", "yes"),
    ("own AT_SECURE", "0"),
    ("own AT_PLATFORM", MACHINE),
    ("own AT_HWCAP nonzero", "yes"),
    ("own AT_HWCAP2", None),
    ("own AT_CLKTCK", None),
    ("own AT_MINSIGSTKSZ", None),
    ("own AT_RSEQ_FEATURE_SIZE", None),
    ("own AT_RSEQ_ALIGN", None),
    ("own AT_SYSINFO_EHDR", "an ELF"),
    ("own AT_SYSINFO_EHDR maps", "[vdso]"),
    ("own AT_EXECFD", "absent"),
    ("own AT_EXECFN last component", "exec_auxv"),
    ("own AT_RANDOM fresh", "no parent"),
    ("own vectors on the stack mapping", "yes"),
    ("own strings on the stack mapping", "yes"),
    ("own strings above the vectors", "yes"),
    ("own argv strings contiguous ascending", "yes"),
    ("own envp[0] after argv's last", "yes"),
    ("own envp strings contiguous ascending", "yes"),
    ("own AT_EXECFN after envp's last", "yes"),
    ("own AT_EXECFN ends 8 below the stack top", "yes"),
    ("own AT_PLATFORM below argv[0]", "yes"),
    ("own AT_RANDOM below AT_PLATFORM", "yes"),
    ("own AT_PLATFORM just below argv[0]", "no"),
    ("own AT_RANDOM just below AT_PLATFORM", "yes"),
    ("own stat code holds main", "yes"),
    ("own stat startstack is sp", "yes"),
    ("own stat arg_start is argv[0]", "yes"),
    ("own stat arg_end is envp[0]", "yes"),
    ("own stat env_start is envp[0]", "yes"),
    ("own stat env_end is AT_EXECFN", "yes"),
    ("own cmdline is argv", "yes"),
    ("own comm", "exec_auxv"),
    ("own uid=euid", "yes"),
    ("exec sp aligned 16", "yes"),
    ("exec argc at sp", "yes"),
    ("exec argv at sp+8", "yes"),
    ("exec envp after argv's NULL", "yes"),
    ("exec auxv after envp's NULL", "yes"),
    ("exec auxv types", None),
    ("exec auxv entries", None),
    ("exec AT_PHDR own", "yes"),
    ("exec AT_PHENT", "56"),
    ("exec AT_PHNUM own", "yes"),
    ("exec AT_PAGESZ", None),
    ("exec AT_ENTRY own", "yes"),
    ("exec AT_BASE maps", None),
    ("exec AT_BASE page aligned", "yes"),
    ("exec AT_FLAGS", "0"),
    ("exec AT_UID/EUID/GID/EGID own", "yes"),
    ("exec AT_SECURE", "0"),
    ("exec AT_PLATFORM", MACHINE),
    ("exec AT_HWCAP nonzero", "yes"),
    ("exec AT_HWCAP2", None),
    ("exec AT_CLKTCK", None),
    ("exec AT_MINSIGSTKSZ", None),
    ("exec AT_RSEQ_FEATURE_SIZE", None),
    ("exec AT_RSEQ_ALIGN", None),
    ("exec AT_SYSINFO_EHDR", "an ELF"),
    ("exec AT_SYSINFO_EHDR maps", "[vdso]"),
    ("exec AT_EXECFD", "absent"),
    ("exec AT_EXECFN last component", "exec_auxv"),
    ("exec AT_RANDOM fresh", "yes"),
    ("exec vectors on the stack mapping", "yes"),
    ("exec strings on the stack mapping", "yes"),
    ("exec strings above the vectors", "yes"),
    ("exec argv strings contiguous ascending", "yes"),
    ("exec envp[0] after argv's last", "yes"),
    ("exec envp strings contiguous ascending", "yes"),
    ("exec AT_EXECFN after envp's last", "yes"),
    ("exec AT_EXECFN ends 8 below the stack top", "yes"),
    ("exec AT_PLATFORM below argv[0]", "yes"),
    ("exec AT_RANDOM below AT_PLATFORM", "yes"),
    ("exec AT_PLATFORM just below argv[0]", "no"),
    ("exec AT_RANDOM just below AT_PLATFORM", "yes"),
    ("exec stat code holds main", "yes"),
    ("exec stat startstack is sp", "yes"),
    ("exec stat arg_start is argv[0]", "yes"),
    ("exec stat arg_end is envp[0]", "yes"),
    ("exec stat env_start is envp[0]", "yes"),
    ("exec stat env_end is AT_EXECFN", "yes"),
    ("exec cmdline is argv", "yes"),
    ("exec comm", "exec_auxv"),
    ("exec uid=euid", "yes"),
    ("suid sp aligned 16", "yes"),
    ("suid argc at sp", "yes"),
    ("suid argv at sp+8", "yes"),
    ("suid envp after argv's NULL", "yes"),
    ("suid auxv after envp's NULL", "yes"),
    ("suid auxv types", None),
    ("suid auxv entries", None),
    ("suid AT_PHDR own", "yes"),
    ("suid AT_PHENT", "56"),
    ("suid AT_PHNUM own", "yes"),
    ("suid AT_PAGESZ", None),
    ("suid AT_ENTRY own", "yes"),
    ("suid AT_BASE maps", None),
    ("suid AT_BASE page aligned", "yes"),
    ("suid AT_FLAGS", "0"),
    ("suid AT_UID/EUID/GID/EGID own", "yes"),
    ("suid AT_SECURE", "0"),
    ("suid AT_PLATFORM", MACHINE),
    ("suid AT_HWCAP nonzero", "yes"),
    ("suid AT_HWCAP2", None),
    ("suid AT_CLKTCK", None),
    ("suid AT_MINSIGSTKSZ", None),
    ("suid AT_RSEQ_FEATURE_SIZE", None),
    ("suid AT_RSEQ_ALIGN", None),
    ("suid AT_SYSINFO_EHDR", "an ELF"),
    ("suid AT_SYSINFO_EHDR maps", "[vdso]"),
    ("suid AT_EXECFD", "absent"),
    ("suid AT_EXECFN last component", "suid"),
    ("suid AT_RANDOM fresh", "yes"),
    ("suid vectors on the stack mapping", "yes"),
    ("suid strings on the stack mapping", "yes"),
    ("suid strings above the vectors", "yes"),
    ("suid argv strings contiguous ascending", "yes"),
    ("suid envp[0] after argv's last", "yes"),
    ("suid envp strings contiguous ascending", "yes"),
    ("suid AT_EXECFN after envp's last", "yes"),
    ("suid AT_EXECFN ends 8 below the stack top", "yes"),
    ("suid AT_PLATFORM below argv[0]", "yes"),
    ("suid AT_RANDOM below AT_PLATFORM", "yes"),
    ("suid AT_PLATFORM just below argv[0]", "no"),
    ("suid AT_RANDOM just below AT_PLATFORM", "yes"),
    ("suid stat code holds main", "yes"),
    ("suid stat startstack is sp", "yes"),
    ("suid stat arg_start is argv[0]", "yes"),
    ("suid stat arg_end is envp[0]", "yes"),
    ("suid stat env_start is envp[0]", "yes"),
    ("suid stat env_end is AT_EXECFN", "yes"),
    ("suid cmdline is argv", "yes"),
    ("suid comm", "suid"),
    ("suid uid=euid", "yes"),
    ("sgid sp aligned 16", "yes"),
    ("sgid argc at sp", "yes"),
    ("sgid argv at sp+8", "yes"),
    ("sgid envp after argv's NULL", "yes"),
    ("sgid auxv after envp's NULL", "yes"),
    ("sgid auxv types", None),
    ("sgid auxv entries", None),
    ("sgid AT_PHDR own", "yes"),
    ("sgid AT_PHENT", "56"),
    ("sgid AT_PHNUM own", "yes"),
    ("sgid AT_PAGESZ", None),
    ("sgid AT_ENTRY own", "yes"),
    ("sgid AT_BASE maps", None),
    ("sgid AT_BASE page aligned", "yes"),
    ("sgid AT_FLAGS", "0"),
    ("sgid AT_UID/EUID/GID/EGID own", "yes"),
    ("sgid AT_SECURE", "0"),
    ("sgid AT_PLATFORM", MACHINE),
    ("sgid AT_HWCAP nonzero", "yes"),
    ("sgid AT_HWCAP2", None),
    ("sgid AT_CLKTCK", None),
    ("sgid AT_MINSIGSTKSZ", None),
    ("sgid AT_RSEQ_FEATURE_SIZE", None),
    ("sgid AT_RSEQ_ALIGN", None),
    ("sgid AT_SYSINFO_EHDR", "an ELF"),
    ("sgid AT_SYSINFO_EHDR maps", "[vdso]"),
    ("sgid AT_EXECFD", "absent"),
    ("sgid AT_EXECFN last component", "sgid"),
    ("sgid AT_RANDOM fresh", "yes"),
    ("sgid vectors on the stack mapping", "yes"),
    ("sgid strings on the stack mapping", "yes"),
    ("sgid strings above the vectors", "yes"),
    ("sgid argv strings contiguous ascending", "yes"),
    ("sgid envp[0] after argv's last", "yes"),
    ("sgid envp strings contiguous ascending", "yes"),
    ("sgid AT_EXECFN after envp's last", "yes"),
    ("sgid AT_EXECFN ends 8 below the stack top", "yes"),
    ("sgid AT_PLATFORM below argv[0]", "yes"),
    ("sgid AT_RANDOM below AT_PLATFORM", "yes"),
    ("sgid AT_PLATFORM just below argv[0]", "no"),
    ("sgid AT_RANDOM just below AT_PLATFORM", "yes"),
    ("sgid stat code holds main", "yes"),
    ("sgid stat startstack is sp", "yes"),
    ("sgid stat arg_start is argv[0]", "yes"),
    ("sgid stat arg_end is envp[0]", "yes"),
    ("sgid stat env_start is envp[0]", "yes"),
    ("sgid stat env_end is AT_EXECFN", "yes"),
    ("sgid cmdline is argv", "yes"),
    ("sgid comm", "sgid"),
    ("sgid uid=euid", "yes"),
    ("fds open fds", "0 1 2 3"),
    ("fds soft limit", None),
    ("soft 3 open fds", "opendir EMFILE"),
    ("soft 3 soft limit", "3"),
    ("soft 4 open fds", "opendir EMFILE"),
    ("soft 4 soft limit", "4"),
    ("soft 8 open fds", "0 1 2 3"),
    ("soft 8 soft limit", "8"),
    ("hard 3 open fds", "opendir EMFILE"),
    ("hard 3 soft limit", "3"),
)
# where the launcher answers otherwise by a stated rule: on the loader path the kernel's image is
# the launcher's, so /proc/self/stat's code, stack and environment fields and the strings' places
# are its (13 item 50); at the border the four fixed variables are the launcher's strings (6.2), so
# the own run's environment is not the kernel's area; an exec under a hard descriptor limit of 3 is
# EMFILE (13 item 12)
EXEC_AUXV_LAUNCHER: dict[str, str] = {
    "own envp[0] after argv's last": "no",
    "own envp strings contiguous ascending": "no",
    "own AT_EXECFN after envp's last": "no",
    "own AT_EXECFN ends 8 below the stack top": "no",
    "own stat code holds main": "no",
    "own stat startstack is sp": "no",
    "own stat arg_end is envp[0]": "no",
    "own stat env_start is envp[0]": "no",
    "own stat env_end is AT_EXECFN": "no",
    "exec AT_EXECFN after envp's last": "no",
    "exec AT_EXECFN ends 8 below the stack top": "no",
    "exec stat code holds main": "no",
    "exec stat startstack is sp": "no",
    "exec stat env_end is AT_EXECFN": "no",
    "suid AT_EXECFN after envp's last": "no",
    "suid AT_EXECFN ends 8 below the stack top": "no",
    "suid stat code holds main": "no",
    "suid stat startstack is sp": "no",
    "suid stat env_end is AT_EXECFN": "no",
    "sgid AT_EXECFN after envp's last": "no",
    "sgid AT_EXECFN ends 8 below the stack top": "no",
    "sgid stat code holds main": "no",
    "sgid stat startstack is sp": "no",
    "sgid stat env_end is AT_EXECFN": "no",
    "hard 3 open fds": "exec EMFILE",
    "hard 3 soft limit": "exec EMFILE",
}
# exec_state HOSTDIR (test/progs/exec_state.c), measured under bwrap on 7.0; what the caller's own
# state decides, the timer slack, the affinity, the umask and the ignored signals of the plain and
# the thread runs, and what the kernel or the host decides, MDWE and the speculation control, is
# any, None
EXEC_STATE: tuple[tuple[str, str | tuple[str, ...] | None], ...] = (
    ("plain SIGUSR1 blocked", "no"),
    ("plain SIGHUP blocked", "no"),
    ("plain SIGSYS blocked", "no"),
    ("plain SIGUSR1 pending", "no"),
    ("plain SIGWINCH pending", "no"),
    ("plain SIGALRM pending", "no"),
    ("plain SIGTTOU pending", "no"),
    ("plain SigBlk", "0000000000000000"),
    ("plain SigPnd", "0000000000000000"),
    ("plain ShdPnd", "0000000000000000"),
    ("plain SigIgn", None),
    ("plain SigCgt", "0000000000000000"),
    ("plain SIGUSR2", "SIG_DFL"),
    ("plain SIGTERM", "SIG_DFL"),
    ("plain SIGCHLD", "SIG_DFL"),
    ("plain SIGSYS", "SIG_DFL"),
    ("plain altstack", "disabled"),
    ("plain ITIMER_REAL", "off"),
    ("plain ITIMER_VIRTUAL", "off"),
    ("plain umask", None),
    ("plain cwd is hostdir", "no"),
    ("plain root", "/"),
    ("plain nice raised by 5", "no parent"),
    ("plain affinity one cpu", None),
    ("plain no_new_privs", "1"),
    ("plain dumpable", "1"),
    ("plain child subreaper", "0"),
    ("plain pdeathsig", "0"),
    ("plain timerslack", None),
    ("plain thp disable", "0"),
    ("plain keepcaps", "0"),
    ("plain mdwe", None),
    ("plain ssb", None),
    ("plain PR_GET_NAME", "exec_state"),
    ("plain Threads", "1"),
    ("plain tid is pid", "yes"),
    ("plain NoNewPrivs", "1"),
    ("after SIGUSR1 blocked", "yes"),
    ("after SIGHUP blocked", "yes"),
    ("after SIGSYS blocked", "yes"),
    ("after SIGUSR1 pending", "yes"),
    ("after SIGWINCH pending", "yes"),
    ("after SIGALRM pending", "no"),
    ("after SIGTTOU pending", "no"),
    ("after SigBlk", "0000000048000201"),
    ("after SigPnd", "0000000000000200"),
    ("after ShdPnd", "0000000008000000"),
    ("after SigIgn", "0000000000010800"),
    ("after SigCgt", "0000000000000000"),
    ("after SIGUSR2", "SIG_IGN"),
    ("after SIGTERM", "SIG_DFL"),
    ("after SIGCHLD", "SIG_IGN"),
    ("after SIGSYS", "SIG_DFL"),
    ("after altstack", "disabled"),
    ("after ITIMER_REAL", "armed"),
    ("after ITIMER_VIRTUAL", "armed"),
    ("after posix timer", "EINVAL"),
    ("after umask", "027"),
    ("after cwd is hostdir", "yes"),
    ("after root", "/"),
    ("after nice raised by 5", "yes"),
    ("after affinity one cpu", "yes"),
    ("after no_new_privs", "1"),
    ("after dumpable", "1"),
    ("after child subreaper", "1"),
    ("after pdeathsig", "1"),
    ("after timerslack", "123456"),
    ("after thp disable", "1"),
    ("after keepcaps", "0"),
    ("after mdwe", None),
    ("after ssb", None),
    ("after PR_GET_NAME", "exec_state"),
    ("after Threads", "1"),
    ("after tid is pid", "yes"),
    ("after NoNewPrivs", "1"),
    ("thread SIGUSR1 blocked", "yes"),
    ("thread SIGHUP blocked", "no"),
    ("thread SIGSYS blocked", "no"),
    ("thread SIGUSR1 pending", "no"),
    ("thread SIGWINCH pending", "yes"),
    ("thread SIGALRM pending", "yes"),
    ("thread SIGTTOU pending", "no"),
    ("thread SigBlk", "0000000008202200"),
    ("thread SigPnd", "0000000000002000"),
    ("thread ShdPnd", "0000000008000000"),
    ("thread SigIgn", None),
    ("thread SigCgt", "0000000000000000"),
    ("thread SIGUSR2", "SIG_DFL"),
    ("thread SIGTERM", "SIG_DFL"),
    ("thread SIGCHLD", "SIG_DFL"),
    ("thread SIGSYS", "SIG_DFL"),
    ("thread altstack", "disabled"),
    ("thread ITIMER_REAL", "off"),
    ("thread ITIMER_VIRTUAL", "off"),
    ("thread umask", None),
    ("thread cwd is hostdir", "no"),
    ("thread root", "/"),
    ("thread nice raised by 5", "no parent"),
    ("thread affinity one cpu", None),
    ("thread no_new_privs", "1"),
    ("thread dumpable", "1"),
    ("thread child subreaper", "0"),
    ("thread pdeathsig", "0"),
    ("thread timerslack", None),
    ("thread thp disable", "0"),
    ("thread keepcaps", "0"),
    ("thread mdwe", None),
    ("thread ssb", None),
    ("thread PR_GET_NAME", "exec_state"),
    ("thread Threads", "1"),
    ("thread tid is pid", "yes"),
    ("thread NoNewPrivs", "1"),
)
# where the launcher answers otherwise by a stated rule: SIGSYS is the launcher's, never blocked
# (7.5.1) and caught by its handler, which a program's sigaction sees (13 item 23)
EXEC_STATE_LAUNCHER: dict[str, str] = {
    "plain SigCgt": "0000000040000000",
    "plain SIGSYS": "handler",
    "after SIGSYS blocked": "no",
    "after SigBlk": "0000000008000201",
    "after SigCgt": "0000000040000000",
    "after SIGSYS": "handler",
    "thread SigCgt": "0000000040000000",
    "thread SIGSYS": "handler",
}


def exec_script_wrong(out: str, *, by_the_kernel: bool = False) -> list[str]:
    """The lines of exec_script's output that differ from the kernel's answers."""
    return lines_wrong(out, EXEC_SCRIPT, EXEC_SCRIPT_LAUNCHER, by_the_kernel=by_the_kernel)


def exec_elf_wrong(out: str, *, by_the_kernel: bool = False) -> list[str]:
    """The lines of exec_elf's output that differ from the kernel's answers."""
    return lines_wrong(out, EXEC_ELF, EXEC_ELF_LAUNCHER, by_the_kernel=by_the_kernel)


# the descriptor cases, which exec a static program the exerciser builds with the tree's compiler
EXEC_AUXV_FDS = ("fds ", "soft ", "hard ")
# what the exerciser prints in their place where the tree has no static libc
EXEC_AUXV_NO_STATIC = ("fds", "cannot build the static program")


def exec_auxv_wrong(
    out: str, *, by_the_kernel: bool = False, static_libc: bool = True
) -> list[str]:
    """The lines of exec_auxv's output that differ from the kernel's answers.

    static_libc: the tree has a static libc; without one the descriptor cases cannot be built and
    the exerciser says so in their place.
    """
    want = EXEC_AUXV
    if not static_libc:
        want = (*(c for c in EXEC_AUXV if not c[0].startswith(EXEC_AUXV_FDS)), EXEC_AUXV_NO_STATIC)
    return lines_wrong(out, want, EXEC_AUXV_LAUNCHER, by_the_kernel=by_the_kernel)


def exec_state_wrong(out: str, *, by_the_kernel: bool = False) -> list[str]:
    """The lines of exec_state's output that differ from the kernel's answers."""
    return lines_wrong(out, EXEC_STATE, EXEC_STATE_LAUNCHER, by_the_kernel=by_the_kernel)


# seccomp_filter HOSTDIR (test/progs/seccomp_filter.c), measured under bwrap on 7.0: a program's own
# filter as the kernel applies it, every install in a child of its own. An older kernel lacks some
# of what the cases use, and those answer as it decides (SECCOMP_FILTER_SINCE).
SECCOMP_FILTER: tuple[tuple[str, str | tuple[str, ...] | None], ...] = (
    ("PR_GET_SECCOMP before", "0"),
    ("errno install openat", "ok"),
    ("errno install newfstatat", "ok"),
    ("errno install readlinkat", "ok"),
    ("errno openat exclave", "EDOM"),
    ("errno openat host", "EDOM"),
    ("errno newfstatat exclave", "ERANGE"),
    ("errno newfstatat host", "ERANGE"),
    ("errno readlinkat exclave", "EXDEV"),
    ("errno readlinkat host", "EXDEV"),
    ("errno faccessat exclave", "ok"),
    ("errno getppid", "ok"),
    ("errno end", "exited 0"),
    ("two errno newer wins exclave", "EACCES"),
    ("two errno newer wins host", "EACCES"),
    ("two errno end", "exited 0"),
    ("errno then allow install", "ok"),
    ("errno then allow exclave", "EPERM"),
    ("errno then allow host", "EPERM"),
    ("errno then allow end", "exited 0"),
    ("allow then errno exclave", "EIO"),
    ("allow then errno end", "exited 0"),
    ("log install", "ok"),
    ("log openat exclave", "ok"),
    ("log openat host", "ok"),
    ("log end", "exited 0"),
    ("allow-list install", "ok"),
    ("allow-list openat exclave", "ok"),
    ("allow-list openat host", "ok"),
    ("allow-list newfstatat exclave", "ok"),
    ("allow-list readlinkat exclave", "EACCES"),
    ("allow-list mkdirat end", "signal SYS"),
    ("allow-list getppid install", "ok"),
    ("allow-list getppid end", "signal SYS"),
    ("tsync install", "ok"),
    ("tsync other thread openat", "EDOM"),
    ("tsync own openat", "EDOM"),
    ("tsync end", "exited 0"),
    ("one thread install", "ok"),
    ("one thread other thread openat", "ok"),
    ("one thread own openat", "EDOM"),
    ("one thread end", "exited 0"),
    ("fork child openat", "EDOM"),
    ("fork end", "exited 0"),
    ("vfork child install", "ok"),
    ("vfork parent openat", "ok"),
    ("vfork end", "exited 0"),
    ("exec mkdirat host", "EMLINK"),
    ("exec mkdirat exclave", "EMLINK"),
    ("exec openat exclave", "ok"),
    ("exec PR_GET_SECCOMP", "2"),
    ("exec end", "exited 0"),
    ("prctl install", "ok"),
    ("prctl openat exclave", "EDOM"),
    ("prctl PR_GET_SECCOMP", "2"),
    ("prctl end", "exited 0"),
    ("strict seccomp", "ok"),
    ("strict seccomp end", "exited 0"),
    ("strict prctl", "ok"),
    ("strict prctl end", "exited 0"),
    ("ret a", "ok"),
    ("ret a end", "exited 0"),
    ("trap action", "ok"),
    ("trap action end", "exited 0"),
    ("trace action", "ok"),
    ("trace action end", "exited 0"),
    ("new listener", "a descriptor"),
    ("new listener end", "exited 0"),
    ("reads the instruction pointer", "ok"),
    ("reads ip end", "exited 0"),
    ("reads the instruction pointer's high word", "ok"),
    ("reads ip high end", "exited 0"),
    ("2100 instructions", "ok"),
    ("2100 end", "exited 0"),
    ("4090 instructions", "ok"),
    ("4090 end", "exited 0"),
    ("4096 instructions", "ok"),
    ("4096 end", "exited 0"),
    ("errno 4094", "ok"),
    ("errno 4094 end", "exited 0"),
    ("errno 65535 install", "ok"),
    ("errno 65535 mkdirat exclave", "errno 4095"),
    ("errno 65535 end", "exited 0"),
    ("errno 0 install", "ok"),
    ("errno 0 mkdirat host", "0"),
    ("errno 0 made the directory", "no"),
    ("errno 0 end", "exited 0"),
    ("unknown flag", "EINVAL"),
    ("tsync probe with no program", "EFAULT"),
    ("strict with a flag", "EINVAL"),
    ("empty program", "EINVAL"),
    ("4097 instructions", "EINVAL"),
    ("a jump past the end", "EINVAL"),
    ("no return at the end", "EINVAL"),
    ("program at NULL", "EINVAL"),
    ("program at an unmapped address", "EFAULT"),
    ("header at an unmapped address", "EFAULT"),
    ("unknown operation", "EINVAL"),
    ("prctl unknown mode", "EINVAL"),
    ("action available", "ok"),
    ("notification sizes", "ok"),
    ("refusals end", "exited 0"),
)
# where the launcher answers otherwise by a stated rule (7.4.2, 13 item 5): its own filter is
# installed before the program runs, and the installs it cannot honour are ENOSYS: strict mode, a
# return of A, the TRAP and TRACE actions, a listener, a read of the instruction pointer, which a
# judged call would see as the judge slot's, a body longer than the room the prologue and the
# epilogue leave, and an ERRNO of MARK_NONE
SECCOMP_FILTER_LAUNCHER: dict[str, str] = {
    "PR_GET_SECCOMP before": "2",
    "strict seccomp": "ENOSYS",
    "strict prctl": "ENOSYS",
    "ret a": "ENOSYS",
    "trap action": "ENOSYS",
    "trace action": "ENOSYS",
    "new listener": "ENOSYS",
    "reads the instruction pointer": "ENOSYS",
    "reads the instruction pointer's high word": "ENOSYS",
    "4090 instructions": "ENOSYS",
    "4096 instructions": "ENOSYS",
    "errno 4094": "ENOSYS",
}


# the cases that need a kernel of at least a version, answered as that kernel decides before it:
# seccomp(2) itself (3.17), whose absence the program meets with the prctl form where it can; the
# LOG action and the availability query (4.14), where an older kernel kills on LOG and the launcher
# refuses it, since the judge would not; a listener and the notification sizes (5.0); the cap of an
# ERRNO action's data at MAX_ERRNO (3.19), before which -65535 reaches the program uncapped and
# its libc reads it as success
SECCOMP_FILTER_SINCE: tuple[tuple[tuple[int, int], tuple[str, ...]], ...] = (
    ((3, 19), ("errno 65535 mkdirat",)),
    ((5, 0), ("new listener", "notification sizes")),
    ((4, 14), ("log ", "action available")),
    (
        (3, 17),
        (
            "tsync ",
            "strict seccomp",
            "unknown flag",
            "tsync probe",
            "strict with a flag",
            "empty program",
            "4097 instructions",
            "a jump past the end",
            "no return at the end",
            "program at",
            "header at",
            "unknown operation",
        ),
    ),
)


def seccomp_filter_wrong(out: str, *, by_the_kernel: bool = False) -> list[str]:
    """The lines of seccomp_filter's output that differ from the kernel's answers."""
    k = kernel()
    want = tuple(
        (
            case,
            None
            if any(k < v and case.startswith(p) for v, ps in SECCOMP_FILTER_SINCE for p in ps)
            else a,
        )
        for case, a in SECCOMP_FILTER
    )
    launcher = {
        c: a
        for c, a in SECCOMP_FILTER_LAUNCHER.items()
        if not any(k < v and c.startswith(p) for v, ps in SECCOMP_FILTER_SINCE for p in ps)
    }
    return lines_wrong(out, want, launcher, by_the_kernel=by_the_kernel)
