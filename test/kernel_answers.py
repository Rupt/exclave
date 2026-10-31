"""The kernel's answers to the path programs of test/progs that print rather than judge.

The suite asserts them of the launcher (test/regress_paths.py) and the namespace oracle asserts
them of the kernel itself, on a read-only bind of the same tree (test/oracle_ns.py), so that an
expectation written by hand is checked against the kernel at every run (DESIGN.md 17 items 1
and 4).
"""

import errno
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


def creat_slash_wrong(out: str) -> list[str]:
    """The lines of creat_slash's output that differ from the kernel's answers."""
    got = out.splitlines()
    return (
        [] if got == list(CREAT_SLASH) else [f"got {got!r}, the kernel says {list(CREAT_SLASH)!r}"]
    )


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
