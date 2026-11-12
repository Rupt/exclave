"""What the running kernel is and has, asked of the kernel itself (DESIGN.md 17).

The handler answers as the newest kernel does, so a table of answers holds the newest kernel's
(test/kernel_answers.py), and a test accepts an older kernel's own answer for a reason this module
gives. `has` asks the kernel, outside any exclave, whether it has a call or a feature: a
distribution's kernel carries backports its version does not show, and an answer taken from the
program under test would excuse a launcher that refused the call wrongly. `version` is for a change
of behaviour that no call can be asked about.
"""

import errno
import functools
import os
import platform
lazy import ctypes
lazy from collections.abc import Callable

import syscalls

MACHINE = platform.machine()
# calls the launcher has no number for (src/sys.h), by the number every architecture gives them
NUMBERS = {"close_range": 436, "pidfd_getfd": 438}
CLOSE_RANGE_CLOEXEC = 4
PR_GET_AUXV = 0x41555856
O_PATH = 0o10000000


def version() -> tuple[int, int]:
    """The running kernel's major and minor version."""
    major, minor = os.uname().release.split(".")[:2]
    return int(major), int(minor.split("-")[0])


def call(nr: int, *args: int) -> int:
    """A raw syscall's errno, 0 when it succeeds: for a probe whose arguments reach nothing."""
    libc = ctypes.CDLL(None, use_errno=True)
    return ctypes.get_errno() if libc.syscall(nr, *(ctypes.c_long(a) for a in args)) < 0 else 0


def _openat2() -> bool:
    """openat2 (5.6), by a call that opens: a filter above this process may refuse it otherwise."""
    libc = ctypes.CDLL(None, use_errno=True)
    how = (ctypes.c_uint64 * 3)(O_PATH, 0, 0)
    fd = libc.syscall(437, -100, b"/", ctypes.byref(how), ctypes.c_size_t(24))
    if fd >= 0:
        os.close(fd)
    return fd >= 0


def _get_auxv() -> bool:
    """prctl(PR_GET_AUXV) (6.4), which answers the vector's length."""
    libc = ctypes.CDLL(None, use_errno=True)
    buf = ctypes.create_string_buffer(16)
    return libc.prctl(PR_GET_AUXV, buf, ctypes.c_ulong(16), 0, 0) >= 0


# What is not a syscall's mere presence. The range of close_range's probe is one descriptor no
# table holds, so nothing closes and nothing is marked.
FEATURES: dict[str, Callable[[], bool]] = {
    "openat2": _openat2,
    "close_range cloexec": lambda: (
        call(NUMBERS["close_range"], 0x7FFFFFFF, 0x7FFFFFFF, CLOSE_RANGE_CLOEXEC) == 0
    ),
    "/proc/thread-self": lambda: os.path.lexists("/proc/thread-self"),
    "PR_GET_AUXV": _get_auxv,
}


@functools.cache
def has(what: str) -> bool:
    """Whether the kernel has what: one of FEATURES, or else a syscall by its name.

    A syscall is there when the kernel answers it anything but ENOSYS, asked with a descriptor of
    -1 and null pointers, which every call this is asked of refuses before it does anything. A
    form this architecture never had (src/sys.h's ABSENT) is not there.
    """
    if what in FEATURES:
        return FEATURES[what]()
    nr = NUMBERS[what] if what in NUMBERS else syscalls.launcher_numbers()[MACHINE][what]
    return nr is not None and call(nr, -1, 0, 0, 0, 0, 0) != errno.ENOSYS
