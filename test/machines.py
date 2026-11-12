"""What the tests know of each architecture, in one table (DESIGN.md 7.1).

The names and numbers a test needs of a machine: the ELF machine, seccomp's architecture word,
Debian's and Go's name for it, glibc's loader, and a syscall's number, which is src/sys.h's for a
call the launcher names (test/syscalls.py holds that table to the kernel's) and, for the few it
does not, the number every architecture gives a call added since 5.1.
"""

import dataclasses
import functools
import os
import platform
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@dataclasses.dataclass(frozen=True)
class Machine:
    """One architecture's names and numbers."""

    em: int  # ELF e_machine
    audit: int  # seccomp_data's arch, AUDIT_ARCH_*
    deb: str  # Debian's name for it, which is Go's and Docker's too
    glibc_loader: str  # the loader glibc's programs name


TABLE = {
    "x86_64": Machine(62, 0xC000003E, "amd64", "/lib64/ld-linux-x86-64.so.2"),
    "aarch64": Machine(183, 0xC00000B7, "arm64", "/lib/ld-linux-aarch64.so.1"),
}
NAME = platform.machine()
HERE = TABLE[NAME]
# calls the launcher has no number for, by the number every architecture gives them
UNIFIED = {"close_range": 436, "pidfd_getfd": 438}


@functools.cache
def numbers() -> dict[str, dict[str, int | None]]:
    """The syscall numbers src/sys.h lays out, by architecture: None for a form marked ABSENT."""
    with open(os.path.join(REPO, "src", "sys.h")) as f:
        sysh = f.read()
    x86, a64 = sysh.split("#if defined(__x86_64__)", 1)[1].split("#elif defined(__aarch64__)", 1)
    return {
        arch: {
            n: None if v.startswith("ABSENT") else int(v)
            for n, v in re.findall(r"NR_([a-z0-9_]+) = (ABSENT\(\d+\)|\d+)", block)
        }
        for arch, block in (("x86_64", x86), ("aarch64", a64.split("#else", 1)[0]))
    }


def nr(call: str) -> int | None:
    """This machine's number for a syscall, or None for a form it never had."""
    return UNIFIED[call] if call in UNIFIED else numbers()[NAME][call]
