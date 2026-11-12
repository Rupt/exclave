"""The tables the launcher, the command, unpack and the tests each carry agree (DESIGN.md 17).

    test/tables_test.py

The host identity files (8.4) are listed in src/vis.c, tool/layout.go and test/tree.py; the
volatile directories (8.1) in src/vis.c, tool/format/format.go, the one copy the command and
unpack share, and test/tree.py, the one the tests share; the identity directories (8.1 rule 5) in
src/vis.c, tool/paths.go and test/tree.py; and the syscalls
src/filter.c traps are exactly the ones `dispatch` in src/handler.c has a case for, since a trapped
call without one is answered ENOSYS (7.4.3), and the ones `sysname` there names for the log, but
for the three it leaves to its default. Each is read from its source here, so a table changed in
one place fails the gate's unit step. Prints one line per table; the exit status is the number
that differ.
"""

import os
import re
import sys

import tree

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(path: str) -> str:
    with open(os.path.join(REPO, path), encoding="utf-8") as f:
        return f.read()


def c_block(path: str, name: str) -> str:
    """The initialiser of the C array `name` in the file, between its braces."""
    m = re.search(re.escape(name) + r"\[[^=]*= \{(.*?)\};", read(path), re.DOTALL)
    if m is None:
        msg = f"{path} has no array {name}"
        raise ValueError(msg)
    return m.group(1)


def c_strings(path: str, name: str) -> tuple[str, ...]:
    return tuple(re.findall(r'"([^"]*)"', c_block(path, name)))


def go_strings(path: str, name: str) -> tuple[str, ...]:
    """The strings of the Go slice `name` in the file, between its braces."""
    m = re.search(r"var " + re.escape(name) + r" = \[\]string\{(.*?)\}", read(path), re.DOTALL)
    if m is None:
        msg = f"{path} has no slice {name}"
        raise ValueError(msg)
    return tuple(re.findall(r'"([^"]*)"', m.group(1)))


def c_syscalls(path: str, name: str) -> set[str]:
    return set(re.findall(r"NR_(\w+)", c_block(path, name)))


def handler_cases(function: str) -> set[str]:
    """The syscalls a switch on the number in src/handler.c has cases for, up to its default."""
    src = read("src/handler.c")
    body = src[src.index(function) :]
    body = body[: body.index("default: return")]
    return set(re.findall(r"case NR_(\w+):", body))


def main() -> int:
    fails = tables = 0

    def same(what: str, values: dict[str, object]) -> None:
        nonlocal fails, tables
        tables += 1
        distinct = {repr(v) for v in values.values()}
        if len(distinct) == 1:
            print(f"ok   {what}: {len(values)} tables agree")
            return
        fails += 1
        print(f"FAIL {what}:")
        for where, v in values.items():
            print(f"     {where}: {v}")

    same(
        "identity files",
        {
            "src/vis.c": c_strings("src/vis.c", "identity_files"),
            "tool/layout.go": go_strings("tool/layout.go", "identityFiles"),
            "test/tree.py": tree.IDENTITY_FILES,
        },
    )
    same(
        "volatile directories",
        {
            "src/vis.c": c_strings("src/vis.c", "volatile_dirs"),
            "tool/format/format.go": go_strings("tool/format/format.go", "VolatileDirs"),
            "test/tree.py": tree.VOLATILE,
        },
    )
    same(
        "identity directories",
        {
            "src/vis.c": c_strings("src/vis.c", "identity_dirs"),
            "tool/paths.go": go_strings("tool/paths.go", "identityDirs"),
            "test/tree.py": tree.IDENTITY_DIRS,
        },
    )
    # singled out by their arguments (7.4.2, 7.4.3): chattr's requests, an install of a filter
    trapped: set[str] = {"ioctl", "seccomp", "prctl"}
    for array in ("path_syscalls", "fd_syscalls", "mask_syscalls", "arg_traps", "zero_traps"):
        trapped |= c_syscalls("src/filter.c", array)
    same(
        "syscalls handled",
        {
            "src/filter.c traps": sorted(trapped),
            "src/handler.c dispatch": sorted(handler_cases("static long dispatch(")),
        },
    )
    unnamed = {"ptrace", "seccomp", "prctl"}  # no path to name: the log's `trap`, sysname's default
    same(
        "syscall names",
        {
            "src/filter.c traps": sorted(trapped - unnamed),
            "src/handler.c sysname": sorted(handler_cases("static const char *sysname(int nr)")),
        },
    )
    print(f"{tables - fails} tables agree, {fails} differ")
    return fails


if __name__ == "__main__":
    sys.exit(main())
