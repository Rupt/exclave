"""The tables the launcher, the command, unpack and the tests each carry agree (DESIGN.md 17).

    test/tables_test.py

The host identity files (8.4) are listed in src/vis.c, tool/layout.go and test/tree.py; the
volatile directories (8.1) in src/vis.c, tool/paths.go, unpack/steps.go, test/suite.py and
test/unpack_test.py; and the name the
launcher logs for a trapped syscall (`sysname` in src/handler.c) must cover exactly the syscalls
src/filter.c traps. Each is read from its source here, so a table changed in one place fails the
gate's unit step. Prints one line per table; the exit status is the number that differ.
"""

import ast
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


def py_tuple(path: str, name: str) -> tuple[str, ...]:
    """The tuple assigned to `name` at the top level of the Python file, without importing it."""
    for node in ast.parse(read(path), path).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            return tuple(ast.literal_eval(node.value))
    msg = f"{path} has no {name}"
    raise ValueError(msg)


def sysname_cases() -> set[str]:
    """The syscalls `sysname` in src/handler.c names, by its case labels."""
    src = read("src/handler.c")
    body = src[src.index("static const char *sysname(int nr)") :]
    body = body[: body.index("default: return")]
    return set(re.findall(r"case NR_(\w+):", body))


def main() -> int:
    fails = 0

    def same(what: str, values: dict[str, object]) -> None:
        nonlocal fails
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
            "tool/paths.go": go_strings("tool/paths.go", "volatileDirs"),
            "unpack/steps.go": go_strings("unpack/steps.go", "volatile"),
            "test/suite.py": py_tuple("test/suite.py", "VOLATILE"),
            "test/unpack_test.py": py_tuple("test/unpack_test.py", "VOLATILE"),
        },
    )
    trapped: set[str] = {"ioctl"}  # singled out for chattr (7.4.3)
    for array in ("path_syscalls", "fd_syscalls", "mask_syscalls", "arg_traps"):
        trapped |= c_syscalls("src/filter.c", array)
    same(
        "syscall names",
        {"src/filter.c traps": sorted(trapped), "src/handler.c sysname": sorted(sysname_cases())},
    )
    print(f"{3 - fails} tables agree, {fails} differ")
    return fails


if __name__ == "__main__":
    sys.exit(main())
