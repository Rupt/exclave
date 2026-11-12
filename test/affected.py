"""The gate's steps a change can affect, derived from what each step runs (DESIGN.md 17).

    test/affected.py [--explain] PATH...

Prints one step name per line: those of STEPS a changed path reaches, `every` and every step
when a path reaches everything, and `matrix` when the change reaches the VMs; given no path, every
step, since a change that names nothing is not known to be small. A step reaches a
path when the path is one the step runs or builds from, or one its Python drivers import or name:
a sibling module in test/ is followed, and a path under the repository
named through `os.path.join(REPO, ...)` is what the driver runs there (`build/exclave` is the
command, so `tool/` and `unpack/`; `build/exclave-fetch` the fetchers, so `fetch/`; `build/launcher`
the launcher, so `src/`). Nothing
here is kept by hand but
the list of what each step runs, which is the gate's own definition of its steps. --explain names
the reason for each step.
"""

import argparse
import ast
import fnmatch
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# What each step runs, as the gate's functions build and call it; src/ is listed where it is
# compiled in, though it runs every step anyway.
STEPS: dict[str, tuple[str, ...]] = {
    "unit": (
        "test/*_test.c",
        "test/sanitize.c",
        "test/grammar_test.py",
        "test/readers_test.py",
        "test/syscalls.py",
        "test/tables_test.py",
        "test/affected_test.py",
        "src/*",
    ),
    "stack": ("test/stackcheck.py", "src/*"),
    "go": ("tool/*", "fetch/*", "unpack/*"),
    "unpack": ("test/unpack_test.py",),
    "fetch": ("test/fetch_test.py",),
    "suite": ("test/run.py",),
    "oracles": (
        "test/oracle_resolve.py",
        "test/oracle_ns.py",
        "test/oracle_syscalls.py",
        "test/docker_profile.py",
    ),
    "nss": ("test/nss_test.py",),
    "caches": ("test/caches_test.py",),
    "gdb": ("test/run.py",),
    # this build against the baseline release (6.7): the launcher, the command and the identity
    # table it reads from tool/layout.go
    "compat": ("test/compat_test.py", "src/*", "tool/*", "unpack/*"),
}
# What everything runs on: the launcher and its build, the licence it carries, the Python every
# driver runs on, the Go the commands are built by, the gate and this derivation.
EVERY = (
    "src/*",
    "VERSION",
    "scripts/build",
    "scripts/lib.sh",
    "scripts/install-go",
    "go.mod",
    "go.sum",
    "LICENSE",
    ".python-version",
    "scripts/gate",
    "scripts/steps.sh",
    "test/affected.py",
)
# What the VMs run: the launcher, the command with its unpack (the suite's ld.so.cache regression
# runs it there), the Python, the licence the launcher carries, and the matrix's own code.
MATRIX = (
    "src/*",
    "tool/*",
    "unpack/*",
    "go.mod",
    "go.sum",
    "scripts/install-go",
    "scripts/build",
    "scripts/lib.sh",
    "scripts/reproduce",
    "LICENSE",
    ".python-version",
    "test/matrix.py",
    "test/vm_run.py",
)
# scripts/check's alone when no step reaches them: documents, settings, other scripts and drivers.
CHECK_ONLY = (
    "*.md",
    "docs/*",
    "scripts/*",
    "test/*.py",
    "pyproject.toml",
    "uv.lock",
    "taplo.toml",
    ".gitignore",
    ".github/*",
)
# A path under build/ a driver names stands for the sources it is built from; the longest name it
# starts with is the program's, so that build/exclave-fetch is not taken for build/exclave.
BUILT = {
    "build/exclave": ("tool/*", "unpack/*"),
    "build/exclave-fetch": ("fetch/*",),
    "build/launcher": ("src/*",),
}


ROOTS = {
    "REPO": (),
    "HERE": ("test",),
}  # the names the drivers give the repository and their own directory


def joined_paths(tree: ast.AST) -> set[str]:
    """The repository paths a module names as os.path.join(REPO, "a", "b", ...), as "a/b".

    The constant prefix of the parts is the path: join(HERE, "progs", f) names test/progs.
    """
    out: set[str] = set()
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
        ):
            continue
        if not (node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in ROOTS):
            continue
        parts = list(ROOTS[node.args[0].id])
        for arg in node.args[1:]:
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                break
            parts.append(arg.value)
        if parts:
            out.add("/".join(parts))
    return out


def dependencies(path: str, seen: dict[str, set[str]]) -> set[str]:
    """The patterns a driver depends on: itself, its sibling imports, and the paths it names."""
    if path in seen:
        return seen[path]
    deps: set[str] = {path}
    seen[path] = deps
    with open(os.path.join(REPO, path), "rb") as f:
        tree = ast.parse(f.read(), path)
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        for name in names:
            top = name.split(".")[0]
            if os.path.isfile(os.path.join(REPO, "test", top + ".py")):
                deps |= dependencies("test/" + top + ".py", seen)
    for named in joined_paths(tree):
        built = max((b for b in BUILT if named.startswith(b)), key=len, default=None)
        if built is not None:
            deps.update(BUILT[built])
        else:
            deps.add(named + "/*" if os.path.isdir(os.path.join(REPO, named)) else named)
    return deps


def reach() -> dict[str, set[str]]:
    """Each step's patterns, its Python drivers expanded."""
    seen: dict[str, set[str]] = {}
    out: dict[str, set[str]] = {}
    for step, runs in STEPS.items():
        deps: set[str] = set()
        for pattern in runs:
            deps.add(pattern)
            if pattern.endswith(".py") and "*" not in pattern:
                deps |= dependencies(pattern, seen)
        out[step] = deps
    return out


def matches(path: str, patterns: set[str] | tuple[str, ...]) -> str | None:
    """The first pattern path matches, or None."""
    return next((p for p in sorted(patterns) if path == p or fnmatch.fnmatchcase(path, p)), None)


def chosen(paths: list[str]) -> list[tuple[str, str]]:
    """The steps a change to paths reaches, in STEPS' order, each with its reason."""
    steps = reach()
    why: dict[str, str] = {}
    every = not paths
    if every:
        why["every"] = "no path given"
    for path in paths:
        if (p := matches(path, EVERY)) is not None:
            every = True
            why.setdefault("every", f"{path} is {p}")
        for step, deps in steps.items():
            if (p := matches(path, deps)) is not None:
                why.setdefault(step, f"{path} is {p}")
        if (p := matches(path, MATRIX)) is not None:
            why.setdefault("matrix", f"{path} is {p}")
        if (
            not every
            and not any(matches(path, deps) for deps in steps.values())
            and matches(path, CHECK_ONLY) is None
        ):
            every = True
            why.setdefault("every", f"nothing names {path}")
    names = [*STEPS, "every"] if every else [s for s in STEPS if s in why]
    if "matrix" in why:
        names.append("matrix")
    return [(step, why.get(step, why.get("every", ""))) for step in names]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--explain", action="store_true", help="print why each step runs")
    ap.add_argument("paths", nargs="*", help="the changed paths, relative to the repository")
    args = ap.parse_args()
    for step, reason in chosen(args.paths):
        print(f"{step}: {reason}" if args.explain else step)
    return 0


if __name__ == "__main__":
    sys.exit(main())
