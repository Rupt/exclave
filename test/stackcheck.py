"""Check the signal handler's stack budget (DESIGN.md 7.5.4).

The check reads the gcc -fcallgraph-info=su output of the current build.

    test/stackcheck.py build/launcher.debug-*.ci

The handler path is every function the call graph reaches from exclave_on_sigsys, each with the
frame gcc wrote beside it, so a function is on the path because it is called there, not because a
list names it. Fails if one of them has a frame above 512 bytes or an unbounded dynamic frame, if
the graph has a cycle other than exec_target's own (a #! chain of host scripts, exec_script inlined
into it, six frames as binfmt_script allows five interpreters), if exclave_on_sigsys or exec_target
is not in the graph (a rename must be loud), or if the deepest chain, with the 48 bytes the entry
stub takes for the trap's record and its call (src/handler.c, 7.5.7), exceeds 3072 bytes. gcc
writes no edge for a call through a pointer, and the launcher makes none.

The trampoline's C (src/tramp.c, 7.5.7) is a second path, from exclave_tramp_present and
exclave_tramp_after: it runs below the presented frame where the reserved register may hold a
program's value, so it fails on any call out of src/tramp.c, a helper gcc emits included, and its
deepest chain is held to 512 bytes.
"""

import re
import sys

LIMIT_FRAME = 512
LIMIT_PATH = 3072  # 7.5.4: under 3 KB with a five-deep chain of host scripts
ROOT, NESTED, NEST_MAX = "exclave_on_sigsys", "exec_target", 6
# the entry stub's record and its call's return address, or its saved x30 (src/handler.c)
ENTRY_STUB = 48
TRAMP_ROOTS, TRAMP_FILE, LIMIT_TRAMP = (
    ("exclave_tramp_present", "exclave_tramp_after"),
    "src/tramp.c",
    512,
)


def base(title: str) -> str:
    """Return a node's function name, without a static function's file prefix or clone suffixes."""
    return re.sub(r"(\.(isra|constprop|part|cold)(\.\d+)?)+$", "", title.rsplit(":", 1)[-1])


type Graph = tuple[dict[str, int], dict[str, str], dict[str, set[str]], dict[str, str]]


def read_graph(paths: list[str]) -> Graph:
    """Read the .ci files: each node's frame size, kind and source file, and each node's callees."""
    frames: dict[str, int] = {}
    kinds: dict[str, str] = {}
    calls: dict[str, set[str]] = {}
    files: dict[str, str] = {}
    for f in paths:
        with open(f) as ci:
            lines = list(ci)
        source = ""
        for line in lines:
            m = re.match(r'graph: \{ title: "([^"]*)"', line)
            if m:
                source = m.group(1)
                continue
            m = re.match(r'node: \{ title: "([^"]*)" label: "[^"]*?(\d+) bytes \(([^)]*)\)"', line)
            if m:
                frames[m.group(1)], kinds[m.group(1)] = int(m.group(2)), m.group(3)
                files[m.group(1)] = source
                continue
            m = re.match(r'edge: \{ sourcename: "([^"]*)" targetname: "([^"]*)"', line)
            if m:
                calls.setdefault(m.group(1), set()).add(m.group(2))
    return frames, kinds, calls, files


def tramp_path(
    frames: dict[str, int], calls: dict[str, set[str]], files: dict[str, str]
) -> list[str]:
    """The trampoline's C: its deepest chain, and a failure for any call out of src/tramp.c."""
    fails: list[str] = []

    def walk(t: str, seen: tuple[str, ...]) -> int:
        best = 0
        for c in sorted(calls.get(t, ())):
            if c in seen:
                fails.append(f"recursion through {base(c)} in the trampoline")
                continue
            if files.get(c) != TRAMP_FILE:
                fails.append(f"the trampoline calls {base(c)}, outside {TRAMP_FILE}")
                continue
            best = max(best, walk(c, (*seen, c)))
        return frames.get(t, 0) + best

    for name in TRAMP_ROOTS:
        found = [t for t in frames if base(t) == name and files.get(t) == TRAMP_FILE]
        if len(found) != 1:
            fails.append(f"{name} is not in the call graph (renamed?)")
            continue
        root = found[0]
        depth = walk(root, (root,))
        print(f"trampoline path from {name}: {depth:d} bytes")
        if depth > LIMIT_TRAMP:
            fails.append(f"trampoline path from {name} {depth:d} > {LIMIT_TRAMP:d}")
    return fails


def main() -> int:
    paths = sys.argv[1:]
    frames, kinds, calls, files = read_graph(paths)
    roots = [t for t in frames if base(t) == ROOT]
    if len(roots) != 1 or not any(base(t) == NESTED for t in frames):
        sys.exit(
            "FAIL {} or {} is not in the call graph of {} (renamed, or no .ci files)".format(
                ROOT, NESTED, " ".join(paths) or "nothing"
            )
        )
    fails: list[str] = []
    memo: dict[tuple[str, int], tuple[int, list[str]]] = {}
    stack: list[str] = []
    reached: set[str] = set()

    def deepest(t: str, nested: int) -> tuple[int, list[str]]:
        """Return (bytes, chain) of the deepest chain from t.

        nested is the number of exec_target frames already on the stack.
        """
        key = (t, nested)
        if key in memo:
            return memo[key]
        reached.add(t)
        here = frames.get(t, 0)
        if base(t) == NESTED:
            nested += 1
        best: tuple[int, list[str]] = (0, [])
        stack.append(t)
        for c in sorted(calls.get(t, ())):
            if c in stack and not (base(c) == NESTED and nested < NEST_MAX):
                if base(c) != NESTED:
                    fails.append(
                        "recursion through {}: the stack it takes is unbounded".format(
                            " -> ".join(base(s) for s in [*stack[stack.index(c) :], c])
                        )
                    )
                continue
            if c not in frames:
                continue  # a name no .ci file defines: an assembly routine, which takes no frame
            d = deepest(c, nested)
            if d[0] > best[0]:
                best = d
        stack.pop()
        memo[key] = (here + best[0], [f"{base(t)}={here:d}"] + best[1])
        return memo[key]

    worst, chain = deepest(roots[0], 0)
    worst += ENTRY_STUB
    chain = [f"entry stub={ENTRY_STUB:d}", *chain]
    for t in sorted(reached):
        if frames[t] > LIMIT_FRAME:
            fails.append(f"{base(t)}: frame {frames[t]:d} over {LIMIT_FRAME:d}")
        if kinds[t] not in ("static", "dynamic,bounded"):
            fails.append(f"{base(t)}: unbounded dynamic frame ({kinds[t]})")
    nfuncs = len({base(t) for t in reached})
    print(
        f"handler path worst case: {worst:d} bytes over {nfuncs:d} functions reached from {ROOT}: "
        + " > ".join(chain)
    )
    if worst > LIMIT_PATH:
        fails.append(f"handler path {worst:d} > {LIMIT_PATH:d}")
    fails += tramp_path(frames, calls, files)
    for f in sorted(set(fails)):
        print("FAIL " + f)
    print("stack budget OK" if not fails else "stack budget FAILED")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
