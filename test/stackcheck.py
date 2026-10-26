"""Check the signal handler's stack budget (DESIGN.md 7.5.4).

The check reads the gcc -fcallgraph-info=su output of the current build.

    test/stackcheck.py build/launcher.debug-*.ci

The handler path is every function the call graph reaches from on_sigsys, each with the frame gcc
wrote beside it, so a function is on the path because it is called there, not because a list names
it. Fails if one of them has a frame above 512 bytes or an unbounded dynamic frame, if the graph has
a cycle other than exec_target's own (a #! chain of host scripts, exec_script inlined into it, six
frames as binfmt_script allows five interpreters), if on_sigsys or exec_target is not in the graph
(a rename must be loud), or if the deepest chain exceeds 3072 bytes. gcc writes no edge for a call
through a pointer, and the launcher makes none.
"""

import re
import sys

LIMIT_FRAME = 512
LIMIT_PATH = 3072  # 7.5.4: under 3 KB with a five-deep chain of host scripts
ROOT, NESTED, NEST_MAX = "on_sigsys", "exec_target", 6


def base(title: str) -> str:
    """Return a node's function name, without a static function's file prefix or clone suffixes."""
    return re.sub(r"(\.(isra|constprop|part|cold)(\.\d+)?)+$", "", title.rsplit(":", 1)[-1])


type Graph = tuple[dict[str, int], dict[str, str], dict[str, set[str]]]


def read_graph(paths: list[str]) -> Graph:
    """Read the .ci files: each node's frame size and kind, and each node's callees."""
    frames: dict[str, int] = {}
    kinds: dict[str, str] = {}
    calls: dict[str, set[str]] = {}
    for f in paths:
        with open(f) as ci:
            lines = list(ci)
        for line in lines:
            m = re.match(r'node: \{ title: "([^"]*)" label: "[^"]*?(\d+) bytes \(([^)]*)\)"', line)
            if m:
                frames[m.group(1)], kinds[m.group(1)] = int(m.group(2)), m.group(3)
                continue
            m = re.match(r'edge: \{ sourcename: "([^"]*)" targetname: "([^"]*)"', line)
            if m:
                calls.setdefault(m.group(1), set()).add(m.group(2))
    return frames, kinds, calls


def main() -> int:
    paths = sys.argv[1:]
    frames, kinds, calls = read_graph(paths)
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
    for f in sorted(set(fails)):
        print("FAIL " + f)
    print("stack budget OK" if not fails else "stack budget FAILED")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
