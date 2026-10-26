"""Stack budget check (DESIGN.md 7.5.4): reads the gcc -fcallgraph-info=su output of the current build.

    test/stackcheck.py build/launcher.debug-*.ci

The handler path is every function the call graph reaches from on_sigsys, each with the frame gcc wrote beside
it, so a function is on the path because it is called there, not because a list names it. Fails if one of them
has a frame above 512 bytes or an unbounded dynamic frame, if the graph has a cycle other than exec_target's
own (a #! chain of host scripts, exec_script inlined into it, six frames as binfmt_script allows five
interpreters), if on_sigsys or exec_target is not in the graph (a rename must be loud), or if the
deepest chain exceeds 3072 bytes. gcc writes no edge for a call through a pointer, and the launcher makes none.
"""
import re
import sys

LIMIT_FRAME = 512
LIMIT_PATH = 3072                # 7.5.4: under 3 KB with a five-deep chain of host scripts
ROOT, NESTED, NEST_MAX = "on_sigsys", "exec_target", 6


def base(title):
    """A node's function name: the file prefix of a static function and gcc's clone suffixes dropped."""
    return re.sub(r"(\.(isra|constprop|part|cold)(\.\d+)?)+$", "", title.rsplit(":", 1)[-1])


frames, kinds, calls = {}, {}, {}
for f in sys.argv[1:]:
    for line in open(f):
        m = re.match(r'node: \{ title: "([^"]*)" label: "[^"]*?(\d+) bytes \(([^)]*)\)"', line)
        if m:
            frames[m.group(1)], kinds[m.group(1)] = int(m.group(2)), m.group(3)
            continue
        m = re.match(r'edge: \{ sourcename: "([^"]*)" targetname: "([^"]*)"', line)
        if m:
            calls.setdefault(m.group(1), set()).add(m.group(2))
roots = [t for t in frames if base(t) == ROOT]
fails = []
if len(roots) != 1 or not any(base(t) == NESTED for t in frames):
    sys.exit("FAIL %s or %s is not in the call graph of %s (renamed, or no .ci files)" % (ROOT, NESTED, " ".join(sys.argv[1:]) or "nothing"))

memo, stack, reached = {}, [], set()


def deepest(t, nested):
    """(bytes, chain) of the deepest chain from t, with nested frames of exec_target already on the stack."""
    key = (t, nested)
    if key in memo:
        return memo[key]
    reached.add(t)
    here = frames.get(t, 0)
    if base(t) == NESTED:
        nested += 1
    best = (0, [])
    stack.append(t)
    for c in sorted(calls.get(t, ())):
        if c in stack and not (base(c) == NESTED and nested < NEST_MAX):
            if base(c) != NESTED:
                fails.append("recursion through %s: the stack it takes is unbounded" % " -> ".join(base(s) for s in stack[stack.index(c):] + [c]))
            continue
        if c not in frames:
            continue                          # a name no .ci file defines: an assembly routine, which takes no frame
        d = deepest(c, nested)
        if d[0] > best[0]:
            best = d
    stack.pop()
    memo[key] = (here + best[0], ["%s=%d" % (base(t), here)] + best[1])
    return memo[key]


worst, chain = deepest(roots[0], 0)
for t in sorted(reached):
    if frames[t] > LIMIT_FRAME:
        fails.append("%s: frame %d over %d" % (base(t), frames[t], LIMIT_FRAME))
    if kinds[t] not in ("static", "dynamic,bounded"):
        fails.append("%s: unbounded dynamic frame (%s)" % (base(t), kinds[t]))
print("handler path worst case: %d bytes over %d functions reached from %s: %s" % (worst, len({base(t) for t in reached}), ROOT, " > ".join(chain)))
if worst > LIMIT_PATH:
    fails.append("handler path %d > %d" % (worst, LIMIT_PATH))
for f in sorted(set(fails)):
    print("FAIL " + f)
print("stack budget OK" if not fails else "stack budget FAILED")
sys.exit(1 if fails else 0)
