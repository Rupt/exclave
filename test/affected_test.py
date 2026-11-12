"""The gate's choice of steps for a change (DESIGN.md 17), held to changes whose steps are known.

    test/affected_test.py

A change to what a built program is made from reaches the steps whose drivers run that program, a
launcher source reaches every step and the VMs, a document reaches none, and a path nothing names
reaches every step. The steps scripts/gate runs are the ones test/affected.py lists, which is
where the gate takes their names from. Prints one line per case; the exit status is the number
that fail.
"""

import os
import re
import sys

import affected

# (the changed path, steps it must reach, steps it must not)
CASES: tuple[tuple[str, frozenset[str], frozenset[str]], ...] = (
    ("fetch/debs.go", frozenset({"go", "fetch"}), frozenset({"every"})),
    ("unpack/rules.go", frozenset({"go", "unpack", "suite"}), frozenset({"every"})),
    ("tool/check.go", frozenset({"go", "suite", "compat"}), frozenset({"every"})),
    ("test/progs/probe.c", frozenset({"oracles"}), frozenset({"every"})),
    ("src/handler.c", frozenset({*affected.STEPS, "every", "matrix"}), frozenset()),
    ("docs/DESIGN.md", frozenset(), frozenset({*affected.STEPS, "every", "matrix"})),
    ("a-path-nothing-names", frozenset({*affected.STEPS, "every"}), frozenset()),
)


def gate_steps() -> set[str]:
    """The steps scripts/gate runs when a change reaches them, by its `has NAME` tests."""
    with open(os.path.join(affected.REPO, "scripts", "gate"), encoding="utf-8") as f:
        return set(re.findall(r"\bhas (\w+)(?: &&|; then)", f.read())) - {"every", "matrix"}


def main() -> int:
    fails = 0
    if (ran := gate_steps()) != set(affected.STEPS):
        fails += 1
        listed = sorted(affected.STEPS)
        print(f"FAIL scripts/gate runs {sorted(ran)}, test/affected.py lists {listed}")
    for path, reached, unreached in CASES:
        got = {step for step, _why in affected.chosen([path])}
        wrong = [f"not {s}" for s in sorted(reached - got)] + sorted(unreached & got)
        fails += bool(wrong)
        print(f"{'FAIL' if wrong else 'ok  '} {path}: {', '.join(wrong) or 'the steps expected'}")
    print(f"{len(CASES) + 1 - fails} of the gate's choices are as expected, {fails} are not")
    return fails


if __name__ == "__main__":
    sys.exit(main())
