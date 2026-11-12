"""The gate's choice of steps for a change (DESIGN.md 17), held to changes whose steps are known.

    test/affected_test.py

A change to what a built program is made from reaches the steps whose drivers run that program, a
launcher source reaches every step and the VMs, a document reaches none, and a path nothing names
reaches every step. Prints one line per case; the exit status is the number that fail.
"""

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


def main() -> int:
    fails = 0
    for path, reached, unreached in CASES:
        got = {step for step, _why in affected.chosen([path])}
        wrong = [f"not {s}" for s in sorted(reached - got)] + sorted(unreached & got)
        fails += bool(wrong)
        print(f"{'FAIL' if wrong else 'ok  '} {path}: {', '.join(wrong) or 'the steps expected'}")
    print(f"{len(CASES) - fails} changes reach the steps expected, {fails} do not")
    return fails


if __name__ == "__main__":
    sys.exit(main())
