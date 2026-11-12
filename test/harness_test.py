"""The drivers' harness, held to what it says of a program that outlives a test's budget.

    test/harness_test.py

A program run() starts is killed with its process group when the test's budget runs out
(DESIGN.md 17), and the FAIL line carries the program's last lines, since a tool that waits, on
the network or on a lock, has usually said what for: without them the line names a tool and no
cause. Prints one line per case; the exit status is the number that fail.
"""

import contextlib
import io
import sys
import time

import harness

BUDGET = 0.5  # seconds: the programs below would run for a minute

# (what the program does, the shell that does it, what the FAIL line must hold)
CASES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "says why on standard error, then waits",
        "echo first >&2; echo second >&2; echo third >&2; echo 'waits for a mirror' >&2; sleep 60",
        ("killed at the test's budget", "having written:", "second", "waits for a mirror"),
    ),
    (
        "says it on standard output alone",
        "echo 'still resolving'; sleep 60",
        ("killed at the test's budget", "having written:", "still resolving"),
    ),
    ("says nothing", "sleep 60", ("killed at the test's budget", "having written nothing")),
    (
        "leaves a child with the pipes open",
        "echo 'child holds the pipe' >&2; sleep 60 & wait",
        ("killed at the test's budget", "child holds the pipe"),
    ),
)


def main() -> int:
    fails = 0
    for what, shell, wanted in CASES:

        def test(shell: str = shell) -> None:
            harness.run(["sh", "-c", shell])

        test.__name__ = "outlives"
        printed = io.StringIO()
        t0 = time.monotonic()
        with contextlib.redirect_stdout(printed):
            failed = harness.run_tests([test], lambda t: t(), budget=BUDGET)
        took = time.monotonic() - t0
        line = printed.getvalue()
        missing = [w for w in wanted if w not in line]
        # the first of four lines is the oldest: only the last three are kept
        extra = [w for w in ("first",) if w in line]
        ok = failed == [test] and not missing and not extra and took < BUDGET + 8
        fails += not ok
        print(
            f"{'ok  ' if ok else 'FAIL'} a program that {what}: killed and reported in {took:.1f} s"
        )
        if not ok:
            print(f"     the line lacks {missing}, holds {extra}:\n     {line.strip()}")
    return fails


if __name__ == "__main__":
    sys.exit(main())
