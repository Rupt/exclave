"""Run the regression suite: the part of DESIGN.md 17.4 that a single machine can run.

    scripts/test [--tree DIR | --exclave EXCLAVE] [--work DIR] [--keep] [-k NAME|SUBSTRING]
                 [--order given|reverse|random] [--seed N] [--budget SECONDS]

The suite makes an exclave under WORK (default build/test-work) from TREE (default
$EXCLAVE_TEST_TREE) or from the unwrapped tree of an existing EXCLAVE, adds a few test files to its
tree, compiles test/progs/*.c with the tree's own C compiler (test/tree.py), and runs every named
test. Given --exclave, it runs on the pruned fixture kept under build/fixtures/ when there is one
(17).

It runs on the pinned Python (scripts/test) and needs a tree with a C compiler (see README.md).
strace is optional, for the isolation test, and so is /usr/bin/gcc-13, for the identical-object
test. The exit status is the number of failures, at most 255.

The tests are in eight files, one per group of DESIGN.md 17 item 4, test/regress_*.py; the
fixtures are made in test/suite.py, and test/harness.py runs them.

Tests are independent. Every test makes what it needs: the fixtures made at setup are the exclave,
the compiled programs and the environment, never another test's output. Any subset therefore runs
in any order, and `--order reverse` and `--order random` check that.
"""

import argparse
import contextlib
import os
import shutil
import sys
import time
from typing import TYPE_CHECKING, Any
lazy import random

import regress_check
import regress_exec
import regress_launcher
import regress_ownership
import regress_paths
import regress_programs
import regress_threads
import regress_tool
from harness import TESTS, read_text, run_tests, select
from suite import REPO, STAMP, fixture_keys, left_alone, make_fixture, prepare

if TYPE_CHECKING:
    from harness import Test
    from suite import Ctx

# the groups of DESIGN.md 17 item 4; importing one registers its tests, in this order
GROUPS = (
    regress_threads,
    regress_exec,
    regress_launcher,
    regress_paths,
    regress_programs,
    regress_ownership,
    regress_tool,
    regress_check,
)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--tree", default=os.environ.get("EXCLAVE_TEST_TREE"))
    ap.add_argument("--exclave", help="use this exclave's tree, unwrapped")
    ap.add_argument("--work", default=os.path.join(REPO, "build", "test-work"))
    ap.add_argument(
        "--launcher",
        default=os.path.join(REPO, "build", "launcher"),
        help="the launcher under test (default build/launcher; launcher-debug has UBSan's checks)",
    )
    ap.add_argument("--keep", action="store_true")
    ap.add_argument(
        "-k",
        default="",
        help="run the test of this name, or else every test whose name contains it",
    )
    ap.add_argument(
        "--order",
        default="given",
        choices=["given", "reverse", "random"],
        help="run order; reverse and random expose tests that depend on one another",
    )
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument(
        "--budget",
        type=float,
        default=30,
        help="seconds a test may take before it fails (default 30)",
    )
    args = ap.parse_args()
    if args.exclave:
        args.tree = os.path.join(args.exclave, "tree")
    if not args.tree or not os.path.isdir(args.tree):
        sys.exit(
            "need --tree DIR (or $EXCLAVE_TEST_TREE) or --exclave EXCLAVE: a gcc tree to wrap; "
            "see README.md"
        )
    # The pruned fixture (17) is the given exclave pruned to what the suite touches. The first run
    # on an exclave makes it, and every later run uses it until the exclave changes.
    fixture, sources, stale, logging = None, "", False, False
    keys = fixture_keys(args.exclave) if args.exclave else None
    tree_ = os.path.abspath(args.tree)
    if keys:
        name = os.path.basename(os.path.abspath(args.exclave)).replace(".exclave", "")
        fixture, sources = os.path.join(REPO, "build", "fixtures", f"{name}-{keys[0]}"), keys[1]
    if fixture and os.path.isdir(os.path.join(fixture, "tree")):
        tree_ = os.path.join(fixture, "tree")
        try:
            stale = read_text(os.path.join(fixture, STAMP)).strip() != sources
        except OSError:
            stale = True
        print(
            f"fixture: {fixture}"
            + (" (made with other sources: a failure is rechecked)" if stale else "")
        )
    elif fixture:
        logging = True
        print("fixture: none yet for this exclave; this run makes it")
    ctx = prepare(args, tree_, os.path.abspath(args.work), logging=logging)
    order = select(TESTS, args.k)
    if args.order == "reverse":
        order.reverse()
    elif args.order == "random":
        seed = args.seed if args.seed is not None else int(time.time()) % 100000
        random.Random(seed).shuffle(order)
        print(f"random order, seed {seed}")
    failed = suite_run(ctx, order, args.budget)
    if stale and failed and fixture:
        # A fixture made with other sources may lack a file these sources touch. The failures run
        # again on the whole exclave, whose answer stands, and the fixture is removed for the next
        # run to make afresh.
        print(f"rechecking {len(failed)} on the whole exclave, the fixture predating these sources")
        whole = prepare(
            args, os.path.abspath(args.tree), os.path.abspath(args.work) + "-whole", logging=False
        )
        failed = suite_run(whole, failed, args.budget)
        shutil.rmtree(fixture, ignore_errors=True)
        if not args.keep and not failed:
            shutil.rmtree(whole.work, ignore_errors=True)
    elif stale and not args.k and fixture and os.path.isdir(os.path.join(fixture, "tree")):
        # still enough for these sources, unless another run has found otherwise and removed it
        with contextlib.suppress(FileNotFoundError), open(os.path.join(fixture, STAMP), "w") as f:
            f.write(sources + "\n")
    print(f"{len(order)} tests, {len(failed)} failures")
    if logging and fixture and not failed and not args.k:
        make_fixture(ctx, fixture, sources)
    if not args.keep and not failed:
        shutil.rmtree(ctx.work, ignore_errors=True)
    return min(len(failed), 255)


def suite_run(ctx: Ctx, order: list[Test[Any]], budget: float) -> list[Test[Any]]:
    """Run the tests on the fixtures, each checked for leaving the shared exclave alone (17)."""
    return run_tests(order, lambda t: t(ctx), budget=budget, after=lambda _t: left_alone(ctx))


if __name__ == "__main__":
    sys.exit(main())
