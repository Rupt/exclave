"""Run the regression suite: the part of DESIGN.md 17.4 that a single machine can run.

    scripts/test [--tree DIR | --exclave EXCLAVE] [--work DIR] [--keep] [-k NAME|SUBSTRING]
                 [--launcher FILE] [--budget SECONDS]

The suite makes an exclave under WORK (default build/test-work) from TREE (default
$EXCLAVE_TEST_TREE) or from the unwrapped tree of an existing EXCLAVE, adds a few test files to its
tree, compiles test/progs/*.c with the tree's own C compiler (test/tree.py), and runs every named
test. Given --exclave, it refuses an exclave whose tree is not the one its hashes file records, and
runs on the pruned fixture kept under build/fixtures/ when there is one (17).

It runs on the pinned Python (scripts/test) and needs a tree with a C compiler (see README.md).
strace is optional, for the isolation test, and so is /usr/bin/gcc-13, for the identical-object
test. The exit status is the number of failures, at most 255.

The tests are in eight files, one per group of DESIGN.md 17 item 4, test/regress_*.py; the
fixtures are made in test/suite.py, and test/harness.py runs them.

What a file of test/ is shows in its name. regress_*.py is a group of this suite. oracle_*.py
compares two worlds, the kernel's and the launcher's. *_test.py is a driver of its own that passes
or fails, as docker_profile.py, stackcheck.py and syscalls.py are, and *_test.c a unit test of the
launcher's C; the gate's steps run them (test/affected.py). A bare name is a module the drivers
share (harness, suite, tree, kernel, machines, kernel_answers, packages, b3), a check or a tool
(affected, figures, c_unused, bytecode, fuzz), or a run made when asked (matrix, vm_run, exercise,
bench, profile_spawn, workloads, realsoft, sysroot). progs/ holds the C programs the tests compile
with the tree's compiler; one that prints a line per case is registered once, with its judge, in
kernel_answers.EXERCISERS.

Tests are independent. Every test makes what it needs: the fixtures made at setup are the exclave,
the compiled programs and the environment, never another test's output, so any one runs alone.
"""

import argparse
import contextlib
import os
import shutil
import sys
from typing import TYPE_CHECKING, Any

import regress_check
import regress_exec
import regress_launcher
import regress_ownership
import regress_paths
import regress_programs
import regress_threads
import regress_tool
from harness import TESTS, run_tests, select
from suite import (
    REPO,
    CompileError,
    fixture_keys,
    input_drift,
    left_alone,
    make_fixture,
    prepare,
    read_stamp,
    write_stamp,
)

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
    drift = input_drift(args.exclave) if args.exclave else None
    if drift:
        sys.exit(drift)
    # The pruned fixture (17) is the given exclave pruned to what the suite touches. The first run
    # on an exclave makes it, and every later run uses it until the exclave changes.
    fixture, sources, made, made_skips, logging = None, "", "", set[str](), False
    keys = fixture_keys(args.exclave) if args.exclave else None
    tree_ = os.path.abspath(args.tree)
    if keys:
        name = os.path.basename(os.path.abspath(args.exclave)).replace(".exclave", "")
        fixture, sources = os.path.join(REPO, "build", "fixtures", f"{name}-{keys[0]}"), keys[1]
    if fixture and os.path.isdir(os.path.join(fixture, "tree")):
        tree_ = os.path.join(fixture, "tree")
        made, made_skips = read_stamp(fixture)
        print(
            f"fixture: {fixture}"
            + (" (made with other sources: a failure is rechecked)" if made != sources else "")
        )
    elif fixture:
        logging = True
        print("fixture: none yet for this exclave; this run makes it")
    on_fixture = tree_ != os.path.abspath(args.tree)
    stale = on_fixture and made != sources
    try:
        ctx = prepare(args, tree_, os.path.abspath(args.work), logging=logging)
    except CompileError as e:
        # a program needs what the prune left out of a fixture made before it existed (a header,
        # say): the whole exclave decides, and this run makes the fixture afresh
        if not on_fixture or not fixture:
            sys.exit(str(e))
        print(f"fixture: {e.name} does not compile on it; remade from the whole exclave")
        shutil.rmtree(fixture, ignore_errors=True)
        tree_, on_fixture, stale, made, made_skips, logging = (
            os.path.abspath(args.tree),
            False,
            False,
            "",
            set(),
            True,
        )
        ctx = prepare(args, tree_, os.path.abspath(args.work), logging=logging)
    order = select(TESTS, args.k)
    failed, skipped = suite_run(ctx, order, args.budget)
    # The whole exclave decides for a test the fixture may have misled: one that fails on a fixture
    # made with other sources, which may lack a file these sources touch, and one that skips on the
    # fixture but ran when the fixture was made, since a test can skip for what the prune left out.
    recheck = [t for t in order if t in failed and stale]
    # a test that skipped when the fixture was made and passes now is expected to skip no more
    ran = {t.__name__ for t in order if t not in failed and t not in skipped} & made_skips
    made_skips -= ran
    recheck += [t for t in skipped if on_fixture and t.__name__ not in made_skips]
    if recheck and fixture:
        for t in recheck:
            what = "failed on a fixture made with other sources" if t in failed else "skipped"
            print(f"RECHECK {t.__name__} {what}: run again on the whole exclave")
        whole = prepare(
            args, os.path.abspath(args.tree), os.path.abspath(args.work) + "-whole", logging=False
        )
        again, also = suite_run(whole, recheck, args.budget)
        passed = [t for t in recheck if t not in again and t not in also]
        for t in passed:
            print(
                f"RECHECK {t.__name__} passed on the whole exclave, which decides: the fixture "
                "lacks what it needs, or the test is flaky"
            )
        failed = [t for t in failed if t not in recheck] + again
        skipped = [t for t in skipped if t not in recheck] + also
        # a test that skips on the whole exclave too skips for this machine, not for the fixture
        made_skips |= {t.__name__ for t in also}
        if passed or again:
            # the fixture goes, for the next run to make afresh
            shutil.rmtree(fixture, ignore_errors=True)
        if not args.keep and not again:
            shutil.rmtree(whole.work, ignore_errors=True)
    if on_fixture and fixture and os.path.isdir(fixture) and (stale or recheck or ran):
        # A fixture made with other sources is still enough for these when every test passes, and
        # the stamp is renewed after a whole run; unless another run has found otherwise and
        # removed it.
        with contextlib.suppress(FileNotFoundError):
            write_stamp(fixture, sources if not failed and not args.k else made, made_skips)
    if logging and fixture and not failed and not args.k:
        make_fixture(ctx, fixture, sources, {t.__name__ for t in skipped})
    print(
        f"{len(order)} tests, {len(failed)} failures, {len(skipped)} skipped"
        + (f", {len(recheck)} rechecked" if recheck else "")
    )
    if not args.keep and not failed:
        shutil.rmtree(ctx.work, ignore_errors=True)
    return min(len(failed), 255)


def suite_run(
    ctx: Ctx, order: list[Test[Any]], budget: float
) -> tuple[list[Test[Any]], list[Test[Any]]]:
    """Run the tests on the fixtures, each checked for leaving the shared exclave alone (17).

    Returns the tests that failed and those that skipped.
    """
    skipped: list[Test[Any]] = []
    failed = run_tests(
        order, lambda t: t(ctx), budget=budget, after=lambda _t: left_alone(ctx), skipped=skipped
    )
    return failed, skipped


if __name__ == "__main__":
    sys.exit(main())
