"""The harness the test drivers share: a registry, a runner and the checks a test makes.

A test is a function of one fixture, registered with `@test`. It fails by raising AssertionError,
through `expect`; it skips through `skip`, which raises Skip with the reason it cannot run here (a
missing tool, a tree or a kernel that cannot answer); otherwise it returns a note for its PASS line
or None. A test that asserted part of what it states and cannot run the rest passes, with a note
naming the rest.
`run_tests` prints one PASS, SKIP or FAIL line per test, any other exception a FAIL, and returns
the failures. test/run.py, test/unpack_test.py, test/readers_test.py and test/fetch_test.py run
on it, each with its own fixture; a driver that is one run of checks prints each through `step`. A
driver that cannot run at all says so through `cannot_run` and exits with its status.
"""

import contextlib
import os
import signal
import subprocess
import time
from typing import IO, TYPE_CHECKING, Any, NoReturn, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence


class Test[C](Protocol):
    """A test: given its fixture, it returns a note for the PASS line, or None."""

    __name__: str

    def __call__(self, ctx: C, /) -> str | None: ...


TESTS: list[Test[Any]] = []


# The exit status of a driver that cannot run here at all, for want of a tool, a kernel feature or
# an input: the step runner prints its step as SKIP, not ok (scripts/steps.sh), and the matrix does
# not fail the row for it.
CANNOT_RUN = 77


def cannot_run(what: str, why: str) -> int:
    """Say that what cannot run here and why; the status a driver then exits with."""
    print(f"{why}; {what} cannot run here")
    return CANNOT_RUN


# The checks of a driver that is one run and not a list of tests (the compatibility, release and
# caches tests): each is printed as it is made, and the names of those that failed are kept.
FAILED: list[str] = []


def step(name: str, ok: object, detail: str = "") -> None:
    """Print one check of such a driver, ok or FAIL with its detail, and keep a failure's name."""
    if not ok:
        FAILED.append(name)
    print(f"{'ok  ' if ok else 'FAIL'} {name}{': ' + detail if detail and not ok else ''}")


class Skip(Exception):  # noqa: N818 -- an outcome, like a pass, not an error
    """Raised by a test that cannot run here, with the reason; printed SKIP and counted apart."""


def skip(why: str) -> NoReturn:
    """Skip the test: it cannot run here, for the reason why."""
    raise Skip(why)


def test[T: Test[Any]](f: T) -> T:
    """Register a test with the driver that imports it."""
    TESTS.append(f)
    return f


def select[T: Test[Any]](tests: Sequence[T], k: str) -> list[T]:
    """The test named k, or else every test whose name contains k; every test for the empty k.

    An exact name runs alone, so that `-k spawn` does not also run spawn_threads.
    """
    return [t for t in tests if t.__name__ == k] or [t for t in tests if k in t.__name__]


class _Clock:
    """The running test's deadline, a time.monotonic() value, which run() keeps to; None outside."""

    deadline: float | None = None


def run_tests[T: Test[Any]](
    order: Sequence[T],
    call: Callable[[T], str | None],
    *,
    budget: float | None = None,
    after: Callable[[T], str | None] | None = None,
    skipped: list[T] | None = None,
) -> list[T]:
    """Run each test by call(test), print a PASS, SKIP or FAIL line for it and return the failures.

    A test over budget seconds fails (DESIGN.md 17): a program run() starts is killed, with its
    process group, when the test's budget runs out, and a test that returns late fails here.
    after(test), when given, runs whether the test passed, skipped or failed, and a message from it
    fails the test too. The tests that skip are added to skipped.
    """
    width = max((len(t.__name__) for t in order), default=0)
    failed: list[T] = []
    for t in order:
        t0 = time.monotonic()
        _Clock.deadline = None if budget is None else t0 + budget
        try:
            note = call(t)
            took = time.monotonic() - t0
            if budget is not None:
                expect(took <= budget, f"took {took:.1f} s, over the budget of {budget:g} s")
            print(f"PASS {t.__name__:<{width}} {took:5.1f}s {note or ''}")
        except Skip as e:
            if skipped is not None:
                skipped.append(t)
            print(f"SKIP {t.__name__:<{width}} {time.monotonic() - t0:5.1f}s {e}")
        except AssertionError as e:
            failed.append(t)
            why = str(e).strip().replace("\n", "\n     ")
            print(f"FAIL {t.__name__:<{width}} {time.monotonic() - t0:5.1f}s {why}")
        except subprocess.TimeoutExpired as e:
            failed.append(t)
            took = time.monotonic() - t0
            prog = e.cmd[0] if isinstance(e.cmd, list) else e.cmd
            why = (
                f"{prog} killed at the test's budget of {budget:g} s"
                if budget is not None and took >= budget
                else f"{prog} killed after its timeout of {e.timeout:g} s"
            )
            print(f"FAIL {t.__name__:<{width}} {took:5.1f}s {why}, {last_words(e)}")
        except Exception as e:  # noqa: BLE001 -- any exception is that test's FAIL line
            failed.append(t)
            print(
                f"FAIL {t.__name__:<{width}} {time.monotonic() - t0:5.1f}s {type(e).__name__}: {e}"
            )
        _Clock.deadline = None
        why = after(t) if after else None
        if why:
            print(f"FAIL {t.__name__:<{width}} {time.monotonic() - t0:5.1f}s {why}")
            if t not in failed:
                failed.append(t)
            if skipped is not None and t in skipped:
                skipped.remove(t)
    return failed


def run(
    cmd: Sequence[str],
    *,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
    inp: bytes | None = None,
    stdin: IO[bytes] | None = None,
    timeout: float | None = 300,
    executable: str | None = None,
    preexec: Callable[[], object] | None = None,
) -> tuple[int, str, str]:
    """Run cmd and return its status, stdout and stderr.

    Its standard input is inp through a pipe, or the file stdin, or else this process's own.

    It runs in a session of its own, and when timeout seconds pass (None: no limit), or the running
    test's budget runs out first, its whole process group is killed, so that a launcher's children
    die with it, and TimeoutExpired is raised.
    """
    if _Clock.deadline is not None:
        left = _Clock.deadline - time.monotonic()
        timeout = max(left if timeout is None else min(timeout, left), 0.01)
    with subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env,
        stdin=stdin if inp is None else subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        executable=executable,
        preexec_fn=preexec,  # noqa: PLW1509 -- only a test passes one, while no other thread runs
        start_new_session=True,
    ) as p:
        try:
            out, err = p.communicate(inp, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(p.pid, signal.SIGKILL)
            # what it had written goes with the exception, for the line that reports the kill; a
            # program that left the group may still hold the pipes: not waited for
            with contextlib.suppress(subprocess.TimeoutExpired):
                e.output, e.stderr = p.communicate(timeout=5)
            raise
    return p.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def last_words(e: subprocess.TimeoutExpired) -> str:
    """What a program run() killed had written, for the line that reports the kill.

    Its last lines on standard error, or on standard output when that was silent: a tool that
    waits, on the network or on a lock, has usually said what for.
    """
    for stream in (e.stderr, e.output):
        text = stream.decode("utf-8", "replace").strip() if isinstance(stream, bytes) else ""
        if text:
            return "having written:\n     " + "\n     ".join(text.splitlines()[-3:])
    return "having written nothing"


def expect(cond: object, msg: str) -> None:
    """Fail the test with msg unless cond holds."""
    if not cond:
        raise AssertionError(msg)


def read_text(path: str) -> str:
    with open(path) as f:
        return f.read()


def read_bytes(path: str, n: int = -1) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)
