"""The harness the test drivers share: a registry, a runner and the checks a test makes.

A test is a function of one fixture, registered with `@test`. It fails by raising AssertionError,
through `expect`, and returns a note for its PASS line or None. `run_tests` prints one PASS or FAIL
line per test, any exception a FAIL, and returns the failures. test/run.py and
test/unpack_test.py run on it, each with its own fixture.
"""

import subprocess
import time
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence


class Test[C](Protocol):
    """A test: given its fixture, it returns a note for the PASS line, or None."""

    __name__: str

    def __call__(self, ctx: C, /) -> str | None: ...


TESTS: list[Test[Any]] = []


def test[T: Test[Any]](f: T) -> T:
    """Register a test with the driver that imports it."""
    TESTS.append(f)
    return f


def select[T: Test[Any]](tests: Sequence[T], k: str) -> list[T]:
    """The test named k, or else every test whose name contains k; every test for the empty k.

    An exact name runs alone, so that `-k spawn` does not also run spawn_threads.
    """
    return [t for t in tests if t.__name__ == k] or [t for t in tests if k in t.__name__]


def run_tests[T: Test[Any]](
    order: Sequence[T],
    call: Callable[[T], str | None],
    *,
    budget: float | None = None,
    after: Callable[[T], str | None] | None = None,
) -> list[T]:
    """Run each test by call(test), print a PASS or FAIL line for it and return the failures.

    A test over budget seconds fails: one that hangs is caught by run()'s timeouts, one that
    crawls here (DESIGN.md 17). after(test), when given, runs whether the test passed or not, and a
    message from it fails the test too.
    """
    width = max((len(t.__name__) for t in order), default=0)
    failed: list[T] = []
    for t in order:
        t0 = time.monotonic()
        try:
            note = call(t)
            took = time.monotonic() - t0
            if budget is not None:
                expect(took <= budget, f"took {took:.1f} s, over the budget of {budget:g} s")
            print(f"PASS {t.__name__:<{width}} {took:5.1f}s {note or ''}")
        except AssertionError as e:
            failed.append(t)
            why = str(e).strip().replace("\n", "\n     ")
            print(f"FAIL {t.__name__:<{width}} {time.monotonic() - t0:5.1f}s {why}")
        except Exception as e:  # noqa: BLE001 -- any exception is that test's FAIL line
            failed.append(t)
            print(
                f"FAIL {t.__name__:<{width}} {time.monotonic() - t0:5.1f}s {type(e).__name__}: {e}"
            )
        why = after(t) if after else None
        if why:
            print(f"FAIL {t.__name__:<{width}} {time.monotonic() - t0:5.1f}s {why}")
            if t not in failed:
                failed.append(t)
    return failed


def run(
    cmd: Sequence[str],
    *,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
    inp: bytes | None = None,
    timeout: float = 300,
    executable: str | None = None,
    preexec: Callable[[], object] | None = None,
) -> tuple[int, str, str]:
    p = subprocess.run(
        cmd,
        check=False,
        cwd=cwd,
        env=env,
        input=inp,
        timeout=timeout,
        executable=executable,
        preexec_fn=preexec,
        capture_output=True,
    )
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


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
