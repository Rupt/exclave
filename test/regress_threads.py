"""Signals and threads: a group of the regression suite (DESIGN.md 17 item 4).

Run by test/run.py, on the fixtures test/suite.py makes.
"""

import os
import platform
import shutil
import subprocess

import tree
from harness import expect, run, skip, test
from suite import REPO, Ctx, inside


@test
def signals(ctx: Ctx) -> None:
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "signals"))
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def threads(ctx: Ctx) -> None:
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "threads"))
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def relative_to_a_renamed_directory(ctx: Ctx) -> str | None:
    """A descriptor-relative host path resolves while the directory's parent is renamed (7.4.3).

    In both forms of the walk: from the directory itself, where the one-step host check vouches
    for it, and from the root, lstat by lstat, where it cannot (16.6 item 5), made here by a second
    mount of the tree's filesystem in a user namespace, as on a btrfs host; the second form runs
    where bwrap and user namespaces are available.
    """
    d = os.path.join(ctx.work, f"hostdir-race-{os.getpid()}")
    os.makedirs(d, exist_ok=True)
    prog = os.path.join(ctx.progs, "rename_race")
    rc, out, err = inside(ctx, prog, [d], timeout=120)
    expect(rc == 0 and "FAIL" not in out, "from the directory: " + out + err)
    if (
        not shutil.which("bwrap")
        or subprocess.run(
            ["bwrap", "--dev-bind", "/", "/", "true"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
    ):
        return "the walk from the root not run: no bwrap or user namespaces"
    rc, out, err = run(
        ["bwrap", "--dev-bind", "/", "/", "--bind", ctx.exclave, "/mnt", ctx.launcher, prog, d],
        cwd=ctx.work,
        env=dict(ctx.env),
        timeout=120,
    )
    expect(rc == 0 and "FAIL" not in out, "from the root: " + out + err)
    return None


@test
def fifo(ctx: Ctx) -> None:
    d = os.path.join(ctx.work, "hostdir")
    os.makedirs(d, exist_ok=True)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "fifo"), [d], timeout=60)
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def longjmp_out_of_trapped_open(ctx: Ctx) -> None:
    """7.5.4: siglongjmp out of a handler that interrupted a trapped blocking open, 200 times."""
    d = os.path.join(ctx.work, "hostdir")
    os.makedirs(d, exist_ok=True)
    rc, out, err = inside(
        ctx, os.path.join(ctx.progs, "ljmp"), [os.path.join(d, "ljfifo"), "200"], timeout=120
    )
    expect(
        rc == 0 and out == "timed out 200 of 200 rounds\n",
        f"longjmp rounds: rc={rc} {out!r} {err!r}",
    )


@test
def spawn_threads(ctx: Ctx) -> str:
    """7.5.4: the handler under concurrency.

    Threads trap throughout posix_spawns from another thread, so a vfork child's handler runs beside
    the parent's and every copy from program memory names the trap's own pid, never a process-wide
    one the child overwrote; and a forked child whose traps nest, a timer's handler trapping inside
    a trapped stat, while every chunk the pool had is held by threads blocked in the parent, so the
    child's pool grows under nesting, which a lock left held by the fork would have hung.
    """
    d = os.path.join(ctx.work, "spawnhost")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(
        ctx, os.path.join(ctx.progs, "spawn_threads"), [d, ctx.vbin("true")], timeout=120
    )
    expect(
        rc == 0 and "0 failures" in out and "hung" not in out,
        f"spawn_threads: rc={rc} {out!r} {err!r}",
    )
    return out.strip().splitlines()[-1]


@test
def go_paths(ctx: Ctx) -> str | None:
    """17.4: a Go program doing path syscalls from goroutines.

    Go issues syscalls raw, makes threads with clone, installs its own handler for every signal,
    SIGSYS included (7.5.2), and runs on small stacks; built static by go with cgo off and run
    inside as a host program, twice: as go links it for the machine, and from 0x10000 as its aarch64
    linker does, an image reaching past the syscall page's former address (13 item 24). Built here
    by the host's go, or taken from build/go/<machine>, where the matrix puts the ones it built for
    a VM without go; skips with the reason when there is neither.
    """
    go, prebuilt = tree.go_toolchain(), os.path.join(REPO, "build", "go", platform.machine())
    if go:
        try:
            exes = tree.go_build(go, ctx.progs, platform.machine(), ctx.work)
        except RuntimeError as e:
            msg = str(e)
            raise AssertionError(msg) from e
    elif all(os.path.exists(os.path.join(prebuilt, n)) for n, f in tree.GO_BUILDS):
        # copied under the work directory, which the exclave lets through
        exes = [
            (n, shutil.copy2(os.path.join(prebuilt, n), os.path.join(ctx.progs, n)))
            for n, f in tree.GO_BUILDS
        ]
    else:
        skip("no go toolchain (golang-go) and nothing in build/go/" + platform.machine())
    for name, exe in exes:
        if name == "go_paths_low":
            lo, hi = tree.load_span(exe)
            expect(
                lo < 0x3F0000 and hi > 0x3F1000,
                f"{name} spans {lo:#x}-{hi:#x}, not across 0x3f0000",
            )
        rc, out, err = inside(ctx, exe)
        expect(rc == 0 and "FAIL" not in out, f"{name}: {out}{err}")
    return None


@test
def working_directory_races(ctx: Ctx) -> str:
    """8.2, 13 item 14: relative creates while another thread changes the working directory.

    The working directory moves back and forth between a host directory and /usr/share while four
    threads create the same name relative to it: each create succeeds or is EROFS, as it resolves
    against one or the other, and the tree is never written, which it would be if a relative path
    were re-issued as given and resolved against the directory current by then. The program stops
    once it has seen each answer a thousand times.
    """
    d = os.path.join(ctx.work, f"hostdir-cwd-race-{os.getpid()}")
    os.makedirs(d, exist_ok=True)
    written = os.path.join(ctx.root, "usr", "share", "cwdrace-x")
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "cwd_race"), [d], timeout=60)
    in_tree = os.path.lexists(written)
    if in_tree:
        os.remove(written)
    expect(not in_tree, f"a relative create wrote {written}: {out}{err}")
    expect(rc == 0 and "FAIL" not in out and out.endswith(" 0 other\n"), out + err)
    return out.strip().splitlines()[-1]
