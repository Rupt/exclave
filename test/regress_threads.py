"""Signals and threads: a group of the regression suite (DESIGN.md 17 item 4).

Run by test/run.py, on the fixtures test/suite.py makes.
"""

import os
import platform
import shutil
import subprocess

import kernel_answers
import tree
from harness import expect, run, skip, test
from suite import REPO, Ctx, inside


@test
def signals(ctx: Ctx) -> None:
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "signals"))
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def signal_calls_in_order(ctx: Ctx) -> None:
    """7.5.2: the trapped signal syscalls answer in the kernel's order.

    rt_sigaction, rt_sigprocmask, rt_sigsuspend and the waits that carry a mask, each with a
    wrong set size, a bad pointer, an invalid how or timeout, a signal the kernel owns, beside
    another fault, so that the order of the checks shows: the timeout is read and checked before
    the mask, the old mask is written after the new one is in force, an install for SIGSYS reads
    its action before it is ignored; a restorer the program supplies, SA_RESETHAND, SA_NODEFER
    and unknown flag bits round-trip. The kernel's answers (test/kernel_answers.py), which the
    namespace oracle confirms under bwrap.
    """
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "sigcalls"))
    wrong = kernel_answers.sigcalls_wrong(out)
    expect(rc == 0 and not wrong, "\n".join(wrong) + err)


@test
def signals_during_traps(ctx: Ctx) -> None:
    """7.5.3: signals arriving during trapped syscalls.

    A 1 ms timer raining on loops of stat, open, readlink and execve of a missing file, with and
    without SA_RESTART, blocked, ignored, with a handler that traps and one that siglongjmps out;
    kill from a child process and tgkill from a sibling thread in tight loops, the second a
    thread-directed signal pending at the trap itself, which the kernel dequeues after the
    synchronous SIGSYS; the restart rules of pause, sigsuspend, ppoll, pselect and a blocking
    open; the mask inside a handler across its own traps; a path that faults in a file mapping
    past its end or runs off its mapping, EFAULT with no signal. Every answer is the call's
    result, as the kernel gives it (test/kernel_answers.py), confirmed under bwrap by the
    namespace oracle.
    """
    d = os.path.join(ctx.work, f"hostdir-sigrain-{os.getpid()}")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "sigrain"), [d], timeout=60)
    wrong = kernel_answers.sigrain_wrong(out)
    expect(rc == 0 and not wrong, "\n".join(wrong) + err)


@test
def alternate_stacks(ctx: Ctx) -> str:
    """7.5.3, 13 items 30 and 51: the alternate signal stack under the launcher.

    A handler that traps on an alternate stack of each size from MINSIGSTKSZ to 16 KB above a
    guard page: the kernel passes every size, the launcher 8 KB and up, since the trap adds the
    kernel's frame and the handler's budget (item 30); a 5 KB handler without SA_ONSTACK landing
    during traps beside an 8 KB alternate stack, which natively runs on the main stack and under
    the launcher on the alternate stack, into the guard page (item 51); SS_AUTODISARM, sigaltstack
    queried and changed inside a handler, traps nested on the alternate stack and from a handler
    on the main stack while one is armed, all the kernel's answers (test/kernel_answers.py),
    confirmed under bwrap by the namespace oracle.
    """
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "sigstack"), timeout=60)
    wrong = kernel_answers.sigstack_wrong(out)
    expect(rc == 0 and not wrong, "\n".join(wrong) + err)
    small = [
        line.split(": ")[1]
        for line in out.splitlines()
        if line.startswith("alternate stack of 6 KB, handler traps")
    ]
    return "a handler trapping on 6 KB: " + (small[0] if small else "?")


@test
def clones_trapping(ctx: Ctx) -> None:
    """7.5.4, 7.5.5: threads and clones trapping.

    A vfork child and clone(CLONE_VM) children trapping before they exit, on stacks of 64 KB down
    to 2 KB above a guard page, where 4 KB and below cannot hold the kernel's frame and the
    handler (13 item 30); a thread with a 16 KB stack and one with the least glibc allows; 64
    threads trapping while the main thread sends each a SIGUSR1 whose handler traps;
    pthread_cancel of a thread blocked in a trapped open and of one looping over traps with
    asynchronous cancellation, which unwind through the launcher's frames; a sibling exiting
    while a trap blocks; exit_group and pthread_exit from a handler that interrupted a blocking
    trap. The kernel's answers (test/kernel_answers.py), confirmed under bwrap by the namespace
    oracle.
    """
    d = os.path.join(ctx.work, f"hostdir-clones-{os.getpid()}")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "clones"), [d], timeout=60)
    wrong = kernel_answers.clones_wrong(out)
    expect(rc == 0 and not wrong, "\n".join(wrong) + err)


@test
def threads(ctx: Ctx) -> None:
    """7.5.5: threads, TLS and dlopen; 64 threads trapping at once, each answered for its path."""
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
    """7.5.4: siglongjmp out of a handler that interrupted a trapped blocking open, 80 times.

    Each round leaves the handler's frame behind; 80 rounds pass the handler's nesting limit of
    64, which a launcher that did not release what a left frame held would reach.
    """
    d = os.path.join(ctx.work, "hostdir")
    os.makedirs(d, exist_ok=True)
    rc, out, err = inside(
        ctx, os.path.join(ctx.progs, "ljmp"), [os.path.join(d, "ljfifo"), "80"], timeout=60
    )
    expect(
        rc == 0 and out == "timed out 80 of 80 rounds\n", f"longjmp rounds: rc={rc} {out!r} {err!r}"
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
        rc == 0
        and "spawns beside trapping threads: 200 spawned, 0 failures" in out.splitlines()
        and "hung" not in out,
        f"spawn_threads: rc={rc} {out!r} {err!r}",
    )
    return out.strip().splitlines()[-1]


@test
def go_paths(ctx: Ctx) -> str | None:
    """17.4: a Go program doing path syscalls from goroutines.

    Go issues syscalls raw, makes threads with clone, installs its own handler for every signal,
    SIGSYS included (7.5.2), and runs on small stacks, beside a goroutine collecting garbage, whose
    preemption signal lands in the launcher's handler mid-trap (7.5.3); built static by go with cgo
    off and run inside as a host program. The image from 0x10000 that Go's aarch64 linker lays out
    is low_image's (13 item 24). Built here by the host's go, or taken from build/go/<machine>,
    where the matrix puts the one it built for a VM without go; skips with the reason when there is
    neither.
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
