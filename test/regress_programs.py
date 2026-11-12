"""Programs that matter: a group of the regression suite (DESIGN.md 17 item 4).

Run by test/run.py, on the fixtures test/suite.py makes.
"""

import os
import re
import shutil
import subprocess
import time

from harness import expect, read_bytes, run, skip, test
from suite import Ctx, copy_exclave, hello_source, inside, wrapper


# ------------------------------------------------------------------ tests
@test
def hello(ctx: Ctx) -> str | None:
    src = hello_source(ctx)
    exe = os.path.join(ctx.work, "hello")
    rc, out, err = run([wrapper(ctx, ctx.gcc), "-O2", src, "-o", exe], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "compile: " + err)
    rc, out, err = inside(ctx, exe, ["a", "b"])
    expect(rc == 0 and out == f"hello {exe} 3\n", f"loader-mode run: {out!r} {err!r}")
    try:
        rc, out, err = run([exe, "a"], cwd=ctx.work)
    except OSError:  # no glibc loader on this host at all (a musl host): exec itself fails
        rc, err = 1, "GLIBC_"
    # the host's libc cannot load the output: it runs inside the exclave only (9)
    if rc != 0 and "GLIBC_" in err:
        return "host cannot load the exclave's output; it runs inside the exclave only"
    expect(rc == 0 and out == f"hello {exe} 2\n", f"host run: {out!r} {err!r}")
    return None


@test
def identical_object(ctx: Ctx) -> str | None:
    """The exclave's gcc-13 through the launcher writes the object the host's writes natively.

    It measures that translation changes nothing a compile reads or writes, where the host has the
    same compiler: a byte read short or a write lost would change the object. It cannot tell a file
    served from the host from the tree's, which are the same files on such a host, and skips where
    the host has no gcc-13.
    """
    host = "/usr/bin/gcc-13"
    if "gcc-13" not in ctx.gcc:
        skip(f"the exclave's compiler is {ctx.gcc}: no host twin")
    if not os.path.exists(host):
        skip("no host gcc-13")
    src = hello_source(ctx)
    a, b = os.path.join(ctx.work, "h_host.o"), os.path.join(ctx.work, "h_exclave.o")
    run([host, "-O2", "-c", src, "-o", a], cwd=ctx.work)
    rc, _out, err = run(
        [wrapper(ctx, ctx.gcc), "-O2", "-c", src, "-o", b], cwd=ctx.work, env=ctx.env
    )
    expect(rc == 0, err)
    expect(read_bytes(a) == read_bytes(b), "objects differ")
    return None


@test
def interp_from_original(ctx: Ctx) -> str | None:
    """7.3: the loader honours each program's own PT_INTERP, resolved in the exclave.

    A program naming a loader the exclave lacks fails with a message naming it, before anything
    runs.
    """
    src = read_bytes(ctx.payload("true"))
    interp = ctx.interp.encode() + b"\0"
    i = src.index(interp)
    other = (ctx.other_interp.encode() + b"\0").ljust(len(interp), b"\0")
    exe = os.path.join(ctx.work, "other-true")
    with open(exe, "wb") as f:
        f.write(src[:i] + other + src[i + len(interp) :])
    os.chmod(exe, 0o755)
    rc, out, err = inside(ctx, exe)
    expect(
        rc == 127 and os.path.basename(ctx.other_interp) in err and "does not have" in err,
        f"a loader the exclave lacks: rc={rc} {err!r}",
    )
    os.makedirs(os.path.join(ctx.work, "same"), exist_ok=True)
    # by its own name: busybox chooses the applet from argv[0]
    same = os.path.join(ctx.work, "same", "true")
    shutil.copy2(ctx.payload("true"), same)
    rc, out, err = inside(ctx, same)
    expect(
        rc == 0, f"a program naming the exclave's loader by its own header runs: rc={rc} {err!r}"
    )
    # one world (7.4.5): a loader on a host path, the shape of a Nix or --dynamic-linker binary, is
    # refused
    if not ctx.libc:
        return "musl's libc is its loader; the host-path loader case needs libc.so.6 beside one"
    hostlib = os.path.join(ctx.work, "hostworld")
    os.makedirs(hostlib, exist_ok=True)
    for f, v in ((ctx.ldso_name, ctx.interp), ("libc.so.6", ctx.libc)):
        shutil.copy2(ctx.payload(v), os.path.join(hostlib, f))
    src = hello_source(ctx)
    world = os.path.join(ctx.work, "world")
    rc, out, err = run(
        [
            wrapper(ctx, ctx.gcc),
            "-O1",
            src,
            "-o",
            world,
            "-Wl,--dynamic-linker=" + os.path.join(hostlib, ctx.ldso_name),
            "-Wl,-rpath," + hostlib,
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(rc == 0, err)
    rc, out, err = inside(ctx, world)
    expect(
        rc == 127 and "does not have" in err and hostlib in err,
        f"a host-path loader must be refused: rc={rc} {out!r} {err!r}",
    )
    rc, out, err = run([wrapper(ctx, "sh"), "-c", world], cwd=ctx.work, env=ctx.env)
    expect(
        rc == 127 and "does not have" in err, f"the same from the exclave's shell: rc={rc} {err!r}"
    )
    return None


@test
def ld_so(ctx: Ctx) -> str | None:
    """7.3: the exclave's ld.so run as a program lists and verifies inside the exclave.

    --list names the exclave's libc, never a path below the tree; --verify, run from inside and
    through the entry, succeeds on the compiler's original under .real/, a path the host lacks, so
    its lookup happened inside.
    """
    ld = ctx.interp
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", f"{ld} --list {ctx.vbin(ctx.gcc)}"], cwd=ctx.work, env=ctx.env
    )
    expect(
        rc == 0 and (ctx.musl or f"libc.so.6 => {ctx.libc}" in out) and ctx.root not in out,
        f"ld.so --list: {out!r} {err!r}",
    )
    if ctx.musl:
        return "musl's loader has no --verify"
    original = "/" + os.path.relpath(ctx.payload(ctx.gcc), ctx.root)
    expect(not os.path.lexists(original), f"{original} is on the host too: no proof")
    for how, cmd in (
        ("from inside", [wrapper(ctx, "sh"), "-c", f"{ld} --verify {original}"]),
        ("through the entry", [ctx.launcher, ld, "--verify", original]),
    ):
        rc, out, err = run(cmd, cwd=ctx.work, env=ctx.env)
        expect(rc == 0, f"ld.so --verify {original} {how}: rc={rc} {out!r} {err!r}")
    return None


@test
def origin(ctx: Ctx) -> None:
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "origin_main"), cwd=ctx.work)
    expect(rc == 0 and out == "origin 42\n", f"RUNPATH=$ORIGIN: {out!r} {err!r}")


@test
def gconv_and_locale(ctx: Ctx) -> None:
    """Gconv's modules load from the exclave: iconv converts to a code page it has no built-in for.

    The locale the border sets, C.UTF-8, is the environment test's.
    """
    if not os.path.exists(wrapper(ctx, "iconv")):
        skip("no iconv in the tree")
    p = subprocess.run(
        [wrapper(ctx, "iconv"), "-f", "utf-8", "-t", "cp1252"],
        check=False,
        input="caf\xe9".encode(),
        env=ctx.env,
        cwd=ctx.work,
        capture_output=True,
    )
    expect(
        p.returncode == 0 and p.stdout == b"caf\xe9",
        f"iconv via gconv: rc={p.returncode} {p.stdout!r} {p.stderr!r}",
    )


@test
def rust(ctx: Ctx) -> str | None:
    rustc = shutil.which("rustc") or shutil.which("rustc", path=os.path.expanduser("~/.cargo/bin"))
    if not rustc:
        skip("no rustc")
    if ctx.musl:
        skip("the host's rustc targets glibc; the exclave has musl")
    # rustup's rustc installs its toolchain at the first call where the machine has none, from
    # the network and for minutes; told not to, it says at once that none is installed, and a
    # machine whose rustc does not run is one without rustc. A test touches no network (17).
    env = {**os.environ, "RUSTUP_AUTO_INSTALL": "0"}
    t0 = time.monotonic()
    rc, version, err = run([rustc, "--version"], env=env)
    if rc:
        skip("the machine's rustc does not run: " + (err.strip().splitlines() or ["no reason"])[0])
    t1 = time.monotonic()
    exe = os.path.join(ctx.progs, "rs")
    rc, out, err = run(
        [rustc, "-O", "-o", exe, os.path.join(ctx.work, "src", "rs.rs")], cwd=ctx.work, env=env
    )
    t2 = time.monotonic()
    expect(rc == 0, "rustc: " + err[-600:])
    rc, out, err = inside(ctx, exe)
    expect(rc == 0 and "FAIL" not in out, out + err)
    # the compiler's time is the machine's, and most of the test's where the machine is slow
    name = " ".join(version.split()[:2]) or "rustc"
    return f"{name} answered in {t1 - t0:.1f} s and compiled in {t2 - t1:.1f} s"


@test
def gdb_hooks(ctx: Ctx) -> str | None:
    """7.6, 13.1: gdb needs no manual command.

    The launcher carries a script gdb auto-loads; a breakpoint in a library hits with the exclave's
    own symbols, the program's source line is known, a wrapped program's libc frames resolve, and
    the positional entry's re-exec does not confuse gdb.
    """
    gdb = shutil.which("gdb")
    if not gdb:
        skip("no gdb")
    rc, out, err = run([gdb, "-batch", "-nx", "-ex", "python print(gdb.VERSION)"])
    if rc or not out.strip():
        skip("gdb without Python")
    src = hello_source(ctx)
    exe = os.path.join(ctx.work, "hello-g")
    rc, out, err = run(
        [wrapper(ctx, ctx.gcc), "-g", "-O0", "-o", exe, src], cwd=ctx.work, env=ctx.env
    )
    expect(rc == 0, "compile -g: " + err)
    base = [
        gdb,
        "-batch",
        "-nx",
        "-iex",
        "set auto-load safe-path /",
        "-iex",
        "set debuginfod enabled off",
        "-ex",
        "set breakpoint pending on",
    ]
    if ctx.musl:
        skip("gdb's breakpoints in a musl libc do not hit, the program's own do (13 item 1)")
    wr = "write"
    rc, out, err = run(
        [
            *base,
            "-ex",
            "break main",
            "-ex",
            "break " + wr,
            "-ex",
            "run",
            "-ex",
            "bt",
            "-ex",
            "continue",
            "-ex",
            "bt",
            "-ex",
            "info auto-load python-scripts",
            "--args",
            ctx.launcher,
            exe,
        ],
        cwd=ctx.work,
        env=ctx.env,
        timeout=300,
    )
    expect(
        re.search(r"^Breakpoint 1, main \(.*\) at \S*hello\.c:\d+", out, re.MULTILINE),
        f"the program's own breakpoint hits with its source line: {out[-800:]!r} {err[-400:]!r}",
    )
    expect(
        "Breakpoint 2, " in out and wr in out.split("Breakpoint 2, ", 1)[1].split("\n")[0],
        f"a breakpoint in the exclave's libc hits with its name: {out[-800:]!r} {err[-400:]!r}",
    )
    expect(
        "__libc_start" in out.split("Breakpoint 2, ", 1)[1],
        f"the libc frames below the program resolve: {out[-800:]!r}",
    )
    expect(
        "exclave-launcher.py" in out
        and "Python Exception" not in out
        and "Cannot insert" not in out,
        f"the script loaded once and quietly: {out[-600:]!r} {err[-400:]!r}",
    )
    rc, out, err = run(
        [
            *base,
            "-ex",
            "break " + wr,
            "-ex",
            "run",
            "-ex",
            "bt",
            "--args",
            wrapper(ctx, "echo"),
            "hi",
        ],
        cwd=ctx.work,
        env=ctx.env,
        timeout=300,
    )
    expect(
        "Breakpoint 1, " in out and "__libc_start" in out,
        f"a wrapped program's libc frames resolve: {out[-800:]!r} {err[-400:]!r}",
    )
    expect(
        "Python Exception" not in out and "Cannot insert" not in out,
        f"quiet for a wrapper: {out[-600:]!r}",
    )
    spaced = os.path.join(ctx.work, "space dir", "exclave")  # an exclave under a path with a space
    copy_exclave(ctx.mini, spaced)
    rc, out, err = run(
        [
            *base,
            "-ex",
            "break main",
            "-ex",
            "run",
            "-ex",
            "bt",
            "--args",
            os.path.join(spaced, ".exclave", "launcher"),
            exe,
        ],
        cwd=ctx.work,
        env=ctx.env,
        timeout=300,
    )
    expect(
        re.search(r"^Breakpoint 1, main \(.*\) at \S*hello\.c:\d+", out, re.MULTILINE)
        and "Python Exception" not in out,
        f"an exclave under a path with a space: {out[-600:]!r} {err[-300:]!r}",
    )
    return None


@test
def gdb_attach(ctx: Ctx) -> str | None:
    """7.6, 13 item 62: gdb attached to a program inside reads the launcher and lets it run on.

    gdb takes an attached process's file from its exe link, the launcher, and places that file's
    symbols by the kernel's copy of the process's auxiliary vector, checking the program headers
    the vector names against the file's. The kernel's copy is the launcher's, so the symbols are
    placed, the carried script's breakpoint lies in mapped memory, and the process continues to its
    end with its translated calls passed. Given the program's vector, which the loader could give
    the kernel with the rest of the record (7.3), gdb leaves the launcher's symbols unplaced and
    refuses to continue: that is why the kernel's copy stays the launcher's.
    """
    gdb = shutil.which("gdb")
    if not gdb:
        skip("no gdb")
    rc, out, err = run([gdb, "-batch", "-nx", "-ex", "python print(gdb.VERSION)"])
    if rc or not out.strip():
        skip("gdb without Python")
    # the program lets any process of its user trace it, which Yama's scopes above 1 still refuse
    try:
        scope = int(read_bytes("/proc/sys/kernel/yama/ptrace_scope"))
    except OSError:
        scope = 0
    if scope > 1:
        skip(f"ptrace_scope {scope}: no process may attach")
    with subprocess.Popen(
        [ctx.launcher, os.path.join(ctx.progs, "attach_me")],
        stdout=subprocess.PIPE,
        cwd=ctx.work,
        env=ctx.env,
        text=True,
    ) as p:
        try:
            assert p.stdout is not None
            pid = p.stdout.readline().strip()
            expect(pid.isdigit(), f"the program prints its pid: {pid!r}")
            rc, out, err = run(
                [
                    gdb,
                    "-batch",
                    "-nx",
                    "-iex",
                    "set auto-load safe-path /",
                    "-iex",
                    "set debuginfod enabled off",
                    "-p",
                    pid,
                    "-ex",
                    "info auto-load python-scripts",
                    "-ex",
                    "continue",
                ],
                cwd=ctx.work,
                env=ctx.env,
                timeout=120,
            )
            status = p.wait(timeout=30)
        finally:
            p.kill()
    expect(
        "exclave-launcher.py" in out and "Cannot insert" not in out + err,
        f"gdb attached reads the launcher and its script: {out[-600:]!r} {err[-400:]!r}",
    )
    expect(
        status == 0 and "exited normally" in out,
        f"the attached program runs on to its end: status {status} {out[-600:]!r} {err[-400:]!r}",
    )
    return None
