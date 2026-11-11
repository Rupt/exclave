"""Spawning and exec: a group of the regression suite (DESIGN.md 17 item 4).

Run by test/run.py, on the fixtures test/suite.py makes.
"""

import errno
import os
import platform
import shlex
import shutil
import struct
import subprocess
import sys
lazy import ctypes
lazy from collections.abc import Callable

import kernel_answers
import tree
from harness import expect, read_bytes, read_text, run, skip, test
from suite import Ctx, copy_exclave, inside, wrapper

PER_LINUX32 = 0x8  # personality(2)


@test
def spawn(ctx: Ctx) -> None:
    rc, out, err = inside(
        ctx, os.path.join(ctx.progs, "spawn"), [ctx.vbin(ctx.gcc), ctx.vbin("true")], timeout=600
    )
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def exec_modes(ctx: Ctx) -> None:
    p = os.path.join(ctx.progs, "exec")
    rc, out, err = inside(ctx, p, ["self"])
    expect(rc == 0 and out == f"child ok argv0={p}\n", f"self: {out!r} {err!r}")
    rc, out, err = inside(ctx, p, ["header", p])
    expect(rc == 0 and out.startswith("header ok"), f"header: {out!r} {err!r}")
    for mode in ("fexecve", "fexecve_opath", "seccomp"):
        rc, out, err = inside(ctx, p, [mode])
        expect(rc == 0, f"{mode}: rc={rc} {out!r} {err!r}")
    # an original's descriptor is mapped back to its wrapper (7.4.5): the shell runs as a wrapper,
    # whose environment as the kernel holds it has no EXCLAVE_EXEC, which the loader path's has
    payload = "/" + os.path.relpath(ctx.payload("sh"), ctx.root)
    rc, out, err = inside(
        ctx,
        p,
        [
            "fexecve_payload",
            payload,
            "sh",
            "-c",
            "tr '\\0' '\\n' < /proc/$$/environ | grep -c ^EXCLAVE_EXEC=",
        ],
    )
    expect(out == "0\n", f"fexecve of {payload} runs its wrapper: {out!r} {err!r}")
    # the persona an exec keeps (begin_new_exec clears only PER_CLEAR_ON_SETID, on a setid exec):
    # ADDR_NO_RANDOMIZE on the loader path, where two runs then place the program alike, and
    # through a wrapper; PER_LINUX32's machine as the kernel reports it natively
    runs = [
        inside(ctx, p, ["personality", "0x40000", "/proc/self/exe", "persona"]) for _ in range(2)
    ]
    expect(
        runs[0][1].startswith("personality 0x40000 machine ") and runs[0][1] == runs[1][1],
        f"ADDR_NO_RANDOMIZE across an exec, twice: {runs!r}",
    )
    rc, out, err = inside(
        ctx, p, ["personality", "0x40000", ctx.vbin("sh"), "-c", "cat /proc/self/personality"]
    )
    expect(out == "00040000\n", f"ADDR_NO_RANDOMIZE across an exec of a wrapper: {out!r} {err!r}")

    def linux32() -> None:
        ctypes.CDLL(None).personality(PER_LINUX32)

    _rc, native, err = run(
        [sys.executable, "-c", "import os; print(os.uname().machine)"], preexec=linux32
    )
    expect(native.strip(), f"no machine natively under PER_LINUX32: {err!r}")
    rc, out, err = inside(ctx, p, ["personality", str(PER_LINUX32), "/proc/self/exe", "persona"])
    expect(
        out.startswith(f"personality {PER_LINUX32:#x} machine {native.strip()} main "),
        f"PER_LINUX32 across an exec: {out!r} {err!r}, natively {native.strip()}",
    )
    rc, out, err = inside(
        ctx,
        p,
        ["personality", str(PER_LINUX32), ctx.vbin("sh"), "-c", "cat /proc/self/personality"],
    )
    expect(
        out == f"{PER_LINUX32:08x}\n", f"PER_LINUX32 across an exec of a wrapper: {out!r} {err!r}"
    )
    rc, out, err = inside(ctx, p, ["nofollow"])
    expect(rc == 0, f"execveat AT_SYMLINK_NOFOLLOW on a symlink: {out!r} {err!r}")
    log = os.path.join(ctx.work, "closefds.log")
    target = os.path.join(ctx.work, "closefds.out")
    rc, out, err = inside(ctx, p, ["closefds", target], env=dict(ctx.env, EXCLAVE_LOG=log))
    expect(
        rc == 0 and read_text(target) == "line one\nline two\n",
        f"log lines in the program's file: {read_text(target)[:200]!r} {err!r}",
    )
    ne = os.path.join(ctx.work, "nonexec")
    os.makedirs(ne, exist_ok=True)
    with open(os.path.join(ne, "true"), "w") as f:
        f.write("not executable\n")
    rc, out, err = run(
        [
            wrapper(ctx, "sh"),
            "-c",
            "PATH={}:{} exec {} execvp".format(ne, os.path.dirname(ctx.vbin("true")), p),
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(rc == 0, f"execvp past non-executable: rc={rc} {err!r}")
    # files executable for others but not for this user, and a plain data file, are refused as the
    # kernel refuses them
    perm = os.path.join(ctx.work, "perm")
    os.makedirs(perm, exist_ok=True)
    victims = []
    for name, mode, body in (
        ("victim.sh", 0o455, "#!/bin/sh\necho VICTIM RAN\n"),
        ("data", 0o644, "#!/bin/sh\necho VICTIM RAN\n"),
    ):
        q = os.path.join(perm, name)
        with open(q, "w") as f:
            f.write(body)
        os.chmod(q, mode)
        victims.append(q)
    shutil.copy2(os.path.join(ctx.progs, "exec"), os.path.join(perm, "velf"))
    os.chmod(os.path.join(perm, "velf"), 0o455)
    victims.append(os.path.join(perm, "velf"))
    rc, out, err = inside(ctx, p, ["perm", *victims])
    expect(rc == 0 and "FAIL" not in out, f"perm: {out!r} {err!r}")
    hs = os.path.join(ctx.work, "host-script.sh")
    with open(hs, "w") as f:
        f.write("#!/bin/sh\necho host script ok $1 $0\n")
    os.chmod(hs, 0o755)
    rc, out, err = inside(ctx, p, ["script", hs])
    expect(rc == 0 and out == f"host script ok arg1 {hs}\n", f"host script: {out!r} {err!r}")
    rc, out, err = inside(ctx, hs, ["z"])
    expect(rc == 0 and out == f"host script ok z {hs}\n", f"host script direct: {out!r} {err!r}")


@test
def scripts(ctx: Ctx) -> None:
    rc, out, err = run([wrapper(ctx, "exclave-test-script"), "hello"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "script ok hello 1\n", f"direct: {out!r} {err!r}")
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "exclave-test-script a b"], cwd=ctx.work, env=ctx.env
    )
    expect(rc == 0 and out == "script ok a 2\n", f"via sh PATH: {out!r} {err!r}")
    rc, out, err = run([wrapper(ctx, "exclave-test-script2"), "q"], cwd=ctx.work, env=ctx.env)
    expect(
        rc == 0 and out.startswith("script ok /usr/bin/exclave-test-script2"),
        f"interpreter chain: {out!r} {err!r}",
    )
    rc, out, err = run(
        [wrapper(ctx, "sh"), "/usr/bin/exclave-test-noshebang"], cwd=ctx.work, env=ctx.env
    )
    expect(rc == 0 and out == "noshebang ok\n", f"sh file: {out!r} {err!r}")
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "/usr/bin/exclave-test-noshebang"], cwd=ctx.work, env=ctx.env
    )
    expect(rc == 0 and out == "noshebang ok\n", f"ENOEXEC fallback: {out!r} {err!r}")
    rc, out, err = run([wrapper(ctx, "exclave-test-noshebang")], cwd=ctx.work, env=ctx.env)
    # a shell's 126: found, not executable
    expect(rc == 126 and "not an executable" in err, f"noshebang direct: rc={rc} {err!r}")
    rc, out, err = run([wrapper(ctx, "exclave-test-exe")], cwd=ctx.work, env=ctx.env)
    expect(
        out == ctx.sh_exe + "\n",
        f"a wrapped script's /proc/self/exe is its interpreter: {out!r} {err!r}",
    )
    if os.path.lexists(wrapper(ctx, "bash")):
        rc, out, err = run(
            [wrapper(ctx, "bash"), "-c", "echo from bash"], cwd=ctx.work, env=ctx.env
        )
        expect(rc == 0 and out == "from bash\n", f"bash starts: rc={rc} {err!r}")


@test
def script_argv0_as_given(ctx: Ctx) -> None:
    """7.4.5: a script's interpreter gets the script path as the caller spelt it.

    The launcher passes it as the kernel does: for a host script run inside by a relative path, and
    through the positional entry; a wrapped script run from outside by a relative path likewise, and
    a wrapped script exec'd from inside, since the handler carries the spelling to the wrapper it
    execs.
    """
    d = os.path.join(ctx.work, "argv0")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "s.sh"), "w") as f:
        f.write('#!/bin/sh\necho "argv0=$0 n=$#"\n')
    os.chmod(os.path.join(d, "s.sh"), 0o755)
    _rc, out, err = run([wrapper(ctx, "sh"), "-c", "./s.sh a b"], cwd=d, env=ctx.env)
    expect(
        out == "argv0=./s.sh n=2\n", f"a host script inside, by a relative path: {out!r} {err!r}"
    )
    _rc, out, err = run([ctx.launcher, "./s.sh", "a"], cwd=d, env=ctx.env)
    expect(out == "argv0=./s.sh n=1\n", f"through the positional entry: {out!r} {err!r}")
    _rc, out, err = run(
        ["./exclave-test-script", "x"], cwd=os.path.join(ctx.root, "usr", "bin"), env=ctx.env
    )
    expect(
        out == "script ok x 1\n",
        f"a wrapped script from outside by a relative path runs: {out!r} {err!r}",
    )
    _rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "cd /usr/bin && ./exclave-test-exe"], cwd=ctx.work, env=ctx.env
    )
    expect(
        out == ctx.sh_exe + "\n",
        f"a wrapped script inside: exe is its interpreter: {out!r} {err!r}",
    )
    _rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "cd /usr/bin && ./exclave-test-script2 q"],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out == "script ok ./exclave-test-script2 2\n",
        "a wrapped script exec'd from inside gets the path as spelt, carried to its wrapper by "
        f"the handler (7.4.5): {out!r} {err!r}",
    )


@test
def wrapped_script_from_outside(ctx: Ctx) -> None:
    """A wrapped script run from outside gets a virtual path as $0 (13 item 39).

    Its own, by a host symlink to it or a relative spelling; through a link in the tree, by the
    link's tree path, a relative spelling, a host symlink to the link or the positional entry, the
    link's virtual path: the launcher's rule (13 item 39), whose last component is the name the
    kernel gives a script reached by a link, on which postgresql-common's pg_wrapper, behind
    /usr/bin/psql and the rest, dispatches.
    """
    link = os.path.join(ctx.work, f"shortcut-{os.getpid()}")
    os.symlink(os.path.join(ctx.root, "usr", "bin", "exclave-test-script2"), link)
    rc, out, err = run([link, "a", "b"], cwd=ctx.work, env=ctx.env)
    expect(
        rc == 0 and out.startswith("script ok /usr/bin/exclave-test-script2 "),
        f"through a host symlink: {out!r} {err!r}",
    )
    rc, out, err = run(
        ["./exclave-test-script2", "x"], cwd=os.path.join(ctx.root, "usr", "bin"), env=ctx.env
    )
    expect(
        rc == 0 and out.startswith("script ok /usr/bin/exclave-test-script2 "),
        f"by a relative spelling from outside: {out!r} {err!r}",
    )
    bindir = os.path.join(ctx.root, "usr", "bin")
    shortcut = os.path.join(ctx.work, f"link-shortcut-{os.getpid()}")
    os.symlink(os.path.join(bindir, "exclave-test-argv0-link"), shortcut)
    for how, argv, cwd in (
        ("by its tree path", [os.path.join(bindir, "exclave-test-argv0-link")], ctx.work),
        ("by a relative spelling", ["./exclave-test-argv0-link"], bindir),
        ("through a host symlink to the link", [shortcut], ctx.work),
        (
            "through the positional entry",
            [ctx.launcher, "/usr/bin/exclave-test-argv0-link"],
            ctx.work,
        ),
    ):
        rc, out, err = run(argv, cwd=cwd, env=ctx.env)
        expect(
            rc == 0 and out == "/usr/bin/exclave-test-argv0-link\n",
            f"a link in the tree to a script, {how}: {out!r} {err!r}",
        )
    rc, out, err = run([os.path.join(bindir, "exclave-test-argv0")], cwd=ctx.work, env=ctx.env)
    expect(
        rc == 0 and out == "/usr/bin/exclave-test-argv0\n", f"the script itself: {out!r} {err!r}"
    )


@test
def inherited_identity_dropped(ctx: Ctx) -> None:
    """7.4.5: an exec from inside drops every inherited copy of the launcher's own variables.

    It drops them before it adds its own, so the program's environment as the kernel holds it
    (/proc/PID/environ, 13 item 46) has one EXCLAVE_EXECFN and one EXCLAVE_COMM, the handler's,
    EXCLAVE_EXEC only on the loader path, and one EXCLAVE_CWD, the run's working directory (8.1
    rule 4). The batch of 16-byte heads is what sees EXCLAVE_EXECFN=; with 12 an inherited copy
    would survive beside the handler's.
    """
    sh = ctx.vbin("sh")
    original = os.path.join(
        ctx.root,
        os.path.dirname(tree.resolve(ctx.root, sh)).lstrip("/"),
        ".real",
        os.path.basename(tree.resolve(ctx.root, sh)),
    )
    hostbin = os.path.join(ctx.work, "identity-bin")
    os.makedirs(hostbin, exist_ok=True)
    hostsh = os.path.join(hostbin, "sh")  # not a wrapper: a host program, run on the loader path
    shutil.copy2(original, hostsh)
    show = (
        "tr '\\0' '\\n' < /proc/$$/environ | grep -a -E '^EXCLAVE_(EXEC|EXECFN|COMM|CWD)=' | sort"
    )
    planted = (
        "EXCLAVE_EXEC=/planted EXCLAVE_EXECFN=/planted EXCLAVE_COMM=planted EXCLAVE_CWD=/planted"
    )
    for target, loader in ((sh, False), (hostsh, True)):
        rc, out, err = run(
            [wrapper(ctx, "sh"), "-c", f"{planted} exec {target} -c {shlex.quote(show)}"],
            cwd=ctx.work,
            env=ctx.env,
        )
        names = [line.split("=", 1)[0] for line in out.splitlines()]
        want = sorted(
            ["EXCLAVE_COMM", "EXCLAVE_CWD", "EXCLAVE_EXECFN"] + (["EXCLAVE_EXEC"] if loader else [])
        )
        expect(
            rc == 0 and names == want and "planted" not in out,
            f"{target}: the kernel's copy of the environment holds {out!r}, "
            f"want one each of {want!r} and nothing planted ({err!r})",
        )


@test
def argv_unbounded(ctx: Ctx) -> None:
    """7.4.5: argument vectors are sized from their counts.

    A wrapped script and a host script with many arguments.
    """
    rc, out, err = run(
        [wrapper(ctx, "exclave-test-script")] + ["a"] * 70000, cwd=ctx.work, env=ctx.env
    )
    expect(
        rc == 0 and out == "script ok a 70000\n",
        f"wrapped script with 70000 arguments: rc={rc} {out[:80]!r} {err[:200]!r}",
    )
    hs = os.path.join(ctx.work, "many.sh")
    with open(hs, "w") as f:
        f.write("#!/bin/sh\necho many $#\n")
    os.chmod(hs, 0o755)
    rc, out, err = run([wrapper(ctx, "sh"), "-c", f"{hs} $(seq 20000)"], cwd=ctx.work, env=ctx.env)
    expect(
        rc == 0 and out == "many 20000\n",
        f"host script with 20000 arguments: rc={rc} {out[:80]!r} {err[:200]!r}",
    )


@test
def shebang_without_newline(ctx: Ctx) -> None:
    """A #! line with no newline runs as the kernel runs it."""
    p = os.path.join(ctx.work, "nonl.sh")
    with open(p, "w") as f:
        f.write("#!/bin/sh")
    os.chmod(p, 0o755)
    rc, _out, err = inside(ctx, p)
    expect(rc == 0, f"no-newline shebang: rc={rc} {err!r}")


@test
def shebang_buffer_rules(ctx: Ctx) -> None:
    """A #! line is read as the kernel's load_script reads it, from its 256-byte buffer.

    With no newline in the buffer, an interpreter path that runs past the first 255 bytes is
    ENOEXEC, never a shorter path; an argument may be cut, and trailing blanks go. A newline in the
    256th byte still ends the line, and only a space or a tab is a blank, so a CR stays in the name.
    The interpreter must be executable, as any file an exec runs. Both the handler's exec and the
    launcher's own entry hold.
    """
    exe = os.path.join(ctx.progs, "exec")
    noexec = os.path.join(ctx.work, "shebang-interp644")
    shutil.copy2(exe, noexec)
    os.chmod(noexec, 0o644)
    cases = (
        ("long-interp", "#!/" + "x" * 300, "Exec format error", 126),
        ("newline-256", "#!/" + "x" * 252 + "\n", "No such file or directory", 127),
        ("long-blanks", "#!/bin/sh -e" + " " * 300, "", 0),
        # an empty interpreter name, looked up as the working directory
        ("blank-interp", "#!   ", "Permission denied", 126),
        # only a space or a tab ends the name (binfmt_script.c's spacetab): /bin/sh\r is absent
        ("crlf", "#!/bin/sh\r\n", "No such file or directory", 127),
        ("tabs", "#!\t/bin/sh\t-e\t\n", "", 0),
        # an interpreter is opened as an exec opens a file: one without execute permission is EACCES
        ("noexec-interp", f"#!{noexec}\n", "Permission denied", 126),
    )
    for name, text, want, entry_rc in cases:
        p = os.path.join(ctx.work, f"shebang-{name}")
        with open(p, "w") as f:
            f.write(text)
        os.chmod(p, 0o755)
        rc, out, err = inside(ctx, exe, ["script", p])
        expect(
            want in err if want else rc == 0, f"{name} exec'd from inside: rc={rc} {out!r} {err!r}"
        )
        rc, out, err = inside(ctx, p)
        expect(rc == entry_rc, f"{name} run by the launcher: rc={rc}, wanted {entry_rc}: {err!r}")


@test
def executable_stack(ctx: Ctx) -> str | None:
    """7.4.5: a program whose PT_GNU_STACK asks for an executable stack runs inside.

    It is built by the exclave's gcc.
    """
    if not os.path.exists(os.path.join(ctx.progs, "execstack")):
        skip(f"{ctx.gcc} has no nested functions: no trampoline program")
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "execstack"))
    expect(rc == 0 and out == "result 12\n", f"nested function trampoline: rc={rc} {out!r} {err!r}")
    return None


@test
def exec_vectors(ctx: Ctx) -> None:
    """7.5.6 for argument vectors: NULL is empty, a bad pointer is EFAULT.

    For a wrapper, a host ELF and a host script; a NULL argv reaches the program and the script's
    interpreter as the kernel makes it.
    """
    p = os.path.join(ctx.progs, "exec")
    hs = os.path.join(ctx.work, "vec-script.sh")
    with open(hs, "w") as f:
        f.write('#!/bin/sh\necho "$0 $#"\n')
    os.chmod(hs, 0o755)
    rc, out, err = inside(ctx, p, ["vectors", ctx.vbin("true"), p, hs], timeout=60)
    expect(rc == 0 and "FAIL" not in out, out + err)
    # a NULL argv reaches the program as this kernel makes it, one empty string since 5.18 and in
    # the stable trees that took the change, none before (fs/exec.c), which only a run on the
    # kernel tells, and a script's interpreter is given the script's path: the native run of the
    # same cases is the expectation, by a static build of the program, since the host's libc is
    # not the tree's
    ps = os.path.join(ctx.work, "vec-exec-static")
    gcc = wrapper(ctx, ctx.gcc)
    src = os.path.join(ctx.work, "src", "exec.c")
    rc, _out, err = run(
        [gcc, "-static", "-pthread", "-o", ps, src, "-lm", "-ldl"], cwd=ctx.work, env=ctx.env
    )
    if rc and "-lc" in err:
        skip("the tree has no static libc")
    expect(rc == 0, f"a static build of exec.c: {err}")
    rc, nat, err = run([ps, "vectors", ps, hs], timeout=60)
    expect(rc == 0 and "FAIL" not in nat, nat + err)
    want = {
        line.replace(ps, p, 1) for line in nat.splitlines() if line.startswith((ps + " ", hs + " "))
    }
    expect(len(want) == 10, f"the native run's cases: {sorted(want)}")
    lines = set(out.splitlines())
    expect(want <= lines, f"an exec with a NULL argv: {sorted(want - lines)} not in {out!r}")
    rc, out, err = inside(ctx, p, ["envedge", p], timeout=60)
    expect(
        rc == 0 and out == "A=1 B=2 EXCLAVE_COMMX=keep\n",
        f"a variable at the end of a mapping, among others: rc={rc} {out!r} {err!r}",
    )


@test
def memfd_exec_permission(ctx: Ctx) -> None:
    """7.4.5, 13 item 25: exec of a memfd, the kernel's exec permission before the header.

    A memfd sealed against execution (MFD_NOEXEC_SEAL) is EACCES whatever it holds, an executable
    one runs the ELF copied into it and refuses an empty one with ENOEXEC; a memfd made with no
    flag is the host's vm.memfd_noexec to decide, and the last line prints the host's facts.
    Measured under bwrap on 7.0, where the launcher agrees; Ubuntu 26.10's 7.3 refuses the plain
    memfd where the launcher does not (the probe's open defect).
    """
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "memfd_exec"))
    expect(rc == 0 and not kernel_answers.memfd_exec_wrong(out), out + err)


@test
def another_process_exe_link(ctx: Ctx) -> None:
    """7.6, 13 item 10: another exclave process's /proc/<pid>/exe names the program it runs.

    A loader-path process is the launcher exec'd by its own path, so the kernel's link names the
    launcher; a forked child reading, stating, opening or running its parent's link, by the pid
    or through a descriptor on the parent's /proc/self, reaches the program the parent runs, the
    one its EXCLAVE_EXEC names (13 item 46), as the kernel's link does natively. Measured under
    bwrap; the launcher once named itself, and running the link ran it without a program.
    """
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "exe_link"))
    expect(rc == 0 and not kernel_answers.exe_link_wrong(out), out + err)


@test
def another_process_exe_relative_interpreter(ctx: Ctx) -> None:
    """7.6: another process's exe link, where it runs a wrapped script with a relative interpreter.

    The reader resolves the script's #! interpreter to name what the process runs; from a working
    directory where it resolves, the answer is the interpreter, the kernel's; from one where its
    walk fails, the answer is the script's virtual path, never what the walk left behind.
    """
    ex2 = os.path.join(ctx.work, f"exe-relinterp-{os.getpid()}.exclave")
    copy_exclave(ctx.exclave, ex2)
    d = os.path.join(ex2, "tree", "opt", "relinterp")
    os.makedirs(os.path.join(d, ".real"))
    # named sh, as busybox picks its applet by the name
    os.makedirs(os.path.join(d, "relinterp-bin"))
    os.symlink(ctx.vbin("sh"), os.path.join(d, "relinterp-bin", "sh"))
    with open(os.path.join(d, ".real", "s"), "w") as f:
        f.write("#!relinterp-bin/sh\necho ready\nread x\n")
    os.chmod(os.path.join(d, ".real", "s"), 0o755)
    os.link(os.path.join(ex2, ".exclave", "launcher"), os.path.join(d, "s"))
    # another working directory, where the walk meets a link, whose text it reads, and then fails
    other = os.path.join(ex2, "tree", "opt", "relinterp-reader")
    os.makedirs(other)
    os.symlink("nowhere", os.path.join(other, "relinterp-bin"))
    p = subprocess.Popen(
        ["./s"],
        cwd=d,
        env=ctx.env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert p.stdout is not None
        ready = p.stdout.readline()
        expect(ready == "ready\n", f"the script did not start: {ready!r}")
        sh = os.path.join(ex2, "tree", ctx.vbin("sh").lstrip("/"))
        for cwd, want in (
            ("/opt/relinterp", ctx.sh_exe),
            ("/opt/relinterp-reader", "/opt/relinterp/s"),
        ):
            rc, out, err = run(
                [sh, "-c", f"cd {cwd} && {ctx.vbin('readlink')} /proc/{p.pid}/exe"],
                cwd=ctx.work,
                env=ctx.env,
            )
            expect(
                rc == 0 and out == want + "\n",
                f"/proc/PID/exe read from {cwd}: {out!r}, want {want!r} {err!r}",
            )
    finally:
        p.kill()
        p.communicate()


@test
def exec_identity(ctx: Ctx) -> None:
    """7.4.5, 7.6: the identity a program exec'd from inside gets, as the kernel gives it.

    comm and AT_EXECFN from the path the program was exec'd by, not from argv[0]; a script's $0,
    AT_EXECFN and comm spelt /dev/fd/N/name relative to a descriptor and /dev/fd/N through one, comm
    then the name of the file finally run, an ELF's own and a script's interpreter's (the kernel
    takes it from the file it loads when the name was empty, comm_from_dentry in fs/exec.c since
    6.12, which the handler answers on every kernel), for a wrapped script of the tree too, whose
    interpreter the child launcher resolves; a close-on-exec script descriptor refused with ENOENT
    before anything runs; a header the loader cannot load, of the 32-bit class or another machine,
    ENOEXEC and a loader the exclave lacks ENOENT from execve itself, rather than a child that dies
    after a successful exec. The kernel under bwrap measured these answers (test/exercise.py).
    """
    d = os.path.join(ctx.work, "identhost")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(
        ctx, os.path.join(ctx.progs, "exec_identity"), [d, ctx.vbin("exclave-test-comm")]
    )
    expect(rc == 0, f"exec_identity: {out!r} {err!r}")
    got = dict(line.split(": ", 1) for line in out.splitlines() if ": " in line)
    want = {
        "abs comm": "prog2",
        "abs execfn": d + "/prog2",
        "abs argv0": "renamed",
        "rel comm": "prog2",
        "rel execfn": "prog2",
        "rel argv0": "renamed",
        "dfd script argv0": "/dev/fd/N/s.sh",
        "dfd script comm": "s.sh",
        "cloexec script": "ENOENT",
        "fd script argv0": "/dev/fd/N",
        "fd script comm": os.path.basename(ctx.sh_exe),
        "fd tree script comm": os.path.basename(ctx.sh_exe),
        "fd elf comm": "prog2",
        "fd elf execfn": "/dev/fd/N",
        "fd elf argv0": "renamed",
        "elf32": "ENOEXEC",
        "no loader": "ENOENT",
        "foreign machine": "ENOEXEC",
    }
    bad = [
        f"{k}: got {got.get(k)}, the kernel says {v}" for k, v in want.items() if got.get(k) != v
    ]
    expect(not bad, "; ".join(bad))


@test
def fexec(ctx: Ctx) -> None:
    """13 item 25, 7.4.5: exec of a descriptor that has no path.

    A memfd holding an ELF and an unlinked file run on the loader path through the child launcher,
    which names the program by its descriptor and answers the link's text for /proc/self/exe as the
    kernel does; a script in a memfd or an unlinked file reaches its interpreter as /dev/fd/N, and a
    close-on-exec script is ENOENT, as natively. The kernel under bwrap measured these answers.
    """
    d = os.path.join(ctx.work, "fexechost")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "fexec"), [d])
    expect(rc == 0, f"fexec: {out!r} {err!r}")
    got = dict(line.split(": ", 1) for line in out.splitlines() if ": " in line)
    want = {
        "memfd elf": "ret=0 errno=0 status=7 out=child ran, exe memfd:prog (deleted), argv0 fexec",
        "memfd elf cloexec": (
            "ret=0 errno=0 status=7 out=child ran, exe memfd:prog (deleted), argv0 memfd-program"
        ),
        "unlinked elf": (
            "ret=0 errno=0 status=7 out=child ran, exe unlinked-prog (deleted), argv0 fexec"
        ),
        "memfd script": "ret=0 errno=0 status=0 out=script ran, argv0 /dev/fd/3",
        "memfd script cloexec": "ret=-1 errno=2",
        "unlinked script": "ret=0 errno=0 status=0 out=script ran, argv0 /dev/fd/3",
        "fd with a path (control)": (
            "ret=0 errno=0 status=7 out=child ran, exe linked-prog, argv0 fexec"
        ),
    }
    bad = [
        f"{k}: got {got.get(k)}, the kernel says {v}" for k, v in want.items() if got.get(k) != v
    ]
    expect(not bad, "; ".join(bad))


def exerciser(ctx: Ctx, name: str, args: list[str]) -> str:
    """Run test/progs/NAME in a fresh host directory of its own, HOSTDIR in args; its output."""
    d = os.path.join(ctx.work, name + "-host")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(
        ctx,
        os.path.join(ctx.progs, name),
        [d if a == "HOSTDIR" else a for a in args],
        env={**ctx.env, "CC": ctx.vbin(ctx.gcc)},  # the programs some cases build
    )
    expect(rc == 0, f"{name}: rc={rc} {out!r} {err!r}")
    return out


@test
def exec_script(ctx: Ctx) -> None:
    """7.4.5: what execve makes of a #! line and of a file that is no program, as the kernel does.

    Lines of 127, 128, 255 and 256 bytes with and without a newline, blanks, an argument with
    spaces, a NUL in the line, an empty interpreter, "#!" alone, chains of three to six (the sixth
    ELOOP), an interpreter that is a wrapper of the tree, a symlink, a directory, a FIFO or absent,
    a script through a descriptor opened O_PATH, O_RDONLY and O_CLOEXEC, relative to a directory
    descriptor and through a symlink, and execve of a directory, a FIFO, a socket, /dev/null, an
    empty file, a file of one byte and files without an execute bit; an executable but unreadable
    file is EACCES, the launcher's own answer (13 item 12). The kernel under bwrap measured these
    answers (test/kernel_answers.py, checked again by the namespace oracle).
    """
    bad = kernel_answers.exec_script_wrong(exerciser(ctx, "exec_script", ["run", "HOSTDIR"]))
    expect(not bad, "; ".join(bad))


@test
def exec_elf(ctx: Ctx) -> None:
    """7.3, 7.4.5: an ELF image is judged as load_elf_binary judges it.

    Before the kernel's point of no return, execve itself answers: ENOEXEC for a type, a machine or
    program headers it cannot load (the class byte is not read: the machine decides), for an
    interpreter path without its NUL, empty, of zero size or longer than PATH_MAX, EIO for one the
    file does not hold whole, and for the interpreter the first PT_INTERP names, its own open's
    error, ENOENT or EACCES, EIO for a header it does not hold whole and ELIBBAD for one that is not
    this machine's ELF. Past it the kernel kills the new image with SIGSEGV, and so does the
    loader, naming what it could not map: no PT_LOAD, overlapping segments, more file than memory
    in a segment, an address and an offset that differ within a page, a segment
    at address zero; a bss segment is given memory at its page whatever its offset, as the kernel
    gives it (elf_load, 6.7). An ET_EXEC interpreter the kernel loads; one that is not the
    exclave's own file the child launcher refuses by name (7.3). Static, static-pie and
    fixed-address programs the tree's compiler builds run. The kernel under bwrap measured these
    answers.
    """
    bad = kernel_answers.exec_elf_wrong(exerciser(ctx, "exec_elf", ["HOSTDIR"]))
    expect(not bad, "; ".join(bad))


@test
def exec_auxv(ctx: Ctx) -> str | None:
    """7.3: the initial stack and the auxiliary vector are the kernel's, from the entry and an exec.

    Every AT_ entry against the program's own header, entry and loader, AT_RANDOM fresh at each
    exec, the vectors and strings placed as create_elf_tables places them, the program's
    environment strings contiguous after its arguments with the launcher's own variables after
    them, cmdline and comm the program's, a setuid and a setgid copy (no_new_privs: AT_SECURE 0),
    and the descriptors an exec'd static program finds open under soft limits of 3, 4 and 8
    lowered below its open descriptors, which the launcher borrows against; the kernel's record of
    the image in /proc/self/stat, its code and its first stack pointer the program's where the
    kernel takes the record from the loader (7.3), the launcher's where it does not; 13 item 50 for
    the environment's end there and item 12 for a hard limit of 3. The kernel under bwrap measured
    these answers.
    """
    static_libc = tree.has_static_libc(ctx.tree)
    bad = kernel_answers.exec_auxv_wrong(
        exerciser(ctx, "exec_auxv", ["HOSTDIR"]), static_libc=static_libc
    )
    expect(not bad, "; ".join(bad))
    return None if static_libc else "the tree has no static libc: the descriptor cases not run"


@test
def exec_state(ctx: Ctx) -> None:
    """7.4.5: what a process keeps and loses across an exec is what the kernel keeps and loses.

    The signal mask, ignored dispositions and pending signals kept, handlers and the alternate
    stack reset, interval timers kept and a POSIX timer gone, the umask, the working directory,
    nice, the affinity and the prctl settings exec keeps and clears, comm set anew, and an exec by
    a second thread, with the thread's own mask and pending signals and the process's; SIGSYS is
    the launcher's (7.5.1, 13 item 23). The kernel under bwrap measured these answers.
    """
    bad = kernel_answers.exec_state_wrong(exerciser(ctx, "exec_state", ["HOSTDIR"]))
    expect(not bad, "; ".join(bad))


@test
def mem_layout(ctx: Ctx) -> None:
    """7.3: a program's memory lies where the kernel's exec puts it and grows as the kernel lets it.

    The break lies above the image, within 1 GB of its end, and grows a [heap] the program's; the
    image lies below its loader and the stack, with [vdso] and [vvar]; the kernel's record of the
    image, /proc/self/stat's data and break, is the program's; /proc/self/exe and AT_EXECFN open the
    program's own file; two runs place it apart, and one without randomization places it at the
    kernel's own base with the break at its end; and an exec under RLIMIT_AS of 16 MB and
    RLIMIT_DATA of 1 MB runs, since the launcher maps its tables as they fill rather than in its
    image (7.3). On a kernel that takes no record of an image from a process the launcher places
    nothing, and what it places is not judged there (13 item 59). 128 KB of RLIMIT_DATA is less
    than the launcher's image charges, so the kernel kills its exec (13 item 60), the launcher's
    variables take room from the argument area (13 item 61), and the kernel's copy of the auxiliary
    vector, /proc/self/auxv and PR_GET_AUXV, is the launcher's (13 item 62). The kernel under
    bwrap measured these answers.
    """
    bad = kernel_answers.mem_layout_wrong(exerciser(ctx, "mem_layout", []))
    expect(not bad, "; ".join(bad))


def refusing(name: str, first: int | None, err: int) -> Callable[[], None]:
    """A function a child runs before its exec: a seccomp filter that answers err to one call.

    The call is the syscall named name, prctl, getrandom or process_vm_readv, with first as its
    first argument where one is given; every other call is allowed. The filter stays around
    whatever the child execs, as a container's profile stays around a launcher.
    """
    arch, numbers = {
        "x86_64": (0xC000003E, {"prctl": 157, "getrandom": 318, "process_vm_readv": 310}),
        "aarch64": (0xC00000B7, {"prctl": 167, "getrandom": 278, "process_vm_readv": 270}),
    }[platform.machine()]
    ld, jeq, ret = 0x20, 0x15, 0x06  # BPF_LD|BPF_W|BPF_ABS, BPF_JMP|BPF_JEQ|BPF_K, BPF_RET|BPF_K
    # seccomp_data: the number at 0, the architecture at 4, the first argument's low word at 16
    tests = [(4, arch), (0, numbers[name])] + ([(16, first)] if first is not None else [])
    prog = b""
    for i, (at, value) in enumerate(tests):
        # on a mismatch, past the tests that remain and the refusal, to the allow
        prog += struct.pack("HBBI", ld, 0, 0, at)
        prog += struct.pack("HBBI", jeq, 0, 2 * (len(tests) - 1 - i) + 1, value)
    prog += struct.pack("HBBI", ret, 0, 0, 0x00050000 | err)  # SECCOMP_RET_ERRNO
    prog += struct.pack("HBBI", ret, 0, 0, 0x7FFF0000)  # SECCOMP_RET_ALLOW

    def install() -> None:
        class Fprog(ctypes.Structure):
            _fields_ = (("len", ctypes.c_ushort), ("filter", ctypes.c_char_p))

        libc = ctypes.CDLL(None, use_errno=True)
        fprog = Fprog(len(prog) // 8, prog)
        zero = ctypes.c_ulong(0)
        # PR_SET_NO_NEW_PRIVS, then PR_SET_SECCOMP with SECCOMP_MODE_FILTER
        if libc.prctl(38, ctypes.c_ulong(1), zero, zero, zero) or libc.prctl(
            22, ctypes.c_ulong(2), ctypes.byref(fprog), zero, zero
        ):
            raise OSError(ctypes.get_errno(), "seccomp filter")

    return install


@test
def layout_without_the_record(ctx: Ctx) -> None:
    """7.3, 13 item 59: a program runs where mmap puts it when the kernel takes no record of it.

    A seccomp filter around the launcher answers EPERM to prctl(PR_SET_MM), as a kernel built
    without PR_SET_MM_MAP answers it, and in a second run ENOSYS to getrandom, as a kernel before
    3.17 does. The loader then gives up the place it reserved two thirds up the address space, or
    reserves none, maps the image where mmap puts it and leaves the break where the kernel put the
    launcher's, and the program runs as it did before the loader placed anything: the break grows a
    [heap], the exec under lowered limits runs, two runs lie apart. mem_layout says the kernel has
    neither, so what the loader places is not judged and its every other answer is.
    """
    prog = os.path.join(ctx.progs, "mem_layout")
    for name, first, err in (("prctl", 35, errno.EPERM), ("getrandom", None, errno.ENOSYS)):
        rc, out, serr = run(
            [ctx.launcher, prog], cwd=ctx.work, env=ctx.env, preexec=refusing(name, first, err)
        )
        expect(
            rc == 0 and "PR_SET_MM_MAP and getrandom: no" in out.splitlines(),
            f"{name} refused: mem_layout runs and finds it refused: rc={rc} {out[:200]!r} {serr!r}",
        )
        bad = kernel_answers.mem_layout_wrong(out)
        expect(not bad, f"{name} refused: " + "; ".join(bad))


@test
def mem_edge(ctx: Ctx) -> None:
    """7.5.6, 13 item 15: what ends where its mapping does is read as the kernel reads it.

    test/progs/mem_edge.c gives calls a path, an attribute's name, an argument vector, an
    environment vector and a variable whose last byte is the last of a mapping, and a buffer that
    ends there: the kernel reads a string to its NUL and a vector to its NULL, so each call answers
    as anywhere else, where the handler reads a window past them, 256 bytes of a path and a page
    of a vector. Twice: with process_vm_readv, which gives what it could read, and with it refused
    by a seccomp filter around the launcher, as Docker's profile refuses it before kernel 4.8,
    where the copy goes through a pipe, which gives nothing of a write that faults partway, so the
    copy steps by the source's pages. A program's vectors lie within a page of its stack's end in
    some starts when its environment is small, where a copy that took the window whole or not at
    all answered its exec EFAULT. The kernel under bwrap measured the answers.
    """
    bad = kernel_answers.mem_edge_wrong(exerciser(ctx, "mem_edge", ["HOSTDIR"]))
    expect(not bad, "; ".join(bad))
    d = os.path.join(ctx.work, "mem_edge-pipe")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    log = os.path.join(d, "log")
    rc, out, err = run(
        [ctx.launcher, os.path.join(ctx.progs, "mem_edge"), d],
        cwd=ctx.work,
        env=dict(ctx.env, EXCLAVE_LOG=log),
        preexec=refusing("process_vm_readv", None, errno.EPERM),
    )
    expect(rc == 0, f"mem_edge without process_vm_readv: rc={rc} {out!r} {err!r}")
    expect(
        "copies through a pipe" in read_text(log),
        "the launcher did not log that process_vm_readv was refused",
    )
    bad = kernel_answers.mem_edge_wrong(out)
    expect(not bad, "without process_vm_readv: " + "; ".join(bad))


@test
def fd_procs(ctx: Ctx) -> None:
    """7.4.3, 7.4.5, 7.5.4: descriptors and processes are the kernel's around trapped calls.

    A program starts with the kernel's descriptors and a trapped open returns the lowest free
    number, in a hole, at a soft limit's edge (the last number, then EMFILE, with the limit kept),
    after close_range with and without CLOSE_RANGE_UNSHARE and CLOEXEC and after dup2 onto every
    low number; another process's fd, cwd and task links read virtual; a clone(CLONE_VM) child's
    chdir leaves its parent's directory alone and a CLONE_FS child's and a thread's move it;
    posix_spawn's chdir and open actions act in the child alone; a tree descriptor passed by
    SCM_RIGHTS or taken by pidfd_getfd is the tree's; wait statuses and sessions of children that
    exec'd wrappers, and the first open of a program exec'd with 0, 1 and 2 closed, are the
    kernel's. The kernel under bwrap measured these answers.
    """
    bad = kernel_answers.fd_procs_wrong(exerciser(ctx, "fd_procs", ["HOSTDIR"]))
    expect(not bad, "; ".join(bad))


@test
def low_image(ctx: Ctx) -> None:
    """13 item 24: a program whose image starts at 0x10000 runs in an exclave.

    A program whose image starts at 0x10000 and reaches past 0x3f0000, as Go's aarch64 linker lays
    one out, runs in an exclave; at 0x3f0000, the syscall page's former address that 13 item 24
    records, such a program died unmapped. Built here by the exclave's compiler -no-pie from that
    address, so every exclave kind and both architectures run it.
    """
    exe = os.path.join(ctx.work, "low_image")
    rc, out, err = run(
        [
            wrapper(ctx, ctx.gcc),
            "-O1",
            "-no-pie",
            "-Wl,-Ttext-segment=0x10000",
            "-o",
            exe,
            os.path.join(ctx.work, "src", "low_image.c"),
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(rc == 0, "compile from 0x10000: " + err)
    rc, out, err = inside(ctx, exe)
    expect(
        rc == 0 and out.startswith("text 0x") and out.rstrip().endswith("marker 0"),
        f"a program from 0x10000 past 0x3f0000: rc={rc} {out!r} {err!r}",
    )


@test
def data_directory(ctx: Ctx) -> None:
    """6.2, 7.3, 7.4.5: nothing under a data directory runs: a program, a loader or an interpreter.

    A program there is EACCES from inside and 126 through the entry; a program whose PT_INTERP names
    a loader there is refused by name with 127 before anything runs, from inside and through the
    entry; a script whose #! names an interpreter there is EACCES, as the interpreter itself is.
    """
    dp = os.path.join(ctx.work, "data-dir.exclave")
    copy_exclave(ctx.mini, dp)
    sdk = os.path.join(dp, "tree", "opt", "sdk")
    os.makedirs(sdk)
    p = os.path.join(ctx.progs, "exec")
    shutil.copy2(p, os.path.join(sdk, "prog"))
    shutil.copy2(ctx.payload(ctx.interp), os.path.join(sdk, "ld.so"))
    with open(os.path.join(dp, ".exclave", "manifest"), "wb") as f:
        f.write(b'exclave 1\n\ndata "/opt/sdk"\n')
    entry, sh = os.path.join(dp, ".exclave", "launcher"), dp + "/tree" + ctx.vbin("sh")
    # the program's own loader named in its header, moved to the data directory
    src = read_bytes(p)
    interp = ctx.interp.encode() + b"\0"
    i = src.index(interp)
    moved = os.path.join(ctx.work, "sdk-loader")
    with open(moved, "wb") as f:
        f.write(src[:i] + b"/opt/sdk/ld.so".ljust(len(interp), b"\0") + src[i + len(interp) :])
    os.chmod(moved, 0o755)
    script = os.path.join(ctx.work, "sdk-script")
    with open(script, "w") as f:
        f.write("#!/opt/sdk/prog child\n")
    os.chmod(script, 0o755)
    for target, refusal, what in (
        ("/opt/sdk/prog", "Permission denied", "a program under a data directory"),
        (moved, "/opt/sdk/ld.so", "a program whose loader is under a data directory"),
        (script, "Permission denied", "a script whose interpreter is under a data directory"),
    ):
        status = 127 if target == moved else 126
        rc, out, err = run([entry, target, "self"], cwd=ctx.work, env=ctx.env)
        expect(
            rc == status and refusal in err and "child ok" not in out,
            f"{what} through the entry: rc={rc}, not {status} naming {refusal!r}: {out!r} {err!r}",
        )
        rc, out, err = run([sh, "-c", f"{target} self"], cwd=ctx.work, env=ctx.env)
        expect(
            rc == status and refusal in err and "child ok" not in out,
            f"{what} from inside: rc={rc}, not {status} naming {refusal!r}: {out!r} {err!r}",
        )
