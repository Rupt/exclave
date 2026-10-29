"""Spawning and exec: a group of the regression suite (DESIGN.md 17 item 4).

Run by test/run.py, on the fixtures test/suite.py makes.
"""

import os
import shlex
import shutil

import tree
from harness import expect, read_text, run, test
from suite import Ctx, inside, wrapper


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
    for mode in ("fexecve", "fexecve_opath", "fexecve_payload", "seccomp"):
        rc, out, err = inside(ctx, p, [mode])
        expect(rc == 0, f"{mode}: rc={rc} {out!r} {err!r}")
    rc, out, err = inside(ctx, p, ["personality"])
    expect(rc == 0 and out.startswith("child ok"), f"personality: {out!r} {err!r}")
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
    """A wrapped script run from outside gets its own virtual path as $0 (13 item 39)."""
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


@test
def inherited_identity_dropped(ctx: Ctx) -> None:
    """7.4.5: an exec from inside drops every inherited copy of the launcher's own variables.

    It drops them before it adds its own, so the program's environment as the kernel holds it
    (/proc/PID/environ, 13 item 46) has one EXCLAVE_EXECFN and one EXCLAVE_COMM, the handler's, and
    EXCLAVE_EXEC only on the loader path. The batch of 16-byte heads is what sees EXCLAVE_EXECFN=;
    with 12 an inherited copy would survive beside the handler's.
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
    show = "tr '\\0' '\\n' < /proc/$$/environ | grep -a -E '^EXCLAVE_(EXEC|EXECFN|COMM)=' | sort"
    planted = "EXCLAVE_EXEC=/planted EXCLAVE_EXECFN=/planted EXCLAVE_COMM=planted"
    for target, loader in ((sh, False), (hostsh, True)):
        rc, out, err = run(
            [wrapper(ctx, "sh"), "-c", f"{planted} exec {target} -c {shlex.quote(show)}"],
            cwd=ctx.work,
            env=ctx.env,
        )
        names = [line.split("=", 1)[0] for line in out.splitlines()]
        want = sorted(["EXCLAVE_COMM", "EXCLAVE_EXECFN"] + (["EXCLAVE_EXEC"] if loader else []))
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
    256th byte still ends the line. Both the handler's exec and the launcher's own entry hold.
    """
    exe = os.path.join(ctx.progs, "exec")
    cases = (
        ("long-interp", "#!/" + "x" * 300, "Exec format error", 126),
        ("newline-256", "#!/" + "x" * 252 + "\n", "No such file or directory", 127),
        ("long-blanks", "#!/bin/sh -e" + " " * 300, "", 0),
        # an empty interpreter name, looked up as the working directory
        ("blank-interp", "#!   ", "Permission denied", 126),
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
        return f"{ctx.gcc} has no nested functions: no trampoline program"
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "execstack"))
    expect(rc == 0 and out == "result 12\n", f"nested function trampoline: rc={rc} {out!r} {err!r}")
    return None


@test
def exec_vectors(ctx: Ctx) -> None:
    """7.5.6 for argument vectors: NULL is empty, a bad pointer is EFAULT.

    For a wrapper, a host ELF and a host script.
    """
    p = os.path.join(ctx.progs, "exec")
    hs = os.path.join(ctx.work, "vec-script.sh")
    with open(hs, "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(hs, 0o755)
    rc, out, err = inside(ctx, p, ["vectors", ctx.vbin("true"), p, hs], timeout=60)
    expect(rc == 0 and "FAIL" not in out, out + err)
    rc, out, err = inside(ctx, p, ["envedge", p], timeout=60)
    expect(
        rc == 0 and out == "A=1 B=2 EXCLAVE_COMMX=keep\n",
        f"a variable at the end of a mapping, among others: rc={rc} {out!r} {err!r}",
    )


@test
def exec_identity(ctx: Ctx) -> None:
    """7.4.5, 7.6: the identity a program exec'd from inside gets, as the kernel gives it.

    comm and AT_EXECFN from the path the program was exec'd by, not from argv[0]; a script's $0,
    AT_EXECFN and comm spelt /dev/fd/N/name relative to a descriptor and /dev/fd/N through one, comm
    then the file's own name; a close-on-exec script descriptor refused with ENOENT before anything
    runs; a header the loader cannot load ENOEXEC and a loader the exclave lacks ENOENT from execve
    itself, rather than a child that dies after a successful exec. The kernel under bwrap measured
    these answers (test/exercise.py).
    """
    d = os.path.join(ctx.work, "identhost")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "exec_identity"), [d])
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
        "fd script comm": "s.sh",
        "fd elf comm": "prog2",
        "fd elf execfn": "/dev/fd/N",
        "fd elf argv0": "renamed",
        "elf32": "ENOEXEC",
        "no loader": "ENOENT",
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
