"""The launcher and its filter: a group of the regression suite (DESIGN.md 17 item 4).

Run by test/run.py, on the fixtures test/suite.py makes.
"""

import os
import shutil
import signal
import struct
import subprocess
import time
lazy import resource

import tree
from harness import expect, read_bytes, read_text, run, test
from suite import REPO, TOOL, Ctx, copy_exclave, inside, wrapper


@test
def filter_model(ctx: Ctx) -> None:
    """The filter against the rule of 7.4.2, with this machine's syscall numbers.

    test/filter_test.c, built by the exclave's compiler for this machine and run inside the exclave,
    so that the arm64 row checks the aarch64 filter, which the gate's unit step, built for the
    reference machine, cannot.
    """
    d = os.path.join(ctx.work, "filter-model")
    for sub, names in (
        ("src", ("filter.c", "str.c", "common.h", "sys.h", "elf.h")),
        ("test", ("filter_test.c",)),
    ):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
        for n in names:
            shutil.copy(os.path.join(REPO, sub, n), os.path.join(d, sub, n))
    exe = os.path.join(d, "filter_test")
    rc, out, err = run(
        [
            wrapper(ctx, ctx.gcc),
            "-std=gnu11",
            "-O1",
            "-fno-builtin",
            "-DHOST_TEST",
            "-o",
            exe,
            os.path.join(d, "test", "filter_test.c"),
            os.path.join(d, "src", "filter.c"),
            os.path.join(d, "src", "str.c"),
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(rc == 0, f"cannot build the filter model: {err[-600:]}")
    rc, out, err = inside(ctx, exe, timeout=300)
    expect(
        rc == 0 and " 0 failures" in out, f"the filter against its rule: {out[-600:]} {err[-300:]}"
    )


@test
def speculation_unchanged(ctx: Ctx) -> None:
    """The filter is installed with SECCOMP_FILTER_FLAG_SPEC_ALLOW.

    Where the kernel's default is spec_store_bypass_disable=seccomp (4.17 to 5.15), a filter without
    it forces Speculative Store Bypass Disable on every process in an exclave (DESIGN.md 16.5). A
    program at the border and one it spawns report what a native one does; on a kernel that never
    forces it the lines agree either way, so the matrix's older rows are the test.
    """

    def lines(text: str) -> list[str]:
        return [line for line in text.splitlines() if line.startswith("Speculation")]

    rc, native, err = run(["cat", "/proc/self/status"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, f"native cat: {err!r}")
    rc, border, err = run([wrapper(ctx, "cat"), "/proc/self/status"], cwd=ctx.work, env=ctx.env)
    expect(
        rc == 0 and lines(border) == lines(native),
        f"at the border: {lines(border)!r}, natively {lines(native)!r} {err!r}",
    )
    rc, child, err = run(
        [wrapper(ctx, "sh"), "-c", "cat /proc/self/status"], cwd=ctx.work, env=ctx.env
    )
    expect(
        rc == 0 and lines(child) == lines(native),
        f"in a spawned child: {lines(child)!r}, natively {lines(native)!r} {err!r}",
    )


@test
def environment(ctx: Ctx) -> None:
    env = dict(
        ctx.env,
        LD_PRELOAD="/nonexistent",
        LD_LIBRARY_PATH="/x",
        GCONV_PATH="/x",
        LOCPATH="/x",
        EXCLAVE_TESTVAR="1",
    )
    rc, out, _err = run([wrapper(ctx, "env")], cwd=ctx.work, env=env)
    expect(
        rc == 0 and "LD_" not in out and "GCONV_PATH" not in out and "LOCPATH" not in out,
        "denied variables leaked: " + out,
    )
    expect("EXCLAVE_TESTVAR=1" in out, "pass-through lost")
    rc, out, _err = run([wrapper(ctx, "env")], cwd=ctx.work, env={})
    expect("PATH=/usr/local/bin:/usr/bin:/bin\n" in out, f"default PATH: {out!r}")
    rc, out, _err = run(
        [wrapper(ctx, "env")], cwd=ctx.work, env=dict(ctx.env, PATH="/home/x/bin:/opt/tools/bin")
    )
    expect(
        "PATH=/usr/local/bin:/usr/bin:/bin\n" in out,
        f"PATH is the exclave's, not the host's: {out!r}",
    )
    rc, out, _err = run([wrapper(ctx, "sh"), "-c", "LD_FOO=1 env"], cwd=ctx.work, env=ctx.env)
    expect("LD_FOO=1" in out, "inside an exclave the environment must pass untouched")
    # 6.2: four values are the exclave's at the border, always the same; the user's are dropped
    loud = dict(
        ctx.env,
        LANG="en_GB.UTF-8",
        LC_ALL="de_DE.UTF-8",
        LC_TIME="fr_FR.UTF-8",
        LANGUAGE="de",
        TZ="Asia/Tokyo",
        SHELL="/usr/bin/zsh",
    )
    rc, out, _err = run([wrapper(ctx, "env")], cwd=ctx.work, env=loud)
    lines = set(out.splitlines())
    expect(
        {"LANG=C.UTF-8", "TZ=UTC0", "SHELL=/bin/sh", "PATH=/usr/local/bin:/usr/bin:/bin"} <= lines,
        "the four constants: {!r}".format(
            sorted(line for line in lines if line.split("=")[0] in ("LANG", "TZ", "SHELL", "PATH"))
        ),
    )
    expect(
        not any(line.startswith(("LC_", "LANGUAGE=")) for line in lines),
        "LC_* and LANGUAGE must be dropped: {!r}".format(
            sorted(line for line in lines if line.startswith(("LC_", "LANGUAGE")))
        ),
    )
    rc, out, _err = run(
        [wrapper(ctx, "sh"), "-c", "LANG=C TZ=Europe/Paris env | grep -E '^(LANG|TZ)='"],
        cwd=ctx.work,
        env=loud,
    )
    expect(
        sorted(out.split()) == ["LANG=C", "TZ=Europe/Paris"],
        f"past the border a wrapper script may set its own: {out!r}",
    )
    rc, out, _err = run(
        [
            wrapper(ctx, "sh"),
            "-c",
            "printf 'caf\\303\\251' | wc -m; echo b a | tr ' ' '\\n' | sort | head -1",
        ],
        cwd=ctx.work,
        env=loud,
    )
    expect(out == "4\na\n", f"C.UTF-8 counts characters and sorts by code point: {out!r}")
    rc, out, _err = inside(ctx, ctx.vbin("env"))
    expect(rc == 0 and "EXCLAVE_EXEC" not in out, "EXCLAVE_EXEC leaked: " + out)


@test
def positional_entry(ctx: Ctx) -> None:
    """7.2: `.exclave/launcher PROGRAM ARGS...` runs PROGRAM inside the exclave.

    PROGRAM has its own argv, cmdline and comm, and is named by an absolute or a relative path;
    EXCLAVE_EXEC is the launcher's own protocol and is never an interface.
    """
    rc, out, err = run([ctx.launcher, "./progs/exec", "self"], cwd=ctx.work, env=ctx.env)
    expect(
        rc == 0 and out == "child ok argv0=./progs/exec\n",
        f"relative program path: {out!r} {err!r}",
    )
    rc, out, err = run(
        [
            ctx.launcher,
            "/bin/sh",
            "-c",
            "cat /proc/$$/comm; tr '\\0' '\\n' < /proc/$$/cmdline | head -1",
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(out == "sh\n/bin/sh\n", f"cmdline and comm are the program's: {out!r} {err!r}")
    rc, out, err = run([ctx.launcher, ctx.vbin("env")], cwd=ctx.work, env=ctx.env)
    expect(
        rc == 0 and "EXCLAVE_EXEC" not in out and "PATH=/usr/local/bin:/usr/bin:/bin" in out,
        "the border policy applies after the re-exec and EXCLAVE_EXEC never reaches the program: "
        f"{out!r}",
    )
    rc, out, err = run([ctx.launcher], cwd=ctx.work, env=ctx.env)
    expect(rc == 127 and "PROGRAM" in err, f"no program named: rc={rc} {err!r}")
    rc, out, err = run([ctx.launcher, "/nonexistent/prog"], cwd=ctx.work, env=ctx.env)
    expect(rc == 127 and "/nonexistent/prog" in err, f"a missing program is named: {err!r}")
    rc, out, err = run([ctx.launcher, "progs/../progs/exec", "self"], cwd=ctx.work, env=ctx.env)
    expect(
        rc == 0 and out == "child ok argv0=progs/../progs/exec\n",
        f"argv[0] is the path as given: {out!r} {err!r}",
    )
    # a wrapper named through an absolute link of the tree runs the tree's program, though the
    # kernel would follow that link on the host, from outside and from inside alike
    ex2 = os.path.join(ctx.work, "entry-link.exclave")
    copy_exclave(ctx.exclave, ex2)
    # named cat, as busybox picks its applet by the name
    os.makedirs(os.path.join(ex2, "tree", "opt", "entry-link"))
    os.symlink(ctx.vbin("cat"), os.path.join(ex2, "tree", "opt", "entry-link", "cat"))
    tree2 = os.path.realpath(os.path.join(ex2, "tree"))
    entry = os.path.join(ex2, ".exclave", "launcher")
    for how, cmd in (
        ("outside", [entry, "/opt/entry-link/cat", "/proc/self/maps"]),
        (
            "inside",
            [
                os.path.join(ex2, "tree", ctx.vbin("sh").lstrip("/")),
                "-c",
                f"{entry} /opt/entry-link/cat /proc/self/maps",
            ],
        ),
    ):
        rc, out, err = run(cmd, cwd=ctx.work, env=ctx.env)
        expect(
            rc == 0 and tree2 + "/" in out,
            f"an absolute link through the entry, from {how}: rc={rc} {out[:300]!r} {err!r}",
        )
    # the entry makes the checks an exec inside makes, with a shell's exit status
    nx = os.path.join(ctx.work, "exec644")
    shutil.copy2(os.path.join(ctx.progs, "exec"), nx)
    os.chmod(nx, 0o644)
    rc, out, err = run([ctx.launcher, nx, "self"], cwd=ctx.work, env=ctx.env)
    expect(
        rc == 126 and "Permission denied" in err and "child ok" not in out,
        f"a file without execute permission is refused as inside: rc={rc} {err!r}",
    )
    rc, out, err = run([ctx.launcher, ctx.work], cwd=ctx.work, env=ctx.env)
    expect(rc == 126 and "Permission denied" in err, f"a directory: rc={rc} {err!r}")
    dp = os.path.join(ctx.work, "dp-entry.exclave")
    copy_exclave(ctx.exclave, dp)
    os.makedirs(os.path.join(dp, "tree", "opt", "sdk", "bin"))
    shutil.copy2(
        os.path.join(ctx.progs, "exec"), os.path.join(dp, "tree", "opt", "sdk", "bin", "prog")
    )
    with open(os.path.join(dp, ".exclave", "manifest"), "wb") as f:
        f.write(b'exclave 1\n\ndata "/opt/sdk"\n')
    rc, out, err = run(
        [os.path.join(dp, ".exclave", "launcher"), "/opt/sdk/bin/prog", "self"],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        rc == 126 and "Permission denied" in err and "child ok" not in out,
        f"a program under a data directory is never executed (6.2): rc={rc} {out!r} {err!r}",
    )
    # EXCLAVE_EXEC in anyone's environment is inert for a wrapper, from outside and from inside
    rc, out, err = run(
        [wrapper(ctx, "echo"), "still echo"],
        cwd=ctx.work,
        env=dict(ctx.env, EXCLAVE_EXEC=ctx.vbin("env")),
    )
    expect(
        rc == 0 and out == "still echo\n",
        f"EXCLAVE_EXEC from the host must not replace a wrapped program: {out!r} {err!r}",
    )
    rc, out, err = run(
        [
            wrapper(ctx, "sh"),
            "-c",
            "export EXCLAVE_EXEC={}; {} still echo".format(ctx.vbin("env"), ctx.vbin("echo")),
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        rc == 0 and out == "still echo\n",
        f"EXCLAVE_EXEC exported inside must not replace a wrapped program: {out!r} {err!r}",
    )
    # the exclave's own launcher runs from inside its exclave (another launcher, 7.4.5)
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "{} {} from inside".format(ctx.launcher, ctx.vbin("echo"))],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        rc == 0 and out == "from inside\n",
        f"the launcher exec'd from inside: rc={rc} {out!r} {err!r}",
    )
    # a wrapped program started through the entry is exec'd as its wrapper, so its identity is
    # the kernel's
    rc, out, err = run(
        [
            ctx.launcher,
            ctx.vbin("sh"),
            "-c",
            # two commands: bash would exec a lone one
            "readlink /proc/$$/exe; true",
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out == ctx.sh_exe + "\n",
        f"a wrapper through the entry keeps the wrapper's identity: {out!r} {err!r}",
    )
    p = subprocess.Popen([ctx.launcher, ctx.vbin("sleep"), "2"], cwd=ctx.work, env=ctx.env)
    time.sleep(0.5)
    exe = os.readlink(f"/proc/{p.pid}/exe")
    p.kill()
    p.wait()
    expect(
        exe == os.path.realpath(wrapper(ctx, "sleep")),
        f"from outside, exe names the wrapper, not the launcher: {exe!r}",
    )


@test
def cross_exclave_distinct_launchers(ctx: Ctx) -> None:
    """7.4.5: a program in another exclave is exec'd as that exclave's launcher.

    A program in another exclave, whose launcher is a different file, is exec'd as that launcher,
    which then serves its own tree inside the first exclave's filter.
    """
    ex2 = os.path.join(ctx.work, "exclave2")
    copy_exclave(ctx.exclave, ex2)
    padded = os.path.join(ctx.work, "launcher2")
    with open(padded, "wb") as f:
        # a different file of a different size, still the launcher
        f.write(read_bytes(ctx.launcher) + b"\0" * 64)
    os.chmod(padded, 0o755)
    tree.relink(ex2, padded)
    rc, out, err = run([*TOOL, "check", ex2])
    expect(rc == 0, "exclave2 check: " + out[-300:] + err[-300:])
    true2 = os.path.join(ex2, "tree", ctx.vbin("true").lstrip("/"))
    sh2 = ex2 + "/tree" + ctx.vbin("sh")
    rc, out, err = run(
        [
            wrapper(ctx, "sh"),
            "-c",
            f"{true2} && {sh2} -c 'echo cross $0 && readlink /proc/self/exe'",
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        rc == 0 and out == "cross {}\n{}\n".format(sh2, ctx.vreal(ctx.vbin("readlink"))),
        f"cross-exclave exec: rc={rc} {out!r} {err!r}",
    )
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", f"cd {ex2} && tree{ctx.vbin(ctx.gcc)} --version | head -1"],
        cwd=ctx.work,
        env=ctx.env,
    )
    _rc0, out0, _ = run([wrapper(ctx, ctx.gcc), "--version"], cwd=ctx.work, env=ctx.env)
    # gcc prints argv[0] first
    expect(
        rc == 0 and out.split("(", 1)[-1] == out0.split("\n", 1)[0].split("(", 1)[-1] + "\n",
        f"gcc of the other exclave: rc={rc} {out!r} {err!r}",
    )


@test
def nested_older_launcher(ctx: Ctx) -> str | None:
    """7.4.2: an older launcher nested in a newer one answers ENOSYS for a trap it does not know.

    An older launcher nested inside a newer one reuses the newer filter and answers ENOSYS for a
    trap it does not know, never re-issuing it to the host. build/launcher-old is the current
    launcher built at filter version 3, without version 4's bind and connect in its filter or
    handler (scripts/build builds it beside build/launcher). Across the syscall page's move (filter
    version 6) neither direction can run, and each is refused by name: this launcher under a filter
    older than 6, and a launcher whose note has the old page generation exec'd from inside.
    """
    old = os.path.join(os.path.dirname(ctx.launcher_src), "launcher-old")
    if not os.path.exists(old):
        return "no build/launcher-old"
    src = os.path.join(ctx.work, "nb.c")
    sock = f"nest-sock-{os.getpid()}"  # relative to the work directory, whatever its depth
    with open(src, "w") as f:  # a bind at a fresh host path: 0 from the kernel
        f.write(
            "#include <stdio.h>\n#include <errno.h>\n#include <string.h>\n#include <unistd.h>\n"
            "#include <sys/socket.h>\n#include <sys/un.h>\n"
            "int main(void) { struct sockaddr_un a; memset(&a, 0, sizeof a); "
            'a.sun_family = AF_UNIX; strncpy(a.sun_path, "@PATH@", sizeof a.sun_path - 1);\n'
            ' int s = socket(AF_UNIX, SOCK_STREAM, 0); unlink("@PATH@"); '
            "long r = bind(s, (struct sockaddr *)&a, sizeof a);\n"
            ' printf("%d %d\\n", r < 0 ? -1 : 0, r < 0 ? errno : 0); unlink("@PATH@"); '
            "return 0; }\n".replace("@PATH@", sock)
        )
    prog = os.path.join(ctx.work, "nb")
    rc, out, err = run([wrapper(ctx, ctx.gcc), "-O0", "-o", prog, src], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "compile: " + err)
    kernel = "0 0\n"
    rc, outer, err = run([wrapper(ctx, "sh"), "-c", prog], cwd=ctx.work, env=ctx.env)
    expect(
        rc == 0 and outer == kernel,
        "inside the current launcher the kernel's answer comes back: "
        f"kernel {kernel!r} exclave {outer!r} {err!r}",
    )
    ex2 = os.path.join(ctx.work, "old-exclave")
    copy_exclave(ctx.exclave, ex2)
    tree.relink(ex2, old)
    log = os.path.join(ctx.work, "nested-old.log")
    rc, inner, err = run(
        [wrapper(ctx, "sh"), "-c", "{}/tree{} -c {}".format(ex2, ctx.vbin("sh"), prog)],
        cwd=ctx.work,
        env=dict(ctx.env, EXCLAVE_LOG=log),
    )
    expect(
        rc == 0 and inner == "-1 38\n",
        "the older launcher nested in the newer one answers ENOSYS (38) for the trap it does not "
        f"know: {inner!r} {err!r}",
    )
    text = read_text(log)
    expect(
        f"launcher 0 inside {prog}" in text
        and "trap -38 -" in text
        and "border" not in text.split("launcher 0 inside", 1)[1],
        f"the inner launcher reused the newer filter and answered the trap itself: {text[-400:]!r}",
    )
    # the page's move: this launcher under launcher-old's version-3 filter refuses before its first
    # trapped syscall
    rc, out, err = run(
        [
            os.path.join(ex2, "tree", ctx.vbin("sh").lstrip("/")),
            "-c",
            "{}; echo rc=$?".format(wrapper(ctx, "true")),
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out == "rc=127\n" and "from before the syscall page moved runs this process" in err,
        f"under a filter older than 6: {out!r} {err!r}",
    )
    # and a launcher whose note says page generation 1, exec'd from inside, is refused by this
    # launcher's child
    gen1 = os.path.join(ctx.work, "launcher-gen1")
    blob = read_bytes(ctx.launcher_src)
    # its own note and the earlier name's
    notes = [(n, n + struct.pack("<I", 2)) for n in (b"exclave\0", b"cont\0\0\0\0")]
    expect(
        all(blob.count(w) == 1 for n, w in notes),
        "each note's page generation is found once in the launcher",
    )
    for n, w in notes:
        blob = blob.replace(w, n + struct.pack("<I", 1))
    with open(gen1, "wb") as f:
        f.write(blob + b"\0")  # a byte more: a launcher of its own size, not a copy of this one
    os.chmod(gen1, 0o755)
    ex3 = os.path.join(ctx.work, "gen1-exclave")
    copy_exclave(ctx.exclave, ex3)
    tree.relink(ex3, gen1)
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "{}/tree{}; echo rc=$?".format(ex3, ctx.vbin("true"))],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out == "rc=127\n" and "from before the syscall page moved cannot run here" in err,
        f"a launcher of page generation 1 from inside: {out!r} {err!r}",
    )
    return None


@test
def earlier_note_name(ctx: Ctx) -> None:
    """A launcher carries its note under two names, exclave and cont.

    The second is the name an opener from before the rename looks for, so that each runs the other
    as another launcher; a launcher whose only note is cont, as an opener's is, runs from inside
    this one. Without the cont note such an opener loads a launcher as a program, which then finds
    the syscall page taken and refuses: measured both ways against such an opener.
    """
    gen = struct.pack("<I", 2)
    blob = read_bytes(ctx.launcher_src)
    expect(
        blob.count(b"cont\0\0\0\0" + gen) == 1 and blob.count(b"exclave\0" + gen) == 1,
        "both notes, at page generation 2",
    )
    only = os.path.join(ctx.work, "launcher-exclave-only")
    with open(only, "wb") as f:
        # a byte more: a launcher of its own size, not a copy of this one
        f.write(blob.replace(b"exclave\0" + gen, b"exclavx\0" + gen) + b"\0")
    os.chmod(only, 0o755)
    ex3 = os.path.join(ctx.work, "note-exclave")
    copy_exclave(ctx.exclave, ex3)
    tree.relink(ex3, only)
    _rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "{}/tree{}; echo rc=$?".format(ex3, ctx.vbin("true"))],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out == "rc=0\n", f"a launcher known by the cont note alone, from inside: {out!r} {err!r}"
    )
    # and the mirror, which a launcher of a later revision without the earlier name would be
    only = os.path.join(ctx.work, "launcher-exclave-only")
    with open(only, "wb") as f:
        # two bytes more: its own size
        f.write(blob.replace(b"cont\0\0\0\0" + gen, b"conx\0\0\0\0" + gen) + b"\0\0")
    os.chmod(only, 0o755)
    note_copy = os.path.join(ctx.work, "exclave-note-copy")
    copy_exclave(ctx.exclave, note_copy)
    tree.relink(note_copy, only)
    _rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "{}/tree{}; echo rc=$?".format(note_copy, ctx.vbin("true"))],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out == "rc=0\n", f"a launcher known by the exclave note alone, from inside: {out!r} {err!r}"
    )


@test
def sigsys_blocked_at_launch(ctx: Ctx) -> None:
    def block() -> None:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGSYS})

    rc, out, err = run(
        [wrapper(ctx, ctx.gcc), "--version"], cwd=ctx.work, env=ctx.env, preexec=block
    )
    expect(rc == 0 and out.strip(), f"launch with SIGSYS blocked: rc={rc} {err!r}")


@test
def kill_sys(ctx: Ctx) -> None:
    rc, _out, err = run([wrapper(ctx, "sh"), "-c", "kill -SYS $$"], cwd=ctx.work, env=ctx.env)
    expect(rc == -signal.SIGSYS, f"kill -SYS: rc={rc} {err!r}")


@test
def adversarial(ctx: Ctx) -> None:
    """17.4: what a hostile program or a fuzzer would try, each case answered in microseconds.

    Arguments with bits above the word where the kernel takes an int (the probe compares the
    answers; this checks the buffer past the count): a readlink size of zero or minus one as an int
    must not have the handler write past the program's buffer; the launcher's own variables set
    before an exec, dropped; a working directory deleted under the program, its . and .. kept; an
    exec with no descriptor to spare, which the handler borrows against a soft limit and which a
    hard limit refuses (13); mounts and roots from inside, refused by the filter (7.4.2); SIGSYS
    ignored, handled or on a signalfd; magic links under /proc/1; interpreter loops and chains; an
    empty executable and a loader that is a directory. A second batch: a descriptor with no path
    handed to exec (a pipe or a socket is EACCES, only a regular file is run), a hard link across
    the border (EXDEV), a symlink chain at the kernel's limit of forty and one past it, the
    read-only rule from other angles (mknod, ftruncate and a shared writable mapping of a read-only
    descriptor, a device node), odd process shapes (CLONE_FS, CLONE_FILES, not dumpable,
    PER_LINUX32, a vfork child, a handler on an alternate stack), the cache saturated and a huge
    environment, io_uring and clone3 refused by the filter, and an execute-only file the loader
    cannot read (EACCES, a limitation). The kernel under bwrap measured the answers, but for the
    variables, the mounts, the hard limit, the filter's refusals and the execute-only files, which
    are the launcher's own.
    """
    d = os.path.join(ctx.work, "advhost")
    # the interpreter chains' #! lines, which a deep work directory would outgrow
    short = f"/tmp/exclave-adv-{os.getpid()}"
    for p in (d, short):
        shutil.rmtree(p, ignore_errors=True)
        os.makedirs(p)
    try:
        rc, out, err = inside(
            ctx,
            os.path.join(ctx.progs, "adversarial"),
            [d, short],
            env=dict(ctx.env, SH=ctx.vbin("sh")),
        )
    finally:
        shutil.rmtree(short, ignore_errors=True)
    expect(rc == 0, f"adversarial: rc={rc} {out!r} {err!r}")
    lines = set(out.splitlines())
    want = [
        "readlink size 1 with upper bits: 1 byte, buffer intact",
        "readlink size -1 as int: EINVAL, buffer intact",
        "readlink size 0 as int: EINVAL, buffer intact",
        "readlinkat AT_FDCWD with upper bits: ok",
        "openat dfd with upper bits: ok",
        "utimensat host, flags upper bits only: ok",
        "utimensat exclave, flags upper bits only: EROFS",
        "faccessat2 exclave, flags upper bits only: ok",
        "newfstatat exclave, flags upper bits only: ok",
        "getcwd size all ones: ok",
        "getcwd size 4 with upper bits: ok",
        "renameat2 flags upper bits only: ok",
        "unlinkat flags upper bits only: ok",
        "bind exclave path, addrlen upper bits: EROFS",
        "connect exclave socket, addrlen upper bits: ECONNREFUSED",
        "openat2 size with upper bits: errno=7",
        "exec of a host ELF with EXCLAVE_* set: ran, exit 0",
        "child sees EXCLAVE_EXEC=unset EXCLAVE_EXECFN=unset EXCLAVE_COMM=unset",
        (
            "wrapper with EXCLAVE_* set: comm=sh "
            "EXCLAVE_EXEC=unset EXCLAVE_EXECFN=unset EXCLAVE_COMM=unset"
        ),
        "deleted cwd: getcwd: ENOENT",
        "deleted cwd: stat .: ok",
        "deleted cwd: open .: ok",
        "deleted cwd: stat ../f: ok",
        "deleted cwd: mkdir x: ENOENT",
        "deleted cwd: open x O_CREAT: ENOENT",
        "no fd left: exec exclave true: ran",
        "no fd left: exec host ELF: ran",
        "no fd left: exec host script: ran",
        "no fd left, hard limit too: exec exclave true: EMFILE",
        "unshare user+mount: ok",
        "mount tmpfs inside: EPERM",
        "chroot inside: EPERM",
        "open_tree: ENOSYS",
        "mount_setattr: ENOSYS",
        "stat with SIGSYS ignored: ok",
        "stat with a SIGSYS handler installed: ok",
        "program's SIGSYS handler ran: no",
        "stat with SIGSYS blocked and on a signalfd: ok",
        "signalfd delivered a SIGSYS: no",
        "stat /proc/1/root/etc: EACCES",
        "stat /proc/1/root: EACCES",
        "lstat /proc/1/root: ok",
        "open /proc/1/cwd: EACCES",
        "readlink /proc/1/exe: EACCES",
        "exec of a script that is its own interpreter: ELOOP",
        "exec of a chain of 3 scripts: ran, exit 0",
        "exec of a chain of 4 scripts: ran, exit 0",
        "exec of a chain of 5 scripts: ran, exit 0",
        "exec of a chain of 6 scripts: ELOOP",
        "exec of a script with an empty #! line: ENOEXEC",
        "exec of an empty executable: ENOEXEC",
        "exec of an ELF whose loader is a directory: EACCES",
        # the second batch: descriptors with no path given to exec, the read-only rule from other
        # angles, odd process shapes, saturation
        "exec with 0, 1 and 2 closed: ran, exit 0",
        "traps with 0, 1 and 2 closed: stat ok, open ok, readlink ok",
        "fexecve of a pipe: EACCES",
        "fexecve of a socket: EACCES",
        "fexecve of /dev/null: EACCES",  # only a regular file is exec'd (do_open_execat)
        "linkat an exclave file by /proc/self/fd to a host name: errno=18",
        # a link across the border is EXDEV
        "linkat an exclave file by empty path to a host name: errno=18",
        "a chain of 40 symlinks: ok",
        "a chain of 41 symlinks: ELOOP",
        "readlink /proc/self/task/tid/exe: the program",
        "stat /proc/self/root/usr/share/exclave-test-marker: ok",
        "a path of 4000 slashes then an exclave file: ok",
        "mknod a char device in the exclave: EROFS",
        "ftruncate a read-only exclave descriptor: EINVAL",
        "mmap PROT_WRITE MAP_SHARED of a read-only exclave descriptor: EACCES",
        "utimensat exclave descriptor NULL path, NOW and OMIT: EROFS",
        "open an exclave file O_PATH with O_WRONLY: ok",
        "truncate /dev/null: EINVAL",
        "unshare CLONE_FS then chdir into the exclave: ok, ok, getcwd /usr/share",
        "unshare CLONE_FILES then trap: ok, stat ok, open ok",
        "not dumpable: stat ok, readlink exe ok",
        "PER_LINUX32 then exec of a wrapper: ran, exit 0",
        "a vfork child that traps and exits: child ok, parent after ok",
        "a trap from a handler on a 16 KB alternate stack: ok",
        "io_uring_setup: ENOSYS",
        "clone3: ENOSYS",  # the filter refuses them (7.4.2); the kernel would answer EINVAL
        "openat on a descriptor of a directory renamed meanwhile: ok",
        (
            "20000 absent exclave paths then a present and an absent one: "
            "0 wrong, present ok, absent ENOENT"
        ),
        "exec of a wrapper with 50000 environment entries: ran, exit 0",
        "exec with a bad pointer among argv: EFAULT",
        "readlink whose write crosses into an unmapped page: EFAULT",
        "exec of an ELF with mode 0111: EACCES",
        # the loader reads what it runs; execute-only is a limitation (13)
        "exec of a script with mode 0111: EACCES",
        "exec of a script whose interpreter is relative: ran, exit 0",
        # the #! remainder is one argument, not two
        "exec of a script whose #! has two options: one argument, the shell rejected it",
        "exec of a wrapper with an empty environment: ran, exit 0",
    ]
    if os.getuid() == 0:
        # root follows init's links and reads an execute-only file
        want = [w for w in want if "/proc/1" not in w and "mode 0111" not in w]
    lacks = {
        # 5.8 and later
        "faccessat2 exclave, flags upper bits only: ok": (
            "faccessat2 exclave, flags upper bits only: ENOSYS"
        ),
        # a kernel or host without user namespaces: any refusal is its own
        "unshare user+mount: ok": None,
    }
    bad = []
    for w in want:
        if w in lines:
            continue
        if w in lacks and (
            lacks[w] in lines
            if lacks[w]
            else any(line.startswith(w.split(": ")[0] + ": ") for line in lines)
        ):
            continue
        bad.append(w)
    expect(
        not bad,
        "missing or different: "
        + "; ".join(bad)
        + "\n     got: "
        + out.strip().replace("\n", "\n          "),
    )
    # the descriptor room the launcher borrows at startup (7.4.5) is the program's again by the time
    # it runs, through the positional entry's re-exec and its exec of a wrapper alike
    hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    rc, out, err = run(
        [ctx.launcher, ctx.vbin("sh"), "-c", "ulimit -n"],
        cwd=ctx.work,
        env=ctx.env,
        preexec=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (8, hard)),
    )
    expect(
        out.strip() == "8",
        f"a wrapper run through the entry under a soft limit of 8 sees {out.strip()!r} "
        f"(rc={rc} {err!r}): the borrowed room was not given back",
    )
