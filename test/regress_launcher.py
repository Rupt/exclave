"""The launcher and its filter: a group of the regression suite (DESIGN.md 17 item 4).

Run by test/run.py, on the fixtures test/suite.py makes.
"""

import os
import re
import shutil
import signal
import struct
import subprocess
import time
lazy import resource

import kernel_answers
import tree
from harness import expect, read_bytes, read_text, run, skip, test
from suite import VOLATILE, Ctx, copy_exclave, inside, wrapper


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


# 6.2: the variables the border drops, which steer the loader or libc to host files; LD_ is a
# prefix, the rest whole names
DROPPED = (
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_BIND_NOW",
    "LD_",
    "GLIBC_TUNABLES",
    "GCONV_PATH",
    "LOCPATH",
    "NLSPATH",
    "RESOLV_HOST_CONF",
    "HOSTALIASES",
    "TZDIR",
    "GCC_EXEC_PREFIX",
    "COMPILER_PATH",
    "LIBRARY_PATH",
)
# names beside them that pass: no LD_ prefix, or a dropped name with more after it
PASSED = ("LDFLAGS", "GCONV_PATHS", "LIBRARY_PATHX", "TZDIRX", "EXCLAVE_TESTVAR")


@test
def environment(ctx: Ctx) -> None:
    """6.2: the border drops each variable of its list by its whole name, or LD_ by its prefix.

    Every other variable passes through, four are the exclave's own values, and inside the border
    nothing is touched.
    """
    env = dict(ctx.env, **dict.fromkeys(DROPPED, "/x"), **dict.fromkeys(PASSED, "kept"))
    rc, out, err = run([wrapper(ctx, "env")], cwd=ctx.work, env=env)
    names = {line.split("=", 1)[0] for line in out.splitlines()}
    expect(rc == 0, f"env at the border: rc={rc} {err!r}")
    expect(not names & set(DROPPED), f"dropped variables passed: {sorted(names & set(DROPPED))}")
    expect(
        {f"{n}=kept" for n in PASSED} <= set(out.splitlines()),
        f"variables to pass were lost: {sorted(set(PASSED) - names)}",
    )
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
    # 6.2: three values are the exclave's at the border, always the same, and TZ is dropped with
    # the user's locale
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
        {"LANG=C.UTF-8", "SHELL=/bin/sh", "PATH=/usr/local/bin:/usr/bin:/bin"} <= lines,
        "the three constants: {!r}".format(
            sorted(line for line in lines if line.split("=")[0] in ("LANG", "SHELL", "PATH"))
        ),
    )
    expect(
        not any(line.startswith(("LC_", "LANGUAGE=", "TZ=")) for line in lines),
        "LC_*, LANGUAGE and TZ must be dropped: {!r}".format(
            sorted(line for line in lines if line.startswith(("LC_", "LANGUAGE", "TZ=")))
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
    # an environment of 100 000 variables, which the kernel takes, passes whole at the border,
    # through the positional entry and across an exec inside: nothing the launcher sizes from it
    # has a fixed bound
    big = {f"V{i}": "1" for i in range(100_000)}
    for how, cmd in (
        ("a wrapper", [wrapper(ctx, "env"), ctx.vbin("env")]),
        ("the positional entry", [ctx.launcher, ctx.vbin("env"), ctx.vbin("env")]),
    ):
        rc, out, err = run(cmd, cwd=ctx.work, env=big)
        lost = {f"V{i}=1" for i in range(100_000)} - set(out.splitlines())
        expect(
            rc == 0 and not lost, f"100 000 variables through {how}: {rc}, {len(lost)} lost {err}"
        )


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
    copy_exclave(ctx.mini, ex2)
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
    # the entry's process becomes the wrapper's once it has exec'd it: polled until it has
    want = os.path.realpath(wrapper(ctx, "sleep"))
    p = subprocess.Popen([ctx.launcher, ctx.vbin("sleep"), "5"], cwd=ctx.work, env=ctx.env)
    try:
        deadline, exe = time.monotonic() + 5, ""
        while exe != want and time.monotonic() < deadline:
            exe = os.readlink(f"/proc/{p.pid}/exe")
            time.sleep(0.002)
    finally:
        p.kill()
        p.wait()
    expect(exe == want, f"from outside, exe names the wrapper, not the launcher: {exe!r}")


@test
def cross_exclave_distinct_launchers(ctx: Ctx) -> None:
    """7.4.5: a program in another exclave is exec'd as that exclave's launcher.

    A program in another exclave, whose launcher is a different file, is exec'd as that launcher,
    which then serves its own tree inside the first exclave's filter: it reads a file only the
    second tree has, and /proc/self/maps names the second tree's files, by an absolute path and by
    a relative one. A program served by the first exclave's launcher or tree would find no such
    file and map the first tree's.
    """
    ex2 = os.path.join(ctx.work, "exclave2")
    copy_exclave(ctx.mini, ex2)
    padded = os.path.join(ctx.work, "launcher2")
    with open(padded, "wb") as f:
        # a different file of a different size, still the launcher
        f.write(read_bytes(ctx.launcher) + b"\0" * 64)
    os.chmod(padded, 0o755)
    tree.relink(ex2, padded)
    # a new file, not a write through the hard links the copy shares with the first tree
    which = "/usr/share/exclave-test-which"
    with open(os.path.join(ex2, "tree", which.lstrip("/")), "w") as f:
        f.write("second\n")
    tree2 = os.path.realpath(os.path.join(ex2, "tree"))
    true2 = os.path.join(ex2, "tree", ctx.vbin("true").lstrip("/"))
    sh2 = ex2 + "/tree" + ctx.vbin("sh")
    show = f"cat {which}; grep -c {tree2}/ /proc/self/maps"
    for how, cmd, argv0 in (
        ("by its absolute path", f"{true2} && {sh2} -c 'echo $0; {show}'", sh2),
        (
            "by a relative path",
            f"cd {ex2} && tree{ctx.vbin('sh')} -c 'echo $0; {show}'",
            "tree" + ctx.vbin("sh"),
        ),
    ):
        rc, out, err = run([wrapper(ctx, "sh"), "-c", cmd], cwd=ctx.work, env=ctx.env)
        lines = out.splitlines()
        maps = lines[2] if len(lines) == 3 else ""
        expect(
            rc == 0 and lines[:2] == [argv0, "second"] and maps.isdigit() and int(maps) > 0,
            f"the other exclave's shell {how} reads its own tree's file and maps its own tree's "
            f"files: rc={rc} {out!r} {err!r}",
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
        skip("no build/launcher-old")
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
    copy_exclave(ctx.mini, ex2)
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
        f"launcher 2 inside {prog}" in text
        and "trap -38 -" in text
        and "border" not in text.split("launcher 2 inside", 1)[1],
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
    notes = [(n, n + struct.pack("<I", 2)) for n in (b"exclave\0",)]
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
    copy_exclave(ctx.mini, ex3)
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
    cannot read (EACCES, a limitation). Last, the deepest handler paths on Rust's alternate stack,
    8 KB or AT_MINSIGSTKSZ above a guard page, which a vfork child shares: rustc is absent from
    most rows of the matrix, and this stands for the rust test there. The kernel under bwrap
    measured the answers, but for the variables, the mounts, the hard limit, the filter's refusals
    and the execute-only files, which are the launcher's own.
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
        "on Rust's alternate stack, a chain of 40 symlinks: ok",
        "on Rust's alternate stack, exec of a chain of 5 scripts: ran, exit 0",
        "on Rust's alternate stack, posix_spawn of a wrapper: ran, exit 0",
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


@test
def x28_kept_mid_trap(ctx: Ctx) -> str:
    """7.5.3: on aarch64 a signal landing in the launcher's handler finds the program's x28.

    Go without cgo keeps its goroutine in x28 and its preemption signal reads the register as it
    finds it. A program built -ffixed-x28, as Go's code is, holds a sentinel in x28 while bare svc
    calls trap under a 200 us timer; the timer's handler counts the reads that find another value,
    which the kernel's answer makes none, and the signals that landed outside the program, which
    must be some for the test to have tested anything. On x86-64 Go reloads its goroutine from
    thread-local storage, and the rule has nothing to keep.
    """
    if ctx.machine != "aarch64":
        skip("aarch64 only: x86-64's Go reloads its goroutine from thread-local storage")
    exe = os.path.join(ctx.work, "x28")
    rc, _out, err = run(
        [
            wrapper(ctx, ctx.gcc),
            "-O1",
            "-ffixed-x28",
            "-o",
            exe,
            os.path.join(ctx.work, "src", "x28.c"),
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(rc == 0, "compile with x28 reserved: " + err[-600:])
    rc, out, err = inside(ctx, exe)
    m = re.fullmatch(
        r"x28: (\d+) signals, (\d+) outside the program, (\d+) read another value, "
        r"(\d+) traps failed\n",
        out,
    )
    expect(
        rc == 0 and m is not None and m[3] == "0" and m[4] == "0" and int(m[2]) > 0,
        f"x28 across signals that land mid-trap: rc={rc} {out!r} {err!r}",
    )
    assert m is not None  # for the type checker: expect has failed otherwise
    return f"{m[1]} signals, {m[2]} of them outside the program"


@test
def shadow_stack_if_glibc_enables_it(ctx: Ctx) -> str | None:
    """13 item 49: a CET-marked program runs inside with the shadow-stack tunable set inside.

    The border drops GLIBC_TUNABLES (6.2), so env sets it inside, where it stays for the programs
    the exclave's programs run. The program takes a signal, runs a thread making trapped calls,
    longjmps across one and forks and execs, each on a shadow stack if glibc enabled one, and says
    whether it did. glibc 2.39 to 2.42 enable none, so the note says off; the day one does, the
    handler's paths run on a shadow stack here.
    """
    if ctx.machine != "x86_64":
        skip("x86-64 only")
    if ctx.musl:
        skip("musl enables no shadow stack")
    prog = os.path.join(ctx.progs, "shstk")
    rc, _out, err = run(
        [
            wrapper(ctx, ctx.gcc),
            "-O1",
            "-fcf-protection=full",
            "-pthread",
            "-o",
            prog,
            os.path.join(ctx.work, "src", "shstk.c"),
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    if rc:
        skip("the exclave's compiler takes no -fcf-protection: " + err[-100:])
    rc, out, err = inside(ctx, "/usr/bin/env", ["GLIBC_TUNABLES=glibc.cpu.x86_shstk=on", prog])
    expect(
        rc == 0 and out.count(" ok\n") == 4 and "FAIL" not in out,
        f"the marked program inside: rc={rc} {out!r} {err[-300:]!r}",
    )
    return "shadow stack " + ("on" if "shstk on" in out else "off, as glibc leaves it")


@test
def start_reads_once(ctx: Ctx) -> str | None:
    """16.4: a start reads what it needs of the tree once.

    A wrapper of true run from outside, under strace: no volatile top-level directory of the tree
    is opened, since the host owns it whatever the tree ships there (8.1 rule 3); the manifest is
    opened once and never stat'ed; each original, the program's and its loader's, is opened once,
    its headers read through that descriptor; and no real path is lstat'ed twice, since a
    classification makes its wrapper check from its own lstat.
    """
    if not shutil.which("strace"):
        skip("no strace")
    tr = os.path.join(ctx.work, f"start-{os.getpid()}.trace")
    rc, _out, err = run(
        [
            "strace",
            "-f",
            "-s",
            "4096",
            "-o",
            tr,
            "-e",
            "trace=openat,newfstatat,stat,lstat",
            wrapper(ctx, "true"),
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(rc == 0, f"true under strace: {err!r}")
    root = os.path.realpath(ctx.root)
    manifest = os.path.join(os.path.dirname(root), ".exclave", "manifest")
    opens: dict[str, int] = {}
    lstats: dict[str, int] = {}
    stats: list[str] = []
    with open(tr) as f:
        for line in f:
            m = re.search(r'\b(openat|newfstatat|stat|lstat)\((?:AT_FDCWD, )?"([^"]*)"(.*)', line)
            if not m:
                continue
            call, path, rest = m.groups()
            if call == "openat":
                opens[path] = opens.get(path, 0) + 1
            elif call == "lstat" or "AT_SYMLINK_NOFOLLOW" in rest:
                lstats[path] = lstats.get(path, 0) + 1
            else:
                stats.append(path)
    volatile = [p for p in opens if any(p == root + v for v in VOLATILE)]
    expect(not volatile, f"volatile top-level directories read: {volatile!r}")
    expect(opens.get(manifest) == 1, f"the manifest opened {opens.get(manifest, 0)} times")
    expect(manifest not in stats and manifest not in lstats, "the manifest stat'ed")
    originals = {p: n for p, n in opens.items() if "/.real/" in p}
    expect(len(originals) >= 1, f"no original opened: {sorted(opens)!r}")
    again = {p: n for p, n in originals.items() if n > 1}
    expect(not again, f"originals opened more than once: {again!r}")
    twice = {p: n for p, n in lstats.items() if n > 1}
    expect(not twice, f"real paths lstat'ed more than once: {twice!r}")
    return f"{len(originals)} originals, {sum(lstats.values())} lstats"


@test
def traceme_exec(ctx: Ctx) -> str | None:
    """7.4.5, 13 item 54: a child that asks to be traced and execs, as gdb and strace start one.

    A traced task's trapped execve stops for its tracer at the SIGSYS, before the handler runs, so
    a vfork child's PTRACE_TRACEME is deferred to its exec: gdb's vfork child would otherwise stop
    while gdb waits in vfork for that very exec, both for ever. The vfork cases are the kernel's
    answers, a second request's EPERM, an exec that fails before the one that runs, and a child that
    exits without one, measured under bwrap, but for the exec stops: the launcher's second exec
    (7.6) is one more, for the program's exec and for sh -c "exec PROGRAM" alike, the shell leaving
    it to the program. A fork child's request is made at once, since it may stop for its tracer
    before its exec, so its tracer's first stop after the exec is that SIGSYS where the kernel's is
    the SIGTRAP that follows the exec (13 item 54). Then, where the tree has a gdb, gdb runs a
    program to its end inside, its SIGSYS stops passed (13 item 1).
    """
    true = ctx.vbin("true")
    rc, out, _err = inside(ctx, os.path.join(ctx.progs, "traceme"), [true], timeout=120)
    # the kernel's answers but the exec stops: the exec that makes a deferred request is followed by
    # the launcher's second (7.6, 13 item 54), one stop more than the kernel's 1 and, through
    # sh -c "exec PROGRAM", its 2
    vfork = [
        "vfork-traceme-exec first stop: stopped TRAP",
        "vfork-traceme-exec exec stops: 2",
        "vfork-traceme-exec end: exited 0",
        "vfork-traceme-twice requests: 0, -1 EPERM",
        "vfork-traceme-twice first stop: stopped TRAP",
        "vfork-traceme-twice end: exited 0",
        "vfork-traceme-fail-exec first stop: stopped TRAP",
        "vfork-traceme-fail-exec end: exited 0",
        "vfork-traceme-exit end: exited 7",
        "vfork-exec end: exited 0",
        "vfork-traceme-shell first stop: stopped TRAP",
        "vfork-traceme-shell exec stops: 3",
        "vfork-traceme-shell end: exited 0",
    ]
    # 13 item 54: the kernel's first stop is TRAP, after a SIGSTOP of the child's own too
    launcher = [
        "fork-traceme-exec first stop: stopped SYS",
        "fork-traceme-exec end: exited 0",
        "fork-traceme-stop-exec first stop: stopped STOP",
        "fork-traceme-stop-exec second stop: stopped SYS",
        "fork-traceme-stop-exec end: exited 0",
    ]
    expect(
        rc == 0 and out.splitlines() == vfork + launcher, f"traced children's execs: rc={rc}\n{out}"
    )
    gdb = os.path.join(ctx.tree, "usr", "bin", "gdb")
    if not os.path.exists(gdb):
        return "the tree has no gdb: its run inside not checked"
    rc, out, err = run(
        [
            wrapper(ctx, "gdb"),
            "-batch",
            "-nx",
            "-iex",
            "handle SIGSYS nostop noprint pass",
            "-ex",
            "run",
            "--args",
            true,
        ],
        cwd=ctx.work,
        env=ctx.env,
        timeout=120,
    )
    expect(
        "exited normally" in out,
        f"gdb's run inside runs the program to its end: rc={rc} {out[-400:]!r} {err[-400:]!r}",
    )
    return None


@test
def tracer_reads_exe(ctx: Ctx) -> str | None:
    """7.6: a tracer reads its tracee's exe link as the kernel gives it; any other reader, 7.6's.

    gdb learns what it debugs from /proc/<pid>/exe at every exec, loads that file's symbols and
    auto-loads its .debug_gdb_scripts, which is how it gets the launcher's script. So the tracer
    of a program on the loader path reads the launcher, and of a wrapped program the launcher too,
    whose file the wrapper is, while a process that does not trace it reads the program's path.
    Then, where the tree has a gdb, gdb inside runs a wrapped program through the positional entry
    and stops at a breakpoint in the exclave's libc, the script loaded (13 item 1).
    """
    launcher = os.path.realpath(ctx.launcher)
    prog = os.path.join(ctx.progs, "tracer_exe")
    true = ctx.vbin("true")
    # the file the kernel runs for it, busybox in an Alpine tree
    tree_root = os.path.realpath(ctx.tree)
    true_file = "/" + os.path.relpath(os.path.realpath(ctx.tree + true), tree_root)
    for target, other, end in ((prog, prog, "end: exited 2"), (true, true_file, "end: exited 0")):
        rc, out, err = inside(ctx, prog, [target], timeout=60)
        expect(
            rc == 0 and out.splitlines() == [f"tracer: {launcher}", f"other: {other}", end],
            f"{target}: the tracer reads the launcher, another process the program: rc={rc}\n"
            f"{out}{err[-300:]}",
        )
    if not os.path.exists(os.path.join(ctx.tree, "usr", "bin", "gdb")):
        return "the tree has no gdb: its breakpoints inside not checked"
    hello = gdb_hello(ctx)
    # a program built inside, by the positional entry (13.1), and a wrapped one by its libc
    for target, brk, want in (
        (hello, "main", "Breakpoint 1, main ("),
        (true, "exit", " in exit ()"),
    ):
        rc, out, err = run(
            [
                wrapper(ctx, "gdb"),
                "-batch",
                "-nx",
                "-iex",
                "set auto-load safe-path /",
                "-iex",
                "set breakpoint pending on",
                "-ex",
                f"break {brk}",
                "-ex",
                "run",
                "-ex",
                "bt",
                "-ex",
                "info auto-load python-scripts",
                "--args",
                ctx.launcher,
                target,
            ],
            cwd=ctx.work,
            env=ctx.env,
            timeout=120,
        )
        expect(
            want in out and "exclave-launcher.py" in out,
            f"gdb inside stops at {brk} in {target}: rc={rc} {out[-600:]!r} {err[-400:]!r}",
        )
    return None


def gdb_hello(ctx: Ctx) -> str:
    """A program built inside with debug information, that prints its argv[0]: its path."""
    hello = os.path.join(ctx.work, "gdb_hello")
    if not os.path.exists(hello):
        src = hello + ".c"
        with open(src, "w") as f:
            f.write("#include <stdio.h>\nint main(int c, char **v) { puts(v[0]); return 0; }\n")
        rc, _out, err = run(
            [wrapper(ctx, ctx.gcc), "-g", "-O0", "-o", hello, src], cwd=ctx.work, env=ctx.env
        )
        expect(rc == 0, "compile: " + err[-600:])
    return hello


@test
def gdb_given_program(ctx: Ctx) -> str | None:
    """7.6, 13 item 1: gdb inside, given the program itself, stops at its breakpoints, every run.

    gdb counts the execs its start expects and takes the image they leave for the file it was
    given, so a vfork child's deferred PTRACE_TRACEME has the launcher exec itself once more: gdb
    meets an exec past its count, reads the launcher there and auto-loads its script. The script
    gives gdb the program back as its file when the process exits, by the name it was exec'd by,
    so that a second run starts it as the first did, a link not resolved: a program built inside,
    given by a link to it, stops at main and prints the link's path both times, and a wrapped one
    stops in the exclave's libc, with no SIGSYS handling given and gdb's start through the shell,
    its default, and without.
    """
    if not os.path.exists(os.path.join(ctx.tree, "usr", "bin", "gdb")):
        return "the tree has no gdb: its breakpoints inside not checked"
    hello = gdb_hello(ctx)
    alias = os.path.join(ctx.work, f"gdb_alias_{os.getpid()}")
    os.symlink(hello, alias)
    try:
        for target, brk, want in (
            (alias, "main", "Breakpoint 1, main ("),
            (ctx.vbin("true"), "exit", " in exit ()"),
        ):
            for shell in ("on", "off"):
                rc, out, err = run(
                    [
                        wrapper(ctx, "gdb"),
                        "-batch",
                        "-nx",
                        "-iex",
                        "set auto-load safe-path /",
                        "-iex",
                        "set breakpoint pending on",
                        "-iex",
                        "set debuginfod enabled off",
                        "-iex",
                        f"set startup-with-shell {shell}",
                        "-ex",
                        f"break {brk}",
                        "-ex",
                        "run",
                        "-ex",
                        "continue",
                        "-ex",
                        "run",
                        "-ex",
                        "continue",
                        "-ex",
                        "info auto-load python-scripts",
                        target,
                    ],
                    cwd=ctx.work,
                    env=ctx.env,
                    timeout=120,
                )
                names = out.splitlines().count(alias) if target == alias else 2
                expect(
                    out.count(want) == 2 and names == 2 and "exclave-launcher.py" in out,
                    f"gdb {target} inside, startup-with-shell {shell}, stops at {brk} in both "
                    f"runs, under its name: rc={rc} {out[-800:]!r} {err[-400:]!r}",
                )
    finally:
        os.unlink(alias)
    return None


@test
def own_seccomp_filter(ctx: Ctx) -> str | None:
    """7.4.2, 13 item 5: a program's own seccomp filter is honoured as the kernel applies it.

    test/progs/seccomp_filter.c installs ERRNO, LOG and ALLOW filters and an sshd-shaped allow-list
    whose default kills, in both forms, with TSYNC and without, and over fork, vfork and an exec of
    itself, and the answers are the kernel's under bwrap (test/kernel_answers.py), but for the
    installs the launcher refuses with ENOSYS. While a program's filter is in force a launcher
    before filter version 10, which would re-issue a trapped call unjudged, is not exec'd: EACCES.
    A case an older kernel lacks answers as that kernel decides (SECCOMP_FILTER_SINCE).
    """
    d = os.path.join(ctx.work, "seccomp-filter-host")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "seccomp_filter"), [d])
    expect(rc == 0, f"seccomp_filter: rc={rc} {out!r} {err!r}")
    bad = kernel_answers.seccomp_filter_wrong(out)
    expect(not bad, "; ".join(bad))
    old = os.path.join(os.path.dirname(ctx.launcher_src), "launcher-old")
    if not os.path.exists(old):
        return "no build/launcher-old: the refusal of an older launcher is untested"
    ex2 = os.path.join(ctx.work, "seccomp-old-exclave")
    copy_exclave(ctx.mini, ex2)
    tree.relink(ex2, old)
    src = os.path.join(ctx.work, "seccomp_exec.c")
    with open(src, "w") as f:  # an ALLOW filter, then an exec of the older launcher's true
        f.write(
            "#include <stdio.h>\n#include <errno.h>\n#include <unistd.h>\n#include <stddef.h>\n"
            "#include <sys/prctl.h>\n#include <sys/syscall.h>\n#include <linux/filter.h>\n"
            "#include <linux/seccomp.h>\n"
            "int main(int c, char **v) { struct sock_filter f[] = "
            "{BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)}; struct sock_fprog p = {1, f};\n"
            " prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);\n"
            " if (c > 2 && syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &p)) return 3;\n"
            ' execl(v[1], v[1], (char *)0); printf("%d\\n", errno); return 0; }\n'
        )
    prog = os.path.join(ctx.work, "seccomp_exec")
    rc, _out, err = run([wrapper(ctx, ctx.gcc), "-O0", "-o", prog, src], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "compile: " + err)
    true_old = f"{ex2}/tree{ctx.vbin('true')}"
    log = os.path.join(ctx.work, "seccomp-old.log")
    rc, out, err = inside(ctx, prog, [true_old, "filter"], env=dict(ctx.env, EXCLAVE_LOG=log))
    expect(
        rc == 0 and out == "13\n" and "before filter version 10" in read_text(log),
        f"under a program's filter the older launcher is refused with EACCES: {out!r} {err!r}",
    )
    rc, out, err = inside(ctx, prog, [true_old])
    expect(rc == 0 and out == "", f"without one it runs: rc={rc} {out!r} {err!r}")
    return None
