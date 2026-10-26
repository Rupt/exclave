"""run.py — the regression suite (DESIGN.md 17.4, the part a single machine can run).

    test/run.py [--tree DIR | --exclave EXCLAVE] [--work DIR] [--keep] [-k NAME|SUBSTRING]
                [--order given|reverse|random] [--seed N] [--budget SECONDS]

Makes an exclave from TREE (default $EXCLAVE_TEST_TREE), or from the tree of an existing EXCLAVE,
unwrapped, under WORK (default build/test-work) with a few test files added to the tree, compiles
test/progs/*.c with the tree's own C compiler (test/tree.py), and runs every named test; with
--exclave, on the fixture kept under build/fixtures/ when there is one (17). Needs python3 and a
tree with a C compiler (see README.md). Optional: strace for the isolation test, /usr/bin/gcc-13
for the identical-object test. Exit status is the number of failures.

Tests are independent: every test makes what it needs (the fixtures made at setup are the exclave,
the compiled programs and the environment, never another test's output), so any subset runs in any
order; `--order reverse` and `--order random` are how that is checked.
"""

import argparse
import os
import platform
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
from typing import TYPE_CHECKING, Protocol

import tree

from exclave import build, cli

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
# the tool, as the pinned Python runs it: the exclave package's entry point
TOOL = (sys.executable, "-m", "exclave")


# Debian's name; make_exclave takes the tree's gcc when that one is absent (an Alpine exclave, an
# arm64 one)
GCC = "x86_64-linux-gnu-gcc-13"

# the synthetic packages of the tool tests carry this machine's architecture
MACHINE = platform.machine()
DEB_ARCH = {"x86_64": "amd64", "aarch64": "arm64"}.get(MACHINE, MACHINE)
VOLATILE = ("/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run")
# the path syscalls the isolation test traces; the legacy forms exist on x86-64 only and strace says
# so elsewhere
TRACED = (
    "open",
    "stat",
    "lstat",
    "access",
    "execve",
    "readlink",
    "openat",
    "newfstatat",
    "readlinkat",
    "faccessat",
    "faccessat2",
    "statx",
    "execveat",
    "chdir",
    "mkdir",
    "mkdirat",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
)

PATH_MAX = 4096


class Ctx:
    """The fixtures made at setup, which every test is given and none may change."""

    from_exclave: bool
    tree: str
    work: str
    launcher_src: str
    env: dict[str, str]
    exclave: str
    root: str
    launcher: str
    cwd_given: bool
    gcc: str
    progs: str
    shared: tuple[bytes, bytes, tuple[tuple[str, int, int, int], ...]]
    machine: str
    triplet: str
    vbin: Callable[[str], str]
    vreal: Callable[[str], str]
    payload: Callable[[str], str]
    interp: str
    ldso_dir: str
    ldso_name: str
    musl: bool
    musl_interp: str
    other_interp: str
    deb_arch: str
    sh_exe: str
    sh_link: str
    busybox: bool
    libc: str | None
    ldso_cache: bool


class Test(Protocol):
    """A test: given the fixtures, it returns a note for the PASS line, or None."""

    __name__: str

    def __call__(self, ctx: Ctx, /) -> str | None: ...


TESTS: list[Test] = []


def test(f: Test) -> Test:
    TESTS.append(f)
    return f


def sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


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


def wrapper(ctx: Ctx, name: str) -> str:
    """A wrapper by name.

    Debian's /usr/bin, or /bin where the tree is not merged (an Alpine exclave).
    """
    p = os.path.join(ctx.root, "usr", "bin", name)
    return p if os.path.lexists(p) else os.path.join(ctx.root, "bin", name)


def inside(
    ctx: Ctx,
    prog: str,
    args: Sequence[str] = (),
    *,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
    inp: bytes | None = None,
    timeout: float = 300,
) -> tuple[int, str, str]:
    """Run a program inside the exclave through the launcher's positional entry (7.2).

    The program is named by its virtual or its host path.
    """
    return run(
        [ctx.launcher, prog, *list(args)],
        cwd=cwd or ctx.work,
        env=dict(env if env is not None else ctx.env),
        inp=inp,
        timeout=timeout,
    )


def expect(cond: object, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def read_text(path: str) -> str:
    with open(path) as f:
        return f.read()


def read_bytes(path: str, n: int = -1) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


# a copy for a test to alter: the tree hard-linked, .exclave/ copied
copy_exclave = tree.copy_exclave


def shared_state(ctx: Ctx) -> tuple[bytes, bytes, tuple[tuple[str, int, int, int], ...]]:
    """What every test shares and none may change.

    The exclave's manifest, its hashes file, and for every entry of its tree the path, size, mode
    and mtime, which an added file, a removed one or a write through a hard link changes; a walk of
    some thousand lstats, cheap enough to compare after every test.
    """
    ex = ctx.exclave
    entries = []
    for dirpath, dirnames, filenames in os.walk(ctx.root):
        for n in dirnames + filenames:
            st = os.lstat(os.path.join(dirpath, n))
            # a directory's mtime moves when a test makes and removes a file there: not a residue
            isdir = stat.S_ISDIR(st.st_mode)
            entries.append(
                (
                    os.path.relpath(os.path.join(dirpath, n), ctx.root),
                    0 if isdir else st.st_size,
                    st.st_mode,
                    0 if isdir else st.st_mtime_ns,
                )
            )
    return (
        read_bytes(os.path.join(ex, ".exclave", "manifest")),
        read_bytes(os.path.join(ex, ".exclave", "hashes"))
        if os.path.exists(os.path.join(ex, ".exclave", "hashes"))
        else b"",
        tuple(sorted(entries)),
    )


def fixture_keys(ex: str) -> tuple[str, str] | None:
    """The keys of the pruned fixture (17): the exclave's, and the sources'; None without hashes.

    The fixture is named by the exclave's hashes file, which hashes its tree, so each exclave has
    one. What the tests touch is decided by their sources, the tool's and the launcher's, whose key
    the fixture keeps as a stamp: a fixture made with other sources is almost always still enough,
    and a run on it checks any failure again on the whole exclave (main).
    """
    import hashlib

    lock = os.path.join(ex, ".exclave", "hashes")
    if not os.path.isfile(lock):
        return None
    files = [os.path.join(HERE, "run.py"), os.path.join(HERE, "tree.py")]
    files += sorted(os.path.join(HERE, "progs", f) for f in os.listdir(os.path.join(HERE, "progs")))
    files += sorted(
        os.path.join(REPO, "src", f)
        for f in os.listdir(os.path.join(REPO, "src"))
        if f[-2:] in (".c", ".h")
    )
    files += sorted(
        os.path.join(REPO, "exclave", f)
        for f in os.listdir(os.path.join(REPO, "exclave"))
        if f.endswith(".py")
    )
    sources = hashlib.blake2b(digest_size=6)
    for f in files:
        sources.update(os.path.basename(f).encode() + b"\0" + read_bytes(f) + b"\0")
    return hashlib.blake2b(read_bytes(lock), digest_size=6).hexdigest(), sources.hexdigest()


STAMP = ".sources"  # in a fixture: the sources' key it was made with


def make_fixture(ctx: Ctx, dst: str, sources: str) -> None:
    """Keep the shared exclave, pruned to what this run touched, for the next run (17).

    The prune is the tool's own, from every EXCLAVE_LOG file the run wrote: the same tree the tests
    just passed on, about a fifth of its files. Made only from a run with no failure, so that a
    partial log never fixes a partial fixture.
    """
    logs = sorted(
        os.path.join(dp, f) for dp, dn, fn in os.walk(ctx.work) for f in fn if f.endswith(".log")
    )
    # two runs may make the same fixture at once (scripts/gate)
    tmp = f"{dst}.tmp{os.getpid()}"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    copy_exclave(ctx.exclave, tmp)
    if cli.cmd_prune(tmp, logs):
        print("fixture not kept: the pruned exclave does not pass the static check")
        shutil.rmtree(tmp, ignore_errors=True)
        return
    with open(os.path.join(tmp, STAMP), "w") as f:
        f.write(sources + "\n")
    if os.path.isdir(dst):  # another run made it meanwhile
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        os.rename(tmp, dst)
    # one fixture per exclave name: those of the exclave's earlier contents go
    name = os.path.basename(dst).rsplit("-", 1)[0]
    for old in os.listdir(os.path.dirname(dst)):
        if old.rsplit("-", 1)[0] == name and old != os.path.basename(dst) and ".tmp" not in old:
            shutil.rmtree(os.path.join(os.path.dirname(dst), old), ignore_errors=True)
    n = sum(len(fn) for dp, dn, fn in os.walk(os.path.join(dst, "tree")))
    print(f"fixture: {n} files, kept at {dst}")


def hello_source(ctx: Ctx) -> str:
    """hello.c in the work directory: a fixture any test may make, made once."""
    src = os.path.join(ctx.work, "hello.c")
    if not os.path.exists(src):
        with open(src, "w") as f:
            f.write(
                "#include <stdio.h>\n"
                'int main(int c, char **v) { printf("hello %s %d\\n", v[0], c); return 0; }\n'
            )
    return src


# ------------------------------------------------------------------ setup
def make_exclave(ctx: Ctx) -> None:
    ex = os.path.join(ctx.work, "exclave")
    root = os.path.join(ex, "tree")
    os.makedirs(os.path.join(ex, ".exclave"))
    shutil.copy2(ctx.launcher_src, os.path.join(ex, ".exclave", "launcher"))
    os.chmod(os.path.join(ex, ".exclave", "launcher"), 0o755)
    shutil.copytree(ctx.tree, root, symlinks=True, copy_function=cli.link_or_copy)
    # a copy made under a setgid directory inherits the bit; the suite tests the launcher, not the
    # copy
    for dirpath, dirnames, _filenames in os.walk(root):
        for d in dirnames:
            p = os.path.join(dirpath, d)
            if not os.path.islink(p):
                m = os.lstat(p).st_mode
                if m & 0o7000:
                    os.chmod(p, m & 0o777)
    if ctx.from_exclave:
        build.unwrap(ex, log=lambda *_: None)
    # test additions to the tree
    with open(os.path.join(root, "usr", "share", "exclave-test-marker"), "w") as f:
        f.write("marker\n")
    # a socket file in the tree (13 item 31); a fixture carries one already
    tree.socket_file(os.path.join(root, "usr", "share", "exclave-test.sock"))
    for name, body in (
        ("exclave-test-script", "#!/bin/sh\necho script ok $1 $#\n"),
        ("exclave-test-noshebang", "echo noshebang ok\n"),
        ("exclave-test-script2", "#!/usr/bin/exclave-test-script\n"),
        ("exclave-test-exe", "#!/bin/sh\nreadlink /proc/$$/exe\n"),
    ):
        p = os.path.join(root, "usr", "bin", name)
        with open(p, "w") as f:
            f.write(body)
        os.chmod(p, 0o755)
    top = "/" + ctx.work.split("/")[1]
    recs = [cli.Record("exclave", [("t", b"1")])]
    ctx.cwd_given = top not in VOLATILE
    if ctx.cwd_given:
        recs.append(cli.Record("own", [("s", top.encode())]))
    with open(os.path.join(ex, ".exclave", "manifest"), "wb") as f:
        f.write(cli.dump(recs, "exclave"))
    cli.wrap_files(ex, quiet=True)
    # wrapped: a hashes file with the hashes (6.4)
    build.write_lock(
        ex, [], manifest_hash=cli.b2_file(os.path.join(ex, ".exclave", "manifest")), tree=True
    )
    ctx.exclave, ctx.root, ctx.launcher = ex, root, os.path.join(ex, ".exclave", "launcher")
    tree_facts(ctx)
    ctx.gcc = tree.compiler(root, ctx.machine) or GCC  # the tree's C compiler


def tree_facts(ctx: Ctx) -> None:
    """What the tree says about its architecture (7.1).

    The machine, Debian's multiarch triplet, the loader named by the originals' PT_INTERP and the
    directory it lives in, and the syscall numbers strace shows for a trapped call.
    """
    import platform

    from exclave import elfcheck

    ctx.machine = platform.machine()
    ctx.triplet = tree.triplet(ctx.root, ctx.machine)
    t = elfcheck.Tree(ctx.root)

    def vbin(name: str) -> str:
        return tree.vbin(ctx.root, name)

    def vreal(vpath: str) -> str:
        """A virtual path resolved through the tree's links, as a virtual path.

        The file behind the name.
        """
        return t.resolve(vpath) or vpath

    def payload(name: str) -> str:
        """The real file of a program's original, behind its wrapper and its links.

        One of its links may be an applet link to busybox.
        """
        return t.payload(vreal(name if name.startswith("/") else vbin(name)))

    ctx.vbin, ctx.vreal, ctx.payload = vbin, vreal, payload
    true = payload("true")
    interp = (
        elfcheck.Elf(true).interp
        if os.path.exists(true)
        else {"x86_64": "/lib64/ld-linux-x86-64.so.2", "aarch64": "/lib/ld-linux-aarch64.so.1"}[
            ctx.machine
        ]
    )
    assert interp, f"{true} names no loader"
    ctx.interp = interp
    ctx.ldso_dir, ctx.ldso_name = ctx.interp.split("/")[1], os.path.basename(ctx.interp)
    ctx.musl = os.path.basename(ctx.interp).startswith("ld-musl")
    ctx.musl_interp = f"/lib/ld-musl-{ctx.machine}.so.1"
    # a loader this exclave lacks, no longer than its own
    ctx.other_interp = f"/lib/ld-gnu-{ctx.machine}.so.2" if ctx.musl else ctx.musl_interp
    ctx.deb_arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(ctx.machine, ctx.machine)
    # what /proc/self/exe reads for a script: dash, bash or busybox by its path
    ctx.sh_exe = vreal(vbin("sh"))
    ctx.sh_link = (
        os.readlink(os.path.join(ctx.root, vbin("sh").lstrip("/")))
        if os.path.islink(os.path.join(ctx.root, vbin("sh").lstrip("/")))
        else ""
    )
    ctx.busybox = os.path.basename(ctx.sh_exe) == "busybox"
    # libc.so.6 as the loader names it; none on musl
    ctx.libc = next(
        (
            v
            for v in (
                f"/lib/{ctx.triplet}/libc.so.6",
                "/lib64/libc.so.6",
                "/lib/libc.so.6",
                "/usr/lib/libc.so.6",
            )
            if os.path.lexists(os.path.join(ctx.root, v.lstrip("/")))
        ),
        None,
    )
    ctx.ldso_cache = os.path.exists(os.path.join(ctx.root, "etc", "ld.so.cache"))
    # the test programs read the tree's spellings from the environment, which the border passes
    # through
    ctx.env.update(
        EXCLAVE_TEST_SH=vbin("sh"),
        EXCLAVE_TEST_SH_EXE=ctx.sh_exe,
        EXCLAVE_TEST_SH_LINK=ctx.sh_link,
        EXCLAVE_TEST_TRUE=vbin("true"),
        EXCLAVE_TEST_TRUE_PAYLOAD="/" + os.path.relpath(true, ctx.root),
    )


def compile_progs(ctx: Ctx) -> None:
    """Compile the test programs with the tree's own C compiler.

    The sources are copied into the work directory: with the work directory's top-level directory
    owned by the exclave (8.1), only the working directory's subtree is the host's.
    """
    ctx.progs = os.path.join(ctx.work, "progs")
    src = os.path.join(ctx.work, "src")
    shutil.copytree(os.path.join(HERE, "progs"), src)
    os.makedirs(ctx.progs, exist_ok=True)
    gcc = wrapper(ctx, ctx.gcc)
    for name in (
        "ro_matrix",
        "signals",
        "threads",
        "spawn",
        "exec",
        "fifo",
        "execstack",
        "ljmp",
        "fdpress",
        "openat2",
        "unix_socket",
        "openat2_xdev",
        "fexec",
        "exec_identity",
        "path_length",
        "spawn_threads",
        "adversarial",
    ):
        rc, _out, err = run(
            [
                gcc,
                "-O1",
                "-g",
                "-pthread",
                "-o",
                os.path.join(ctx.progs, name),
                os.path.join(src, name + ".c"),
                "-lm",
                "-ldl",
            ],
            cwd=ctx.work,
            env=ctx.env,
        )
        # nested functions are gcc's; clang has none
        if rc and name == "execstack" and "not allowed here" in err:
            continue
        if rc:
            sys.exit(f"cannot compile {name} with the exclave's gcc:\n{err}")
    rc, _out, err = run(
        [
            gcc,
            "-shared",
            "-fPIC",
            "-o",
            os.path.join(ctx.progs, "liborigin.so"),
            os.path.join(src, "origin_lib.c"),
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    rc2, _out, err2 = run(
        [
            gcc,
            "-o",
            os.path.join(ctx.progs, "origin_main"),
            os.path.join(src, "origin_main.c"),
            "-L" + ctx.progs,
            "-lorigin",
            "-Wl,-rpath,$ORIGIN",
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    if rc or rc2:
        sys.exit(f"cannot build the origin test:\n{err}{err2}")


# ------------------------------------------------------------------ tests
@test
def version(ctx: Ctx) -> None:
    rc, out, err = run([wrapper(ctx, ctx.gcc), "--version"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out.strip(), f"{ctx.gcc} --version: rc={rc} out={out!r} err={err!r}")


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
    host = "/usr/bin/gcc-13"
    if "gcc-13" not in ctx.gcc:
        return f"the exclave's compiler is {ctx.gcc}: no host twin"
    if not os.path.exists(host):
        return "no host gcc-13"
    src = hello_source(ctx)
    a, b = os.path.join(ctx.work, "h_host.o"), os.path.join(ctx.work, "h_can.o")
    run([host, "-O2", "-c", src, "-o", a], cwd=ctx.work)
    rc, _out, err = run(
        [wrapper(ctx, ctx.gcc), "-O2", "-c", src, "-o", b], cwd=ctx.work, env=ctx.env
    )
    expect(rc == 0, err)
    expect(read_bytes(a) == read_bytes(b), "objects differ")
    return None


@test
def isolation(ctx: Ctx) -> str | None:
    if not shutil.which("strace"):
        return "no strace"
    tr = os.path.join(ctx.work, "trace")
    src = hello_source(ctx)
    names = list(TRACED)
    while True:  # an older strace may not know the newest names
        rc, _out, err = run(
            [
                "strace",
                "-f",
                "-s",
                "4096",
                "-o",
                tr,
                "-e",
                "trace=" + ",".join(names),
                wrapper(ctx, ctx.gcc),
                "-O1",
                src,
                "-o",
                os.path.join(ctx.work, "hello2"),
            ],
            cwd=ctx.work,
            env=ctx.env,
        )
        m = re.search(r"invalid system call '(\w+)'", err)
        if m and m.group(1) in names:
            names.remove(m.group(1))
            continue
        break
    expect(rc == 0, "compile under strace failed: " + err)
    bad, seen = [], 0
    # 8.1 as the launcher computes it: a top-level name outside it is the host's
    owned = cli.owned(ctx.exclave)
    allowed_files = set(build.IDENTITY_FILES)
    # the launcher resolves each identity file's host symlink chain at startup
    for f in build.IDENTITY_FILES:
        p = f
        for _ in range(40):
            if not os.path.islink(p):
                break
            t = os.readlink(p)
            p = os.path.normpath(t if t.startswith("/") else os.path.join(os.path.dirname(p), t))
            allowed_files.add(p)
    # A trapped syscall appears in the trace too, at its exit stop, with the registers the kernel
    # rolled back (x86-64 shows the number as its result, aarch64 the first argument); its SIGSYS
    # line, naming it, follows. That call is the one the kernel skipped and the handler re-issued,
    # so a line followed by its own SIGSYS is not judged. A trapped syscall outside the traced set
    # prints no line, only the SIGSYS, hence the name.
    lines: list[str] = []
    pending: dict[str, str] = {}
    with open(tr) as trace:
        for line in trace:
            m = re.match(r"^(\d+)\s+(.*)", line)
            pid, rest = (m.group(1), m.group(2)) if m else ("", line)
            m = re.match(r"--- SIGSYS .*si_syscall=__NR_(\w+)", rest)
            if m:
                if pid in pending and re.match(r"^\d+\s+" + m.group(1) + r"\(", pending[pid]):
                    pending.pop(pid)
                continue
            if pid in pending:
                lines.append(pending.pop(pid))
            pending[pid] = line
    lines.extend(pending.values())
    for line in lines:
        m = re.match(r"^\d+\s+(\w+)\((.*)\)\s+=\s+(-?\d+)", line)
        if not m:
            continue
        name, args, res = m.group(1), m.group(2), int(m.group(3))
        if res < 0:
            continue
        paths = re.findall(r'"((?:[^"\\]|\\.)*)"', args)
        if name in ("execve", "execveat", "readlink", "readlinkat") and paths:
            # the rest are argv strings, or the link's text (Fedora's /usr/bin/ld ->
            # /etc/alternatives/ld)
            paths = paths[:1]
        for given in paths:
            seen += 1
            p = os.path.normpath(given) if given.startswith("/") else given
            # a top-level name the exclave does not own, absent or a placeholder,
            # is the host's (8.1)
            ok = (
                not p.startswith("/")
                or p.startswith((ctx.root, ctx.work))
                or p.startswith(VOLATILE)
                or p in allowed_files
                or ctx.work.startswith(p + "/")
                or "/" + p.split("/")[1] not in owned
            )
            if not ok:
                bad.append(f"{name} {p}")
    expect(seen > 50, f"trace looks empty ({seen} paths)")
    expect(not bad, "host paths touched: " + ", ".join(sorted(set(bad))[:10]))
    return None


@test
def ro_matrix(ctx: Ctx) -> None:
    d = os.path.join(ctx.work, "hostdir")
    os.makedirs(d, exist_ok=True)
    # the wrapper itself, behind a link
    rc, out, err = inside(
        ctx, os.path.join(ctx.progs, "ro_matrix"), [d, ctx.vreal(ctx.vbin(ctx.gcc))]
    )
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def coreutils_ro(ctx: Ctx) -> None:
    def w(name: str, *args: str) -> tuple[int, str, str]:
        return run([wrapper(ctx, name), *list(args)], cwd=ctx.work, env=ctx.env)

    rc, out, err = w("touch", "/usr/newfile")
    expect(rc and "Read-only" in err, err)
    rc, out, err = w("mkdir", "-p", "/usr/lib")
    expect(rc == 0, err)
    rc, out, err = w("install", "-d", "/usr/lib")
    # busybox's install -d chmods an existing directory, which the read-only rule refuses as a mount
    # would
    if ctx.busybox:
        expect(rc and "Read-only" in err, err)
    else:
        expect(rc == 0, err)
    rc, out, err = w("mkdir", "/usr/lib")
    expect(rc and "exists" in err, err)
    rc, out, err = w("rm", ctx.vbin(ctx.gcc))
    expect(rc and "Read-only" in err, err)
    rc, out, err = w("ln", ctx.vbin(ctx.gcc), os.path.join(ctx.work, "lnk-x"))
    expect(rc and "cross-device" in err.lower(), err)
    rc, out, err = w("cp", ctx.vbin(ctx.gcc), os.path.join(ctx.work, "gcc-copy"))
    expect(rc == 0, err)
    payload = ctx.payload(ctx.gcc)
    expect(
        os.path.getsize(os.path.join(ctx.work, "gcc-copy")) == os.path.getsize(payload),
        "cp of a wrapper did not copy the original",
    )
    expect(read_bytes(os.path.join(ctx.work, "gcc-copy"), 4) == b"\x7fELF", "copy is not ELF")
    rc, out, err = w("cat", "/usr/share/exclave-test-marker")
    expect(out == "marker\n", out + err)


@test
def signals(ctx: Ctx) -> None:
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "signals"))
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def threads(ctx: Ctx) -> None:
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "threads"))
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def spawn(ctx: Ctx) -> None:
    rc, out, err = inside(
        ctx, os.path.join(ctx.progs, "spawn"), [ctx.vbin(ctx.gcc), ctx.vbin("true")], timeout=600
    )
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def fifo(ctx: Ctx) -> None:
    d = os.path.join(ctx.work, "hostdir")
    os.makedirs(d, exist_ok=True)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "fifo"), [d], timeout=60)
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
def identity(ctx: Ctx) -> None:
    rc, out, err = run([wrapper(ctx, "cat"), "/etc/passwd"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == read_text("/etc/passwd"), "passwd differs from the host")
    rc, out, err = run([wrapper(ctx, "cat"), "/etc/hostname"], cwd=ctx.work, env=ctx.env)
    if os.path.lexists(os.path.join(ctx.root, "etc", "hostname")):
        expect(
            rc == 0 and out == read_text(os.path.join(ctx.root, "etc", "hostname")),
            f"an exclave shipping /etc/hostname shows its own: {out!r} {err!r}",
        )
    else:
        expect(rc != 0 and "No such file" in err, f"host /etc/hostname must be invisible: {err!r}")
    # 6.2: the time zone is not the host's: UTC inside, whatever TZ and /etc/localtime say outside
    rc, out, err = run(
        [wrapper(ctx, "date"), "+%Z"], cwd=ctx.work, env=dict(ctx.env, TZ="Asia/Tokyo")
    )
    expect(out.strip() == "UTC", f"the zone inside an exclave is UTC: {out!r} {err!r}")
    if not os.path.lexists(os.path.join(ctx.root, "etc", "localtime")):
        rc, out, err = run([wrapper(ctx, "cat"), "/etc/localtime"], cwd=ctx.work, env=ctx.env)
        expect(
            rc != 0 and "No such file" in err,
            f"the host's /etc/localtime must be invisible: {err!r}",
        )


@test
def host_walk_one_step(ctx: Ctx) -> None:
    """DESIGN.md 16.6 item 4: one openat2 stands in for a host walk's lstats.

    Where the directories ahead of a walk are all the host's, one openat2 with RESOLVE_NO_SYMLINKS
    stands in for their lstats, and anything it cannot vouch for is the walk's. A host symlink into
    /usr deep in the chain still reaches the exclave's /usr; a file where a directory should be is
    ENOTDIR and a missing directory ENOENT, as the walk answers; a plain deep path reads as it does
    natively.
    """
    base = os.path.join(ctx.work, f"deephost-{os.getpid()}")
    deep = os.path.join(base, "h1", "h2", "h3", "h4")
    os.makedirs(deep, exist_ok=True)
    with open(os.path.join(deep, "f"), "w") as f:
        f.write("deep\n")
    if not os.path.lexists(os.path.join(deep, "lnk")):
        os.symlink("/usr", os.path.join(deep, "lnk"))
    cat = wrapper(ctx, "cat")
    rc, out, err = run([cat, os.path.join(deep, "f")], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "deep\n", f"a deep host file: rc={rc} {out!r} {err!r}")
    rc, out, err = run(
        [cat, os.path.join(deep, "lnk", "share", "exclave-test-marker")], cwd=ctx.work, env=ctx.env
    )
    expect(
        rc == 0 and out == "marker\n",
        "a host link into /usr deep in a host chain reaches the exclave's: "
        f"rc={rc} {out!r} {err!r}",
    )
    rc, out, err = run(
        [
            cat,
            os.path.join(
                f"deephost-{os.getpid()}",
                "h1",
                "h2",
                "h3",
                "h4",
                "lnk",
                "share",
                "exclave-test-marker",
            ),
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(rc == 0 and out == "marker\n", f"the same, relative: rc={rc} {out!r} {err!r}")
    rc, out, err = run([cat, os.path.join(deep, "f", "x", "y")], cwd=ctx.work, env=ctx.env)
    expect(rc != 0 and "Not a directory" in err, f"a file in the middle: {err!r}")
    rc, out, err = run(
        [cat, os.path.join(base, "h1", "missing", "h3", "f")], cwd=ctx.work, env=ctx.env
    )
    expect(rc != 0 and "No such file" in err, f"a missing directory in the middle: {err!r}")
    # the answers above hold with or without the one-step check; where the launcher would use it, it
    # must have run
    if shutil.which("strace") and has_openat2() and mounted_once(ctx.root):
        trace = os.path.join(ctx.work, f"deephost-{os.getpid()}.trace")
        run(
            ["strace", "-f", "-e", "trace=openat2", "-o", trace, cat, os.path.join(deep, "f")],
            cwd=ctx.work,
            env=ctx.env,
        )
        expect(
            "RESOLVE_NO_SYMLINKS" in read_text(trace),
            "the one-step check did not run where the tree's filesystem is mounted once",
        )


def has_openat2() -> bool:
    """The one-step check's other condition: the kernel has openat2 (5.6).

    Asked of the kernel, not of its version.
    """
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    how = (ctypes.c_uint64 * 3)(0o10000000, 0, 0)  # O_PATH
    nr = {"x86_64": 437, "aarch64": 437}.get(os.uname().machine, 437)
    fd = libc.syscall(nr, -100, b"/", ctypes.byref(how), ctypes.c_size_t(24))
    if fd >= 0:
        os.close(fd)
        return True
    return False


def mounted_once(path: str) -> bool:
    """The one-step check's condition (canon.c tree_mounted_once).

    The mount holding path is its filesystem's only one in /proc/self/mountinfo, with path's own
    device number.
    """
    real = os.path.realpath(path)
    dev = os.stat(real).st_dev
    best, mm, lines = -1, None, []
    with open("/proc/self/mountinfo") as mountinfo:
        for entry in mountinfo:
            f = entry.split()
            mp = f[4].encode().decode("unicode_escape")
            lines.append(f[2])
            if (real == mp or real.startswith(mp.rstrip("/") + "/")) and len(mp) >= best:
                best, mm = len(mp), f[2]
    return mm is not None and lines.count(mm) == 1 and mm == f"{os.major(dev)}:{os.minor(dev)}"


@test
def casefold_alias(ctx: Ctx) -> str | None:
    """The tree's other spellings on a case-insensitive filesystem stay the tree's.

    On a case-insensitive filesystem the tree's root has other spellings, x.exclave/TREE for
    X.exclave/tree, on the same mount; a host walk that stood in for its lstats with one openat2
    must still see the tree there, read-only. Made on a casefold tmpfs (6.13) in a user namespace;
    skipped where either is missing.
    """
    if subprocess.run(
        ["unshare", "-Urm", "true"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode:
        return "no user namespaces"
    mnt = os.path.join(ctx.work, f"casefold-{os.getpid()}")
    os.makedirs(mnt, exist_ok=True)
    sh = wrapper(ctx, "sh")
    rel = os.path.relpath(sh, ctx.exclave)
    setup = (
        f"mount -t tmpfs -o casefold tmpfs {mnt} && mkdir {mnt}/cf && chattr +F {mnt}/cf "
        "|| exit 99; "
        # names that differ only in case (the kernel's headers) are skipped
        f"cp -a {ctx.exclave} {mnt}/cf/X.exclave 2>/dev/null; "
        f"test -x {mnt}/cf/X.exclave/{rel} || exit 98"
    )
    inner = (
        f"touch {mnt}/cf/x.exclave/TREE/usr/zz-cf; echo rc=$?; "
        f"cat {mnt}/cf/x.exclave/TREE/usr/share/exclave-test-marker; "
        f"cd {mnt}/cf/x.exclave/TREE/usr && touch zz-cf2; echo rc=$?"
    )
    # what reached the tree
    cmd = (
        f"{setup} && {mnt}/cf/X.exclave/{rel} -c '{inner}'; "
        f"ls {mnt}/cf/X.exclave/tree/usr | grep zz-cf"
    )
    rc, out, err = run(
        ["unshare", "-Urm", "sh", "-c", cmd], cwd=ctx.work, env=dict(ctx.env, PATH="/usr/bin:/bin")
    )
    if rc == 99:
        return f"no casefold tmpfs here: {err.strip()[-120:]}"
    expect(rc != 98, f"the exclave's shell did not copy onto the casefold tmpfs: {err[-300:]!r}")
    expect(
        out == "rc=1\nmarker\nrc=1\n" and err.count("Read-only") >= 2,
        f"a case-folded spelling of the tree's root: rc={rc} {out!r} {err!r}",
    )
    return None


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
        f.write(
            cli.dump(
                [cli.Record("exclave", [("t", b"1")]), cli.Record("data", [("s", b"/opt/sdk")])],
                "exclave",
            )
        )
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
def cwd_rules(ctx: Ctx) -> str | None:
    rc, out, err = run([wrapper(ctx, "pwd")], cwd=os.path.join(ctx.root, "usr", "bin"), env=ctx.env)
    expect(out == "/usr/bin\n", f"cwd inside tree/: {out!r}")
    rc, out, err = run(
        [wrapper(ctx, "touch"), "x"], cwd=os.path.join(ctx.root, "usr", "bin"), env=ctx.env
    )
    expect(rc and "Read-only" in err, f"write in tree/ cwd: {err!r}")
    sub = os.path.join(ctx.work, "sub", "sub2")
    os.makedirs(sub, exist_ok=True)
    with open(os.path.join(sub, "file"), "w") as f:
        f.write("deep\n")
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "pwd; cd sub && pwd && cat sub2/file"], cwd=ctx.work, env=ctx.env
    )
    expect(out == f"{ctx.work}\n{ctx.work}/sub\ndeep\n", f"cwd given to the host: {out!r} {err!r}")
    inc, outd = os.path.join(ctx.work, "inc"), os.path.join(ctx.work, "out")
    os.makedirs(inc, exist_ok=True)
    os.makedirs(outd, exist_ok=True)
    with open(os.path.join(inc, "x.h"), "w") as f:
        f.write("#define X 41\n")
    with open(os.path.join(ctx.work, "sub", "y.c"), "w") as f:
        f.write(
            '#include "x.h"\n#include <stdio.h>\nint main(void){printf("%d\\n", X+1);return 0;}\n'
        )
    rc, out, err = run(
        [wrapper(ctx, ctx.gcc), "-Iinc", "sub/y.c", "-o", "out/y"], cwd=ctx.work, env=ctx.env
    )
    expect(rc == 0, "compile with subdirectory include and output: " + err)
    rc, out, err = inside(ctx, os.path.join(outd, "y"))
    expect(out == "42\n", f"built output run inside: {out!r} {err!r}")
    if not ctx.cwd_given:
        return "work dir under a volatile prefix; the cwd given to the host is not exercised"
    # the launcher's line for rule 4 and the dynamic check's reading of it, both spellings at once:
    # a library the workload opened under that directory is its own output, a warning, where without
    # the line it would pass unseen
    from exclave import elfcheck

    log = os.path.join(ctx.work, f"cwd-given-{os.getpid()}.log")
    rc, out, err = run([wrapper(ctx, "true")], cwd=ctx.work, env=dict(ctx.env, EXCLAVE_LOG=log))
    expect(
        rc == 0 and f"launcher 0 cwd given to the host {ctx.work}\n" in read_text(log),
        f"the rule-4 log line: {read_text(log)[:400]!r}",
    )
    with open(log, "a") as f:
        f.write(f"open 3 {ctx.work}/sub/libown.so.1\n")
    rep = elfcheck.dynamic_check(ctx.exclave, [log], cli.owned(ctx.exclave), log=lambda *_: None)
    expect(
        any("working directory" in w and "libown.so.1" in w for w in rep.warnings)
        and not rep.errors,
        f"the dynamic check's reading of the rule-4 line: {rep.warnings!r} {rep.errors!r}",
    )
    return None


@test
def exclave_directory_visible(ctx: Ctx) -> None:
    """8.1: the exclave's real location resolves as a host path from any working directory.

    It does so even under a prefix the exclave owns (/home here), so a program can reach its files
    relative to its executable's real path.
    """
    real = os.path.join(ctx.root, ctx.vbin("true").lstrip("/"))
    rc, out, err = run([wrapper(ctx, "ls"), real], cwd="/", env=ctx.env)
    expect(
        rc == 0 and out.strip() == real, f"real exclave path from cwd /: rc={rc} {out!r} {err!r}"
    )
    rc, out, err = run(
        [
            wrapper(ctx, "sh"),
            "-c",
            "cd {} && pwd && ls tree{}".format(ctx.exclave, ctx.vbin("true")),
        ],
        cwd="/",
        env=ctx.env,
    )
    expect(
        rc == 0 and out == "{}\ntree{}\n".format(ctx.exclave, ctx.vbin("true")),
        f"cd into the exclave dir: rc={rc} {out!r} {err!r}",
    )
    rc, out, err = run(
        [wrapper(ctx, "cat"), os.path.join(ctx.root, "usr", "share", "exclave-test-marker")],
        cwd="/",
        env=ctx.env,
    )
    expect(out == "marker\n", f"a file inside tree/ by its real path: {out!r} {err!r}")


@test
def cross_exclave_distinct_launchers(ctx: Ctx) -> None:
    """7.4.5: a program in another exclave is exec'd as that exclave's launcher.

    A program in another exclave, whose launcher is a different file, is exec'd as that launcher,
    which then serves its own tree inside the first exclave's filter (the dogfooding case of 10.5).
    """
    ex2 = os.path.join(ctx.work, "can2")
    copy_exclave(ctx.exclave, ex2)
    padded = os.path.join(ctx.work, "launcher2")
    with open(padded, "wb") as f:
        # a different file of a different size, still the launcher
        f.write(read_bytes(ctx.launcher) + b"\0" * 64)
    os.chmod(padded, 0o755)
    cli.cmd_relink(ex2, padded)
    rc, out, err = run([*TOOL, "check", ex2])
    expect(rc == 0, "can2 check: " + out[-300:] + err[-300:])
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
    handler (make builds it beside build/launcher). Across the syscall page's move (filter version
    6) neither direction can run, and each is refused by name: this launcher under a filter older
    than 6, and a launcher whose note has the old page generation exec'd from inside.
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
    cli.cmd_relink(ex2, old)
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
    cli.cmd_relink(ex3, gen1)
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
    cli.cmd_relink(ex3, only)
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
    can4 = os.path.join(ctx.work, "exclave-note-can")
    copy_exclave(ctx.exclave, can4)
    cli.cmd_relink(can4, only)
    _rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "{}/tree{}; echo rc=$?".format(can4, ctx.vbin("true"))],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out == "rc=0\n", f"a launcher known by the exclave note alone, from inside: {out!r} {err!r}"
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
            [wrapper(ctx, "sh"), "-c", f"{planted} exec {target} -c {sh_quote(show)}"],
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
def pre_rename_can_refused(ctx: Ctx) -> None:
    """A can, an exclave from before the rename (.can/, root/), is refused by name.

    Every command that takes an exclave refuses it before anything is read or written, rather than
    ending in a traceback; docs/DESIGN.md 13 item 45 says how to convert it.
    """
    old = os.path.join(ctx.work, f"old-{os.getpid()}.can")
    os.makedirs(os.path.join(old, ".can"))
    os.makedirs(os.path.join(old, "root", "usr", "bin"))
    with open(os.path.join(old, ".can", "manifest"), "w") as f:
        f.write("can 1\n")
    log = os.path.join(ctx.work, "old-can.log")
    open(log, "w").close()
    before = sorted(os.walk(old))
    for args in (["wrap"], ["unwrap"], ["check"], ["prune", log], ["hash"], ["relink"]):
        rc, _o, e = run([*TOOL, args[0], old, *args[1:]])
        expect(
            rc != 0 and "is a can, an exclave from before the rename" in e and "Traceback" not in e,
            f"{args[0]} on a can: rc={rc} {e[-300:]!r}",
        )
    expect(sorted(os.walk(old)) == before, "a refused command changed the can")


@test
def real_root_is_the_tree(ctx: Ctx) -> None:
    """The tree's real root is an alias of /.

    A path spelt through <exclave>/tree/ obeys the same rules.
    """
    root = ctx.root
    _rc, out, err = run(
        [
            wrapper(ctx, "sh"),
            "-c",
            (
                "touch {}/usr/zz; echo rc=$?; rm {}{}; echo rc=$?; "
                "cat {}/usr/share/exclave-test-marker; ls -l {}{} | cut -c1 "
            ).format(root, root, ctx.vbin("true"), root, root, ctx.vbin("sh")),
        ],
        cwd="/",
        env=ctx.env,
    )
    expect(
        out == "rc=1\nrc=1\nmarker\nl\n" and "Read-only" in err,
        f"real-root spelling: {out!r} {err!r}",
    )
    expect(
        not os.path.exists(os.path.join(root, "usr", "zz"))
        and os.path.exists(os.path.join(root, ctx.vbin("true").lstrip("/"))),
        "the tree was written through its real path",
    )
    # other spellings of the same path, which the walk resolves rather than the shortcut for the
    # exact one: relative from a host working directory, and with a doubled slash (a mutant without
    # the walk's refusal of the root's name wrote)
    relp = os.path.relpath(os.path.join(root, "usr", "zz2"), ctx.work)
    slashed = root.replace("/", "//", 1) + "/usr/zz3"
    _rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", f"touch {relp}; echo rc=$?; touch {slashed}; echo rc=$?"],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out == "rc=1\nrc=1\n" and err.count("Read-only") == 2,
        f"relative and doubled-slash spellings: {out!r} {err!r}",
    )
    expect(
        not os.path.exists(os.path.join(root, "usr", "zz2"))
        and not os.path.exists(os.path.join(root, "usr", "zz3")),
        "the tree was written through another spelling of its real path",
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
def identity_link_consistency(ctx: Ctx) -> str | None:
    """lstat, readlink and the link's target agree for an identity file that is a host symlink."""
    link = next(
        (f for f in ("/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf") if os.path.islink(f)),
        None,
    )
    if not link:
        return "no host identity file is a symlink"
    target = os.readlink(link)
    # the content is reached through the identity name; its host target is not an exclave path (8.4)
    head = read_bytes(link, 8)
    _rc, out, err = run(
        [
            wrapper(ctx, "sh"),
            "-c",
            f"test -L {link} && echo link; readlink {link}; head -c 8 {link}",
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out.encode() == b"link\n" + target.encode() + b"\n" + head,
        f"identity link {link}: {out!r} {err!r}",
    )
    return None


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
def proc_magic_links(ctx: Ctx) -> None:
    """/dev/stdin on a pipe, process substitution and /proc/self/fd of a file are reachable."""
    _rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "cat /dev/stdin"], cwd=ctx.work, env=ctx.env, inp=b"hi\n"
    )
    expect(out == "hi\n", f"/dev/stdin on a pipe: {out!r} {err!r}")
    if os.path.exists(wrapper(ctx, "bash")):
        _rc, out, err = run(
            [wrapper(ctx, "bash"), "-c", "cat <(echo psub)"], cwd=ctx.work, env=ctx.env
        )
        expect(out == "psub\n", f"process substitution: {out!r} {err!r}")
    _rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "exec 3</etc/passwd; head -1 /proc/self/fd/3 | cut -d: -f1"],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(out == "root\n", f"/proc/self/fd of a file: {out!r} {err!r}")


@test
def new_xattr_syscalls(ctx: Ctx) -> str | None:
    """The *at xattr syscalls of 6.13 are translated.

    On older kernels they are ENOSYS either way.
    """
    src = os.path.join(ctx.work, "xat.c")
    with open(src, "w") as f:
        f.write(
            "#include <stdio.h>\n#include <errno.h>\n#include <unistd.h>\n"
            "#include <sys/syscall.h>\n#include <fcntl.h>\n"
            "int main(void){char b[64];errno=0;"
            'long r=syscall(465,AT_FDCWD,"/etc/hostname",0,b,sizeof b);printf("%ld %d\\n",r,errno);'
            'errno=0;r=syscall(465,AT_FDCWD,"/usr/share/exclave-test-marker",0,b,sizeof b);'
            'printf("%ld %d\\n",r,errno);return 0;}\n'
        )
    exe = os.path.join(ctx.work, "xat")
    rc, out, err = run([wrapper(ctx, ctx.gcc), "-O1", src, "-o", exe], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, err)
    rc, out, err = inside(ctx, exe)
    lines = out.splitlines()
    if lines and lines[0].endswith(" 38"):
        return "kernel has no listxattrat"
    # an exclave that ships the file shows its own
    own = os.path.lexists(os.path.join(ctx.root, "etc", "hostname"))
    # SELinux hosts label every file
    ok = (
        len(lines) == 2
        and (lines[0] == "-1 2" if not own else int(lines[0].split()[0]) >= 0)
        and lines[1].endswith(" 0")
        and int(lines[1].split()[0]) >= 0
    )
    expect(ok, f"listxattrat sees the exclave, not the host: {out!r} {err!r}")
    return None


@test
def bind_mount_alias(ctx: Ctx) -> str | None:
    """A second spelling of the tree's root through a bind mount is the tree, read-only."""
    if subprocess.run(
        ["unshare", "-Urm", "true"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode:
        return "no user namespaces"
    alias = os.path.join(ctx.work, "alias")
    os.makedirs(alias, exist_ok=True)
    cmd = (
        "mount --bind {} {} && {} -c 'touch {}/tree/usr/zz-alias; echo rc=$?; "
        "cat {}/tree/usr/share/exclave-test-marker'"
    ).format(ctx.exclave, alias, wrapper(ctx, "sh"), alias, alias)
    rc, out, err = run(
        ["unshare", "-Urm", "sh", "-c", cmd], cwd=ctx.work, env=dict(ctx.env, PATH="/usr/bin:/bin")
    )
    expect(out == "rc=1\nmarker\n" and "Read-only" in err, f"bind alias: rc={rc} {out!r} {err!r}")
    expect(
        not os.path.exists(os.path.join(ctx.root, "usr", "zz-alias")),
        "the tree was written through a bind mount",
    )
    # relative names from a working directory inside the alias: the walk that starts from the
    # kernel's name of the directory (DESIGN.md 16.6 item 5) must still see the tree there
    cmd = (
        "mount --bind {} {} && cd {}/tree/usr && {} -c 'touch zz-alias; echo rc=$?; "
        "cat share/exclave-test-marker'"
    ).format(ctx.exclave, alias, alias, wrapper(ctx, "sh"))
    rc, out, err = run(
        ["unshare", "-Urm", "sh", "-c", cmd], cwd=ctx.work, env=dict(ctx.env, PATH="/usr/bin:/bin")
    )
    expect(
        out == "rc=1\nmarker\n" and "Read-only" in err,
        f"bind alias, relative: rc={rc} {out!r} {err!r}",
    )
    expect(
        not os.path.exists(os.path.join(ctx.root, "usr", "zz-alias")),
        "the tree was written through a bind mount, relative",
    )
    return None


# a package member: (path, kind, None for a directory, a link's target or a file's bytes, mode)
type Member = tuple[str, str, str | bytes | None, int]


def make_deb(path: str, name: str, members: Sequence[Member], control_extra: str = "") -> None:
    """A minimal .deb: ar(debian-binary, control.tar.gz, data.tar.gz).

    members: [(tar-name, kind, target_or_bytes, mode)].
    """
    import io
    import tarfile
    import time as _t

    def tgz(entries: Sequence[Member]) -> bytes:
        bio = io.BytesIO()
        with tarfile.open(fileobj=bio, mode="w:gz") as t:
            for n, kind, val, mode in entries:
                ti = tarfile.TarInfo(n)
                ti.mtime = int(_t.time())
                ti.mode = mode
                if kind == "dir":
                    ti.type = tarfile.DIRTYPE
                    t.addfile(ti)
                elif kind == "sym":
                    assert isinstance(val, str)
                    ti.type = tarfile.SYMTYPE
                    ti.linkname = val
                    t.addfile(ti)
                else:
                    assert isinstance(val, bytes)
                    ti.size = len(val)
                    t.addfile(ti, io.BytesIO(val))
        return bio.getvalue()

    control = (
        f"Package: {name}\nVersion: 1\nArchitecture: {DEB_ARCH}\nMaintainer: t\n"
        f"Description: t\n{control_extra}"
    ).encode()
    parts = [
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", tgz([("./control", "file", control, 0o644)])),
        ("data.tar.gz", tgz(members)),
    ]
    with open(path, "wb") as f:
        f.write(b"!<arch>\n")
        for n, data in parts:
            f.write((f"{n:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n").encode())
            f.write(data)
            if len(data) % 2:
                f.write(b"\n")


def make_apk(path: str, name: str, members: Sequence[Member], pkginfo_extra: str = "") -> None:
    """A minimal unsigned .apk.

    Two gzip members, the control stream (.PKGINFO) and the data stream, the way apk-tools lays them
    out. members as for make_deb.
    """
    import gzip
    import io
    import tarfile
    import time as _t

    def tgz(entries: Sequence[Member], *, trailer: bool) -> bytes:
        bio = io.BytesIO()
        with tarfile.open(fileobj=bio, mode="w:") as t:
            for n, kind, val, mode in entries:
                ti = tarfile.TarInfo(n)
                ti.mtime = int(_t.time())
                ti.mode = mode
                if kind == "dir":
                    ti.type = tarfile.DIRTYPE
                    t.addfile(ti)
                elif kind == "sym":
                    assert isinstance(val, str)
                    ti.type = tarfile.SYMTYPE
                    ti.linkname = val
                    t.addfile(ti)
                else:
                    assert isinstance(val, bytes)
                    ti.size = len(val)
                    t.addfile(ti, io.BytesIO(val))
        raw = bio.getvalue()
        if not trailer:
            raw = raw.rstrip(b"\0")  # the control stream carries no end-of-archive blocks
            raw += b"\0" * (-len(raw) % 512)
        return gzip.compress(raw)

    info = (
        f"pkgname = {name}\npkgver = 1.0-r0\narch = {MACHINE}\nsize = 1\n{pkginfo_extra}"
    ).encode()
    with open(path, "wb") as f:
        f.write(tgz([(".PKGINFO", "file", info, 0o644)], trailer=False))
        f.write(tgz(members, trailer=True))


def make_rpm(
    path: str,
    name: str,
    members: Sequence[Member],
    *,
    requires: Sequence[tuple[str, int, str]] = (),
    provides: Sequence[tuple[str, int, str]] = (),
    postin: str = "",
) -> None:
    """A minimal binary rpm.

    Lead, a signature header, a header with the tags the reader uses, a gzip newc cpio payload.
    members as for make_deb; requires and provides are (name, flags, version) triples.
    """
    import gzip
    import struct
    import time as _t

    # entries: [(tag, type, values)]; types 4 int32, 6 string, 8 string array
    def header(entries: Sequence[tuple[int, int, Sequence[int | str]]]) -> bytes:
        index, data = b"", b""
        for tag, typ, vals in entries:
            if typ == 4:
                data += b"\0" * (-len(data) % 4)
                off = len(data)
                data += b"".join(struct.pack(">i", v) for v in vals)
                index += struct.pack(">IIII", tag, 4, off, len(vals))
            else:
                off = len(data)
                data += b"".join(str(v).encode() + b"\0" for v in vals)
                index += struct.pack(">IIII", tag, typ, off, len(vals))
        return (
            b"\x8e\xad\xe8\x01"
            + b"\0" * 4
            + struct.pack(">II", len(entries), len(data))
            + index
            + data
        )

    def cpio(entries: Sequence[Member]) -> bytes:
        out, ino = b"", 1
        for n, kind, val, mode in entries:
            body = b""
            if kind == "dir":
                m = 0o040000 | mode
            elif kind == "sym":
                assert isinstance(val, str)
                m, body = 0o120000 | mode, val.encode()
            else:
                assert isinstance(val, bytes)
                m, body = 0o100000 | mode, val
            nm = ("./" + n).encode() + b"\0"
            h = b"070701" + b"".join(
                b"%08x" % v
                for v in (ino, m, 0, 0, 1, int(_t.time()), len(body), 0, 0, 0, 0, len(nm), 0)
            )
            rec = h + nm
            rec += b"\0" * (-len(rec) % 4) + body
            rec += b"\0" * (-len(rec) % 4)
            out += rec
            ino += 1
        nm = b"TRAILER!!!\0"
        h = b"070701" + b"".join(b"%08x" % v for v in (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(nm), 0))
        out += h + nm
        return out + b"\0" * (-len(out) % 512)

    payload = gzip.compress(cpio(members))
    entries: list[tuple[int, int, Sequence[int | str]]] = [
        (1000, 6, [name]),
        (1001, 6, ["1.0"]),
        (1002, 6, ["1"]),
        (1022, 6, [MACHINE]),
        (1125, 6, ["gzip"]),
        (1124, 6, ["cpio"]),
    ]
    if requires:
        entries += [
            (1049, 8, [r[0] for r in requires]),
            (1048, 4, [r[1] for r in requires]),
            (1050, 8, [r[2] for r in requires]),
        ]
    if provides:
        entries += [
            (1047, 8, [p[0] for p in provides]),
            (1112, 4, [p[1] for p in provides]),
            (1113, 8, [p[2] for p in provides]),
        ]
    if postin:
        entries += [(1024, 6, [postin])]
    sig = header([(1000, 4, [len(payload)])])
    lead = (
        b"\xed\xab\xee\xdb"
        + bytes([3, 0])
        + struct.pack(">hh", 0, 1)
        + name.encode().ljust(66, b"\0")[:66]
        + struct.pack(">hh", 1, 5)
        + b"\0" * 16
    )
    with open(path, "wb") as f:
        f.write(lead + sig + b"\0" * (-len(sig) % 8) + header(entries) + payload)


@test
def rpm_unpack(ctx: Ctx) -> None:
    """10.1: unpack reads .rpm files by the file.

    Lead, headers, cpio payload; Requires and Provides with rpm's flags, so-called provides, file
    dependencies asked of the tree, rpmlib features and rich dependencies skipped; the merged-usr
    links; alternatives --install lines in %post synthesised; one format per exclave.
    """
    d = os.path.join(ctx.work, "rpms")
    os.makedirs(d, exist_ok=True)
    # rpm's RPMSENSE_EQUAL, and RPMSENSE_GREATER | RPMSENSE_EQUAL
    sense_eq, sense_ge = 8, 12
    make_rpm(
        os.path.join(d, "tool-1.0-1.x86_64.rpm"),
        "tool",
        [
            ("usr", "dir", None, 0o755),
            ("usr/bin", "dir", None, 0o755),
            ("usr/bin/tool-2", "file", b"#!/bin/sh\necho tool ok\n", 0o755),
            (
                "usr/bin/tool",
                "file",
                b"#!/bin/sh\necho the shipped file, which %post removes\n",
                0o755,
            ),
        ],
        requires=[
            ("libfoo.so.1()(64bit)", 0, ""),
            ("absent-pkg", sense_ge, "2"),
            ("/bin/sh", 0, ""),
            ("/usr/bin/absent-file", 0, ""),
            ("rpmlib(CompressedFileNames)", (1 << 24) | 10, "3.0.4-1"),
            ("(a or b)", 0, ""),
        ],
        postin="/usr/bin/rm -f /usr/bin/tool\n"
        "/usr/sbin/alternatives --install /usr/bin/tool tool /usr/bin/tool-2 20\n",
    )
    make_rpm(
        os.path.join(d, "libfoo-1.0-1.x86_64.rpm"),
        "libfoo",
        [
            ("usr", "dir", None, 0o755),
            ("usr/lib64", "dir", None, 0o755),
            ("usr/lib64/libfoo.so.1", "file", b"data\n", 0o644),
            ("usr/bin", "dir", None, 0o755),
            ("usr/bin/sh", "file", b"#!/bin/true\n", 0o755),  # /bin/sh through the merged-usr link
            ("usr/share", "dir", None, 0o755),
            ("usr/share/doc", "file", b"doc\n", 0o644),
        ],
        provides=[("libfoo.so.1()(64bit)", 0, ""), ("libfoo", sense_eq, "1.0-1")],
    )
    out = os.path.join(ctx.work, "rpm.exclave")
    rc, o, e = run(
        [
            *TOOL,
            "unpack",
            out,
            os.path.join(d, "tool-1.0-1.x86_64.rpm"),
            os.path.join(d, "libfoo-1.0-1.x86_64.rpm"),
        ]
    )
    expect(rc == 0, "unpack: " + o + e)
    expect(
        "depends: tool needs absent-pkg (>= 2), not in the set" in o,
        "the versioned dependency was not reported: " + o,
    )
    expect(
        "libfoo" not in o.replace("libfoo-1.0", "")
        and "/bin/sh" not in o
        and "rpmlib" not in o
        and "(a or b)" not in o,
        "a provide in the set, a file dependency the tree has, an rpmlib feature or a rich "
        "dependency was reported: " + o,
    )
    expect(
        "depends: tool needs /usr/bin/absent-file, not in the set" in o,
        "a file dependency the tree lacks was not reported: " + o,
    )
    root = os.path.join(out, "tree")
    expect(
        os.readlink(os.path.join(root, "bin")) == "usr/bin"
        and os.readlink(os.path.join(root, "lib64")) == "usr/lib64",
        "the merged-usr links",
    )
    expect(
        os.path.exists(os.path.join(root, "usr", "lib64", "libfoo.so.1"))
        and os.path.exists(os.path.join(root, "usr", "bin", "tool-2")),
        "payload extracted",
    )
    expect(
        os.path.islink(os.path.join(root, "usr", "bin", "tool"))
        and os.readlink(os.path.join(root, "usr", "bin", "tool")) == "/etc/alternatives/tool"
        and os.readlink(os.path.join(root, "etc", "alternatives", "tool")) == "/usr/bin/tool-2",
        "alternatives from %post replace the shipped file at the link path: {!r}".format(
            os.listdir(os.path.join(root, "usr", "bin"))
        ),
    )
    lock = cli.load(os.path.join(out, ".exclave", "hashes"), "hashes")
    pkgs = cli.values(lock, "pkg")
    expect(
        [tuple(p[:3]) for p in pkgs]
        == [(b"libfoo", b"1.0-1", MACHINE.encode()), (b"tool", b"1.0-1", MACHINE.encode())],
        f"pkg records: {pkgs!r}",
    )
    rc, o, e = run([*TOOL, "wrap", out])
    expect(
        rc == 0 and cli.values(cli.load(os.path.join(out, ".exclave", "hashes"), "hashes"), "tree"),
        "wrap: " + o + e,
    )
    make_apk(os.path.join(d, "x-1.0-r0.apk"), "x", [("usr", "dir", None, 0o755)])
    rc, o, e = run(
        [
            *TOOL,
            "unpack",
            out + "2",
            os.path.join(d, "x-1.0-r0.apk"),
            os.path.join(d, "tool-1.0-1.x86_64.rpm"),
        ]
    )
    expect(rc != 0 and "one format per exclave" in o + e, "a mixed set must be refused: " + o + e)


@test
def apk_unpack(ctx: Ctx) -> None:
    """10.1: unpack reads .apk files by the file, with .PKGINFO's depend and provides.

    Names and file dependencies are asked of the tree; Alpine's directories are its own, not merged
    /usr; busybox's applet links are synthesised from /etc/busybox-paths.d as relative links; one
    format per exclave.
    """
    d = os.path.join(ctx.work, "apks")
    os.makedirs(d, exist_ok=True)
    make_apk(
        os.path.join(d, "tool-1.0-r0.apk"),
        "tool",
        [
            ("usr", "dir", None, 0o755),
            ("usr/bin", "dir", None, 0o755),
            ("usr/bin/tool", "file", b"#!/bin/sh\necho tool ok\n", 0o755),
        ],
        "depend = so:libfoo.so.1\ndepend = absent-pkg>=2\ndepend = /bin/sh\n"
        "depend = /usr/bin/absent-file\n",
    )
    make_apk(
        os.path.join(d, "libfoo-1.0-r0.apk"),
        "libfoo",
        [
            ("bin", "dir", None, 0o755),
            ("bin/busybox", "file", b"#!/bin/true\n", 0o755),
            ("etc", "dir", None, 0o755),
            ("etc/busybox-paths.d", "dir", None, 0o755),
            ("etc/busybox-paths.d/busybox", "file", b"bin/sh\nusr/bin/tool2\n", 0o644),
            ("usr", "dir", None, 0o755),
            ("usr/lib", "dir", None, 0o755),
            ("usr/lib/libfoo.so.1", "file", b"data\n", 0o644),
        ],
        "provides = so:libfoo.so.1=1\nprovides = cmd:busybox=1.0-r0\n",
    )
    out = os.path.join(ctx.work, "apk.exclave")
    rc, o, e = run(
        [
            *TOOL,
            "unpack",
            out,
            os.path.join(d, "tool-1.0-r0.apk"),
            os.path.join(d, "libfoo-1.0-r0.apk"),
        ]
    )
    expect(rc == 0, "unpack: " + o + e)
    expect(
        "depends: tool needs absent-pkg (>= 2), not in the set" in o,
        "the versioned dependency was not reported: " + o,
    )
    expect(
        "libfoo" not in o.replace("libfoo-1.0", "") and "/bin/sh" not in o,
        "a so: provides in the set or a file dependency the tree has (the applet link) was "
        "reported: " + o,
    )
    expect(
        "depends: tool needs /usr/bin/absent-file, not in the set" in o,
        "a file dependency the tree lacks was not reported: " + o,
    )
    root = os.path.join(out, "tree")
    expect(
        os.path.isdir(os.path.join(root, "bin")) and not os.path.islink(os.path.join(root, "bin")),
        "Alpine's /bin is a directory of its own",
    )
    expect(
        os.readlink(os.path.join(root, "bin", "sh")) == "busybox"
        and os.readlink(os.path.join(root, "usr", "bin", "tool2")) == "../../bin/busybox",
        "applet links relative to their target: {!r}".format(os.listdir(os.path.join(root, "bin"))),
    )
    lock = cli.load(os.path.join(out, ".exclave", "hashes"), "hashes")
    pkgs = cli.values(lock, "pkg")
    expect(
        [tuple(p[:3]) for p in pkgs]
        == [(b"libfoo", b"1.0-r0", MACHINE.encode()), (b"tool", b"1.0-r0", MACHINE.encode())],
        f"pkg records: {pkgs!r}",
    )
    rc, o, e = run([*TOOL, "wrap", out])
    expect(
        rc == 0 and cli.values(cli.load(os.path.join(out, ".exclave", "hashes"), "hashes"), "tree"),
        "wrap: " + o + e,
    )
    make_deb(os.path.join(d, "x.deb"), "x", [("./usr", "dir", None, 0o755)])
    rc, o, e = run(
        [*TOOL, "unpack", out + "2", os.path.join(d, "x.deb"), os.path.join(d, "tool-1.0-r0.apk")]
    )
    expect(rc != 0 and "one format per exclave" in o + e, "a mixed set must be refused: " + o + e)


@test
def exclave_readme(ctx: Ctx) -> None:
    """6.1: every exclave explains itself to whoever finds it.

    Unpack, wrap and relink write README at the top where the exclave has none and leave the maker's
    own, or a shortcut by that name, alone; the files it names are there; the launcher run bare
    names it, and a launcher outside any exclave says so. The launcher carries the licence's text,
    and the README names its copyright line.
    """
    d = os.path.join(ctx.work, "readme-apks")
    os.makedirs(d, exist_ok=True)
    make_apk(
        os.path.join(d, "x-1.0-r0.apk"),
        "x",
        [
            ("usr", "dir", None, 0o755),
            ("usr/share", "dir", None, 0o755),
            ("usr/share/x", "file", b"x\n", 0o644),
        ],
    )
    out = os.path.join(ctx.work, "readme-unpacked.exclave")
    rc, o, e = run([*TOOL, "unpack", out, os.path.join(d, "x-1.0-r0.apk")])
    expect(rc == 0, "unpack: " + o + e)
    with open(os.path.join(out, "README"), "rb") as f:
        expect(f.read() == cli.README_TEXT, "unpack wrote no README")
    # a bare directory holding tree/, made an exclave by wrap alone
    bare = os.path.join(ctx.work, "readme-bare")
    os.makedirs(os.path.join(bare, "tree", "usr", "share"))
    os.makedirs(os.path.join(bare, ".exclave"))
    shutil.copy2(ctx.launcher, os.path.join(bare, ".exclave", "launcher"))
    with open(os.path.join(bare, "tree", "usr", "share", "x"), "w") as f:
        f.write("x\n")
    rc, o, e = run([*TOOL, "wrap", bare])
    expect(rc == 0, "wrap: " + o + e)
    with open(os.path.join(bare, "README"), "rb") as f:
        expect(f.read() == cli.README_TEXT, "wrap wrote no README")
    here = cli.README_TEXT.split(b"\nWhat is here\n")[1].split(b"\nRunning it\n")[0].decode()
    for name in re.findall(r"^  (\S+/\S*)", here, re.MULTILINE):
        expect(
            os.path.lexists(os.path.join(bare, name)),
            f"the README names {name}, which a wrapped exclave lacks",
        )
    with open(os.path.join(REPO, "LICENSE"), "rb") as f:
        licence = f.read()
    with open(os.path.join(bare, ".exclave", "launcher"), "rb") as f:
        expect(licence in f.read(), "the launcher does not carry LICENSE's text")
    notice = next(line for line in licence.decode().splitlines() if line.startswith("Copyright"))
    expect(
        notice.encode() in cli.README_TEXT.replace(b"\n", b" "),
        f"the README does not name {notice!r}",
    )
    rc, _out, err = run([os.path.join(bare, ".exclave", "launcher")], cwd=ctx.work)
    expect(
        rc == 127 and "exclave's launcher" in err and "README" in err,
        f"the launcher run bare: rc={rc} {err!r}",
    )
    lone = os.path.join(ctx.work, f"readme-lone-{os.getpid()}")
    os.makedirs(lone, exist_ok=True)
    shutil.copy2(ctx.launcher, os.path.join(lone, "launcher"))
    rc, _out, err = run([os.path.join(lone, "launcher"), "true"], cwd=ctx.work)
    expect(
        rc == 127 and "not inside an exclave" in err and ".exclave/manifest" in err,
        f"a launcher outside an exclave: rc={rc} {err!r}",
    )
    with open(os.path.join(bare, "README"), "w") as f:  # the maker's own notes stay
        f.write("notes\n")
    rc, o, e = run([*TOOL, "wrap", bare])
    expect(
        rc == 0 and read_text(os.path.join(bare, "README")) == "notes\n",
        "wrap replaced the maker's README: " + o + e,
    )
    cli.cmd_relink(bare, ctx.launcher)
    expect(
        read_text(os.path.join(bare, "README")) == "notes\n", "relink replaced the maker's README"
    )
    os.remove(os.path.join(bare, "README"))
    # a shortcut by that name stays a shortcut
    os.symlink("tree/usr/share/x", os.path.join(bare, "README"))
    cli.cmd_relink(bare, ctx.launcher)
    expect(
        os.readlink(os.path.join(bare, "README")) == "tree/usr/share/x",
        "relink replaced a shortcut named README",
    )
    os.remove(os.path.join(bare, "README"))
    cli.cmd_relink(bare, ctx.launcher)  # an exclave wrapped before there was a README gets one
    with open(os.path.join(bare, "README"), "rb") as f:
        expect(f.read() == cli.README_TEXT, "relink wrote no README")


@test
def tool_extraction_rules(ctx: Ctx) -> None:
    """10.1: a member reached through a package's own symlink is refused.

    Two spellings of one path under merged usr conflict.
    """
    d = os.path.join(ctx.work, "debs")
    os.makedirs(d, exist_ok=True)
    outside = os.path.join(ctx.work, "escaped")
    os.makedirs(outside, exist_ok=True)
    with open(os.path.join(outside, "README"), "w") as f:
        f.write("ORIGINAL\n")
    make_deb(
        os.path.join(d, "evil.deb"),
        "evil",
        [
            ("./usr", "dir", None, 0o755),
            ("./usr/share", "dir", None, 0o755),
            ("./usr/share/doc", "sym", "../../../../escaped", 0o777),
            ("./usr/share/doc/README", "file", b"ESCAPED\n", 0o644),
        ],
    )
    root = os.path.join(ctx.work, "root-evil")
    try:
        build.extract(root, [("evil", os.path.join(d, "evil.deb"), {})], log=lambda *_: None)
    except build.BuildError as e:
        expect("escapes" in str(e), str(e))
    else:
        msg = "a member behind a symlink out of the tree was extracted"
        raise AssertionError(msg)
    expect(
        read_text(os.path.join(outside, "README")) == "ORIGINAL\n",
        "the file outside the tree was written",
    )
    make_deb(
        os.path.join(d, "a.deb"),
        "a",
        [
            ("./usr", "dir", None, 0o755),
            ("./usr/lib", "dir", None, 0o755),
            ("./usr/lib/libfoo.so.1", "file", b"A", 0o644),
        ],
    )
    make_deb(
        os.path.join(d, "b.deb"),
        "b",
        [("./lib", "dir", None, 0o755), ("./lib/libfoo.so.1", "file", b"B", 0o644)],
    )
    root = os.path.join(ctx.work, "root-alias")
    try:
        build.extract(
            root,
            [("a", os.path.join(d, "a.deb"), {}), ("b", os.path.join(d, "b.deb"), {})],
            log=lambda *_: None,
        )
    except build.BuildError as e:
        expect("both ship" in str(e), str(e))
    else:
        msg = "the merged-usr spellings of one file were not seen as a conflict"
        raise AssertionError(msg)


@test
def unpack_and_wrap(ctx: Ctx) -> None:
    """10.1 as files: unpack, wrap, unwrap and check on package files.

    Unpack takes package files and nothing else, records every input by hash, reports what the set's
    own control files say it lacks, refuses two versions of one package; wrap wraps it and records
    the manifest and tree hashes; unwrap, check and a second wrap keep the hashes file; a tree
    assembled by hand becomes an exclave by wrap alone.
    """
    from exclave import elfcheck

    d = os.path.join(ctx.work, "updebs")
    os.makedirs(d, exist_ok=True)
    true_bytes = read_bytes(ctx.payload("true"))
    make_deb(
        os.path.join(d, "tool.deb"),
        "tool",
        [
            ("./usr", "dir", None, 0o755),
            ("./usr/bin", "dir", None, 0o755),
            ("./usr/bin/tool", "file", b"#!/bin/sh\necho tool ok\n", 0o755),
        ],
        "Depends: libfoo1 (>= 2), virt | missing-alt\nPre-Depends: absent-pkg\n",
    )
    make_deb(
        os.path.join(d, "libfoo1.deb"),
        "libfoo1",
        [
            ("./usr", "dir", None, 0o755),
            ("./usr/share", "dir", None, 0o755),
            ("./usr/share/foo", "file", b"data\n", 0o644),
        ],
        "Provides: virt\n",
    )
    out = os.path.join(ctx.work, "up.exclave")
    rc, o, e = run(
        [*TOOL, "unpack", out, os.path.join(d, "tool.deb"), os.path.join(d, "libfoo1.deb")]
    )
    expect(rc == 0, "unpack: " + o + e)
    expect(
        "depends: tool needs absent-pkg, not in the set" in o,
        "the missing Pre-Depends was not reported: " + o,
    )
    expect(
        "depends: tool needs libfoo1 (>= 2), not in the set" in o,
        "the version constraint was not checked: " + o,
    )
    expect("virt" not in o, "a Provides in the set was reported missing: " + o)
    lock = cli.load(os.path.join(out, ".exclave", "hashes"), "hashes")
    pkgs = cli.values(lock, "pkg")
    expect(
        [p[0] for p in pkgs] == [b"libfoo1", b"tool"]
        and pkgs[1][1] == b"1"
        and pkgs[1][2] == DEB_ARCH.encode(),
        f"pkg records: {pkgs!r}",
    )
    expect(
        pkgs[1][3].decode() == cli.b2_file(os.path.join(d, "tool.deb")),
        "the input hash is the file's",
    )
    expect(not cli.values(lock, "tree"), "an unwrapped exclave has no tree hash yet")
    expect(
        os.path.exists(os.path.join(out, "tree", "opt"))
        and os.path.exists(os.path.join(out, "tree", "etc", "passwd")),
        "placeholders",
    )
    expect(
        os.path.exists(os.path.join(out, ".exclave", "launcher"))
        and not os.path.exists(os.path.join(out, ".exclave", "manifest")),
        "an unwrapped exclave: launcher yes, manifest not yet",
    )
    # the exclave is a directory between the two steps: put an ELF in by hand, then wrap it
    with open(os.path.join(out, "tree", "usr", "bin", "t2"), "wb") as f:
        f.write(true_bytes)
    os.chmod(os.path.join(out, "tree", "usr", "bin", "t2"), 0o755)
    rc, o, e = run([*TOOL, "wrap", out])
    expect(
        rc == 1 and "does not resolve" in o,
        f"an ELF whose loader the tree lacks must refuse the wrap: rc={rc} {o[-400:]}",
    )
    os.remove(os.path.join(out, "tree", "usr", "bin", "t2"))
    rc, o, e = run([*TOOL, "wrap", out])
    expect(rc == 0 and f"{out} is wrapped" in o, "wrap: " + o + e)
    lock = cli.load(os.path.join(out, ".exclave", "hashes"), "hashes")
    expect(
        len(cli.values(lock, "pkg")) == 2
        and cli.values(lock, "tree")
        and cli.values(lock, "manifest"),
        "the wrapped hashes file keeps its inputs and adds the hashes: "
        f"{[(r.key) for r in lock]!r}",
    )
    expect(
        read_bytes(os.path.join(out, ".exclave", "manifest")) == b"exclave 1\n",
        "the default manifest",
    )
    rc, o, e = run([*TOOL, "hash", out])
    expect(o.strip().encode() == cli.values(lock, "tree")[0][0], "hash agrees with the hashes file")
    expect(
        cli.is_wrapper(os.path.join(out, "tree", "usr", "bin", "tool"), cli.launcher_ino(out)),
        "the script was wrapped",
    )
    rc, o, e = run(
        [
            *TOOL,
            "unpack",
            os.path.join(ctx.work, "dup.exclave"),
            os.path.join(d, "tool.deb"),
            os.path.join(d, "tool.deb"),
        ]
    )
    expect(
        rc != 0 and "one version of a package" in e,
        f"two files of one package must be refused: {o} {e}",
    )
    # a hand-made tree becomes an exclave by wrap alone: no manifest, no inputs in the hashes file
    hand = os.path.join(ctx.work, "hand.exclave")
    os.makedirs(os.path.join(hand, "tree", "usr", "bin"))
    with open(os.path.join(hand, "tree", "usr", "bin", "hi"), "w") as f:
        f.write("#!/bin/sh\necho hi\n")
    os.chmod(os.path.join(hand, "tree", "usr", "bin", "hi"), 0o755)
    rc, o, e = run([*TOOL, "wrap", hand])
    expect(rc == 0, "wrap of a bare tree: " + o + e)
    lock = cli.load(os.path.join(hand, ".exclave", "hashes"), "hashes")
    expect(
        not cli.values(lock, "pkg") and cli.values(lock, "tree") and cli.values(lock, "launcher"),
        "a hand-made exclave's hashes file has no inputs, a launcher hash and a tree hash",
    )
    rep = elfcheck.static_check(hand, cli.owned(hand), [])
    expect(not rep.errors, f"static check of a tree with no ELF: {rep.errors!r}")
    expect(
        os.path.exists(os.path.join(hand, "tree", "etc", "passwd"))
        and os.path.isdir(os.path.join(hand, "tree", "opt")),
        "wrap adds the placeholders a hand-made tree lacks",
    )
    # the hashes file through the life of an exclave
    wrapped = read_bytes(os.path.join(out, ".exclave", "hashes"))
    rc, o, e = run([*TOOL, "unwrap", out])
    expect(rc == 0, "unwrap: " + o + e)
    lock = cli.load(os.path.join(out, ".exclave", "hashes"), "hashes")
    expect(
        len(cli.values(lock, "pkg")) == 2
        and not cli.values(lock, "tree")
        and not cli.values(lock, "manifest")
        and not cli.values(lock, "launcher"),
        "an unwrapped exclave's hashes file keeps its inputs and has no hashes: "
        f"{[r.key for r in lock]!r}",
    )
    rc, o, e = run([*TOOL, "check", out])
    expect(rc == 1 and "an unwrapped exclave" in o, "check names an unwrapped exclave: " + o[-300:])
    rc, o, e = run([*TOOL, "wrap", out])
    expect(
        rc == 0 and read_bytes(os.path.join(out, ".exclave", "hashes")) == wrapped,
        "wrap after unwrap reproduces the hashes file byte for byte",
    )
    os.remove(os.path.join(out, "tree", "usr", "share", "foo"))
    rc, o, e = run([*TOOL, "check", out])
    expect(
        rc == 1 and "differs from the hashes file" in o,
        "a file removed from a wrapped exclave must show against the hashes file: " + o[-300:],
    )
    rc, o, e = run([*TOOL, "hash", os.path.join(ctx.work, "not-an-exclave")])
    expect(rc != 0 and "no tree" in e, "hash of a non-exclave is refused")
    lockcopy = os.path.join(ctx.work, "some.hashes.txt")
    shutil.copy2(os.path.join(out, ".exclave", "hashes"), lockcopy)
    rc, o, e = run([*TOOL, "format", "--check", lockcopy])
    expect(rc == 0, "format recognises a hashes file by its first record, not its name: " + o + e)


@test
def wrap_refusals(ctx: Ctx) -> None:
    """Wrap refuses, and wraps nothing when it refuses.

    It refuses a stale wrapper of another launcher, a file its user cannot execute, an original
    without a wrapper, an ELF whose loader the tree lacks, a manifest or a tree beyond the
    launcher's tables, which the launcher refuses too; executables in a data directory are left
    alone.
    """

    def hand(
        name: str, files: Sequence[tuple[str, bytes, int]], manifest: bytes | None = None
    ) -> str:
        ex = os.path.join(ctx.work, name)
        shutil.rmtree(ex, ignore_errors=True)
        for v, body, mode in files:
            p = os.path.join(ex, "tree", v.lstrip("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(body)
            os.chmod(p, mode)
        if manifest is not None:
            os.makedirs(os.path.join(ex, ".exclave"), exist_ok=True)
            with open(os.path.join(ex, ".exclave", "manifest"), "wb") as f:
                f.write(manifest)
        return ex

    script = b"#!/bin/sh\necho hi\n"
    true_bytes = read_bytes(ctx.payload("true"))
    # a copy whose launcher differs by a byte, then wrap: the original must survive
    a = hand("st.exclave", [("/usr/bin/hi", script, 0o755)])
    rc, o, e = run([*TOOL, "wrap", a])
    expect(rc == 0, o + e)
    b = os.path.join(ctx.work, "st2.exclave")
    shutil.rmtree(b, ignore_errors=True)
    shutil.copytree(a, b, symlinks=True)  # plain copies: the hard links are broken
    with open(os.path.join(b, ".exclave", "launcher"), "ab") as f:
        f.write(b"\0")
    rc, o, e = run([*TOOL, "wrap", b])
    expect(
        rc != 0 and "stale wrapper" in o + e and "relink" in o + e,
        f"a stale wrapper must be refused: {rc} {o[-300:]} {e[-300:]}",
    )
    expect(
        read_bytes(os.path.join(b, "tree", "usr", "bin", ".real", "hi")) == script,
        "the original was overwritten",
    )
    rc, o, e = run([*TOOL, "relink", b, ctx.launcher_src])
    rc, o, e = run([*TOOL, "wrap", b])
    expect(rc == 0, "after relink the copy is wrapped: " + o + e)
    # an executable its user cannot execute
    c = hand("nx.exclave", [("/usr/bin/gx", script, 0o601)])
    rc, o, e = run([*TOOL, "wrap", c])
    expect(
        rc != 0
        and "cannot execute" in o + e
        and not os.path.exists(os.path.join(c, "tree", "usr", "bin", ".real")),
        f"a 0601 file must not become a 0755 launcher: {o[-300:]} {e[-300:]}",
    )
    # an original without a wrapper
    d = hand("stray.exclave", [("/usr/bin/hi", script, 0o755)])
    rc, o, e = run([*TOOL, "wrap", d])
    expect(rc == 0, o + e)
    h1 = run([*TOOL, "hash", d])[1].strip()
    with open(os.path.join(d, "tree", "usr", "bin", ".real", "stray"), "wb") as f:
        f.write(true_bytes)
    os.chmod(os.path.join(d, "tree", "usr", "bin", ".real", "stray"), 0o755)
    h2 = run([*TOOL, "hash", d])[1].strip()
    expect(h1 != h2, "a stray original must change the tree hash")
    for cmd in ("wrap", "unwrap", "check"):
        rc, o, e = run([*TOOL, cmd, d])
        expect(
            rc != 0 and "original without wrapper" in o + e,
            f"{cmd} must refuse a stray original: {o[-300:]} {e[-300:]}",
        )
    rc, o, e = run([*TOOL, "relink", d, ctx.launcher_src])
    expect(
        rc == 0
        and "left alone" in o
        and not os.path.exists(os.path.join(d, "tree", "usr", "bin", "stray")),
        "relink must not make a wrapper for a stray: " + o,
    )
    # a refused wrap wraps nothing
    e_ = hand(
        "noloader.exclave", [("/usr/bin/hi", script, 0o755), ("/usr/bin/t", true_bytes, 0o755)]
    )
    rc, o, e = run([*TOOL, "wrap", e_])
    expect(
        rc == 1
        and "nothing was wrapped" in o
        and not os.path.exists(os.path.join(e_, "tree", "usr", "bin", ".real")),
        "a refused wrap must leave the tree unwrapped: " + o[-400:],
    )
    # the launcher's tables
    f_ = hand(
        "lim.exclave",
        [("/usr/bin/hi", script, 0o755)],
        b"exclave 1\n\n" + b"".join(b'own "/own%03d"\n' % i for i in range(300)),
    )
    rc, o, e = run([*TOOL, "wrap", f_])
    expect(
        rc != 0 and "line 259 col 1: more than 256 own records" in o + e,
        "300 own records must be refused at the 257th: " + (o + e)[-300:],
    )
    g = hand(
        "lim2.exclave",
        [("/usr/bin/hi", script, 0o755)],
        b"exclave 1\n\n" + b"".join(b'host "/hostpath%03d"\n' % i for i in range(40)),
    )
    rc, o, e = run([*TOOL, "wrap", g])
    expect(
        rc != 0 and "line 35 col 1: more than 32 host records" in o + e,
        "40 host records must be refused at the 33rd: " + (o + e)[-300:],
    )
    t_ = hand(
        "lim3.exclave",
        [("/usr/bin/hi", script, 0o755)] + [(f"/top{i:03}", b"", 0o644) for i in range(300)],
    )
    for i in range(20):
        # placeholders take no slot, as the launcher counts
        os.makedirs(os.path.join(t_, "tree", f"empty{i:02}"))
    rc, o, e = run([*TOOL, "wrap", t_])
    # /usr, /etc with its identity placeholders, the 300
    m = re.search(r"tree/ has (\d+) top-level entries; the launcher holds 256", o + e)
    expect(
        rc != 0 and m and 301 < int(m.group(1)) < 320,
        "300 top-level files must be refused, the placeholders not counted: " + (o + e)[-300:],
    )
    ex2 = os.path.join(ctx.work, "hosts30.exclave")
    copy_exclave(ctx.exclave, ex2)
    with open(os.path.join(ex2, ".exclave", "manifest"), "wb") as f:
        f.write(b"exclave 1\n\n" + b"".join(b'host "/hostpath%03d"\n' % i for i in range(30)))
    rc, out, err = run(
        [os.path.join(ex2, "tree", ctx.vbin("cat").lstrip("/")), "/etc/hosts"],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        rc == 0 and out == read_text("/etc/hosts"),
        f"30 host records leave the identity files the host's: {out[:80]!r} {err!r}",
    )
    # the tree's 256 slots are its own, whatever the manifest owns
    ex3 = os.path.join(ctx.work, "top300.exclave")
    copy_exclave(ctx.exclave, ex3)
    for i in range(300):
        open(os.path.join(ex3, "tree", f"top{i:03}"), "w").close()
    rc, out, err = run(
        [os.path.join(ex3, "tree", ctx.vbin("cat").lstrip("/")), "/etc/hosts"],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        rc != 0 and "more than 256 top-level entries" in err,
        f"300 top-level entries must be refused by the launcher: {err[-300:]!r}",
    )
    # a data directory is neither wrapped nor executed
    dp = os.path.join(ctx.work, "data.exclave")
    copy_exclave(ctx.exclave, dp)
    sys_ = os.path.join(dp, "tree", "opt", "sysroot", "bin")
    os.makedirs(sys_)
    with open(os.path.join(sys_, "true"), "wb") as f:
        f.write(true_bytes)
    os.chmod(os.path.join(sys_, "true"), 0o755)
    with open(os.path.join(dp, ".exclave", "manifest"), "wb") as f:
        f.write(b'exclave 1\n\ndata "/opt/sysroot"\n')
    rc, o, e = run([*TOOL, "wrap", dp])
    expect(
        rc == 0 and not os.path.exists(os.path.join(sys_, ".real")),
        "the data directory was wrapped or the exclave refused: " + (o + e)[-400:],
    )
    rc, o, e = run([*TOOL, "check", dp])
    expect(rc == 0, "check with a data directory: " + o[-300:])
    rc, out, err = run(
        [
            os.path.join(dp, "tree", ctx.vbin("sh").lstrip("/")),
            "-c",
            "/opt/sysroot/bin/true; echo rc=$?",
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        "Permission denied" in out + err and "rc=126" in out,
        f"a data directory is never executed: {out!r} {err!r}",
    )


@test
def wrap_refuses_unreadable(ctx: Ctx) -> None:
    """10.1, 10.3: a file the user cannot read is an error of the static check.

    Wrap therefore refuses before it wraps anything and the exclave stays the directory it was;
    check names the third state, a wrapped exclave without a hashes file (N4).
    """
    ex = os.path.join(ctx.work, "unread.exclave")
    shutil.rmtree(ex, ignore_errors=True)
    os.makedirs(os.path.join(ex, "tree", "usr", "bin"))
    os.makedirs(os.path.join(ex, "tree", "etc"))
    with open(os.path.join(ex, "tree", "usr", "bin", "hi"), "w") as f:
        f.write("#!/bin/sh\necho hi\n")
    os.chmod(os.path.join(ex, "tree", "usr", "bin", "hi"), 0o755)
    with open(os.path.join(ex, "tree", "etc", "private"), "w") as f:
        f.write("secret\n")
    os.chmod(os.path.join(ex, "tree", "etc", "private"), 0)
    try:
        rc, o, e = run([*TOOL, "wrap", ex])
        expect(
            rc != 0 and "unreadable file /etc/private" in o + e and "nothing was wrapped" in o + e,
            f"an unreadable file must refuse the wrap: {rc} {o[-300:]} {e[-300:]}",
        )
        expect(
            not os.path.exists(os.path.join(ex, "tree", "usr", "bin", ".real"))
            and not os.path.exists(os.path.join(ex, ".exclave", "hashes")),
            "a refused wrap leaves the tree as it was",
        )
        os.chmod(os.path.join(ex, "tree", "etc", "private"), 0o600)
        rc, o, e = run([*TOOL, "wrap", ex])
        expect(rc == 0, "readable again, the exclave is wrapped: " + o + e)
        os.remove(os.path.join(ex, ".exclave", "hashes"))
        rc, o, e = run([*TOOL, "check", ex])
        expect(
            rc != 0 and "wrap never finished" in o + e,
            f"a wrapped exclave without a hashes file is reported: {rc} {o[-300:]}",
        )
    finally:
        os.chmod(os.path.join(ex, "tree", "etc", "private"), 0o600)


@test
def ownership_fails_closed(ctx: Ctx) -> None:
    """8.1: a top-level directory the launcher cannot list is the exclave's, not a placeholder.

    A spawn with no descriptor to spare fails loudly instead of running on the host.
    """
    ex2 = os.path.join(ctx.work, "perm.exclave")
    copy_exclave(ctx.exclave, ex2)
    secret = os.path.join(ex2, "tree", "secret")
    os.makedirs(secret)
    with open(os.path.join(secret, "file"), "w") as f:
        f.write("data\n")
    cat = os.path.join(ex2, "tree", ctx.vbin("cat").lstrip("/"))
    os.chmod(secret, 0)
    try:
        rc, out, err = run([cat, "/secret/file"], cwd=ctx.work, env=ctx.env)
        expect(
            "Permission denied" in err and "No such file" not in err,
            f"an unlistable directory must be the exclave's: {err!r}",
        )
        expect("/secret" in cli.owned(ex2), "the tool's ownership must agree")
    finally:
        os.chmod(secret, 0o755)
    # built by the exclave's gcc: runs inside, like every built program
    press = os.path.join(ctx.progs, "fdpress")
    # the exclave's libc as the maps show it
    libc_real = ".real/" + (os.path.basename(ctx.libc) if ctx.libc else ctx.ldso_name)
    rc, out, err = inside(ctx, press, ["1", cat, "/proc/self/maps"])
    # musl's posix_spawn wants a pipe first
    loud = (rc == 127 and "Too many open files" in err) or (
        ctx.musl and "No file descriptors" in err
    )
    expect(
        loud and libc_real not in out,
        "with one spare descriptor the launcher must fail loudly, never run the host's libc: "
        f"rc={rc} {out[:200]!r} {err!r}",
    )
    rc, out, err = inside(ctx, press, ["4", cat, "/proc/self/maps"])
    expect(
        rc == 0 and libc_real in out,
        f"with four spare descriptors the exclave runs: rc={rc} {err!r}",
    )


@test
def root_listing_is_the_tree(ctx: Ctx) -> None:
    """8.3: the root directory itself is the tree's.

    ls / lists the tree's entries, and cd into a placeholder works whether or not the host has the
    name.
    """
    rc, out, err = run([wrapper(ctx, "ls"), "-A", "/"], cwd=ctx.work, env=ctx.env)
    expect(
        rc == 0 and sorted(out.split()) == sorted(os.listdir(ctx.root)),
        f"ls / must list the tree: {out!r}",
    )
    rc, out, err = run(
        [
            wrapper(ctx, "sh"),
            "-c",
            "cd /srv && pwd && cd / && pwd && touch /x 2>&1 || echo refused",
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out.startswith("/srv\n/\n") and "refused" in out,
        f"cd into a placeholder and the read-only root: {out!r} {err!r}",
    )


@test
def log_names_and_escapes(ctx: Ctx) -> None:
    """6.2: a failed resolution logs the path as given.

    A path with a newline or backslash is escaped in the log and undone by the tool, so prune keeps
    the file the workload opened; prune refuses a log that names no program.
    """
    log = os.path.join(ctx.work, "names.log")
    if os.path.exists(log):
        os.remove(log)
    rc, out, err = run(
        [wrapper(ctx, "cat"), "/usr/share/no/such/file"],
        cwd=ctx.work,
        env=dict(ctx.env, EXCLAVE_LOG=log),
    )
    text = read_text(log)
    expect(
        "open -2 /usr/share/no/such/file" in text,
        "a failed intermediate component must be logged by name: " + text[-300:],
    )
    ex2 = os.path.join(ctx.work, "odd.exclave")
    copy_exclave(ctx.exclave, ex2)
    odd = os.path.join(ex2, "tree", "usr", "share", "odd")
    os.makedirs(odd)
    # the last a backslash before an n, not a newline
    names = ("with\nnewline", "back\\slash", "back\\nslash")
    for name in names:
        with open(os.path.join(odd, name), "w") as f:
            f.write(name)
    log2 = os.path.join(ctx.work, "odd.log")
    for name in names:
        rc, out, err = run(
            [os.path.join(ex2, "tree", ctx.vbin("cat").lstrip("/")), "/usr/share/odd/" + name],
            cwd=ctx.work,
            env=dict(ctx.env, EXCLAVE_LOG=log2),
        )
        expect(out == name, f"cat of the odd name: {out!r} {err!r}")
    lines = read_text(log2).split("\n")
    expect(
        any(line == "open 3 /usr/share/odd/with\\nnewline" for line in lines)
        and any(line == "open 3 /usr/share/odd/back\\\\slash" for line in lines),
        f"escapes in the log: {[line for line in lines if 'odd' in line]!r}",
    )
    src = hello_source(ctx)
    rc, out, err = run(
        [
            os.path.join(ex2, "tree", ctx.vbin(ctx.gcc).lstrip("/")),
            "-O1",
            src,
            "-o",
            os.path.join(ctx.work, "hello-odd"),
        ],
        cwd=ctx.work,
        env=dict(ctx.env, EXCLAVE_LOG=log2),
    )
    expect(rc == 0, err)
    rc, o, e = run([*TOOL, "prune", ex2, log2])
    expect(rc == 0, "prune: " + o + e)
    expect(
        sorted(os.listdir(odd)) == sorted(names),
        f"the odd names must survive pruning: {os.listdir(odd)!r}",
    )
    empty = os.path.join(ctx.work, "empty.log")
    open(empty, "w").close()
    before = sum(1 for _ in cli.walk_files(os.path.join(ex2, "tree")))
    rc, o, e = run([*TOOL, "prune", ex2, empty])
    expect(
        rc != 0
        and "name no program" in o + e
        and sum(1 for _ in cli.walk_files(os.path.join(ex2, "tree"))) == before,
        f"an empty log must be refused: {o[-200:]} {e[-200:]}",
    )


@test
def ownership_from_tree(ctx: Ctx) -> None:
    """8.1: the ownership set is read from the tree at startup.

    A file added under a placeholder therefore makes the directory the exclave's with nothing to
    refresh; an empty placeholder stays the host's.
    """
    ex2 = os.path.join(ctx.work, "own.exclave")
    copy_exclave(ctx.exclave, ex2)
    sh = os.path.join(ex2, "tree", ctx.vbin("sh").lstrip("/"))
    _rc, out, err = run(
        [sh, "-c", "cat /opt/exclave-probe 2>&1; ls /srv"], cwd=ctx.work, env=ctx.env
    )
    expect(
        "No such file" in out,
        f"before: /opt is the host's, the probe does not exist there: {out!r}",
    )
    os.makedirs(os.path.join(ex2, "tree", "opt"), exist_ok=True)
    with open(os.path.join(ex2, "tree", "opt", "exclave-probe"), "w") as f:
        f.write("probe\n")
    _rc, out, err = run(
        [sh, "-c", "cat /opt/exclave-probe; touch /opt/x 2>&1 || echo refused"],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out.startswith("probe\n") and "refused" in out,
        f"after: /opt is the exclave's, read-only, with no index refreshed: {out!r} {err!r}",
    )
    _rc, out, err = run(
        [
            sh,
            "-c",
            (
                f"ls -d /srv && touch /srv/exclave-probe-{os.getpid()} "
                f"&& rm /srv/exclave-probe-{os.getpid()} && echo host"
            ),
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out.strip().endswith("host") or "Permission denied" in err,
        f"an empty placeholder stays the host's: {out!r} {err!r}",
    )


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
def prune_and_check_with_logs(ctx: Ctx) -> str:
    """10.3 and 10.4 take files.

    The dynamic check reads EXCLAVE_LOG files a workload wrote; prune keeps what the logs touched
    plus the libraries kept ELF files need and the packages' licence texts, those the tree has and
    two planted where Debian and RPM put them, and drops the rest, and the pruned exclave still
    compiles.
    """
    from exclave import build

    log = os.path.join(ctx.work, "prune.log")
    if os.path.exists(log):
        os.remove(log)
    src = hello_source(ctx)
    rc, out, err = run(
        [wrapper(ctx, ctx.gcc), "-O1", src, "-o", os.path.join(ctx.work, "hello-prune")],
        cwd=ctx.work,
        env=dict(ctx.env, EXCLAVE_LOG=log),
    )
    expect(rc == 0, err)
    rc, out, err = run([*TOOL, "check", ctx.exclave, log])
    expect(
        rc == 0 and "0 errors" in out and "dynamic check:" in out and "log lines" in out,
        "check with a log: " + out[-500:] + err,
    )
    ex2 = os.path.join(ctx.work, "pruned.exclave")
    copy_exclave(ctx.exclave, ex2)
    planted = [
        "/usr/share/doc/exclave-planted/copyright",
        "/usr/share/licenses/exclave-planted/COPYING",
    ]
    for v in planted:
        os.makedirs(os.path.dirname(os.path.join(ex2, "tree", v.lstrip("/"))), exist_ok=True)
        with open(os.path.join(ex2, "tree", v.lstrip("/")), "w") as f:
            f.write("a licence no workload reads\n")
    licences = set(build.licence_files(os.path.join(ex2, "tree")))
    before = sum(1 for _ in cli.walk_files(os.path.join(ex2, "tree")))
    rc, out, err = run([*TOOL, "prune", ex2, log])
    expect(rc == 0 and "pruned" in out, "prune: " + out + err)
    after = sum(1 for _ in cli.walk_files(os.path.join(ex2, "tree")))
    expect(after < before // 2, f"pruning removed little: {after} of {before} files remain")
    expect(
        os.path.isdir(os.path.join(ex2, "tree", "usr", "share"))
        and os.path.exists(os.path.join(ex2, "tree", "etc", "passwd")),
        "directories and placeholders stay",
    )
    lost = sorted(
        v for v in licences if not os.path.exists(os.path.join(ex2, "tree", v.lstrip("/")))
    )
    expect(
        not lost and set(planted) <= licences,
        f"the licence texts stay: {len(lost)} of {len(licences)} lost, {lost[:3]}",
    )
    gcc2 = os.path.join(ex2, "tree", ctx.vbin(ctx.gcc).lstrip("/"))
    rc, out, err = run(
        [gcc2, "-O1", src, "-o", os.path.join(ctx.work, "hello-pruned")], cwd=ctx.work, env=ctx.env
    )
    expect(rc == 0, "the pruned exclave compiles: " + err[-500:])
    rc, out, err = inside(ctx, os.path.join(ctx.work, "hello-pruned"))
    expect(rc == 0 and out.startswith("hello "), f"the output runs: {out!r} {err!r}")
    rc, out, err = run([*TOOL, "check", ex2])
    expect(rc == 0, "the pruned exclave passes the static check: " + out[-600:])
    return f"{after} of {before} files kept, {len(licences)} licence texts among them"


@test
def static_check_loader_model(ctx: Ctx) -> str | None:
    """10.3: the static check models the loader.

    DT_RPATH is inherited down the chain, ld.so.cache is read, a search directory the exclave does
    not own is refused; a hand-made glibc layout is wrapped, a truncated ELF is an error by name, a
    host record is applied as the launcher applies it, a library a workload built in its own
    directory is a note; a separate debug file, whose segments carry no bytes, is not a program; a
    DT_NEEDED that is a path through $ORIGIN resolves where glibc's loader expands it, and not under
    musl's, which does not.
    """
    from exclave import elfcheck

    x = os.path.join(ctx.root, "usr", "local", "x")
    base = os.path.join(x, "lib")
    made_local = not os.path.exists(os.path.dirname(x))
    os.makedirs(base, exist_ok=True)
    src = os.path.join(ctx.work, "rp")
    os.makedirs(src, exist_ok=True)
    with open(os.path.join(src, "bar.c"), "w") as f:
        f.write("int bar(void) { return 1; }\n")
    with open(os.path.join(src, "foo.c"), "w") as f:
        f.write("int bar(void); int foo(void) { return bar(); }\n")
    with open(os.path.join(src, "prog.c"), "w") as f:
        f.write("int foo(void); int main(void) { return foo(); }\n")
    with open(os.path.join(src, "dst.c"), "w") as f:
        f.write("int bar(void); int main(void) { return bar(); }\n")
    gcc = wrapper(ctx, ctx.gcc)
    built = os.path.join(src, "out")  # built on the host side, then placed in the tree by hand:
    # from inside the exclave the tree's real path is the read-only exclave
    os.makedirs(built, exist_ok=True)
    try:
        for cmd in (
            [
                "-shared",
                "-fPIC",
                "-Wl,-soname,libbar.so.1",
                "-o",
                os.path.join(built, "libbar.so.1"),
                "bar.c",
            ],
            [
                "-shared",
                "-fPIC",
                "-Wl,-soname,libfoo.so.1",
                "-o",
                os.path.join(built, "libfoo.so.1"),
                "foo.c",
                "-L" + built,
                "-l:libbar.so.1",
            ],
            [
                "-o",
                os.path.join(built, "prog"),
                "prog.c",
                "-L" + built,
                "-l:libfoo.so.1",
                "-Wl,-rpath-link," + built,
                "-Wl,--disable-new-dtags",
                "-Wl,-rpath,/usr/local/x/lib",
            ],
            [
                "-o",
                os.path.join(built, "hostprog"),
                "prog.c",
                "-L" + built,
                "-l:libfoo.so.1",
                "-Wl,-rpath-link," + built,
                "-Wl,-rpath,/tmp/exclave-hostlib",
            ],
            [
                "-shared",
                "-fPIC",
                "-Wl,-soname,$ORIGIN/../lib/libdst.so",
                "-o",
                os.path.join(built, "libdst.so"),
                "bar.c",
            ],
            ["-o", os.path.join(built, "dstprog"), "dst.c", "-L" + built, "-l:libdst.so"],
        ):
            rc, out, err = run([gcc, *cmd], cwd=src, env=ctx.env)
            expect(rc == 0, err)
        rc, out, err = run(
            [
                wrapper(ctx, "objcopy"),
                "--only-keep-debug",
                os.path.join(built, "prog"),
                os.path.join(built, "prog.debug"),
            ],
            cwd=src,
            env=ctx.env,
        )
        expect(rc == 0, "objcopy: " + err)
        # as /usr/lib/debug holds them: an empty PT_INTERP
        shutil.copy2(os.path.join(built, "prog.debug"), os.path.join(x, "prog.debug"))
        for f in ("libbar.so.1", "libfoo.so.1", "libdst.so"):
            shutil.copy2(os.path.join(built, f), os.path.join(base, f))
        # $ORIGIN/../lib from /usr/local/x/bin is /usr/local/x/lib
        os.makedirs(os.path.join(x, "bin"), exist_ok=True)
        shutil.copy2(os.path.join(built, "dstprog"), os.path.join(x, "bin", "dstprog"))
        for f in ("prog", "hostprog"):
            shutil.copy2(os.path.join(built, f), os.path.join(x, f))
        rep = elfcheck.static_check(
            ctx.exclave, cli.owned(ctx.exclave), cli.data_prefixes(ctx.exclave)
        )
        bad = [
            e
            for e in rep.errors
            if "/usr/local/x/prog" in e or ("libfoo" in e and "hostprog" not in e)
        ]
        expect(not bad, "RPATH inheritance: " + "; ".join(bad))
        debug = [e for e in rep.errors if "prog.debug" in e]
        expect(not debug, f"a separate debug file is not a program: {debug!r}")
        expect(
            any("hostprog" in e and "does not own" in e for e in rep.errors),
            f"a host RPATH must be refused: {rep.errors[:3]!r}",
        )
        dst = [e for e in rep.errors if "libdst" in e]
        expect(
            bool(dst) == ctx.musl,
            "a DT_NEEDED through $ORIGIN ({}): {!r}".format(
                "unexpanded by musl" if ctx.musl else "expanded by glibc", dst
            ),
        )
        cache = elfcheck.read_cache(elfcheck.Tree(ctx.root))
        if ctx.ldso_cache:
            expect(
                cache and "libc.so.6" in cache and cache["libc.so.6"][0].endswith("/libc.so.6"),
                f"ld.so.cache parsed: {list(cache.items())[:2] if cache else cache!r}",
            )
    finally:
        shutil.rmtree(x, ignore_errors=True)
        if made_local:
            os.rmdir(os.path.dirname(x))  # the shared exclave is left as it was (17)
    # a hand-made tree with the loader at /usr/lib64 and no ld.so.cache is wrapped; the loader
    # satisfies its own soname and its default directories come from the loader itself. without /lib
    # the host's would be searched.
    if not ctx.libc:
        return "no libc.so.6 in the tree (musl): the hand-made glibc layout is not made"
    hand2 = os.path.join(ctx.work, "hand2.exclave")
    shutil.rmtree(hand2, ignore_errors=True)
    # where the tree keeps libc: usr/lib/<triplet>, or usr/lib64
    libdir = os.path.dirname(ctx.vreal(ctx.libc)).lstrip("/")
    for d in ("usr/" + ctx.ldso_dir, libdir, "usr/bin", "etc"):
        os.makedirs(os.path.join(hand2, "tree", d), exist_ok=True)
    # the tree's own top-level links, as the loader's defaults expect
    for top in ("lib", "lib64", "lib32"):
        if os.path.islink(os.path.join(ctx.root, top)):
            os.symlink(os.readlink(os.path.join(ctx.root, top)), os.path.join(hand2, "tree", top))
    # the loader where PT_INTERP names it
    shutil.copy2(
        ctx.payload(ctx.interp), os.path.join(hand2, "tree", "usr", ctx.ldso_dir, ctx.ldso_name)
    )
    shutil.copy2(ctx.payload(ctx.libc), os.path.join(hand2, "tree", libdir, "libc.so.6"))
    shutil.copy2(ctx.payload("true"), os.path.join(hand2, "tree", "usr", "bin", "true"))
    rc, out, err = run([*TOOL, "wrap", hand2])
    expect(rc == 0, "a tree with the loader in /usr/lib64 and no cache must wrap: " + out[-500:])
    rc, out, err = run(
        [os.path.join(hand2, "tree", "usr", "bin", "true")], cwd=ctx.work, env=ctx.env
    )
    expect(rc == 0, f"and run: {err!r}")
    top = ctx.libc.split("/")[1]  # the top-level link libc is reached through: lib, or lib64
    os.remove(os.path.join(hand2, "tree", top))
    rep = elfcheck.static_check(hand2, cli.owned(hand2), [])
    expect(
        any(
            (os.path.dirname(ctx.libc) in e_ and "does not own" in e_)
            or (ctx.ldso_dir == top and "loader" in e_)
            for e_ in rep.errors
        ),
        f"a tree without /{top} searches the host's: {rep.errors[:3]!r}",
    )
    os.symlink(os.readlink(os.path.join(ctx.root, top)), os.path.join(hand2, "tree", top))
    shutil.rmtree(os.path.join(hand2, "tree", "etc"))
    os.makedirs(os.path.join(hand2, "tree", "etc"))
    rep = elfcheck.static_check(hand2, cli.owned(hand2), [])
    expect(
        any("/etc is the host's" in e_ for e_ in rep.errors),
        f"a tree without /etc would read the host's ld.so.cache: {rep.errors[:3]!r}",
    )
    # a truncated ELF is an error by name, not a traceback
    bad = os.path.join(hand2, "tree", "usr", "bin", "broken")
    with open(bad, "wb") as f:
        f.write(b"\x7fELF\x02\x01\x01\x00garbage")
    os.chmod(bad, 0o755)
    rep = elfcheck.static_check(hand2, cli.owned(hand2), [])
    expect(
        any("broken" in e_ and ("malformed" in e_ or "not ELF64" in e_) for e_ in rep.errors),
        f"a truncated ELF must be reported by name: {rep.errors[:3]!r}",
    )
    # a host record takes a path back from the tree by the launcher's longest prefix (8.1): over the
    # loader's directory it leaves the exclave no loader the launcher will take, and the check must
    # say so rather than read the tree alone
    with open(os.path.join(hand2, ".exclave", "manifest"), "w") as f:
        f.write(f'exclave 1\n\nhost "/usr/{ctx.ldso_dir}"\n')
    rep = elfcheck.static_check(hand2, cli.owned(hand2), [])
    expect(
        any("/usr/bin/true wants interpreter" in e_ and "does not own" in e_ for e_ in rep.errors),
        f"a host record over the loader: {rep.errors[:3]!r}",
    )
    # a library the workload built in its own directory is a note, not an error
    bld = os.path.join(ctx.work, "bld")
    os.makedirs(bld, exist_ok=True)
    with open(os.path.join(bld, "foo.c"), "w") as f:
        f.write("int foo(void) { return 42; }\n")
    with open(os.path.join(bld, "usefoo.c"), "w") as f:
        f.write(
            "#include <stdio.h>\n"
            'int foo(void); int main(void) { printf("%d\\n", foo()); return 0; }\n'
        )
    gcc = wrapper(ctx, ctx.gcc)
    rc, out, err = run([gcc, "-shared", "-fPIC", "-o", "libfoo.so", "foo.c"], cwd=bld, env=ctx.env)
    rc2, out, err2 = run(
        [gcc, "usefoo.c", "-L.", "-lfoo", "-Wl,-rpath,$ORIGIN", "-o", "usefoo"],
        cwd=bld,
        env=ctx.env,
    )
    expect(rc == 0 and rc2 == 0, err + err2)
    log = os.path.join(ctx.work, "bld.log")
    if os.path.exists(log):
        os.remove(log)
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "./usefoo"], cwd=bld, env=dict(ctx.env, EXCLAVE_LOG=log)
    )
    expect(out == "42\n", f"usefoo: {out!r} {err!r}")
    rc, out, err = run([*TOOL, "check", ctx.exclave, log])
    expect(
        rc == 0 and "working directory" in out and "0 errors" in out.splitlines()[-1],
        "a build-directory library is a note, not an error: " + out[-500:],
    )
    # the same library, in a directory the host owns by rule 3, opened by a workload run from /: the
    # check must still report it (nothing is given to the host from /), where a run from that
    # directory would note it as the build's own
    import tempfile

    tmp = tempfile.mkdtemp(prefix="exclave-bld-", dir="/tmp")
    try:
        for f in ("libfoo.so", "usefoo"):
            shutil.copy2(os.path.join(bld, f), os.path.join(tmp, f))
        log2 = os.path.join(ctx.work, "bld-root.log")
        rc, out, err = run(
            [wrapper(ctx, "sh"), "-c", f"{tmp}/usefoo"],
            cwd="/",
            env=dict(ctx.env, EXCLAVE_LOG=log2),
        )
        expect(out == "42\n", f"usefoo from /: {out!r} {err!r}")
        rc, out, err = run([*TOOL, "check", ctx.exclave, log2])
        expect(
            rc != 0 and "library opened on the host" in out and tmp + "/libfoo.so" in out,
            "a workload run from / must not excuse a host library: " + out[-500:],
        )
        # and a run from that directory, the host's by rule 3 with nothing to give, notes it as the
        # build's own
        log3 = os.path.join(ctx.work, "bld-tmp.log")
        rc, out, err = run(
            [wrapper(ctx, "sh"), "-c", "./usefoo"], cwd=tmp, env=dict(ctx.env, EXCLAVE_LOG=log3)
        )
        expect(out == "42\n", f"usefoo from its /tmp directory: {out!r} {err!r}")
        rc, out, err = run([*TOOL, "check", ctx.exclave, log3])
        expect(
            rc == 0 and "working directory" in out and "0 errors" in out.splitlines()[-1],
            "a build directory under /tmp is a note, not an error: " + out[-500:],
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@test
def readlink_bad_buffer(ctx: Ctx) -> None:
    """7.5.6: an unwritable readlink buffer answers EFAULT, not SIGSEGV."""
    src = os.path.join(ctx.work, "rl.c")
    with open(src, "w") as f:
        f.write(
            "#include <unistd.h>\n#include <errno.h>\n#include <stdio.h>\n"
            "int main(int c, char **v) { for (int i = 1; i < c; i++) { errno = 0; "
            'long r = readlink(v[i], (char *)8, 64); printf("%ld %d\\n", r, errno); } return 0; }\n'
        )
    exe = os.path.join(ctx.work, "rl")
    rc, out, err = run([wrapper(ctx, ctx.gcc), "-O1", src, "-o", exe], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, err)
    # a link in the tree; a directory would be EINVAL before the copy
    lib = "/lib" if os.path.islink(os.path.join(ctx.root, "lib")) else ctx.vbin("sh")
    rc, out, err = inside(ctx, exe, [lib, "/proc/self/exe", ctx.vbin("sh"), "/nonexistent"])
    expect(rc == 0 and out == "-1 14\n-1 14\n-1 14\n-1 2\n", f"bad buffer: rc={rc} {out!r} {err!r}")


@test
def host_symlink_into_usr(ctx: Ctx) -> None:
    lnk = os.path.join(ctx.work, "lnk")
    if os.path.lexists(lnk):
        os.remove(lnk)
    os.symlink("/usr/share", lnk)
    _rc, out, err = run(
        [wrapper(ctx, "cat"), os.path.join(lnk, "exclave-test-marker")], cwd=ctx.work, env=ctx.env
    )
    expect(out == "marker\n", f"host symlink into /usr resolves in the exclave: {out!r} {err!r}")


@test
def ld_so(ctx: Ctx) -> str | None:
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
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", f"{ld} --verify {ctx.vbin(ctx.gcc)}"], cwd=ctx.work, env=ctx.env
    )
    expect(rc == 0, f"ld.so --verify rc={rc}")
    rc, out, err = run(
        [os.path.join(ctx.root, ctx.interp.lstrip("/")), "--verify", ctx.vbin(ctx.gcc)],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(rc == 0, f"ld.so run by its real path from the host: rc={rc} {err!r}")
    return None


@test
def nested_and_log(ctx: Ctx) -> None:
    log = os.path.join(ctx.work, "exclave.log")
    if os.path.exists(log):
        os.remove(log)
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", ctx.gcc + " --version"],
        cwd=ctx.work,
        env=dict(ctx.env, EXCLAVE_LOG=log),
    )
    expect(rc == 0 and out.strip(), out + err)
    text = read_text(log)
    expect(
        "launcher 0 border " + ctx.sh_exe in text
        and "launcher 0 inside " + ctx.vreal(ctx.vbin(ctx.gcc)) in text,
        "log: " + text[:400],
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
def origin(ctx: Ctx) -> None:
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "origin_main"), cwd=ctx.work)
    expect(rc == 0 and out == "origin 42\n", f"RUNPATH=$ORIGIN: {out!r} {err!r}")


@test
def gconv_and_locale(ctx: Ctx) -> str:
    notes: list[str] = []
    if os.path.exists(wrapper(ctx, "iconv")):
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
    else:
        notes.append("no iconv in the tree")
    if os.path.isdir(os.path.join(ctx.root, "usr", "lib", "locale", "C.utf8")):
        _rc, out, _err = run(
            [wrapper(ctx, "wc"), "-m"],
            cwd=ctx.work,
            env=dict(ctx.env, LC_ALL="C.UTF-8"),
            inp="caf\xe9".encode(),
        )
        expect(out.strip() == "4", f"wc -m under C.UTF-8: {out!r}")
    else:
        notes.append("no C.utf8 locale in the tree")
    return "; ".join(notes)


@test
def tool_check(ctx: Ctx) -> None:
    rc, out, err = run([*TOOL, "check", ctx.exclave])
    expect(rc == 0 and "0 wrapper problems" in out and "0 errors" in out, out + err)
    rc, out, err = run(
        [*TOOL, "format", "--check", os.path.join(ctx.exclave, ".exclave", "manifest")]
    )
    expect(rc == 0, "manifest not canonical: " + out + err)


@test
def mixed_tree_refused(ctx: Ctx) -> None:
    """10.3: a tree whose ELF files name two loaders is refused by the static check.

    The check reads the loaders from the files; nothing declares one.
    """
    from exclave import elfcheck

    mixed = os.path.join(ctx.work, "mixed.exclave")
    d = os.path.join(mixed, "tree")
    os.makedirs(os.path.join(d, "usr", "bin"), exist_ok=True)
    src = read_bytes(ctx.payload("true"))
    interp = ctx.interp.encode() + b"\0"
    i = src.index(interp)
    other = (ctx.other_interp.encode() + b"\0").ljust(len(interp), b"\0")
    with open(os.path.join(d, "usr", "bin", "true"), "wb") as f:
        f.write(src[:i] + other + src[i + len(interp) :])
    with open(os.path.join(d, "usr", "bin", "false"), "wb") as f:
        f.write(src)
    for n in ("true", "false"):
        os.chmod(os.path.join(d, "usr", "bin", n), 0o755)
    os.symlink(ctx.interp, os.path.join(d, "usr", "bin", "ld-glibc"))  # so that one loader resolves
    os.makedirs(os.path.join(d, ctx.ldso_dir), exist_ok=True)
    shutil.copy2(ctx.payload(ctx.interp), os.path.join(d, ctx.interp.lstrip("/")))
    # the other loader's directory
    os.makedirs(os.path.dirname(os.path.join(d, ctx.other_interp.lstrip("/"))), exist_ok=True)
    shutil.copy2(ctx.payload(ctx.interp), os.path.join(d, ctx.other_interp.lstrip("/")))
    rep = elfcheck.static_check(mixed, ["/usr", "/lib", "/lib64"], [])
    expect(
        any("mixes loaders" in e for e in rep.errors),
        f"a tree with two loaders was not refused: {rep.errors[:4]!r}",
    )


@test
def rust(ctx: Ctx) -> str | None:
    rustc = shutil.which("rustc") or shutil.which("rustc", path=os.path.expanduser("~/.cargo/bin"))
    if not rustc:
        return "no rustc"
    if ctx.musl:
        return "the host's rustc targets glibc; the exclave has musl"
    exe = os.path.join(ctx.progs, "rs")
    rc, out, err = run(
        [rustc, "-O", "-o", exe, os.path.join(ctx.work, "src", "rs.rs")], cwd=ctx.work
    )
    expect(rc == 0, "rustc: " + err[-600:])
    rc, out, err = inside(ctx, exe)
    expect(rc == 0 and "FAIL" not in out, out + err)
    return None


@test
def openat2_resolve(ctx: Ctx) -> str | None:
    """7.4.3: openat2 in the exclave's world.

    RESOLVE_IN_ROOT and RESOLVE_BENEATH scope the walk to the descriptor's directory,
    RESOLVE_NO_SYMLINKS refuses the tree's own links as a bind mount would, magic links are refused
    by the scoped flags, RESOLVE_NO_XDEV refuses the exclave-to-host crossing, the read-only rule
    holds, and the struct's own rules answer EINVAL before any lookup. Skips on a kernel without
    openat2.
    """
    d = os.path.join(ctx.work, "o2host")
    os.makedirs(d, exist_ok=True)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "openat2"), [d])
    if rc == 3:
        return "no openat2 on this kernel (5.6 and later)"
    expect(rc == 0 and "FAIL" not in out, out + err)
    return None


@test
def openat2_xdev(ctx: Ctx) -> str | None:
    """13 item 22, 7.4.3: an openat2 whose walk never touches the exclave is re-issued as given.

    It keeps its resolve flags, so the kernel enforces RESOLVE_NO_XDEV across the host's own mounts,
    and the other flags, on host-only walks. The kernel's answers come from this harness itself,
    natively, for the same cases with the same descriptors (bwrap rebuilds /dev and cannot be the
    oracle for the host's mounts); the walks that touch the exclave assert the crossing rule. Skips
    on a kernel without openat2.
    """
    d = os.path.join(ctx.work, "xdevhost")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "openat2_xdev"), [d])
    if rc == 3:
        return "no openat2 on this kernel (5.6 and later)"
    expect(rc == 0, out + err)
    got = dict(line.split(": ", 1) for line in out.splitlines() if ": " in line)
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    no_xdev, no_magic, no_symlinks, beneath, in_root = 1, 2, 4, 8, 16
    rd, rd_dir = os.O_RDONLY, os.O_RDONLY | os.O_DIRECTORY
    dev, proc, hd = (os.open(x, os.O_PATH | os.O_DIRECTORY) for x in ("/dev", "/proc", d))
    cases = [
        ("no_xdev cwd to .", -100, ".", rd_dir, no_xdev),
        ("no_xdev cwd to sub", -100, "sub", rd_dir, no_xdev),
        ("no_xdev cwd to ..", -100, "..", rd_dir, no_xdev),
        ("no_xdev /dev fd to null", dev, "null", rd, no_xdev),
        ("no_xdev /dev fd to shm", dev, "shm", rd_dir, no_xdev),
        ("no_xdev /dev fd to ..", dev, "..", rd_dir, no_xdev),
        ("no_xdev /proc fd to self/status", proc, "self/status", rd, no_xdev),
        ("no_xdev host fd to file", hd, "file", rd, no_xdev),
        ("no_symlinks host fd to lnk", hd, "lnk", rd, no_symlinks),
        ("no_symlinks host fd to file", hd, "file", rd, no_symlinks),
        ("no_magiclinks /proc fd to self/status", proc, "self/status", rd, no_magic),
        ("no_magiclinks /proc fd to version", proc, "version", rd, no_magic),
        ("beneath host fd to sub", hd, "sub", rd_dir, beneath),
        ("beneath host fd to ..", hd, "..", rd_dir, beneath),
        ("beneath host fd to sub/..", hd, "sub/..", rd_dir, beneath),
        ("in_root host fd to /etc/passwd", hd, "/etc/passwd", rd, in_root),
        ("in_root host fd to ../../../file", hd, "../../../file", rd, in_root),
        ("in_root /dev fd to /null", dev, "/null", rd, in_root),
        ("beneath|no_xdev /dev fd to shm", dev, "shm", rd_dir, beneath | no_xdev),
    ]
    here = os.getcwd()
    os.chdir(d)  # the AT_FDCWD cases start where the program started them
    try:
        bad = []
        for label, dfd, path, flags, resolve in cases:
            how = (ctypes.c_ulonglong * 3)(flags, 0, resolve)
            r = libc.syscall(437, dfd, path.encode(), how, 24)
            native = "ret=0 errno=0" if r >= 0 else f"ret=-1 errno={ctypes.get_errno()}"
            if r >= 0:
                os.close(r)
            if got.get(label) != native:
                bad.append(f"{label}: the exclave says {got.get(label)}, the kernel says {native}")
    finally:
        os.chdir(here)
        for fd in (dev, proc, hd):
            os.close(fd)
    expect(not bad, "; ".join(bad))
    # a .. that reaches the root is the walk's
    crossing = {
        "no_xdev cwd to /dev/null": "ret=-1 errno=18",
        "no_xdev cwd to /dev/shm": "ret=-1 errno=18",
        "no_xdev cwd to /proc/self/status": "ret=-1 errno=18",
        "no_xdev cwd to /usr/share (exclave)": "ret=0 errno=0",
        "no_xdev host fd to /dev/null (absolute)": "ret=-1 errno=18",
        "root by .. from host fd is the tree's": "yes",
        "no_xdev host fd to the root by ..": "ret=-1 errno=18",
    }
    bad = [f"{k}: {got.get(k)}, wanted {v}" for k, v in crossing.items() if got.get(k) != v]
    expect(not bad, "the exclave-to-host crossing under RESOLVE_NO_XDEV: " + "; ".join(bad))
    return None


@test
def exec_identity(ctx: Ctx) -> None:
    """7.4.5, 7.6: the identity a program exec'd from inside gets, as the kernel gives it.

    comm and AT_EXECFN from the path the program was exec'd by, not from argv[0]; a script's $0,
    AT_EXECFN and comm spelt /dev/fd/N/name relative to a descriptor and /dev/fd/N through one, comm
    then the file's own name; a close-on-exec script descriptor refused with ENOENT before anything
    runs; a header the loader cannot load ENOEXEC and a loader the exclave lacks ENOENT from execve
    itself, where the child used to die after a successful exec. The kernel under bwrap measured
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
def path_length(ctx: Ctx) -> str | None:
    """13 item 13, 7.4.4: an exclave path too long for PATH_MAX is ENAMETOOLONG.

    An exclave path whose real spelling, the root prefix and the virtual path, would not fit
    PATH_MAX is refused with ENAMETOOLONG and never cut to a shorter name, which once answered
    ENOENT for the cut; its parent, which fits, is fine. And a relative path from a working
    directory so deep that the two together pass PATH_MAX is ENAMETOOLONG too, where the kernel,
    walking relatively, succeeds: the stated limitation. On a private copy of the exclave, since the
    chain is made in the tree.
    """
    copy = os.path.join(ctx.work, "lengthcan")
    shutil.rmtree(copy, ignore_errors=True)
    copy_exclave(ctx.exclave, copy)
    rootlen = len(os.path.join(copy, "tree"))
    if rootlen > 200:
        return "the work directory's path is too long for the window: skipped"
    base = "/usr/share/exclave-deep"
    # /usr/share
    fd = os.open(os.path.join(copy, "tree", base.lstrip("/")[:9]), os.O_RDONLY | os.O_DIRECTORY)
    os.mkdir("exclave-deep", dir_fd=fd)
    nfd = os.open("exclave-deep", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
    os.close(fd)
    fd = nfd
    v = base
    for _i in range(19):  # 19 components of 200: 3839 characters
        os.mkdir("a" * 200, dir_fd=fd)
        nfd = os.open("a" * 200, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
        os.close(fd)
        fd = nfd
        v += "/" + "a" * 200
    parent = v
    # a directory whose real spelling is exactly PATH_MAX long
    last = "b" * (PATH_MAX - rootlen - len(v) - 1)
    os.mkdir(last, dir_fd=fd)
    nfd = os.open(last, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
    os.close(fd)
    fd = nfd
    with os.fdopen(os.open("f", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd), "w") as f:
        f.write("deep\n")
    os.close(fd)
    deep, dfile = v + "/" + last, v + "/" + last + "/f"
    expect(
        len(dfile) < PATH_MAX and rootlen + len(deep) == PATH_MAX,
        f"the window: root {rootlen}, dir {len(deep)}, file {len(dfile)}",
    )
    # the deep working directory on the host: 14 components of 200 below the work directory, then 7
    # more reached relatively
    d = "d" * 200
    hostdeep = os.path.join(ctx.work, "deepcwd")
    os.makedirs(hostdeep)
    fd = os.open(hostdeep, os.O_RDONLY | os.O_DIRECTORY)
    for _i in range(14):
        os.mkdir(d, dir_fd=fd)
        nfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
        os.close(fd)
        fd = nfd
        hostdeep = os.path.join(hostdeep, d)
    with os.fdopen(os.open("f", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd), "w") as f:
        f.write("here\n")
    rel = ""
    for _i in range(7):
        os.mkdir(d, dir_fd=fd)
        nfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
        os.close(fd)
        fd = nfd
        rel += d + "/"
    with os.fdopen(os.open("f", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd), "w") as f:
        f.write("below\n")
    os.close(fd)
    rel += "f"
    expect(
        len(hostdeep) < PATH_MAX and len(hostdeep) + 1 + len(rel) > PATH_MAX,
        f"the deep working directory: {len(hostdeep)} + {len(rel)}",
    )
    rc, out, err = run(
        [
            os.path.join(copy, ".exclave", "launcher"),
            os.path.join(ctx.progs, "path_length"),
            parent,
            deep,
            dfile,
            "cd:" + hostdeep,
            rel,
            "f",
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(rc == 0, f"path_length: rc={rc} {out!r} {err!r}")
    want = [
        "1: stat=ok open=ok",
        "2: stat=ENAMETOOLONG open=ENAMETOOLONG",
        "3: stat=ENAMETOOLONG open=ENAMETOOLONG",
        "4: stat=ENAMETOOLONG open=ENAMETOOLONG",
        "5: stat=ok open=ok",
    ]
    expect(
        out.splitlines() == want,
        "the parent fits, the directory at the limit and its file are ENAMETOOLONG, a relative "
        "path past PATH_MAX from a deep working directory is ENAMETOOLONG (13), a short one is "
        f"fine: {out!r}",
    )
    shutil.rmtree(copy, ignore_errors=True)
    return None


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
def adversarial(ctx: Ctx) -> None:
    """17.4: what a hostile program or a fuzzer would try, each case answered in microseconds.

    Arguments with bits above the word where the kernel takes an int (the probe compares the
    answers; this checks the buffer past the count): a readlink size of zero or minus one as an int
    once had the handler write past the program's buffer; the launcher's own variables set before an
    exec, dropped; a working directory deleted under the program, its . and .. kept; an exec with no
    descriptor to spare, which the handler borrows against a soft limit and which a hard limit
    refuses (13); mounts and roots from inside, refused by the filter (7.4.2); SIGSYS ignored,
    handled or on a signalfd; magic links under /proc/1; interpreter loops and chains; an empty
    executable and a loader that is a directory. A second batch: a descriptor with no path handed to
    exec (a pipe or a socket is EACCES, only a regular file is run), a hard link across the border
    (EXDEV), a symlink chain at the kernel's limit of forty and one past it, the read-only rule from
    other angles (mknod, ftruncate and a shared writable mapping of a read-only descriptor, a device
    node), odd process shapes (CLONE_FS, CLONE_FILES, not dumpable, PER_LINUX32, a vfork child, a
    handler on an alternate stack), the cache saturated and a huge environment, io_uring and clone3
    refused by the filter, and an execute-only file the loader cannot read (EACCES, a limitation).
    The kernel under bwrap measured the answers, but for the variables, the mounts, the hard limit,
    the filter's refusals and the execute-only files, which are the launcher's own.
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
    import resource

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
def unix_socket(ctx: Ctx) -> None:
    """7.4.3, 13 item 31: a sockaddr_un's path is a path.

    bind and connect at a path of every class answer what the kernel answers on a read-only bind
    mount (the namespace oracle measured these): a bind on an exclave path is EADDRINUSE for an
    existing name and EROFS otherwise, from a working directory inside the tree too; a connect to an
    exclave path is ENOENT, ENOTDIR or ECONNREFUSED; host paths and abstract names work; the
    structure's own limits are EINVAL. A datagram destination in sendto stays as written (13), so
    only its host case is asserted.
    """
    # absolute host names a program can write in sun_path's 108 bytes
    d = f"/tmp/exclave-sockhost-{os.getpid()}"
    # relative ones from a working directory deeper than sun_path holds
    deep = os.path.join(ctx.work, "sockhost")
    deep = os.path.join(deep, "d" * max(1, 120 - len(deep)))
    shutil.rmtree(os.path.join(ctx.work, "sockhost"), ignore_errors=True)
    for p in (d, deep):
        shutil.rmtree(p, ignore_errors=True)
        os.makedirs(p)
    try:
        rc, out, err = inside(
            ctx,
            os.path.join(ctx.progs, "unix_socket"),
            [d, "/usr/share", ctx.vbin("true"), "/usr/share/exclave-test.sock", deep],
        )
    finally:
        shutil.rmtree(d, ignore_errors=True)
    expect(rc == 0, f"unix_socket: {out!r} {err!r}")
    got = dict(line.split(": ", 1) for line in out.splitlines() if ": " in line)
    want = {
        "bind host dir": "ret=0 errno=0",
        "bind /tmp": "ret=0 errno=0",
        "bind exclave dir": "ret=-1 errno=30",
        "bind existing exclave file": "ret=-1 errno=98",
        "bind existing exclave socket": "ret=-1 errno=98",
        "bind missing exclave parent": "ret=-1 errno=2",
        "bind under an exclave file": "ret=-1 errno=20",
        "bind exclave dir itself": "ret=-1 errno=98",
        "bind exclave dir trailing slash name": "ret=-1 errno=2",
        "bind abstract": "ret=0 errno=0",
        "bind relative in host cwd": "ret=0 errno=0",
        "bind relative in exclave cwd": "ret=-1 errno=30",
        "connect host listener": "ret=0 errno=0",
        "connect host socket no listener": "ret=-1 errno=111",
        "connect exclave file": "ret=-1 errno=111",
        "connect exclave socket": "ret=-1 errno=111",
        "connect missing exclave path": "ret=-1 errno=2",
        "connect exclave dir": "ret=-1 errno=111",
        "connect under an exclave file": "ret=-1 errno=20",
        "connect missing host path": "ret=-1 errno=2",
        "sendto host dgram": "ret=1 errno=0",
        "bind through /proc/self/cwd": "ret=0 errno=0",
        "connect through /proc/self/cwd": "ret=0 errno=0",
        "bind addrlen too long": "ret=-1 errno=22",
        "bind addrlen too short": "ret=-1 errno=22",
        "bind wrong family": "ret=-1 errno=22",
        "bind exclave path of 107 bytes": "ret=-1 errno=30",
        "connect exclave path of 107 bytes": "ret=-1 errno=2",
    }
    bad = [
        f"{k}: got {got.get(k)}, the kernel says {v}" for k, v in want.items() if got.get(k) != v
    ]
    expect(not bad, "; ".join(bad))
    expect(
        not os.path.exists(os.path.join(ctx.root, "usr", "share", "sock-rel")),
        "a relative bind from a working directory inside the tree wrote into the tree",
    )


@test
def go_paths(ctx: Ctx) -> str | None:
    """17.4: a Go program doing path syscalls from goroutines.

    Go issues syscalls raw, makes threads with clone, installs its own handler for every signal,
    SIGSYS included (7.5.2), and runs on small stacks; built static by go with cgo off and run
    inside as a host program, twice: as go links it for the machine, and from 0x10000 as its aarch64
    linker does, an image past where the syscall page lay in early versions (13 item 24). Built here
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
        return "no go toolchain (golang-go) and nothing in build/go/" + platform.machine()
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
def low_image(ctx: Ctx) -> None:
    """13 item 24: a program whose image starts at 0x10000 runs in an exclave.

    A program whose image starts at 0x10000 and reaches past 0x3f0000, as Go's aarch64 linker lays
    one out, runs in an exclave; the syscall page lay at 0x3f0000 in early versions and such a
    program died unmapped. Built here by the exclave's compiler -no-pie from that address, so every
    exclave kind and both architectures run it.
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
def gdb_hooks(ctx: Ctx) -> str | None:
    """7.6, 13.1: gdb needs no manual command.

    The launcher carries a script gdb auto-loads; a breakpoint in a library hits with the exclave's
    own symbols, the program's source line is known, a wrapped program's libc frames resolve, and
    the positional entry's re-exec does not confuse gdb.
    """
    gdb = shutil.which("gdb")
    if not gdb:
        return "no gdb"
    rc, out, err = run([gdb, "-batch", "-nx", "-ex", "python print(gdb.VERSION)"])
    if rc or not out.strip():
        return "gdb without Python"
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
        return "gdb's breakpoints in a musl libc do not hit, the program's own do (13 item 1)"
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
    copy_exclave(ctx.exclave, spaced)
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
def stat_bench(ctx: Ctx) -> str:
    src = os.path.join(ctx.work, "bench.c")
    with open(src, "w") as f:
        f.write(
            "#include <sys/stat.h>\n#include <stdio.h>\n#include <time.h>\n"
            "int main(void){struct stat st;struct timespec a,b;"
            "clock_gettime(CLOCK_MONOTONIC,&a);"
            'for(int i=0;i<100000;i++)stat("/usr/share/exclave-test-marker",&st);'
            "clock_gettime(CLOCK_MONOTONIC,&b);"
            'printf("%.0f\\n",((b.tv_sec-a.tv_sec)*1e9+(b.tv_nsec-a.tv_nsec))/100000);return 0;}\n'
        )
    exe = os.path.join(ctx.work, "bench")
    rc, out, err = run([wrapper(ctx, ctx.gcc), "-O2", src, "-o", exe], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, err)
    rc, out, err = inside(ctx, exe)
    expect(rc == 0, err)
    return f"stat of an exclave path: {int(out.strip())} ns per call"


# ------------------------------------------------------------------ main
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--tree", default=os.environ.get("EXCLAVE_TEST_TREE"))
    ap.add_argument("--exclave", help="use this exclave's tree, unwrapped")
    ap.add_argument("--work", default=os.path.join(REPO, "build", "test-work"))
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("-k", default="")
    ap.add_argument(
        "--order",
        default="given",
        choices=["given", "reverse", "random"],
        help="run order; reverse and random expose tests that depend on one another",
    )
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument(
        "--budget",
        type=float,
        default=30,
        help="seconds a test may take before it fails; the slowest takes 2 natively",
    )
    ap.add_argument("-v", action="store_true")
    a = ap.parse_args()
    if a.exclave:
        a.tree = os.path.join(a.exclave, "tree")
    if not a.tree or not os.path.isdir(a.tree):
        sys.exit(
            "need --tree DIR (or $EXCLAVE_TEST_TREE) or --exclave EXCLAVE: a gcc tree to wrap; "
            "see README.md"
        )
    # the pruned fixture (17): the source exclave pruned to what the suite touches, made by the
    # first run on an exclave and used by every later one until the exclave changes
    fixture, sources, stale, logging = None, "", False, False
    keys = fixture_keys(a.exclave) if a.exclave else None
    tree_ = os.path.abspath(a.tree)
    if keys:
        name = os.path.basename(os.path.abspath(a.exclave)).replace(".exclave", "")
        fixture, sources = os.path.join(REPO, "build", "fixtures", f"{name}-{keys[0]}"), keys[1]
    if fixture and os.path.isdir(fixture):
        tree_ = os.path.join(fixture, "tree")
        try:
            stale = read_text(os.path.join(fixture, STAMP)).strip() != sources
        except OSError:
            stale = True
        print(
            f"fixture: {fixture}"
            + (" (made with other sources: a failure is rechecked)" if stale else "")
        )
    elif fixture:
        logging = True
        print("fixture: none yet for this exclave; this run makes it")
    ctx = prepare(a, tree_, os.path.abspath(a.work), logging=logging)
    # a test's own name runs it alone, spawn beside spawn_threads
    exact = [t for t in TESTS if t.__name__ == a.k]
    order = exact or [t for t in TESTS if not a.k or a.k in t.__name__]
    if a.order == "reverse":
        order.reverse()
    elif a.order == "random":
        import random

        seed = a.seed if a.seed is not None else int(time.time()) % 100000
        random.Random(seed).shuffle(order)
        print(f"random order, seed {seed}")
    failed = run_tests(ctx, order, a.budget)
    if stale and failed and fixture:
        # the fixture may lack a file these sources now touch: the failures again on the whole
        # exclave decide, and the fixture goes, for the next run to make afresh
        print(f"rechecking {len(failed)} on the whole exclave, the fixture predating these sources")
        whole = prepare(
            a, os.path.abspath(a.tree), os.path.abspath(a.work) + "-whole", logging=False
        )
        failed = run_tests(whole, failed, a.budget)
        shutil.rmtree(fixture, ignore_errors=True)
        if not a.keep and not failed:
            shutil.rmtree(whole.work, ignore_errors=True)
    elif stale and not a.k and fixture:
        with open(os.path.join(fixture, STAMP), "w") as f:  # still enough for these sources
            f.write(sources + "\n")
    print(f"{len(order)} tests, {len(failed)} failures")
    if logging and fixture and not failed and not a.k:
        make_fixture(ctx, fixture, sources)
    if not a.keep and not failed:
        shutil.rmtree(ctx.work, ignore_errors=True)
    return len(failed)


def prepare(a: argparse.Namespace, tree_: str, work: str, *, logging: bool) -> Ctx:
    """The fixtures every test is given: the exclave wrapped from tree_, the programs compiled."""
    ctx = Ctx()
    ctx.from_exclave = bool(a.exclave)
    ctx.tree = tree_
    ctx.work = work
    ctx.launcher_src = os.path.join(REPO, "build", "launcher")
    if not os.path.exists(ctx.launcher_src):
        sys.exit("build/launcher missing: run make")
    if os.path.exists(ctx.work):
        shutil.rmtree(ctx.work)
    os.makedirs(ctx.work)
    ctx.env = {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/"), "LANG": "C"}
    t0 = time.time()
    make_exclave(ctx)
    if logging:
        # from here every in-exclave run of the suite's own is logged, the test programs' compile
        # first
        ctx.env["EXCLAVE_LOG"] = os.path.join(ctx.work, "fixture.log")
    compile_progs(ctx)
    ctx.shared = shared_state(ctx)
    print(f"exclave made and programs compiled in {time.time() - t0:.1f}s")
    return ctx


def run_tests(ctx: Ctx, order: list[Test], budget: float) -> list[Test]:
    """Run the tests in order, one PASS or FAIL line each; the ones that failed."""
    failed: list[Test] = []
    for t in order:
        t0 = time.time()
        try:
            note = t(ctx)
            # a test that hangs is caught by run()'s timeouts; one that crawls, here (17)
            took = time.time() - t0
            expect(took <= budget, f"took {took:.1f} s, over the budget of {budget:g} s")
            print(f"PASS {t.__name__:<26} {time.time() - t0:5.1f}s {note or ''}")
        except AssertionError as e:
            failed.append(t)
            why = str(e).strip().replace("\n", "\n     ")
            print(f"FAIL {t.__name__:<26} {time.time() - t0:5.1f}s {why}")
        except Exception as e:  # noqa: BLE001
            failed.append(t)
            print(f"FAIL {t.__name__:<26} {time.time() - t0:5.1f}s {type(e).__name__}: {e}")
        # a test must leave the fixtures alone, whether it passed or not (17)
        now = shared_state(ctx)
        changed = [
            n
            for n, a, b in zip(("manifest", "hashes", "tree"), ctx.shared, now, strict=False)
            if a != b
        ]
        if "tree" in changed:
            d = sorted(set(now[2]) ^ set(ctx.shared[2]))
            changed[changed.index("tree")] = "tree: " + ", ".join(sorted({e[0] for e in d})[:6])
        if changed:
            print(
                f"FAIL {t.__name__:<26} {time.time() - t0:5.1f}s "
                f"the test changed the shared exclave: {', '.join(changed)}"
            )
            if t not in failed:
                failed.append(t)
            ctx.shared = now
    return failed


if __name__ == "__main__":
    sys.exit(main())
