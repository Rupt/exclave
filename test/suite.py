"""The regression suite's fixtures (DESIGN.md 17 item 4) and the helpers its tests share.

The fixtures are the exclave wrapped from the given tree, the compiled test programs and the
environment, made once by `prepare` and given to every test as a `Ctx`, which no test may change;
the pruned fixture kept under build/fixtures/ is made and keyed here too.
"""

import os
import platform
import shutil
import stat
import subprocess
import sys
import time
from typing import TYPE_CHECKING
lazy import argparse
lazy import hashlib

import tree

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
from harness import read_bytes, run

HERE = os.path.dirname(os.path.abspath(__file__))


REPO = os.path.dirname(HERE)


TOOL = tree.TOOL


# Debian's name; make_exclave takes the tree's gcc when that one is absent (an Alpine exclave, an
# arm64 one)
GCC = "x86_64-linux-gnu-gcc-13"


VOLATILE = ("/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run")


# what every test shares and none may change: the exclave's manifest, its hashes file, its
# launcher's (inode, size, mtime), the environment the tests are given, and its tree's entries
type Shared = tuple[
    bytes,
    bytes,
    tuple[int, int, int],
    tuple[tuple[str, str], ...],
    tuple[tuple[str, int, int, int], ...],
]
SHARED_PARTS = ("manifest", "hashes", "launcher", "environment", "tree")


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
    mini: str
    shared: Shared
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


# a copy for a test to alter: the tree hard-linked, .exclave/ copied
copy_exclave = tree.copy_exclave


def shared_state(ctx: Ctx) -> Shared:
    """Return what every test shares and none may change (SHARED_PARTS).

    That is the exclave's manifest, its hashes file, its launcher's inode, size and mtime, the
    environment, and the path, size, mode and mtime of every entry of its tree, directories
    included. An added file, a removed one, one made and removed again, or a write through a hard
    link changes these: the tree is hard-linked to the fixture or to the given exclave, so a write
    that escaped the read-only refusal would outlast the run. The walk is one lstat per entry,
    cheap enough to repeat after every test.
    """
    ex = ctx.exclave
    entries = []
    for dirpath, dirnames, filenames in os.walk(ctx.root):
        for n in dirnames + filenames:
            st = os.lstat(os.path.join(dirpath, n))
            entries.append(
                (
                    os.path.relpath(os.path.join(dirpath, n), ctx.root),
                    0 if stat.S_ISDIR(st.st_mode) else st.st_size,
                    st.st_mode,
                    st.st_mtime_ns,
                )
            )
    ls = os.lstat(ctx.launcher)
    return (
        read_bytes(os.path.join(ex, ".exclave", "manifest")),
        read_bytes(os.path.join(ex, ".exclave", "hashes"))
        if os.path.exists(os.path.join(ex, ".exclave", "hashes"))
        else b"",
        (ls.st_ino, ls.st_size, ls.st_mtime_ns),
        tuple(sorted(ctx.env.items())),
        tuple(sorted(entries)),
    )


def left_alone(ctx: Ctx) -> str | None:
    """What a test changed of the shared exclave, which it must leave alone (17), or None.

    The changed state becomes the new baseline, so that one test's residue fails only that test.
    """
    now = shared_state(ctx)
    changed = [n for n, a, b in zip(SHARED_PARTS, ctx.shared, now, strict=True) if a != b]
    if not changed:
        return None
    if "environment" in changed:
        d = sorted(set(now[3]) ^ set(ctx.shared[3]))
        changed[changed.index("environment")] = "environment: " + ", ".join(
            sorted({e[0] for e in d})
        )
    if "tree" in changed:
        d = sorted(set(now[4]) ^ set(ctx.shared[4]))
        changed[changed.index("tree")] = "tree: " + ", ".join(sorted({e[0] for e in d})[:6])
    ctx.shared = now
    return f"the test changed the shared exclave: {', '.join(changed)}"


def fixture_keys(ex: str) -> tuple[str, str] | None:
    """Return the keys of the pruned fixture (17): the exclave's and the sources'.

    The fixture is named by a hash of the exclave's hashes file, which hashes its tree, so each
    exclave has its own. What the tests touch depends on the sources of the suite, the tool and the
    launcher, and the fixture keeps their key as a stamp. A fixture made with other sources is
    almost always still enough, and a failure on it is checked again on the whole exclave. Returns
    None when the exclave has no hashes file.
    """
    hashes = os.path.join(ex, ".exclave", "hashes")
    if not os.path.isfile(hashes):
        return None
    # the suite's own files: its driver, harness, fixtures, groups and the helpers they import
    names = sorted(f for f in os.listdir(HERE) if f.startswith("regress_") and f.endswith(".py"))
    names += ["run.py", "harness.py", "suite.py", "tree.py", "packages.py"]
    files = [os.path.join(HERE, f) for f in names]
    files += sorted(os.path.join(HERE, "progs", f) for f in os.listdir(os.path.join(HERE, "progs")))
    files += sorted(
        os.path.join(REPO, "src", f)
        for f in os.listdir(os.path.join(REPO, "src"))
        if f[-2:] in (".c", ".h")
    )
    files += sorted(
        os.path.join(REPO, "tool", f)
        for f in os.listdir(os.path.join(REPO, "tool"))
        if not f.startswith(".")
    )
    sources = hashlib.blake2b(digest_size=6)
    for f in files:
        sources.update(os.path.basename(f).encode() + b"\0" + read_bytes(f) + b"\0")
    return hashlib.blake2b(read_bytes(hashes), digest_size=6).hexdigest(), sources.hexdigest()


# in a fixture: the key of the sources it was made with, then the name of each test that skipped
# when it was made, one a line
STAMP = ".sources"


def read_stamp(fixture: str) -> tuple[str, set[str]]:
    """Return the key of the sources fixture was made with and the tests that skipped then.

    A fixture without a stamp has the empty key, which no sources have.
    """
    try:
        lines = read_bytes(os.path.join(fixture, STAMP)).decode().splitlines()
    except OSError:
        return "", set()
    return (lines[0] if lines else ""), set(lines[1:])


def write_stamp(fixture: str, sources: str, skipped: set[str]) -> None:
    with open(os.path.join(fixture, STAMP), "w") as f:
        f.write("".join(n + "\n" for n in [sources, *sorted(skipped)]))


def input_drift(ex: str) -> str | None:
    """Why ex's tree is not the tree its hashes file records (6.4), or None when it is.

    A write through a hard-linked copy changes the input itself: the suite would then test a tree
    no exclave has, and the fixture, keyed by the hashes file, would never notice.
    """
    hashes = os.path.join(ex, ".exclave", "hashes")
    recorded = tree.records(hashes).get("tree", [[""]])[0][0] if os.path.isfile(hashes) else ""
    rc, out, err = run([*TOOL, "hash", ex])
    if rc or not recorded or out.strip() != recorded:
        return (
            f"{ex}: its tree hashes to {out.strip() or err.strip()}, but its hashes file records "
            f"{recorded or 'no tree hash'}; scripts/inputs DIR remakes it"
        )
    return None


def make_fixture(ctx: Ctx, dst: str, sources: str, skipped: set[str]) -> None:
    """Keep the shared exclave, pruned to what this run touched, for the next run (17).

    The prune is the tool's own, from every EXCLAVE_LOG file the run wrote, so the fixture is the
    tree the tests just passed on. Call it only after a run with no failure, so that a partial log
    never makes a partial fixture; skipped names the tests that skipped in it, which a run on the
    fixture expects to skip.
    """
    logs = sorted(
        os.path.join(dp, f) for dp, dn, fn in os.walk(ctx.work) for f in fn if f.endswith(".log")
    )
    # two runs may make the same fixture at once (scripts/gate), each in a directory named by its
    # pid; one whose process has gone was interrupted, and its leftover goes
    tmp = f"{dst}.tmp{os.getpid()}"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    for left in os.listdir(os.path.dirname(dst)):
        pid = left.rpartition(".tmp")[2]
        if ".tmp" in left and pid.isdigit() and not os.path.exists(f"/proc/{pid}"):
            shutil.rmtree(os.path.join(os.path.dirname(dst), left), ignore_errors=True)
    copy_exclave(ctx.exclave, tmp)
    if subprocess.run([*TOOL, "prune", tmp, *logs], capture_output=True, check=False).returncode:
        print("fixture not kept: the pruned exclave does not pass the static check")
        shutil.rmtree(tmp, ignore_errors=True)
        return
    write_stamp(tmp, sources, skipped)
    try:
        os.rename(tmp, dst)
    except OSError:  # another run made it meanwhile
        shutil.rmtree(tmp, ignore_errors=True)
    # one fixture per exclave name: those of the exclave's earlier contents go
    name = os.path.basename(dst).rsplit("-", 1)[0]
    for old in os.listdir(os.path.dirname(dst)):
        if old.rsplit("-", 1)[0] == name and old != os.path.basename(dst) and ".tmp" not in old:
            shutil.rmtree(os.path.join(os.path.dirname(dst), old), ignore_errors=True)
    n = sum(len(fn) for dp, dn, fn in os.walk(os.path.join(dst, "tree")))
    print(f"fixture: {n} files, kept at {dst}")


def check(ex: str, *logs: str) -> tuple[list[str], list[str], str]:
    """Run exclave check on ex with the given EXCLAVE_LOG files (10.3).

    Returns its error lines and its warning lines, each without its prefix, and its whole output.
    A status but 0 or 1, or no summary line, fails the test: a crash or a refusal before the report
    is never an empty list of errors.
    """
    rc, out, err = run([*TOOL, "check", ex, *logs])
    lines = out.splitlines()
    if rc not in (0, 1) or not any(
        x.startswith("static check: ") and x.endswith(" errors") for x in lines
    ):
        msg = f"check {ex} exited {rc} without its summary: {(out + err)[-600:]}"
        raise AssertionError(msg)
    errors = [x.removeprefix("error: ") for x in lines if x.startswith("error: ")]
    warnings = [x.removeprefix("warning: ") for x in lines if x.startswith("warning: ")]
    return errors, warnings, out + err


def hello_source(ctx: Ctx) -> str:
    """Return hello.c in the work directory, writing it if no test has yet."""
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
    """Make the shared exclave from ctx.tree, add the test files and wrap it."""
    ex = os.path.join(ctx.work, "exclave")
    root = os.path.join(ex, "tree")
    os.makedirs(os.path.join(ex, ".exclave"))
    shutil.copy2(ctx.launcher_src, os.path.join(ex, ".exclave", "launcher"))
    os.chmod(os.path.join(ex, ".exclave", "launcher"), 0o755)
    shutil.copytree(ctx.tree, root, symlinks=True, copy_function=tree.link_or_copy)
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
        tree.unwrap_tree(ex)

    # test additions to the tree, each a new file: the copy's files are hard links to the given
    # tree's, which a fixture shares with every run made from it, and a fixture has these already
    def add(path: str, body: str, mode: int = 0o644) -> None:
        if os.path.lexists(path):
            os.remove(path)
        with open(path, "w") as f:
            f.write(body)
        os.chmod(path, mode)

    add(os.path.join(root, "usr", "share", "exclave-test-marker"), "marker\n")
    # a socket file in the tree (13 item 31); a fixture carries one already
    tree.socket_file(os.path.join(root, "usr", "share", "exclave-test.sock"))
    for name, body in (
        ("exclave-test-script", "#!/bin/sh\necho script ok $1 $#\n"),
        ("exclave-test-noshebang", "echo noshebang ok\n"),
        ("exclave-test-script2", "#!/usr/bin/exclave-test-script\n"),
        ("exclave-test-exe", "#!/bin/sh\nreadlink /proc/$$/exe\n"),
        ("exclave-test-comm", '#!/bin/sh\nread c </proc/self/comm\necho "$L comm: $c"\n'),
    ):
        add(os.path.join(root, "usr", "bin", name), body, 0o755)
    top = "/" + ctx.work.split("/")[1]
    ctx.cwd_given = top not in VOLATILE
    # wrapped by the suite, since the tree it is given need not pass the static check
    own = f'\nown "{top}"\n'.encode() if ctx.cwd_given else b""
    tree.wrap_unchecked(ex, b"exclave 1\n" + own)
    ctx.exclave, ctx.root, ctx.launcher = ex, root, os.path.join(ex, ".exclave", "launcher")
    tree_facts(ctx)
    ctx.gcc = tree.compiler(root, ctx.machine) or GCC  # the tree's C compiler


def tree_facts(ctx: Ctx) -> None:
    """Record in ctx what the tree says about its architecture (7.1).

    That is the machine, Debian's multiarch triplet, the loader named by the originals' PT_INTERP
    and the directory it lives in, the shell's spellings and the libc.
    """
    ctx.machine = platform.machine()
    ctx.triplet = tree.triplet(ctx.root, ctx.machine)

    def vbin(name: str) -> str:
        return tree.vbin(ctx.root, name)

    def vreal(vpath: str) -> str:
        """Resolve a virtual path through the tree's links to the file behind it, a virtual path."""
        return tree.resolve(ctx.root, vpath)

    def payload(name: str) -> str:
        """The real file of a program's original, behind its wrapper and its links.

        One of its links may be an applet link to busybox.
        """
        return tree.payload(ctx.root, vreal(name if name.startswith("/") else vbin(name)))

    ctx.vbin, ctx.vreal, ctx.payload = vbin, vreal, payload
    true = payload("true")
    interp = (
        tree.interp(true)
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


# the test programs compile_progs builds, each from test/progs/NAME.c
PROGS = (
    "ro_matrix",
    "signals",
    "sigcalls",
    "sigrain",
    "sigstack",
    "clones",
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
    "exe_link",
    "memfd_exec",
    "path_length",
    "spawn_threads",
    "adversarial",
    "magic_links",
    "rename_race",
    "cwd_race",
    "creat_slash",
    "slash_links",
    "open_flags",
    "xattrat",
    "readlink_fault",
    "identity_nofollow",
    "rename_dots",
    "program_perm",
    "exec_script",
    "exec_elf",
    "exec_auxv",
    "exec_state",
)


class CompileError(Exception):
    """A test program the tree's compiler cannot build: on a pruned fixture, a file it lacks."""

    def __init__(self, name: str, err: str) -> None:
        super().__init__(f"cannot compile {name} with the exclave's compiler:\n{err}")
        self.name = name


def compile_progs(ctx: Ctx) -> None:
    """Compile the test programs with the tree's own C compiler, one at a time.

    Raises CompileError for a program that does not compile.

    One compiler at a time, as every build in the repository runs, so that the suite never loads
    the machine with more than one.

    The sources are copied into the work directory: with the work directory's top-level directory
    owned by the exclave (8.1), only the working directory's subtree is the host's.
    """
    ctx.progs = os.path.join(ctx.work, "progs")
    src = os.path.join(ctx.work, "src")
    shutil.copytree(os.path.join(HERE, "progs"), src)
    os.makedirs(ctx.progs, exist_ok=True)
    gcc = wrapper(ctx, ctx.gcc)

    def build(name: str) -> str | None:
        """Build one program, or the origin test's library and program; the error, or None."""
        if name != "origin":
            out = os.path.join(ctx.progs, name)
            cmd = [
                "-O1",
                "-g",
                "-pthread",
                "-o",
                out,
                os.path.join(src, name + ".c"),
                "-lm",
                "-ldl",
            ]
            rc, _out, err = run([gcc, *cmd], cwd=ctx.work, env=ctx.env)
            # nested functions are gcc's; clang has none
            return None if not rc or (name == "execstack" and "not allowed here" in err) else err
        lib = os.path.join(ctx.progs, "liborigin.so")
        rc, _out, err = run(
            [gcc, "-shared", "-fPIC", "-o", lib, os.path.join(src, "origin_lib.c")],
            cwd=ctx.work,
            env=ctx.env,
        )
        if rc:
            return err
        main = os.path.join(src, "origin_main.c")
        out = os.path.join(ctx.progs, "origin_main")
        rc, _out, err = run(
            [gcc, "-o", out, main, "-L" + ctx.progs, "-lorigin", "-Wl,-rpath,$ORIGIN"],
            cwd=ctx.work,
            env=ctx.env,
        )
        return err if rc else None

    errors = {name: build(name) for name in (*PROGS, "origin")}
    for name, err in errors.items():
        if err is not None:
            raise CompileError(name, err)


def make_mini(ctx: Ctx) -> None:
    """Make the small exclave a test copies when it relinks one or alters its manifest or tree.

    It is the shared exclave pruned (10.4) to what a shell, cat, grep and a compiled test program
    touch, so that a copy and a relink take milliseconds; like the shared exclave, no test changes
    it.
    """
    log = os.path.join(ctx.work, "mini.log")
    # by their paths, which a shell's builtins do not shadow
    true, cat, grep = (ctx.vbin(n) for n in ("true", "cat", "grep"))
    rc, _out, err = run(
        [
            wrapper(ctx, "sh"),
            "-c",
            f"{true}; {cat} </dev/null; {grep} -c x </dev/null; {ctx.progs}/exec child",
        ],
        cwd=ctx.work,
        env=dict(ctx.env, EXCLAVE_LOG=log),
    )
    if rc:
        sys.exit(f"the mini exclave's commands failed: {err}")
    ctx.mini = copy_exclave(ctx.exclave, os.path.join(ctx.work, "mini.exclave"))
    rc, out, err = run([*TOOL, "prune", ctx.mini, log])
    if rc:
        sys.exit(f"cannot prune the mini exclave: {out}{err}")


def prepare(args: argparse.Namespace, tree_: str, work: str, *, logging: bool) -> Ctx:
    """Make the fixtures every test is given: the exclave wrapped from tree_, the programs."""
    ctx = Ctx()
    ctx.from_exclave = bool(args.exclave)
    ctx.tree = tree_
    ctx.work = work
    ctx.launcher_src = os.path.abspath(args.launcher)
    if not os.path.exists(ctx.launcher_src):
        sys.exit(f"{args.launcher} missing: run scripts/build")
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
    make_mini(ctx)
    ctx.shared = shared_state(ctx)
    print(f"exclave made and programs compiled in {time.time() - t0:.1f}s")
    return ctx
