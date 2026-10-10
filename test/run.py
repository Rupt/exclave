#!/usr/bin/env python3
"""run.py — the regression suite (PROPOSAL.md 17.4, the part a single machine can run).

    test/run.py [--tree DIR | --can CAN] [--work DIR] [--keep] [-k NAME|SUBSTRING] [--order given|reverse|random] [--seed N] [--budget SECONDS]

Makes a can from TREE (default $CONT_TREE), or from the unwrapped root of an existing CAN, under WORK
(default build/test-work) with a few test files added to the tree, compiles test/progs/*.c with the tree's
own C compiler (test/tree.py), and runs every named test; with --can, on the fixture kept under build/fixtures/
when there is one (17). Needs python3 and a tree with a C compiler (see README.md). Optional:
strace for the isolation test, /usr/bin/gcc-13 for the identical-object test. Exit status is the number of
failures.

Tests are independent: every test makes what it needs (the fixtures made at setup are the can, the compiled
programs and the environment, never another test's output), so any subset runs in any order; `--order
reverse` and `--order random` are how that is checked.
"""
import argparse
import os
import re
import shutil
import socket
import signal
import stat
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "cannery"))
import build  # noqa: E402
import cannery  # noqa: E402
import tree  # noqa: E402

GCC = "x86_64-linux-gnu-gcc-13"      # Debian's name; make_can takes the tree's gcc when that one is absent (an Alpine can, an arm64 one)
import platform  # noqa: E402
MACHINE = platform.machine()                                        # the synthetic packages of the cannery tests carry this machine's architecture
DEB_ARCH = {"x86_64": "amd64", "aarch64": "arm64"}.get(MACHINE, MACHINE)
VOLATILE = ("/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run")
# the path syscalls the isolation test traces; the legacy forms exist on x86-64 only and strace says so elsewhere
TRACED = ("open", "stat", "lstat", "access", "execve", "readlink", "openat", "newfstatat", "readlinkat", "faccessat",
          "faccessat2", "statx", "execveat", "chdir", "mkdir", "mkdirat", "unlink", "unlinkat", "rename", "renameat",
          "renameat2", "link", "linkat", "symlink", "symlinkat")

TESTS = []
PATH_MAX = 4096


def test(f):
    TESTS.append(f)
    return f


class Ctx:
    pass


def sh_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def run(cmd, cwd=None, env=None, inp=None, timeout=300, executable=None, preexec=None):
    p = subprocess.run(cmd, cwd=cwd, env=env, input=inp, timeout=timeout, executable=executable, preexec_fn=preexec,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def wrapper(ctx, name):
    """A wrapper by name: Debian's /usr/bin, or /bin where the tree is not merged (an Alpine can)."""
    p = os.path.join(ctx.root, "usr", "bin", name)
    return p if os.path.lexists(p) else os.path.join(ctx.root, "bin", name)


def inside(ctx, prog, args=(), cwd=None, env=None, inp=None, timeout=300):
    """Run a program by virtual or host path inside the can through the opener's positional entry (7.2)."""
    return run([ctx.opener, prog] + list(args), cwd=cwd or ctx.work, env=dict(env if env is not None else ctx.env), inp=inp, timeout=timeout)


def expect(cond, msg):
    if not cond:
        raise AssertionError(msg)


copy_can = tree.copy_can                                     # a copy for a test to alter: the tree hard-linked, .can/ copied


def shared_state(ctx):
    """What every test shares and none may change: the can's manifest, its lock, and for every entry of its tree the
    path, size, mode and mtime, which an added file, a removed one or a write through a hard link changes (review
    O5-5); a walk of some thousand lstats, cheap enough to compare after every test."""
    can = ctx.can
    entries = []
    for dirpath, dirnames, filenames in os.walk(ctx.root):
        for n in dirnames + filenames:
            st = os.lstat(os.path.join(dirpath, n))
            isdir = stat.S_ISDIR(st.st_mode)                  # a directory's mtime moves when a test makes and removes a file there: not a residue
            entries.append((os.path.relpath(os.path.join(dirpath, n), ctx.root), 0 if isdir else st.st_size, st.st_mode, 0 if isdir else st.st_mtime_ns))
    return (open(os.path.join(can, ".can", "manifest"), "rb").read(), open(os.path.join(can, ".can", "lock"), "rb").read() if os.path.exists(os.path.join(can, ".can", "lock")) else b"",
            tuple(sorted(entries)))


def fixture_key(can):
    """The pruned fixture (17) depends on the source can, whose lock hashes its tree, and on what the tests touch,
    which their sources decide; a can without a lock gets no fixture."""
    import hashlib
    lock = os.path.join(can, ".can", "lock")
    if not os.path.isfile(lock):
        return None
    h = hashlib.blake2b(digest_size=6)
    h.update(open(lock, "rb").read())
    files = [os.path.join(HERE, "run.py")]
    files += sorted(os.path.join(HERE, "progs", f) for f in os.listdir(os.path.join(HERE, "progs")))
    files += sorted(os.path.join(REPO, "cannery", f) for f in os.listdir(os.path.join(REPO, "cannery")) if f.endswith(".py"))
    for f in files:
        h.update(os.path.basename(f).encode() + b"\0" + open(f, "rb").read() + b"\0")
    return h.hexdigest()


def make_fixture(ctx, dst):
    """The shared can pruned to what this run touched, from every CAN_LOG file the run wrote, kept for the next
    run (17): the same tree the tests just passed on, about a fifth of its files, the cannery's
    own prune. Made only from a run with no failure, so that a partial log never fixes a partial fixture."""
    logs = sorted(os.path.join(dp, f) for dp, dn, fn in os.walk(ctx.work) for f in fn if f.endswith(".log"))
    tmp = "%s.tmp%d" % (dst, os.getpid())                        # two runs may make the same fixture at once (test/gate.sh)
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    copy_can(ctx.can, tmp)
    if cannery.cmd_prune(tmp, logs):
        print("fixture not kept: the pruned can does not pass the static check")
        shutil.rmtree(tmp, ignore_errors=True)
        return
    if os.path.isdir(dst):                                        # another run made it meanwhile
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        os.rename(tmp, dst)
    n = sum(len(fn) for dp, dn, fn in os.walk(os.path.join(dst, "root")))
    print("fixture: %d files, kept at %s" % (n, dst))


def hello_source(ctx):
    """hello.c in the work directory: a fixture any test may make, made once."""
    src = os.path.join(ctx.work, "hello.c")
    if not os.path.exists(src):
        with open(src, "w") as f:
            f.write('#include <stdio.h>\nint main(int c, char **v) { printf("hello %s %d\\n", v[0], c); return 0; }\n')
    return src


# ------------------------------------------------------------------ setup
def make_can(ctx):
    global GCC
    can = os.path.join(ctx.work, "can")
    root = os.path.join(can, "root")
    os.makedirs(os.path.join(can, ".can"))
    shutil.copy2(ctx.opener_src, os.path.join(can, ".can", "opener"))
    os.chmod(os.path.join(can, ".can", "opener"), 0o755)
    shutil.copytree(ctx.tree, root, symlinks=True, copy_function=cannery.link_or_copy)
    for dirpath, dirnames, filenames in os.walk(root):       # a copy made under a setgid directory inherits the bit; the suite tests the opener, not the copy
        for d in dirnames:
            p = os.path.join(dirpath, d)
            if not os.path.islink(p):
                m = os.lstat(p).st_mode
                if m & 0o7000:
                    os.chmod(p, m & 0o777)
    if ctx.from_can:
        build.unwrap(can, log=lambda *a: None)
    # test additions to the tree
    with open(os.path.join(root, "usr", "share", "cont-test-marker"), "w") as f:
        f.write("marker\n")
    sk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)                    # a socket file in the tree (13 item 31)
    if os.path.lexists(os.path.join(root, "usr", "share", "cont-test.sock")):   # a fixture made by an earlier run carries it already
        os.remove(os.path.join(root, "usr", "share", "cont-test.sock"))
    sk.bind(os.path.join(root, "usr", "share", "cont-test.sock"))
    sk.close()
    for name, body in (("cont-test-script", "#!/bin/sh\necho script ok $1 $#\n"),
                       ("cont-test-noshebang", "echo noshebang ok\n"),
                       ("cont-test-script2", "#!/usr/bin/cont-test-script\n"),
                       ("cont-test-exe", "#!/bin/sh\nreadlink /proc/$$/exe\n")):
        p = os.path.join(root, "usr", "bin", name)
        with open(p, "w") as f:
            f.write(body)
        os.chmod(p, 0o755)
    top = "/" + ctx.work.split("/")[1]
    recs = [cannery.Record("can", [("t", b"1")])]
    ctx.claim = top not in VOLATILE
    if ctx.claim:
        recs.append(cannery.Record("own", [("s", top.encode())]))
    with open(os.path.join(can, ".can", "manifest"), "wb") as f:
        f.write(cannery.dump(recs, "can"))
    cannery.wrap_files(can, quiet=True)
    build.write_lock(can, [], manifest_hash=cannery.b2_file(os.path.join(can, ".can", "manifest")), tree=True)   # closed: a lock with the hashes (6.4)
    ctx.can, ctx.root, ctx.opener = can, root, os.path.join(can, ".can", "opener")
    tree_facts(ctx)
    GCC = tree.compiler(root, ctx.machine) or GCC                      # the tree's C compiler


def tree_facts(ctx):
    """What the tree says about its architecture (7.1): the machine, Debian's multiarch triplet, the loader named by
    the payloads' PT_INTERP and the directory it lives in, and the syscall numbers strace shows for a trapped call."""
    import platform
    import elfcheck
    ctx.machine = platform.machine()
    ctx.triplet = tree.triplet(ctx.root, ctx.machine)
    t = elfcheck.Tree(ctx.root)

    def vbin(name):
        return tree.vbin(ctx.root, name)

    def vreal(vpath):
        """A virtual path resolved through the tree's links, as a virtual path: the file behind the name."""
        return t.resolve(vpath) or vpath

    def payload(name):
        """The real file of a program's payload, behind its wrapper and its links (an applet link to busybox)."""
        return t.payload(vreal(name if name.startswith("/") else vbin(name)))
    ctx.vbin, ctx.vreal, ctx.payload = vbin, vreal, payload
    true = payload("true")
    ctx.interp = elfcheck.Elf(true).interp if os.path.exists(true) else {"x86_64": "/lib64/ld-linux-x86-64.so.2", "aarch64": "/lib/ld-linux-aarch64.so.1"}[ctx.machine]
    ctx.ldso_dir, ctx.ldso_name = ctx.interp.split("/")[1], os.path.basename(ctx.interp)
    ctx.musl = os.path.basename(ctx.interp).startswith("ld-musl")
    ctx.musl_interp = "/lib/ld-musl-%s.so.1" % ctx.machine
    ctx.other_interp = "/lib/ld-gnu-%s.so.2" % ctx.machine if ctx.musl else ctx.musl_interp   # a loader this can lacks, no longer than its own
    ctx.deb_arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(ctx.machine, ctx.machine)
    ctx.sh_exe = vreal(vbin("sh"))                            # what /proc/self/exe reads for a script: dash, bash or busybox by its path
    ctx.sh_link = os.readlink(os.path.join(ctx.root, vbin("sh").lstrip("/"))) if os.path.islink(os.path.join(ctx.root, vbin("sh").lstrip("/"))) else ""
    ctx.busybox = os.path.basename(ctx.sh_exe) == "busybox"
    ctx.libc = next((v for v in ("/lib/%s/libc.so.6" % ctx.triplet, "/lib64/libc.so.6", "/lib/libc.so.6", "/usr/lib/libc.so.6")
                     if os.path.lexists(os.path.join(ctx.root, v.lstrip("/")))), None)   # libc.so.6 as the loader names it; none on musl
    ctx.ldso_cache = os.path.exists(os.path.join(ctx.root, "etc", "ld.so.cache"))
    # the test programs read the tree's spellings from the environment, which the boundary passes through
    ctx.env.update(CONT_SH=vbin("sh"), CONT_SH_EXE=ctx.sh_exe, CONT_SH_LINK=ctx.sh_link, CONT_TRUE=vbin("true"),
                   CONT_TRUE_PAYLOAD="/" + os.path.relpath(true, ctx.root))


def compile_progs(ctx):
    """The sources are copied into the work directory: with the work directory's top-level directory claimed
    for the can (8.1), only the working directory's subtree is the host's."""
    ctx.progs = os.path.join(ctx.work, "progs")
    src = os.path.join(ctx.work, "src")
    shutil.copytree(os.path.join(HERE, "progs"), src)
    os.makedirs(ctx.progs, exist_ok=True)
    gcc = wrapper(ctx, GCC)
    for name in ("ro_matrix", "signals", "threads", "spawn", "exec", "fifo", "execstack", "ljmp", "fdpress", "openat2", "unix_socket", "openat2_xdev", "fexec", "exec_identity", "path_length", "spawn_threads", "adversarial"):
        rc, out, err = run([gcc, "-O1", "-g", "-pthread", "-o", os.path.join(ctx.progs, name), os.path.join(src, name + ".c"), "-lm", "-ldl"], cwd=ctx.work, env=ctx.env)
        if rc and name == "execstack" and "not allowed here" in err:      # nested functions are gcc's; clang has none
            continue
        if rc:
            sys.exit("cannot compile %s with the can's gcc:\n%s" % (name, err))
    rc, out, err = run([gcc, "-shared", "-fPIC", "-o", os.path.join(ctx.progs, "liborigin.so"), os.path.join(src, "origin_lib.c")], cwd=ctx.work, env=ctx.env)
    rc2, out, err2 = run([gcc, "-o", os.path.join(ctx.progs, "origin_main"), os.path.join(src, "origin_main.c"), "-L" + ctx.progs, "-lorigin", "-Wl,-rpath,$ORIGIN"], cwd=ctx.work, env=ctx.env)
    if rc or rc2:
        sys.exit("cannot build the origin test:\n%s%s" % (err, err2))


# ------------------------------------------------------------------ tests
@test
def version(ctx):
    rc, out, err = run([wrapper(ctx, GCC), "--version"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out.strip(), "%s --version: rc=%d out=%r err=%r" % (GCC, rc, out, err))


@test
def hello(ctx):
    src = hello_source(ctx)
    exe = os.path.join(ctx.work, "hello")
    rc, out, err = run([wrapper(ctx, GCC), "-O2", src, "-o", exe], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "compile: " + err)
    rc, out, err = inside(ctx, exe, ["a", "b"])
    expect(rc == 0 and out == "hello %s 3\n" % exe, "loader-mode run: %r %r" % (out, err))
    try:
        rc, out, err = run([exe, "a"], cwd=ctx.work)
    except OSError:                                           # no glibc loader on this host at all (a musl host): exec itself fails
        rc, err = 1, "GLIBC_"
    if rc != 0 and "GLIBC_" in err:                           # the host's libc cannot load the output: it runs inside the can only (9)
        return "host cannot load the can's output; it runs inside the can only"
    expect(rc == 0 and out == "hello %s 2\n" % exe, "host run: %r %r" % (out, err))


@test
def identical_object(ctx):
    host = "/usr/bin/gcc-13"
    if "gcc-13" not in GCC:
        return "the can's compiler is %s: no host twin" % GCC
    if not os.path.exists(host):
        return "no host gcc-13"
    src = hello_source(ctx)
    a, b = os.path.join(ctx.work, "h_host.o"), os.path.join(ctx.work, "h_can.o")
    run([host, "-O2", "-c", src, "-o", a], cwd=ctx.work)
    rc, out, err = run([wrapper(ctx, GCC), "-O2", "-c", src, "-o", b], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, err)
    expect(open(a, "rb").read() == open(b, "rb").read(), "objects differ")


@test
def isolation(ctx):
    if not shutil.which("strace"):
        return "no strace"
    tr = os.path.join(ctx.work, "trace")
    src = hello_source(ctx)
    names = list(TRACED)
    while True:                                               # an older strace may not know the newest names
        rc, out, err = run(["strace", "-f", "-s", "4096", "-o", tr, "-e", "trace=" + ",".join(names), wrapper(ctx, GCC), "-O1", src, "-o", os.path.join(ctx.work, "hello2")], cwd=ctx.work, env=ctx.env)
        m = re.search(r"invalid system call '(\w+)'", err)
        if m and m.group(1) in names:
            names.remove(m.group(1))
            continue
        break
    expect(rc == 0, "compile under strace failed: " + err)
    bad, seen = [], 0
    owned = cannery.owned(ctx.can)                            # 8.1 as the opener computes it: a top-level name outside it is the host's
    allowed_files = set(build.IDENTITY_FILES)
    for f in build.IDENTITY_FILES:          # the opener resolves each identity file's host symlink chain at startup
        p = f
        for _ in range(40):
            if not os.path.islink(p):
                break
            t = os.readlink(p)
            p = os.path.normpath(t if t.startswith("/") else os.path.join(os.path.dirname(p), t))
            allowed_files.add(p)
    # A trapped syscall appears in the trace too, at its exit stop, with the registers the kernel rolled back
    # (x86-64 shows the number as its result, aarch64 the first argument); its SIGSYS line, naming it, follows.
    # That call is the one the kernel skipped and the handler re-issued, so a line followed by its own SIGSYS
    # is not judged. A trapped syscall outside the traced set prints no line, only the SIGSYS, hence the name.
    lines, pending = [], {}
    for line in open(tr):
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
            paths = paths[:1]                                 # the rest are argv strings, or the link's text (Fedora's /usr/bin/ld -> /etc/alternatives/ld)
        for p in paths:
            seen += 1
            p = os.path.normpath(p) if p.startswith("/") else p
            ok = (not p.startswith("/") or p.startswith(ctx.root) or p.startswith(VOLATILE) or p.startswith(ctx.work)
                  or p in allowed_files
                  or ctx.work.startswith(p + "/")      # a directory on the way to the working directory (8.1.4)
                  or "/" + p.split("/")[1] not in owned)   # a top-level name the can does not own, absent or a placeholder, is the host's (8.1)
            if not ok:
                bad.append("%s %s" % (name, p))
    expect(seen > 50, "trace looks empty (%d paths)" % seen)
    expect(not bad, "host paths touched: " + ", ".join(sorted(set(bad))[:10]))


@test
def ro_matrix(ctx):
    d = os.path.join(ctx.work, "hostdir")
    os.makedirs(d, exist_ok=True)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "ro_matrix"), [d, ctx.vreal(ctx.vbin(GCC))])   # the wrapper itself, behind a link
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def coreutils_ro(ctx):
    def w(name, *args):
        return run([wrapper(ctx, name)] + list(args), cwd=ctx.work, env=ctx.env)
    rc, out, err = w("touch", "/usr/newfile"); expect(rc and "Read-only" in err, err)
    rc, out, err = w("mkdir", "-p", "/usr/lib"); expect(rc == 0, err)
    rc, out, err = w("install", "-d", "/usr/lib")
    if ctx.busybox:                                           # busybox's install -d chmods an existing directory, which the read-only rule refuses as a mount would
        expect(rc and "Read-only" in err, err)
    else:
        expect(rc == 0, err)
    rc, out, err = w("mkdir", "/usr/lib"); expect(rc and "exists" in err, err)
    rc, out, err = w("rm", ctx.vbin(GCC)); expect(rc and "Read-only" in err, err)
    rc, out, err = w("ln", ctx.vbin(GCC), os.path.join(ctx.work, "lnk-x")); expect(rc and "cross-device" in err.lower(), err)
    rc, out, err = w("cp", ctx.vbin(GCC), os.path.join(ctx.work, "gcc-copy")); expect(rc == 0, err)
    payload = ctx.payload(GCC)
    expect(os.path.getsize(os.path.join(ctx.work, "gcc-copy")) == os.path.getsize(payload), "cp of a wrapper did not copy the payload")
    expect(open(os.path.join(ctx.work, "gcc-copy"), "rb").read(4) == b"\x7fELF", "copy is not ELF")
    rc, out, err = w("cat", "/usr/share/cont-test-marker"); expect(out == "marker\n", out + err)


@test
def signals(ctx):
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "signals"))
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def threads(ctx):
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "threads"))
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def spawn(ctx):
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "spawn"), [ctx.vbin(GCC), ctx.vbin("true")], timeout=600)
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def fifo(ctx):
    d = os.path.join(ctx.work, "hostdir")
    os.makedirs(d, exist_ok=True)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "fifo"), [d], timeout=60)
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def exec_modes(ctx):
    p = os.path.join(ctx.progs, "exec")
    rc, out, err = inside(ctx, p, ["self"]); expect(rc == 0 and out == "child ok argv0=%s\n" % p, "self: %r %r" % (out, err))
    rc, out, err = inside(ctx, p, ["header", p]); expect(rc == 0 and out.startswith("header ok"), "header: %r %r" % (out, err))
    for mode in ("fexecve", "fexecve_opath", "fexecve_payload", "seccomp"):
        rc, out, err = inside(ctx, p, [mode]); expect(rc == 0, "%s: rc=%d %r %r" % (mode, rc, out, err))
    rc, out, err = inside(ctx, p, ["personality"]); expect(rc == 0 and out.startswith("child ok"), "personality: %r %r" % (out, err))
    rc, out, err = inside(ctx, p, ["nofollow"]); expect(rc == 0, "execveat AT_SYMLINK_NOFOLLOW on a symlink: %r %r" % (out, err))
    log = os.path.join(ctx.work, "closefds.log")
    target = os.path.join(ctx.work, "closefds.out")
    rc, out, err = inside(ctx, p, ["closefds", target], env=dict(ctx.env, CAN_LOG=log))
    expect(rc == 0 and open(target).read() == "line one\nline two\n", "log lines in the program's file (F3-18): %r %r" % (open(target).read()[:200], err))
    ne = os.path.join(ctx.work, "nonexec")
    os.makedirs(ne, exist_ok=True)
    with open(os.path.join(ne, "true"), "w") as f:
        f.write("not executable\n")
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "PATH=%s:%s exec %s execvp" % (ne, os.path.dirname(ctx.vbin("true")), p)], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "execvp past non-executable: rc=%d %r" % (rc, err))
    # O3-4: files executable for others but not for this user, and a plain data file, are refused as the kernel refuses them
    perm = os.path.join(ctx.work, "perm")
    os.makedirs(perm, exist_ok=True)
    victims = []
    for name, mode, body in (("victim.sh", 0o455, "#!/bin/sh\necho VICTIM RAN\n"), ("data", 0o644, "#!/bin/sh\necho VICTIM RAN\n")):
        q = os.path.join(perm, name)
        with open(q, "w") as f:
            f.write(body)
        os.chmod(q, mode)
        victims.append(q)
    shutil.copy2(os.path.join(ctx.progs, "exec"), os.path.join(perm, "velf"))
    os.chmod(os.path.join(perm, "velf"), 0o455)
    victims.append(os.path.join(perm, "velf"))
    rc, out, err = inside(ctx, p, ["perm"] + victims); expect(rc == 0 and "FAIL" not in out, "perm: %r %r" % (out, err))
    hs = os.path.join(ctx.work, "host-script.sh")
    with open(hs, "w") as f:
        f.write("#!/bin/sh\necho host script ok $1 $0\n")
    os.chmod(hs, 0o755)
    rc, out, err = inside(ctx, p, ["script", hs]); expect(rc == 0 and out == "host script ok arg1 %s\n" % hs, "host script: %r %r" % (out, err))
    rc, out, err = inside(ctx, hs, ["z"]); expect(rc == 0 and out == "host script ok z %s\n" % hs, "host script direct: %r %r" % (out, err))


@test
def scripts(ctx):
    rc, out, err = run([wrapper(ctx, "cont-test-script"), "hello"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "script ok hello 1\n", "direct: %r %r" % (out, err))
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "cont-test-script a b"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "script ok a 2\n", "via sh PATH: %r %r" % (out, err))
    rc, out, err = run([wrapper(ctx, "cont-test-script2"), "q"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out.startswith("script ok /usr/bin/cont-test-script2"), "interpreter chain: %r %r" % (out, err))
    rc, out, err = run([wrapper(ctx, "sh"), "/usr/bin/cont-test-noshebang"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "noshebang ok\n", "sh file: %r %r" % (out, err))
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "/usr/bin/cont-test-noshebang"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "noshebang ok\n", "ENOEXEC fallback: %r %r" % (out, err))
    rc, out, err = run([wrapper(ctx, "cont-test-noshebang")], cwd=ctx.work, env=ctx.env)
    expect(rc == 126 and "not an executable" in err, "noshebang direct: rc=%d %r" % (rc, err))   # a shell's 126: found, not executable
    rc, out, err = run([wrapper(ctx, "cont-test-exe")], cwd=ctx.work, env=ctx.env)
    expect(out == ctx.sh_exe + "\n", "a wrapped script's /proc/self/exe is its interpreter (F3-22): %r %r" % (out, err))
    if os.path.lexists(wrapper(ctx, "bash")):
        rc, out, err = run([wrapper(ctx, "bash"), "-c", "echo from bash"], cwd=ctx.work, env=ctx.env)
        expect(rc == 0 and out == "from bash\n", "bash starts (F3-23): rc=%d %r" % (rc, err))


@test
def script_argv0_as_given(ctx):
    """7.4.5: a script's interpreter gets the script path as the caller spelt it, as the kernel passes it: for a host
    script run inside by a relative path, and through the positional entry; a wrapped script run from outside by a
    relative path likewise (review F5-8), and a wrapped script exec'd from inside, since the handler carries the spelling to
    the wrapper it execs (revision 16)."""
    d = os.path.join(ctx.work, "argv0")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "s.sh"), "w") as f:
        f.write('#!/bin/sh\necho "argv0=$0 n=$#"\n')
    os.chmod(os.path.join(d, "s.sh"), 0o755)
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "./s.sh a b"], cwd=d, env=ctx.env)
    expect(out == "argv0=./s.sh n=2\n", "a host script inside, by a relative path: %r %r" % (out, err))
    rc, out, err = run([ctx.opener, "./s.sh", "a"], cwd=d, env=ctx.env)
    expect(out == "argv0=./s.sh n=1\n", "through the positional entry: %r %r" % (out, err))
    rc, out, err = run(["./cont-test-script", "x"], cwd=os.path.join(ctx.root, "usr", "bin"), env=ctx.env)
    expect(out == "script ok x 1\n", "a wrapped script from outside by a relative path runs: %r %r" % (out, err))
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "cd /usr/bin && ./cont-test-exe"], cwd=ctx.work, env=ctx.env)
    expect(out == ctx.sh_exe + "\n", "a wrapped script inside: exe is its interpreter (F3-22): %r %r" % (out, err))
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "cd /usr/bin && ./cont-test-script2 q"], cwd=ctx.work, env=ctx.env)
    expect(out == "script ok ./cont-test-script2 2\n", "a wrapped script exec'd from inside gets the path as spelt, carried to its wrapper by the handler (7.4.5): %r %r" % (out, err))


@test
def identity(ctx):
    rc, out, err = run([wrapper(ctx, "cat"), "/etc/passwd"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == open("/etc/passwd").read(), "passwd differs from the host")
    rc, out, err = run([wrapper(ctx, "cat"), "/etc/hostname"], cwd=ctx.work, env=ctx.env)
    if os.path.lexists(os.path.join(ctx.root, "etc", "hostname")):
        expect(rc == 0 and out == open(os.path.join(ctx.root, "etc", "hostname")).read(), "a can shipping /etc/hostname shows its own: %r %r" % (out, err))
    else:
        expect(rc != 0 and "No such file" in err, "host /etc/hostname must be invisible: %r" % err)
    # 6.2: the time zone is not the host's: UTC inside, whatever TZ and /etc/localtime say outside
    rc, out, err = run([wrapper(ctx, "date"), "+%Z"], cwd=ctx.work, env=dict(ctx.env, TZ="Asia/Tokyo"))
    expect(out.strip() == "UTC", "the zone inside a can is UTC: %r %r" % (out, err))
    if not os.path.lexists(os.path.join(ctx.root, "etc", "localtime")):
        rc, out, err = run([wrapper(ctx, "cat"), "/etc/localtime"], cwd=ctx.work, env=ctx.env)
        expect(rc != 0 and "No such file" in err, "the host's /etc/localtime must be invisible: %r" % err)


@test
def environment(ctx):
    env = dict(ctx.env, LD_PRELOAD="/nonexistent", LD_LIBRARY_PATH="/x", GCONV_PATH="/x", LOCPATH="/x", CAN_TESTVAR="1")
    rc, out, err = run([wrapper(ctx, "env")], cwd=ctx.work, env=env)
    expect(rc == 0 and "LD_" not in out and "GCONV_PATH" not in out and "LOCPATH" not in out, "denied variables leaked: " + out)
    expect("CAN_TESTVAR=1" in out, "pass-through lost")
    rc, out, err = run([wrapper(ctx, "env")], cwd=ctx.work, env={})
    expect("PATH=/usr/local/bin:/usr/bin:/bin\n" in out, "default PATH: %r" % out)
    rc, out, err = run([wrapper(ctx, "env")], cwd=ctx.work, env=dict(ctx.env, PATH="/home/x/bin:/opt/tools/bin"))
    expect("PATH=/usr/local/bin:/usr/bin:/bin\n" in out, "PATH is the can's, not the host's (F3-3): %r" % out)
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "LD_FOO=1 env"], cwd=ctx.work, env=ctx.env)
    expect("LD_FOO=1" in out, "inside a can the environment must pass untouched")
    # 6.2: four values are the can's at the boundary, always the same; the user's are dropped
    loud = dict(ctx.env, LANG="en_GB.UTF-8", LC_ALL="de_DE.UTF-8", LC_TIME="fr_FR.UTF-8", LANGUAGE="de", TZ="Asia/Tokyo", SHELL="/usr/bin/zsh")
    rc, out, err = run([wrapper(ctx, "env")], cwd=ctx.work, env=loud)
    lines = set(out.splitlines())
    expect({"LANG=C.UTF-8", "TZ=UTC0", "SHELL=/bin/sh", "PATH=/usr/local/bin:/usr/bin:/bin"} <= lines, "the four constants: %r" % sorted(l for l in lines if l.split("=")[0] in ("LANG", "TZ", "SHELL", "PATH")))
    expect(not any(l.startswith(("LC_", "LANGUAGE=")) for l in lines), "LC_* and LANGUAGE must be dropped: %r" % sorted(l for l in lines if l.startswith(("LC_", "LANGUAGE"))))
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "LANG=C TZ=Europe/Paris env | grep -E '^(LANG|TZ)='"], cwd=ctx.work, env=loud)
    expect(sorted(out.split()) == ["LANG=C", "TZ=Europe/Paris"], "inside the boundary a wrapper script may set its own: %r" % out)
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "printf 'caf\\303\\251' | wc -m; echo b a | tr ' ' '\\n' | sort | head -1"], cwd=ctx.work, env=loud)
    expect(out == "4\na\n", "C.UTF-8 counts characters and sorts by code point: %r" % out)
    rc, out, err = inside(ctx, ctx.vbin("env"))
    expect(rc == 0 and "CAN_EXEC" not in out, "CAN_EXEC leaked: " + out)


@test
def positional_entry(ctx):
    """7.2: `.can/opener PROGRAM ARGS...` runs PROGRAM inside the can with its own argv, cmdline and comm, by an
    absolute or a relative path; CAN_EXEC is the opener's own protocol and is never an interface."""
    rc, out, err = run([ctx.opener, "./progs/exec", "self"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "child ok argv0=./progs/exec\n", "relative program path: %r %r" % (out, err))
    rc, out, err = run([ctx.opener, "/bin/sh", "-c", "cat /proc/$$/comm; tr '\\0' '\\n' < /proc/$$/cmdline | head -1"], cwd=ctx.work, env=ctx.env)
    expect(out == "sh\n/bin/sh\n", "cmdline and comm are the program's: %r %r" % (out, err))
    rc, out, err = run([ctx.opener, ctx.vbin("env")], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and "CAN_EXEC" not in out and "PATH=/usr/local/bin:/usr/bin:/bin" in out, "the boundary policy applies after the re-exec and CAN_EXEC never reaches the program: %r" % out)
    rc, out, err = run([ctx.opener], cwd=ctx.work, env=ctx.env)
    expect(rc == 127 and "PROGRAM" in err, "no program named: rc=%d %r" % (rc, err))
    rc, out, err = run([ctx.opener, "/nonexistent/prog"], cwd=ctx.work, env=ctx.env)
    expect(rc == 127 and "/nonexistent/prog" in err, "a missing program is named: %r" % err)
    rc, out, err = run([ctx.opener, "progs/../progs/exec", "self"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "child ok argv0=progs/../progs/exec\n", "argv[0] is the path as given: %r %r" % (out, err))
    # review O5-1, F5-1: the entry makes the checks an exec inside makes, with a shell's exit status
    nx = os.path.join(ctx.work, "exec644")
    shutil.copy2(os.path.join(ctx.progs, "exec"), nx)
    os.chmod(nx, 0o644)
    rc, out, err = run([ctx.opener, nx, "self"], cwd=ctx.work, env=ctx.env)
    expect(rc == 126 and "Permission denied" in err and "child ok" not in out, "a file without execute permission is refused as inside: rc=%d %r" % (rc, err))
    rc, out, err = run([ctx.opener, ctx.work], cwd=ctx.work, env=ctx.env)
    expect(rc == 126 and "Permission denied" in err, "a directory: rc=%d %r" % (rc, err))
    dp = os.path.join(ctx.work, "dp-entry.can")
    copy_can(ctx.can, dp)
    os.makedirs(os.path.join(dp, "root", "opt", "sdk", "bin"))
    shutil.copy2(os.path.join(ctx.progs, "exec"), os.path.join(dp, "root", "opt", "sdk", "bin", "prog"))
    with open(os.path.join(dp, ".can", "manifest"), "wb") as f:
        f.write(cannery.dump([cannery.Record("can", [("t", b"1")]), cannery.Record("data", [("s", b"/opt/sdk")])], "can"))
    rc, out, err = run([os.path.join(dp, ".can", "opener"), "/opt/sdk/bin/prog", "self"], cwd=ctx.work, env=ctx.env)
    expect(rc == 126 and "Permission denied" in err and "child ok" not in out, "a program under a data prefix is never executed (6.2): rc=%d %r %r" % (rc, out, err))
    # review O5-3, F5-4: CAN_EXEC in anyone's environment is inert for a wrapper, from outside and from inside
    rc, out, err = run([wrapper(ctx, "echo"), "still echo"], cwd=ctx.work, env=dict(ctx.env, CAN_EXEC=ctx.vbin("env")))
    expect(rc == 0 and out == "still echo\n", "CAN_EXEC from the host must not replace a wrapped program: %r %r" % (out, err))
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "export CAN_EXEC=%s; %s still echo" % (ctx.vbin("env"), ctx.vbin("echo"))], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "still echo\n", "CAN_EXEC exported inside must not replace a wrapped program: %r %r" % (out, err))
    # review F5-2: the can's own opener runs from inside its can (another opener, 7.4.5)
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "%s %s from inside" % (ctx.opener, ctx.vbin("echo"))], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "from inside\n", "the opener exec'd from inside: rc=%d %r %r" % (rc, out, err))
    # review F5-9: a wrapped program started through the entry is exec'd as its wrapper, so its identity is the kernel's
    rc, out, err = run([ctx.opener, ctx.vbin("sh"), "-c", "readlink /proc/$$/exe; true"], cwd=ctx.work, env=ctx.env)   # two commands: bash would exec a lone one
    expect(out == ctx.sh_exe + "\n", "a wrapper through the entry keeps the wrapper's identity: %r %r" % (out, err))
    p = subprocess.Popen([ctx.opener, ctx.vbin("sleep"), "2"], cwd=ctx.work, env=ctx.env)
    time.sleep(0.5)
    exe = os.readlink("/proc/%d/exe" % p.pid)
    p.kill(); p.wait()
    expect(exe == os.path.realpath(wrapper(ctx, "sleep")), "from outside, exe names the wrapper, not the opener: %r" % exe)


@test
def cwd_rules(ctx):
    rc, out, err = run([wrapper(ctx, "pwd")], cwd=os.path.join(ctx.root, "usr", "bin"), env=ctx.env)
    expect(out == "/usr/bin\n", "cwd inside root/: %r" % out)
    rc, out, err = run([wrapper(ctx, "touch"), "x"], cwd=os.path.join(ctx.root, "usr", "bin"), env=ctx.env)
    expect(rc and "Read-only" in err, "write in root/ cwd: %r" % err)
    sub = os.path.join(ctx.work, "sub", "sub2")
    os.makedirs(sub, exist_ok=True)
    with open(os.path.join(sub, "file"), "w") as f:
        f.write("deep\n")
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "pwd; cd sub && pwd && cat sub2/file"], cwd=ctx.work, env=ctx.env)
    expect(out == "%s\n%s/sub\ndeep\n" % (ctx.work, ctx.work), "claimed cwd: %r %r" % (out, err))
    inc, outd = os.path.join(ctx.work, "inc"), os.path.join(ctx.work, "out")
    os.makedirs(inc, exist_ok=True); os.makedirs(outd, exist_ok=True)
    with open(os.path.join(inc, "x.h"), "w") as f:
        f.write("#define X 41\n")
    with open(os.path.join(ctx.work, "sub", "y.c"), "w") as f:
        f.write('#include "x.h"\n#include <stdio.h>\nint main(void){printf("%d\\n", X+1);return 0;}\n')
    rc, out, err = run([wrapper(ctx, GCC), "-Iinc", "sub/y.c", "-o", "out/y"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "compile with subdirectory include and output: " + err)
    rc, out, err = inside(ctx, os.path.join(outd, "y"))
    expect(out == "42\n", "built output run inside: %r %r" % (out, err))
    if not ctx.claim:
        return "work dir under a volatile prefix; claim not exercised"


@test
def can_directory_visible(ctx):
    """8.1: the can's real location resolves as a host path from any working directory, even under a prefix the
    can owns (/home here), so a program can reach its files relative to its executable's real path."""
    real = os.path.join(ctx.root, ctx.vbin("true").lstrip("/"))
    rc, out, err = run([wrapper(ctx, "ls"), real], cwd="/", env=ctx.env)
    expect(rc == 0 and out.strip() == real, "real can path from cwd /: rc=%d %r %r" % (rc, out, err))
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "cd %s && pwd && ls root%s" % (ctx.can, ctx.vbin("true"))], cwd="/", env=ctx.env)
    expect(rc == 0 and out == "%s\nroot%s\n" % (ctx.can, ctx.vbin("true")), "cd into the can dir: rc=%d %r %r" % (rc, out, err))
    rc, out, err = run([wrapper(ctx, "cat"), os.path.join(ctx.root, "usr", "share", "cont-test-marker")], cwd="/", env=ctx.env)
    expect(out == "marker\n", "a file inside root/ by its real path: %r %r" % (out, err))


@test
def cross_can_distinct_openers(ctx):
    """7.4.5: a program in another can, whose opener is a different file, is exec'd as that opener, which
    then serves its own tree inside the first can's filter (the dogfooding case of 10.5)."""
    can2 = os.path.join(ctx.work, "can2")
    copy_can(ctx.can, can2)
    padded = os.path.join(ctx.work, "opener2")
    with open(padded, "wb") as f:
        f.write(open(ctx.opener, "rb").read() + b"\0" * 64)   # a different file of a different size, still the opener
    os.chmod(padded, 0o755)
    cannery.cmd_reopen(can2, padded)
    rc, out, err = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "check", can2])
    expect(rc == 0, "can2 check: " + out[-300:] + err[-300:])
    true2 = os.path.join(can2, "root", ctx.vbin("true").lstrip("/"))
    sh2 = can2 + "/root" + ctx.vbin("sh")
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "%s && %s -c 'echo cross $0 && readlink /proc/self/exe'" % (true2, sh2)], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "cross %s\n%s\n" % (sh2, ctx.vreal(ctx.vbin("readlink"))), "cross-can exec: rc=%d %r %r" % (rc, out, err))
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "cd %s && root%s --version | head -1" % (can2, ctx.vbin(GCC))], cwd=ctx.work, env=ctx.env)
    rc0, out0, _ = run([wrapper(ctx, GCC), "--version"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out.split("(", 1)[-1] == out0.split("\n", 1)[0].split("(", 1)[-1] + "\n", "gcc of the other can: rc=%d %r %r" % (rc, out, err))   # gcc prints argv[0] first


@test
def nested_older_opener(ctx):
    """7.4.2: an older opener nested inside a newer one reuses the newer filter and answers ENOSYS for a trap
    it does not know, never re-issuing it to the host. build/opener-old is the current opener built at filter version 3,
    without version 4's bind and connect in its filter or handler (make builds it beside build/opener). Across the
    syscall page's move (filter version 6, revision 16) neither direction can run, and each is refused by name: this
    opener under a filter older than 6, and an opener whose note has the old page generation exec'd from inside."""
    old = os.path.join(os.path.dirname(ctx.opener_src), "opener-old")
    if not os.path.exists(old):
        return "no build/opener-old"
    src = os.path.join(ctx.work, "nb.c")
    sock = os.path.join(ctx.work, "nest-sock")
    with open(src, "w") as f:                                                 # a bind at a fresh host path: 0 from the kernel
        f.write('#include <stdio.h>\n#include <errno.h>\n#include <string.h>\n#include <unistd.h>\n#include <sys/socket.h>\n#include <sys/un.h>\n'
                'int main(void) { struct sockaddr_un a; memset(&a, 0, sizeof a); a.sun_family = AF_UNIX; strncpy(a.sun_path, "@PATH@", sizeof a.sun_path - 1);\n'
                ' int s = socket(AF_UNIX, SOCK_STREAM, 0); unlink("@PATH@"); long r = bind(s, (struct sockaddr *)&a, sizeof a);\n'
                ' printf("%d %d\\n", r < 0 ? -1 : 0, r < 0 ? errno : 0); unlink("@PATH@"); return 0; }\n'.replace("@PATH@", sock))
    prog = os.path.join(ctx.work, "nb")
    rc, out, err = run([wrapper(ctx, GCC), "-O0", "-o", prog, src], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "compile: " + err)
    kernel = "0 0\n"
    rc, outer, err = run([wrapper(ctx, "sh"), "-c", prog], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and outer == kernel, "inside the current opener the kernel's answer comes back: kernel %r can %r %r" % (kernel, outer, err))
    can2 = os.path.join(ctx.work, "old-can")
    copy_can(ctx.can, can2)
    cannery.cmd_reopen(can2, old)
    log = os.path.join(ctx.work, "nested-old.log")
    rc, inner, err = run([wrapper(ctx, "sh"), "-c", "%s/root%s -c %s" % (can2, ctx.vbin("sh"), prog)], cwd=ctx.work, env=dict(ctx.env, CAN_LOG=log))
    expect(rc == 0 and inner == "-1 38\n", "the older opener nested in the newer one answers ENOSYS (38) for the trap it does not know: %r %r" % (inner, err))
    text = open(log).read()
    expect("opener 0 inside %s" % prog in text and "trap -38 -" in text and "boundary" not in text.split("opener 0 inside", 1)[1],
           "the inner opener reused the newer filter and answered the trap itself: %r" % text[-400:])
    # the page's move: this opener under opener-old's version-3 filter refuses before its first trapped syscall
    rc, out, err = run([os.path.join(can2, "root", ctx.vbin("sh").lstrip("/")), "-c", "%s; echo rc=$?" % wrapper(ctx, "true")], cwd=ctx.work, env=ctx.env)
    expect(out == "rc=127\n" and "from before the syscall page moved runs this process" in err, "under a filter older than 6: %r %r" % (out, err))
    # and an opener whose note says page generation 1, exec'd from inside, is refused by this opener's child
    gen1 = os.path.join(ctx.work, "opener-gen1")
    blob = open(ctx.opener_src, "rb").read()
    note = b"cont\0\0\0\0" + struct.pack("<I", 2)
    expect(blob.count(note) == 1, "the note's page generation is found once in the opener")
    with open(gen1, "wb") as f:
        f.write(blob.replace(note, b"cont\0\0\0\0" + struct.pack("<I", 1)) + b"\0")   # a byte more: an opener of its own size, not a copy of this one
    os.chmod(gen1, 0o755)
    can3 = os.path.join(ctx.work, "gen1-can")
    copy_can(ctx.can, can3)
    cannery.cmd_reopen(can3, gen1)
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "%s/root%s; echo rc=$?" % (can3, ctx.vbin("true"))], cwd=ctx.work, env=ctx.env)
    expect(out == "rc=127\n" and "from before the syscall page moved cannot run here" in err, "an opener of page generation 1 from inside: %r %r" % (out, err))


@test
def real_root_is_the_tree(ctx):
    """The tree's real root is an alias of /: a path spelt through <can>/root/ obeys the same rules (F3-1)."""
    root = ctx.root
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "touch %s/usr/zz; echo rc=$?; rm %s%s; echo rc=$?; cat %s/usr/share/cont-test-marker; ls -l %s%s | cut -c1 " % (root, root, ctx.vbin("true"), root, root, ctx.vbin("sh"))], cwd="/", env=ctx.env)
    expect(out == "rc=1\nrc=1\nmarker\nl\n" and "Read-only" in err, "real-root spelling: %r %r" % (out, err))
    expect(not os.path.exists(os.path.join(root, "usr", "zz")) and os.path.exists(os.path.join(root, ctx.vbin("true").lstrip("/"))), "the tree was written through its real path")


@test
def argv_unbounded(ctx):
    """7.4.5: argument vectors are sized from their counts (F3-2): a wrapped script and a host script with many arguments."""
    rc, out, err = run([wrapper(ctx, "cont-test-script")] + ["a"] * 70000, cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "script ok a 70000\n", "wrapped script with 70000 arguments: rc=%d %r %r" % (rc, out[:80], err[:200]))
    hs = os.path.join(ctx.work, "many.sh")
    with open(hs, "w") as f:
        f.write("#!/bin/sh\necho many $#\n")
    os.chmod(hs, 0o755)
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "%s $(seq 20000)" % hs], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "many 20000\n", "host script with 20000 arguments: rc=%d %r %r" % (rc, out[:80], err[:200]))


@test
def shebang_without_newline(ctx):
    """A #! line with no newline runs as the kernel runs it (F3-4)."""
    p = os.path.join(ctx.work, "nonl.sh")
    with open(p, "w") as f:
        f.write("#!/bin/sh")
    os.chmod(p, 0o755)
    rc, out, err = inside(ctx, p)
    expect(rc == 0, "no-newline shebang: rc=%d %r" % (rc, err))


@test
def identity_link_consistency(ctx):
    """lstat, readlink and the link's target agree for an identity file that is a host symlink (F3-9)."""
    link = next((f for f in ("/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf") if os.path.islink(f)), None)
    if not link:
        return "no host identity file is a symlink"
    target = os.readlink(link)
    head = open(link, "rb").read(8)                             # the content is reached through the identity name; its host target is not a can path (8.4)
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "test -L %s && echo link; readlink %s; head -c 8 %s" % (link, link, link)], cwd=ctx.work, env=ctx.env)
    expect(out.encode() == b"link\n" + target.encode() + b"\n" + head, "identity link %s: %r %r" % (link, out, err))


@test
def executable_stack(ctx):
    """7.4.5: a program whose PT_GNU_STACK asks for an executable stack, built by the can's gcc, runs inside (O3-7)."""
    if not os.path.exists(os.path.join(ctx.progs, "execstack")):
        return "%s has no nested functions: no trampoline program" % GCC
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "execstack"))
    expect(rc == 0 and out == "result 12\n", "nested function trampoline: rc=%d %r %r" % (rc, out, err))


@test
def longjmp_out_of_trapped_open(ctx):
    """7.5.4: siglongjmp out of a handler that interrupted a trapped blocking open, 200 times (O3-6, F3-15)."""
    d = os.path.join(ctx.work, "hostdir")
    os.makedirs(d, exist_ok=True)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "ljmp"), [os.path.join(d, "ljfifo"), "200"], timeout=120)
    expect(rc == 0 and out == "timed out 200 of 200 rounds\n", "longjmp rounds: rc=%d %r %r" % (rc, out, err))


@test
def exec_vectors(ctx):
    """7.5.6 for argument vectors: NULL is empty, a bad pointer is EFAULT, for a wrapper, a host ELF and a host script (O3-11, F3-14)."""
    p = os.path.join(ctx.progs, "exec")
    hs = os.path.join(ctx.work, "vec-script.sh")
    with open(hs, "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(hs, 0o755)
    rc, out, err = inside(ctx, p, ["vectors", ctx.vbin("true"), p, hs], timeout=60)
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def proc_magic_links(ctx):
    """/dev/stdin on a pipe, process substitution and /proc/self/fd of a file are reachable (F3-11)."""
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "cat /dev/stdin"], cwd=ctx.work, env=ctx.env, inp=b"hi\n")
    expect(out == "hi\n", "/dev/stdin on a pipe: %r %r" % (out, err))
    if os.path.exists(wrapper(ctx, "bash")):
        rc, out, err = run([wrapper(ctx, "bash"), "-c", "cat <(echo psub)"], cwd=ctx.work, env=ctx.env)
        expect(out == "psub\n", "process substitution: %r %r" % (out, err))
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "exec 3</etc/passwd; head -1 /proc/self/fd/3 | cut -d: -f1"], cwd=ctx.work, env=ctx.env)
    expect(out == "root\n", "/proc/self/fd of a file: %r %r" % (out, err))


@test
def new_xattr_syscalls(ctx):
    """O3-5, F3-10: the *at xattr syscalls of 6.13 are translated; on older kernels they are ENOSYS either way."""
    src = os.path.join(ctx.work, "xat.c")
    with open(src, "w") as f:
        f.write('#include <stdio.h>\n#include <errno.h>\n#include <unistd.h>\n#include <sys/syscall.h>\n#include <fcntl.h>\n'
                'int main(void){char b[64];errno=0;long r=syscall(465,AT_FDCWD,"/etc/hostname",0,b,sizeof b);printf("%ld %d\\n",r,errno);'
                'errno=0;r=syscall(465,AT_FDCWD,"/usr/share/cont-test-marker",0,b,sizeof b);printf("%ld %d\\n",r,errno);return 0;}\n')
    exe = os.path.join(ctx.work, "xat")
    rc, out, err = run([wrapper(ctx, GCC), "-O1", src, "-o", exe], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, err)
    rc, out, err = inside(ctx, exe)
    lines = out.splitlines()
    if lines and lines[0].endswith(" 38"):
        return "kernel has no listxattrat"
    own = os.path.lexists(os.path.join(ctx.root, "etc", "hostname"))            # a can that ships the file shows its own
    ok = len(lines) == 2 and (lines[0] == "-1 2" if not own else int(lines[0].split()[0]) >= 0) and lines[1].endswith(" 0") and int(lines[1].split()[0]) >= 0   # SELinux hosts label every file
    expect(ok, "listxattrat sees the can, not the host: %r %r" % (out, err))


@test
def bind_mount_alias(ctx):
    """F3-13: a second spelling of the tree's root through a bind mount is the tree, read-only."""
    if subprocess.run(["unshare", "-Urm", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        return "no user namespaces"
    alias = os.path.join(ctx.work, "alias")
    os.makedirs(alias, exist_ok=True)
    cmd = "mount --bind %s %s && %s -c 'touch %s/root/usr/zz-alias; echo rc=$?; cat %s/root/usr/share/cont-test-marker'" % (ctx.can, alias, wrapper(ctx, "sh"), alias, alias)
    rc, out, err = run(["unshare", "-Urm", "sh", "-c", cmd], cwd=ctx.work, env=dict(ctx.env, PATH="/usr/bin:/bin"))
    expect(out == "rc=1\nmarker\n" and "Read-only" in err, "bind alias: rc=%d %r %r" % (rc, out, err))
    expect(not os.path.exists(os.path.join(ctx.root, "usr", "zz-alias")), "the tree was written through a bind mount")


def make_deb(path, name, members, control_extra=""):
    """A minimal .deb: ar(debian-binary, control.tar.gz, data.tar.gz). members: [(tar-name, kind, target_or_bytes, mode)]."""
    import io
    import tarfile
    import time as _t

    def tgz(entries):
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
                    ti.type = tarfile.SYMTYPE
                    ti.linkname = val
                    t.addfile(ti)
                else:
                    ti.size = len(val)
                    t.addfile(ti, io.BytesIO(val))
        return bio.getvalue()
    control = ("Package: %s\nVersion: 1\nArchitecture: %s\nMaintainer: t\nDescription: t\n%s" % (name, DEB_ARCH, control_extra)).encode()
    parts = [("debian-binary", b"2.0\n"), ("control.tar.gz", tgz([("./control", "file", control, 0o644)])), ("data.tar.gz", tgz(members))]
    with open(path, "wb") as f:
        f.write(b"!<arch>\n")
        for n, data in parts:
            f.write(("%-16s%-12d%-6d%-6d%-8s%-10d`\n" % (n, 0, 0, 0, "100644", len(data))).encode())
            f.write(data)
            if len(data) % 2:
                f.write(b"\n")


def make_apk(path, name, members, pkginfo_extra=""):
    """A minimal unsigned .apk: two gzip members, the control stream (.PKGINFO) and the data stream, the way
    apk-tools lays them out. members as for make_deb."""
    import gzip
    import io
    import tarfile
    import time as _t

    def tgz(entries, trailer):
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
                    ti.type = tarfile.SYMTYPE
                    ti.linkname = val
                    t.addfile(ti)
                else:
                    ti.size = len(val)
                    t.addfile(ti, io.BytesIO(val))
        raw = bio.getvalue()
        if not trailer:
            raw = raw.rstrip(b"\0")                           # the control stream carries no end-of-archive blocks
            raw += b"\0" * (-len(raw) % 512)
        return gzip.compress(raw)
    info = ("pkgname = %s\npkgver = 1.0-r0\narch = %s\nsize = 1\n%s" % (name, MACHINE, pkginfo_extra)).encode()
    with open(path, "wb") as f:
        f.write(tgz([(".PKGINFO", "file", info, 0o644)], False))
        f.write(tgz(members, True))


def make_rpm(path, name, members, requires=(), provides=(), postin=""):
    """A minimal binary rpm: lead, a signature header, a header with the tags the reader uses, a gzip newc cpio
    payload. members as for make_deb; requires and provides are (name, flags, version) triples."""
    import gzip
    import struct
    import time as _t

    def header(entries):                                        # entries: [(tag, type, values)]; types 4 int32, 6 string, 8 string array
        index, data = b"", b""
        for tag, typ, vals in entries:
            if typ == 4:
                data += b"\0" * (-len(data) % 4)
                off = len(data)
                data += b"".join(struct.pack(">i", v) for v in vals)
                index += struct.pack(">IIII", tag, 4, off, len(vals))
            else:
                off = len(data)
                data += b"".join(v.encode() + b"\0" for v in vals)
                index += struct.pack(">IIII", tag, typ, off, len(vals))
        return b"\x8e\xad\xe8\x01" + b"\0" * 4 + struct.pack(">II", len(entries), len(data)) + index + data

    def cpio(entries):
        out, ino = b"", 1
        for n, kind, val, mode in entries:
            body = b""
            if kind == "dir":
                m = 0o040000 | mode
            elif kind == "sym":
                m, body = 0o120000 | mode, val.encode()
            else:
                m, body = 0o100000 | mode, val
            nm = ("./" + n).encode() + b"\0"
            h = b"070701" + b"".join(b"%08x" % v for v in (ino, m, 0, 0, 1, int(_t.time()), len(body), 0, 0, 0, 0, len(nm), 0))
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
    entries = [(1000, 6, [name]), (1001, 6, ["1.0"]), (1002, 6, ["1"]), (1022, 6, [MACHINE]), (1125, 6, ["gzip"]), (1124, 6, ["cpio"])]
    if requires:
        entries += [(1049, 8, [r[0] for r in requires]), (1048, 4, [r[1] for r in requires]), (1050, 8, [r[2] for r in requires])]
    if provides:
        entries += [(1047, 8, [p[0] for p in provides]), (1112, 4, [p[1] for p in provides]), (1113, 8, [p[2] for p in provides])]
    if postin:
        entries += [(1024, 6, [postin])]
    sig = header([(1000, 4, [len(payload)])])
    lead = b"\xed\xab\xee\xdb" + bytes([3, 0]) + struct.pack(">hh", 0, 1) + name.encode().ljust(66, b"\0")[:66] + struct.pack(">hh", 1, 5) + b"\0" * 16
    with open(path, "wb") as f:
        f.write(lead + sig + b"\0" * (-len(sig) % 8) + header(entries) + payload)


@test
def rpm_unpack(ctx):
    """10.1: unpack reads .rpm files by the file: lead, headers, cpio payload; Requires and Provides with rpm's
    flags, so-called provides, file dependencies asked of the tree, rpmlib features and rich dependencies skipped;
    the merged-usr links; alternatives --install lines in %post synthesised; one format per can."""
    d = os.path.join(ctx.work, "rpms")
    os.makedirs(d, exist_ok=True)
    EQ, GE = 8, 12
    make_rpm(os.path.join(d, "tool-1.0-1.x86_64.rpm"), "tool",
             [("usr", "dir", None, 0o755), ("usr/bin", "dir", None, 0o755), ("usr/bin/tool-2", "file", b"#!/bin/sh\necho tool ok\n", 0o755),
              ("usr/bin/tool", "file", b"#!/bin/sh\necho the shipped file, which %post removes\n", 0o755)],
             requires=[("libfoo.so.1()(64bit)", 0, ""), ("absent-pkg", GE, "2"), ("/bin/sh", 0, ""), ("/usr/bin/absent-file", 0, ""), ("rpmlib(CompressedFileNames)", (1 << 24) | 10, "3.0.4-1"), ("(a or b)", 0, "")],
             postin="/usr/bin/rm -f /usr/bin/tool\n/usr/sbin/alternatives --install /usr/bin/tool tool /usr/bin/tool-2 20\n")
    make_rpm(os.path.join(d, "libfoo-1.0-1.x86_64.rpm"), "libfoo",
             [("usr", "dir", None, 0o755), ("usr/lib64", "dir", None, 0o755), ("usr/lib64/libfoo.so.1", "file", b"data\n", 0o644),
              ("usr/bin", "dir", None, 0o755), ("usr/bin/sh", "file", b"#!/bin/true\n", 0o755),                     # /bin/sh through the merged-usr link
              ("usr/share", "dir", None, 0o755), ("usr/share/doc", "file", b"doc\n", 0o644)],
             provides=[("libfoo.so.1()(64bit)", 0, ""), ("libfoo", EQ, "1.0-1")])
    out = os.path.join(ctx.work, "rpm.can")
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "unpack", out, os.path.join(d, "tool-1.0-1.x86_64.rpm"), os.path.join(d, "libfoo-1.0-1.x86_64.rpm")])
    expect(rc == 0, "unpack: " + o + e)
    expect("depends: tool needs absent-pkg (>= 2), not in the set" in o, "the versioned dependency was not reported: " + o)
    expect("libfoo" not in o.replace("libfoo-1.0", "") and "/bin/sh" not in o and "rpmlib" not in o and "(a or b)" not in o, "a provide in the set, a file dependency the tree has, an rpmlib feature or a rich dependency was reported: " + o)
    expect("depends: tool needs /usr/bin/absent-file, not in the set" in o, "a file dependency the tree lacks was not reported: " + o)
    root = os.path.join(out, "root")
    expect(os.readlink(os.path.join(root, "bin")) == "usr/bin" and os.readlink(os.path.join(root, "lib64")) == "usr/lib64", "the merged-usr links")
    expect(os.path.exists(os.path.join(root, "usr", "lib64", "libfoo.so.1")) and os.path.exists(os.path.join(root, "usr", "bin", "tool-2")), "payload extracted")
    expect(os.path.islink(os.path.join(root, "usr", "bin", "tool")) and os.readlink(os.path.join(root, "usr", "bin", "tool")) == "/etc/alternatives/tool"
           and os.readlink(os.path.join(root, "etc", "alternatives", "tool")) == "/usr/bin/tool-2",
           "alternatives from %%post replace the shipped file at the link path (review F5-5): %r" % os.listdir(os.path.join(root, "usr", "bin")))
    lock = cannery.load(os.path.join(out, ".can", "lock"), "lock")
    pkgs = cannery.values(lock, "pkg")
    expect([tuple(p[:3]) for p in pkgs] == [(b"libfoo", b"1.0-1", MACHINE.encode()), (b"tool", b"1.0-1", MACHINE.encode())], "pkg records: %r" % pkgs)
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "wrap", out])
    expect(rc == 0 and cannery.values(cannery.load(os.path.join(out, ".can", "lock"), "lock"), "tree"), "wrap: " + o + e)
    make_apk(os.path.join(d, "x-1.0-r0.apk"), "x", [("usr", "dir", None, 0o755)])
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "unpack", out + "2", os.path.join(d, "x-1.0-r0.apk"), os.path.join(d, "tool-1.0-1.x86_64.rpm")])
    expect(rc != 0 and "one format per can" in o + e, "a mixed set must be refused: " + o + e)


@test
def apk_unpack(ctx):
    """10.1: unpack reads .apk files by the file, with .PKGINFO's depend and provides, so: names and file
    dependencies asked of the tree; Alpine's directories are its own, not merged /usr; busybox's applet links are synthesised
    from /etc/busybox-paths.d as relative links; one format per can."""
    d = os.path.join(ctx.work, "apks")
    os.makedirs(d, exist_ok=True)
    make_apk(os.path.join(d, "tool-1.0-r0.apk"), "tool", [("usr", "dir", None, 0o755), ("usr/bin", "dir", None, 0o755),
                                                          ("usr/bin/tool", "file", b"#!/bin/sh\necho tool ok\n", 0o755)],
             "depend = so:libfoo.so.1\ndepend = absent-pkg>=2\ndepend = /bin/sh\ndepend = /usr/bin/absent-file\n")
    make_apk(os.path.join(d, "libfoo-1.0-r0.apk"), "libfoo", [("bin", "dir", None, 0o755), ("bin/busybox", "file", b"#!/bin/true\n", 0o755),
                                                            ("etc", "dir", None, 0o755), ("etc/busybox-paths.d", "dir", None, 0o755),
                                                            ("etc/busybox-paths.d/busybox", "file", b"bin/sh\nusr/bin/tool2\n", 0o644),
                                                            ("usr", "dir", None, 0o755), ("usr/lib", "dir", None, 0o755), ("usr/lib/libfoo.so.1", "file", b"data\n", 0o644)],
             "provides = so:libfoo.so.1=1\nprovides = cmd:busybox=1.0-r0\n")
    out = os.path.join(ctx.work, "apk.can")
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "unpack", out, os.path.join(d, "tool-1.0-r0.apk"), os.path.join(d, "libfoo-1.0-r0.apk")])
    expect(rc == 0, "unpack: " + o + e)
    expect("depends: tool needs absent-pkg (>= 2), not in the set" in o, "the versioned dependency was not reported: " + o)
    expect("libfoo" not in o.replace("libfoo-1.0", "") and "/bin/sh" not in o, "a so: provides in the set or a file dependency the tree has (the applet link) was reported: " + o)
    expect("depends: tool needs /usr/bin/absent-file, not in the set" in o, "a file dependency the tree lacks was not reported: " + o)
    root = os.path.join(out, "root")
    expect(os.path.isdir(os.path.join(root, "bin")) and not os.path.islink(os.path.join(root, "bin")), "Alpine's /bin is a directory of its own")
    expect(os.readlink(os.path.join(root, "bin", "sh")) == "busybox" and os.readlink(os.path.join(root, "usr", "bin", "tool2")) == "../../bin/busybox",
           "applet links relative to their target: %r" % os.listdir(os.path.join(root, "bin")))
    lock = cannery.load(os.path.join(out, ".can", "lock"), "lock")
    pkgs = cannery.values(lock, "pkg")
    expect([tuple(p[:3]) for p in pkgs] == [(b"libfoo", b"1.0-r0", MACHINE.encode()), (b"tool", b"1.0-r0", MACHINE.encode())], "pkg records: %r" % pkgs)
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "wrap", out])
    expect(rc == 0 and cannery.values(cannery.load(os.path.join(out, ".can", "lock"), "lock"), "tree"), "wrap: " + o + e)
    make_deb(os.path.join(d, "x.deb"), "x", [("./usr", "dir", None, 0o755)])
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "unpack", out + "2", os.path.join(d, "x.deb"), os.path.join(d, "tool-1.0-r0.apk")])
    expect(rc != 0 and "one format per can" in o + e, "a mixed set must be refused: " + o + e)


@test
def can_readme(ctx):
    """6.1: every can explains itself to whoever finds it. Unpack, wrap and reopen write README at the top
    where the can has none and leave the maker's own, or an entry by that name, alone; the files it names are
    there; the opener run bare names it, and an opener outside any can says so."""
    cannery_py = os.path.join(REPO, "cannery", "cannery.py")
    d = os.path.join(ctx.work, "readme-apks")
    os.makedirs(d, exist_ok=True)
    make_apk(os.path.join(d, "x-1.0-r0.apk"), "x", [("usr", "dir", None, 0o755), ("usr/share", "dir", None, 0o755),
                                                    ("usr/share/x", "file", b"x\n", 0o644)])
    out = os.path.join(ctx.work, "readme-unpacked.can")
    rc, o, e = run([sys.executable, cannery_py, "unpack", out, os.path.join(d, "x-1.0-r0.apk")])
    expect(rc == 0, "unpack: " + o + e)
    with open(os.path.join(out, "README"), "rb") as f:
        expect(f.read() == cannery.CAN_README, "unpack wrote no README")
    bare = os.path.join(ctx.work, "readme-bare")                  # a bare directory holding root/, closed by wrap alone
    os.makedirs(os.path.join(bare, "root", "usr", "share"))
    os.makedirs(os.path.join(bare, ".can"))
    shutil.copy2(ctx.opener, os.path.join(bare, ".can", "opener"))
    with open(os.path.join(bare, "root", "usr", "share", "x"), "w") as f:
        f.write("x\n")
    rc, o, e = run([sys.executable, cannery_py, "wrap", bare])
    expect(rc == 0, "wrap: " + o + e)
    with open(os.path.join(bare, "README"), "rb") as f:
        expect(f.read() == cannery.CAN_README, "wrap wrote no README")
    here = cannery.CAN_README.split(b"\nWhat is here\n")[1].split(b"\nRunning it\n")[0].decode()
    for name in re.findall(r"^  (\S+/\S*)", here, re.M):
        expect(os.path.lexists(os.path.join(bare, name)), "the README names %s, which a closed can lacks" % name)
    rc, out_, err = run([os.path.join(bare, ".can", "opener")], cwd=ctx.work)
    expect(rc == 127 and "can's opener" in err and "README" in err, "the opener run bare: rc=%d %r" % (rc, err))
    lone = os.path.join(ctx.work, "readme-lone-%d" % os.getpid())
    os.makedirs(lone, exist_ok=True)
    shutil.copy2(ctx.opener, os.path.join(lone, "opener"))
    rc, out_, err = run([os.path.join(lone, "opener"), "true"], cwd=ctx.work)
    expect(rc == 127 and "not inside a can" in err and ".can/manifest" in err, "an opener outside a can: rc=%d %r" % (rc, err))
    with open(os.path.join(bare, "README"), "w") as f:            # the maker's own notes stay
        f.write("notes\n")
    rc, o, e = run([sys.executable, cannery_py, "wrap", bare])
    expect(rc == 0 and open(os.path.join(bare, "README")).read() == "notes\n", "wrap replaced the maker's README: " + o + e)
    cannery.cmd_reopen(bare, ctx.opener)
    expect(open(os.path.join(bare, "README")).read() == "notes\n", "reopen replaced the maker's README")
    os.remove(os.path.join(bare, "README"))
    os.symlink("root/usr/share/x", os.path.join(bare, "README"))   # an entry by that name stays an entry
    cannery.cmd_reopen(bare, ctx.opener)
    expect(os.readlink(os.path.join(bare, "README")) == "root/usr/share/x", "reopen replaced an entry named README")
    os.remove(os.path.join(bare, "README"))
    cannery.cmd_reopen(bare, ctx.opener)                          # a can closed before there was a README gets one
    with open(os.path.join(bare, "README"), "rb") as f:
        expect(f.read() == cannery.CAN_README, "reopen wrote no README")


@test
def cannery_extraction_rules(ctx):
    """10.1 after the review: a member reached through a package's own symlink is refused (O3-8); two spellings
    of one path under merged usr conflict (O3-9)."""
    d = os.path.join(ctx.work, "debs")
    os.makedirs(d, exist_ok=True)
    outside = os.path.join(ctx.work, "escaped")
    os.makedirs(outside, exist_ok=True)
    with open(os.path.join(outside, "README"), "w") as f:
        f.write("ORIGINAL\n")
    make_deb(os.path.join(d, "evil.deb"), "evil", [("./usr", "dir", None, 0o755), ("./usr/share", "dir", None, 0o755),
                                                     ("./usr/share/doc", "sym", "../../../../escaped", 0o777), ("./usr/share/doc/README", "file", b"ESCAPED\n", 0o644)])
    root = os.path.join(ctx.work, "root-evil")
    try:
        build.extract(root, [("evil", os.path.join(d, "evil.deb"), {})], log=lambda *a: None)
    except build.BuildError as e:
        expect("escapes" in str(e), str(e))
    else:
        raise AssertionError("a member behind a symlink out of the tree was extracted")
    expect(open(os.path.join(outside, "README")).read() == "ORIGINAL\n", "the file outside the tree was written")
    make_deb(os.path.join(d, "a.deb"), "a", [("./usr", "dir", None, 0o755), ("./usr/lib", "dir", None, 0o755), ("./usr/lib/libfoo.so.1", "file", b"A", 0o644)])
    make_deb(os.path.join(d, "b.deb"), "b", [("./lib", "dir", None, 0o755), ("./lib/libfoo.so.1", "file", b"B", 0o644)])
    root = os.path.join(ctx.work, "root-alias")
    try:
        build.extract(root, [("a", os.path.join(d, "a.deb"), {}), ("b", os.path.join(d, "b.deb"), {})], log=lambda *a: None)
    except build.BuildError as e:
        expect("both ship" in str(e), str(e))
    else:
        raise AssertionError("the merged-usr spellings of one file were not seen as a conflict")


@test
def unpack_and_wrap(ctx):
    """10.1 as files: unpack takes package files and nothing else, records every input by hash, reports what the
    set's own control files say it lacks, refuses two versions of one package; wrap closes the can and records
    the manifest and tree hashes; unwrap, check and a second wrap keep the lock (F4-6, O4-18); a tree assembled by hand becomes a can by wrap alone."""
    import elfcheck
    d = os.path.join(ctx.work, "updebs")
    os.makedirs(d, exist_ok=True)
    true_bytes = open(ctx.payload("true"), "rb").read()
    make_deb(os.path.join(d, "tool.deb"), "tool", [("./usr", "dir", None, 0o755), ("./usr/bin", "dir", None, 0o755),
                                                    ("./usr/bin/tool", "file", b"#!/bin/sh\necho tool ok\n", 0o755)],
             "Depends: libfoo1 (>= 2), virt | missing-alt\nPre-Depends: absent-pkg\n")
    make_deb(os.path.join(d, "libfoo1.deb"), "libfoo1", [("./usr", "dir", None, 0o755), ("./usr/share", "dir", None, 0o755),
                                                          ("./usr/share/foo", "file", b"data\n", 0o644)], "Provides: virt\n")
    out = os.path.join(ctx.work, "up.can")
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "unpack", out, os.path.join(d, "tool.deb"), os.path.join(d, "libfoo1.deb")])
    expect(rc == 0, "unpack: " + o + e)
    expect("depends: tool needs absent-pkg, not in the set" in o, "the missing Pre-Depends was not reported: " + o)
    expect("depends: tool needs libfoo1 (>= 2), not in the set" in o, "the version constraint was not checked: " + o)
    expect("virt" not in o, "a Provides in the set was reported missing: " + o)
    lock = cannery.load(os.path.join(out, ".can", "lock"), "lock")
    pkgs = cannery.values(lock, "pkg")
    expect([p[0] for p in pkgs] == [b"libfoo1", b"tool"] and pkgs[1][1] == b"1" and pkgs[1][2] == DEB_ARCH.encode(), "pkg records: %r" % pkgs)
    expect(pkgs[1][3].decode() == cannery.b2_file(os.path.join(d, "tool.deb")), "the input hash is the file's")
    expect(not cannery.values(lock, "tree"), "an open can has no tree hash yet")
    expect(os.path.exists(os.path.join(out, "root", "opt")) and os.path.exists(os.path.join(out, "root", "etc", "passwd")), "placeholders")
    expect(os.path.exists(os.path.join(out, ".can", "opener")) and not os.path.exists(os.path.join(out, ".can", "manifest")), "an open can: opener yes, manifest not yet")
    # the can is a directory between the two steps: put an ELF in by hand, then close it
    with open(os.path.join(out, "root", "usr", "bin", "t2"), "wb") as f:
        f.write(true_bytes)
    os.chmod(os.path.join(out, "root", "usr", "bin", "t2"), 0o755)
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "wrap", out])
    expect(rc == 1 and "does not resolve" in o, "an ELF whose loader the tree lacks must refuse the close: rc=%d %s" % (rc, o[-400:]))
    os.remove(os.path.join(out, "root", "usr", "bin", "t2"))
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "wrap", out])
    expect(rc == 0 and "closed" in o, "wrap: " + o + e)
    lock = cannery.load(os.path.join(out, ".can", "lock"), "lock")
    expect(len(cannery.values(lock, "pkg")) == 2 and cannery.values(lock, "tree") and cannery.values(lock, "manifest"), "the closed lock keeps its inputs and adds the hashes: %r" % [(r.key) for r in lock])
    expect(open(os.path.join(out, ".can", "manifest"), "rb").read() == b"can 1\n", "the default manifest")
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "hash", out])
    expect(o.strip().encode() == cannery.values(lock, "tree")[0][0], "hash agrees with the lock")
    expect(cannery.is_wrapper(os.path.join(out, "root", "usr", "bin", "tool"), cannery.opener_ino(out)), "the script was wrapped")
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "unpack", os.path.join(ctx.work, "dup.can"), os.path.join(d, "tool.deb"), os.path.join(d, "tool.deb")])
    expect(rc != 0 and "one version of a package" in e, "two files of one package must be refused: %s %s" % (o, e))
    # a hand-made tree closes by wrap alone: no manifest, no lock inputs
    hand = os.path.join(ctx.work, "hand.can")
    os.makedirs(os.path.join(hand, "root", "usr", "bin"))
    with open(os.path.join(hand, "root", "usr", "bin", "hi"), "w") as f:
        f.write("#!/bin/sh\necho hi\n")
    os.chmod(os.path.join(hand, "root", "usr", "bin", "hi"), 0o755)
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "wrap", hand])
    expect(rc == 0, "wrap of a bare tree: " + o + e)
    lock = cannery.load(os.path.join(hand, ".can", "lock"), "lock")
    expect(not cannery.values(lock, "pkg") and cannery.values(lock, "tree") and cannery.values(lock, "opener"), "a hand-made can's lock has no inputs, an opener hash and a tree hash")
    rep = elfcheck.static_check(hand, cannery.owned(hand), [])
    expect(not rep.errors, "static check of a tree with no ELF: %r" % rep.errors)
    expect(os.path.exists(os.path.join(hand, "root", "etc", "passwd")) and os.path.isdir(os.path.join(hand, "root", "opt")), "wrap adds the placeholders a hand-made tree lacks")
    # the lock through the life of a can (F4-6, O4-18)
    closed = open(os.path.join(out, ".can", "lock"), "rb").read()
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "unwrap", out])
    expect(rc == 0, "unwrap: " + o + e)
    lock = cannery.load(os.path.join(out, ".can", "lock"), "lock")
    expect(len(cannery.values(lock, "pkg")) == 2 and not cannery.values(lock, "tree") and not cannery.values(lock, "manifest") and not cannery.values(lock, "opener"), "an open can's lock keeps its inputs and has no hashes: %r" % [r.key for r in lock])
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "check", out])
    expect(rc == 1 and "an open can" in o, "check names an open can: " + o[-300:])
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "wrap", out])
    expect(rc == 0 and open(os.path.join(out, ".can", "lock"), "rb").read() == closed, "wrap after unwrap reproduces the lock byte for byte")
    os.remove(os.path.join(out, "root", "usr", "share", "foo"))
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "check", out])
    expect(rc == 1 and "differs from the lock" in o, "a file removed from a closed can must show against the lock (O4-18): " + o[-300:])
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "hash", os.path.join(ctx.work, "not-a-can")])
    expect(rc != 0 and "no root" in e, "hash of a non-can is refused (O4-16)")
    lockcopy = os.path.join(ctx.work, "some.lock.txt")
    shutil.copy2(os.path.join(out, ".can", "lock"), lockcopy)
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "fmt", "--check", lockcopy])
    expect(rc == 0, "fmt recognises a lockfile by its first record, not its name (O4-16): " + o + e)


@test
def wrap_refusals(ctx):
    """wrap refuses, and wraps nothing when it refuses: a stale wrapper of another opener (F4-2), a file its user
    cannot execute (F4-7), a payload without a wrapper (F4-5, O4-11), an ELF whose loader the tree lacks (F4-8,
    O4-7), a manifest or a tree beyond the opener's tables, which the opener refuses too (O4-9, O4-10); executables in a
    data prefix are left alone (O4-1)."""
    cannery_py = os.path.join(REPO, "cannery", "cannery.py")

    def hand(name, files, manifest=None):
        can = os.path.join(ctx.work, name)
        shutil.rmtree(can, ignore_errors=True)
        for v, body, mode in files:
            p = os.path.join(can, "root", v.lstrip("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(body)
            os.chmod(p, mode)
        if manifest is not None:
            os.makedirs(os.path.join(can, ".can"), exist_ok=True)
            with open(os.path.join(can, ".can", "manifest"), "wb") as f:
                f.write(manifest)
        return can
    script = b"#!/bin/sh\necho hi\n"
    true_bytes = open(ctx.payload("true"), "rb").read()
    # F4-2: a copy whose opener differs by a byte, then wrap: the payload must survive
    a = hand("st.can", [("/usr/bin/hi", script, 0o755)])
    rc, o, e = run([sys.executable, cannery_py, "wrap", a])
    expect(rc == 0, o + e)
    b = os.path.join(ctx.work, "st2.can")
    shutil.rmtree(b, ignore_errors=True)
    shutil.copytree(a, b, symlinks=True)                       # plain copies: the hard links are broken
    with open(os.path.join(b, ".can", "opener"), "ab") as f:
        f.write(b"\0")
    rc, o, e = run([sys.executable, cannery_py, "wrap", b])
    expect(rc != 0 and "stale wrapper" in o + e and "reopen" in o + e, "a stale wrapper must be refused: %d %s %s" % (rc, o[-300:], e[-300:]))
    expect(open(os.path.join(b, "root", "usr", "bin", ".real", "hi"), "rb").read() == script, "the payload was overwritten")
    rc, o, e = run([sys.executable, cannery_py, "reopen", b, ctx.opener_src])
    rc, o, e = run([sys.executable, cannery_py, "wrap", b])
    expect(rc == 0, "after reopen the copy closes: " + o + e)
    # F4-7: an executable its user cannot execute
    c = hand("nx.can", [("/usr/bin/gx", script, 0o601)])
    rc, o, e = run([sys.executable, cannery_py, "wrap", c])
    expect(rc != 0 and "cannot execute" in o + e and not os.path.exists(os.path.join(c, "root", "usr", "bin", ".real")), "a 0601 file must not become a 0755 opener: %s %s" % (o[-300:], e[-300:]))
    # F4-5: a payload without a wrapper
    d = hand("stray.can", [("/usr/bin/hi", script, 0o755)])
    rc, o, e = run([sys.executable, cannery_py, "wrap", d])
    expect(rc == 0, o + e)
    h1 = run([sys.executable, cannery_py, "hash", d])[1].strip()
    with open(os.path.join(d, "root", "usr", "bin", ".real", "stray"), "wb") as f:
        f.write(true_bytes)
    os.chmod(os.path.join(d, "root", "usr", "bin", ".real", "stray"), 0o755)
    h2 = run([sys.executable, cannery_py, "hash", d])[1].strip()
    expect(h1 != h2, "a stray payload must change the tree hash")
    for cmd in ("wrap", "unwrap", "check"):
        rc, o, e = run([sys.executable, cannery_py, cmd, d])
        expect(rc != 0 and "payload without wrapper" in o + e, "%s must refuse a stray payload: %s %s" % (cmd, o[-300:], e[-300:]))
    rc, o, e = run([sys.executable, cannery_py, "reopen", d, ctx.opener_src])
    expect(rc == 0 and "left alone" in o and not os.path.exists(os.path.join(d, "root", "usr", "bin", "stray")), "reopen must not make a wrapper for a stray: " + o)
    # F4-8: a refused wrap wraps nothing
    e_ = hand("noloader.can", [("/usr/bin/hi", script, 0o755), ("/usr/bin/t", true_bytes, 0o755)])
    rc, o, e = run([sys.executable, cannery_py, "wrap", e_])
    expect(rc == 1 and "nothing was wrapped" in o and not os.path.exists(os.path.join(e_, "root", "usr", "bin", ".real")), "a refused wrap must leave the tree unwrapped: " + o[-400:])
    # O4-9, O4-10: the opener's tables
    f_ = hand("lim.can", [("/usr/bin/hi", script, 0o755)], b"can 1\n\n" + b"".join(b'own "/claim%03d"\n' % i for i in range(300)))
    rc, o, e = run([sys.executable, cannery_py, "wrap", f_])
    expect(rc != 0 and "line 259 col 1: more than 256 own records" in o + e, "300 own records must be refused at the 257th: " + (o + e)[-300:])
    g = hand("lim2.can", [("/usr/bin/hi", script, 0o755)], b"can 1\n\n" + b"".join(b'host "/hostpath%03d"\n' % i for i in range(40)))
    rc, o, e = run([sys.executable, cannery_py, "wrap", g])
    expect(rc != 0 and "line 35 col 1: more than 32 host records" in o + e, "40 host records must be refused at the 33rd: " + (o + e)[-300:])
    t_ = hand("lim3.can", [("/usr/bin/hi", script, 0o755)] + [("/top%03d" % i, b"", 0o644) for i in range(300)])
    for i in range(20):
        os.makedirs(os.path.join(t_, "root", "empty%02d" % i))           # placeholders take no slot, as the opener counts
    rc, o, e = run([sys.executable, cannery_py, "wrap", t_])
    m = re.search(r"root/ has (\d+) top-level entries; the opener holds 256", o + e)   # /usr, /etc with its identity placeholders, the 300
    expect(rc != 0 and m and 301 < int(m.group(1)) < 320, "300 top-level files must be refused, the placeholders not counted: " + (o + e)[-300:])
    can2 = os.path.join(ctx.work, "hosts30.can")
    copy_can(ctx.can, can2)
    with open(os.path.join(can2, ".can", "manifest"), "wb") as f:
        f.write(b"can 1\n\n" + b"".join(b'host "/hostpath%03d"\n' % i for i in range(30)))
    rc, out, err = run([os.path.join(can2, "root", ctx.vbin("cat").lstrip("/")), "/etc/hosts"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == open("/etc/hosts").read(), "30 host records leave the identity files the host's: %r %r" % (out[:80], err))
    can3 = os.path.join(ctx.work, "top300.can")               # the tree's 256 slots are its own, whatever the manifest claims
    copy_can(ctx.can, can3)
    for i in range(300):
        open(os.path.join(can3, "root", "top%03d" % i), "w").close()
    rc, out, err = run([os.path.join(can3, "root", ctx.vbin("cat").lstrip("/")), "/etc/hosts"], cwd=ctx.work, env=ctx.env)
    expect(rc != 0 and "more than 256 top-level entries" in err, "300 top-level entries must be refused by the opener: %r" % err[-300:])
    # O4-1, O4-3: a data prefix is neither wrapped nor executed
    dp = os.path.join(ctx.work, "data.can")
    copy_can(ctx.can, dp)
    sys_ = os.path.join(dp, "root", "opt", "sysroot", "bin")
    os.makedirs(sys_)
    with open(os.path.join(sys_, "true"), "wb") as f:
        f.write(true_bytes)
    os.chmod(os.path.join(sys_, "true"), 0o755)
    with open(os.path.join(dp, ".can", "manifest"), "wb") as f:
        f.write(b'can 1\n\ndata "/opt/sysroot"\n')
    rc, o, e = run([sys.executable, cannery_py, "wrap", dp])
    expect(rc == 0 and not os.path.exists(os.path.join(sys_, ".real")), "the data prefix was wrapped or the can refused: " + (o + e)[-400:])
    rc, o, e = run([sys.executable, cannery_py, "check", dp])
    expect(rc == 0, "check with a data prefix: " + o[-300:])
    rc, out, err = run([os.path.join(dp, "root", ctx.vbin("sh").lstrip("/")), "-c", "/opt/sysroot/bin/true; echo rc=$?"], cwd=ctx.work, env=ctx.env)
    expect("Permission denied" in out + err and "rc=126" in out, "a data prefix is never executed (O4-3): %r %r" % (out, err))


@test
def wrap_refuses_unreadable(ctx):
    """10.1, 10.3: a file the user cannot read is an error of the static check, so wrap refuses before it wraps anything and
    the can stays the directory it was; check names the third state, a wrapped can without a lock (review O5-2, F5-3, N4)."""
    can = os.path.join(ctx.work, "unread.can")
    shutil.rmtree(can, ignore_errors=True)
    os.makedirs(os.path.join(can, "root", "usr", "bin"))
    os.makedirs(os.path.join(can, "root", "etc"))
    with open(os.path.join(can, "root", "usr", "bin", "hi"), "w") as f:
        f.write("#!/bin/sh\necho hi\n")
    os.chmod(os.path.join(can, "root", "usr", "bin", "hi"), 0o755)
    with open(os.path.join(can, "root", "etc", "private"), "w") as f:
        f.write("secret\n")
    os.chmod(os.path.join(can, "root", "etc", "private"), 0)
    try:
        rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "wrap", can])
        expect(rc != 0 and "unreadable file /etc/private" in o + e and "nothing was wrapped" in o + e, "an unreadable file must refuse the close: %d %s %s" % (rc, o[-300:], e[-300:]))
        expect(not os.path.exists(os.path.join(can, "root", "usr", "bin", ".real")) and not os.path.exists(os.path.join(can, ".can", "lock")), "a refused wrap leaves the tree as it was")
        os.chmod(os.path.join(can, "root", "etc", "private"), 0o600)
        rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "wrap", can])
        expect(rc == 0, "readable again, the can closes: " + o + e)
        os.remove(os.path.join(can, ".can", "lock"))
        rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "check", can])
        expect(rc != 0 and "never closed" in o + e, "a wrapped can without a lock is reported: %d %s" % (rc, o[-300:]))
    finally:
        os.chmod(os.path.join(can, "root", "etc", "private"), 0o600)


@test
def ownership_fails_closed(ctx):
    """8.1: a top-level directory the opener cannot list is the can's, not a placeholder (O4-8 B, F4-4); a spawn with
    no descriptor to spare fails loudly instead of running on the host (O4-8 A)."""
    can2 = os.path.join(ctx.work, "perm.can")
    copy_can(ctx.can, can2)
    secret = os.path.join(can2, "root", "secret")
    os.makedirs(secret)
    with open(os.path.join(secret, "file"), "w") as f:
        f.write("data\n")
    cat = os.path.join(can2, "root", ctx.vbin("cat").lstrip("/"))
    os.chmod(secret, 0)
    try:
        rc, out, err = run([cat, "/secret/file"], cwd=ctx.work, env=ctx.env)
        expect("Permission denied" in err and "No such file" not in err, "an unlistable directory must be the can's: %r" % err)
        expect("/secret" in cannery.owned(can2), "the cannery's ownership must agree")
    finally:
        os.chmod(secret, 0o755)
    press = os.path.join(ctx.progs, "fdpress")                 # built by the can's gcc: runs inside, like every built program
    libc_real = ".real/" + (os.path.basename(ctx.libc) if ctx.libc else ctx.ldso_name)   # the can's libc as the maps show it
    rc, out, err = inside(ctx, press, ["1", cat, "/proc/self/maps"])
    loud = rc == 127 and "Too many open files" in err or ctx.musl and "No file descriptors" in err   # musl's posix_spawn wants a pipe first
    expect(loud and libc_real not in out, "with one spare descriptor the opener must fail loudly, never run the host's libc: rc=%d %r %r" % (rc, out[:200], err))
    rc, out, err = inside(ctx, press, ["4", cat, "/proc/self/maps"])
    expect(rc == 0 and libc_real in out, "with four spare descriptors the can runs: rc=%d %r" % (rc, err))


@test
def root_listing_is_the_tree(ctx):
    """8.3: the root directory itself is the tree's, so ls / lists the tree's entries and cd into a placeholder
    works whether or not the host has the name (O4-17)."""
    rc, out, err = run([wrapper(ctx, "ls"), "-A", "/"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and sorted(out.split()) == sorted(os.listdir(ctx.root)), "ls / must list the tree: %r" % out)
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "cd /srv && pwd && cd / && pwd && touch /x 2>&1 || echo refused"], cwd=ctx.work, env=ctx.env)
    expect(out.startswith("/srv\n/\n") and "refused" in out, "cd into a placeholder and the read-only root: %r %r" % (out, err))


@test
def log_names_and_escapes(ctx):
    """6.2: a failed resolution logs the path as given (O4-6); a path with a newline or backslash is escaped in the
    log and undone by the cannery, so prune keeps the file the workload opened (O4-5); prune refuses a log that
    names no program (O4-4, F4-11)."""
    log = os.path.join(ctx.work, "names.log")
    if os.path.exists(log):
        os.remove(log)
    rc, out, err = run([wrapper(ctx, "cat"), "/usr/share/no/such/file"], cwd=ctx.work, env=dict(ctx.env, CAN_LOG=log))
    text = open(log).read()
    expect("open -2 /usr/share/no/such/file" in text, "a failed intermediate component must be logged by name: " + text[-300:])
    can2 = os.path.join(ctx.work, "odd.can")
    copy_can(ctx.can, can2)
    odd = os.path.join(can2, "root", "usr", "share", "odd")
    os.makedirs(odd)
    names = ("with\nnewline", "back\\slash", "back\\nslash")         # the last a backslash before an n, not a newline
    for name in names:
        with open(os.path.join(odd, name), "w") as f:
            f.write(name)
    log2 = os.path.join(ctx.work, "odd.log")
    for name in names:
        rc, out, err = run([os.path.join(can2, "root", ctx.vbin("cat").lstrip("/")), "/usr/share/odd/" + name], cwd=ctx.work, env=dict(ctx.env, CAN_LOG=log2))
        expect(out == name, "cat of the odd name: %r %r" % (out, err))
    lines = open(log2).read().split("\n")
    expect(any(l == "open 3 /usr/share/odd/with\\nnewline" for l in lines) and any(l == "open 3 /usr/share/odd/back\\\\slash" for l in lines), "escapes in the log: %r" % [l for l in lines if "odd" in l])
    src = hello_source(ctx)
    rc, out, err = run([os.path.join(can2, "root", ctx.vbin(GCC).lstrip("/")), "-O1", src, "-o", os.path.join(ctx.work, "hello-odd")], cwd=ctx.work, env=dict(ctx.env, CAN_LOG=log2))
    expect(rc == 0, err)
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "prune", can2, log2])
    expect(rc == 0, "prune: " + o + e)
    expect(sorted(os.listdir(odd)) == sorted(names), "the odd names must survive pruning: %r" % os.listdir(odd))
    empty = os.path.join(ctx.work, "empty.log")
    open(empty, "w").close()
    before = sum(1 for _ in cannery.walk_files(os.path.join(can2, "root")))
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "prune", can2, empty])
    expect(rc != 0 and "name no program" in o + e and sum(1 for _ in cannery.walk_files(os.path.join(can2, "root"))) == before, "an empty log must be refused: %s %s" % (o[-200:], e[-200:]))


@test
def ownership_from_tree(ctx):
    """8.1: the ownership set is read from the tree at startup, so a file added under a placeholder makes the
    directory the can's with nothing to refresh; an empty placeholder stays the host's."""
    can2 = os.path.join(ctx.work, "own.can")
    copy_can(ctx.can, can2)
    sh = os.path.join(can2, "root", ctx.vbin("sh").lstrip("/"))
    rc, out, err = run([sh, "-c", "cat /opt/cont-probe 2>&1; ls /srv"], cwd=ctx.work, env=ctx.env)
    expect("No such file" in out, "before: /opt is the host's, the probe does not exist there: %r" % out)
    os.makedirs(os.path.join(can2, "root", "opt"), exist_ok=True)
    with open(os.path.join(can2, "root", "opt", "cont-probe"), "w") as f:
        f.write("probe\n")
    rc, out, err = run([sh, "-c", "cat /opt/cont-probe; touch /opt/x 2>&1 || echo refused"], cwd=ctx.work, env=ctx.env)
    expect(out.startswith("probe\n") and "refused" in out, "after: /opt is the can's, read-only, with no index refreshed: %r %r" % (out, err))
    rc, out, err = run([sh, "-c", "ls -d /srv && touch /srv/cont-probe-%d && rm /srv/cont-probe-%d && echo host" % (os.getpid(), os.getpid())], cwd=ctx.work, env=ctx.env)
    expect(out.strip().endswith("host") or "Permission denied" in err, "an empty placeholder stays the host's: %r %r" % (out, err))


@test
def interp_from_payload(ctx):
    """7.3: the loader honours each program's own PT_INTERP, resolved in the can; a program naming a loader the can
    lacks fails with a message naming it, before anything runs."""
    src = open(ctx.payload("true"), "rb").read()
    interp = ctx.interp.encode() + b"\0"
    i = src.index(interp)
    other = (ctx.other_interp.encode() + b"\0").ljust(len(interp), b"\0")
    exe = os.path.join(ctx.work, "other-true")
    with open(exe, "wb") as f:
        f.write(src[:i] + other + src[i + len(interp):])
    os.chmod(exe, 0o755)
    rc, out, err = inside(ctx, exe)
    expect(rc == 127 and os.path.basename(ctx.other_interp) in err and "does not have" in err, "a loader the can lacks: rc=%d %r" % (rc, err))
    os.makedirs(os.path.join(ctx.work, "same"), exist_ok=True)
    same = os.path.join(ctx.work, "same", "true")               # by its own name: busybox chooses the applet from argv[0]
    shutil.copy2(ctx.payload("true"), same)
    rc, out, err = inside(ctx, same)
    expect(rc == 0, "a program naming the can's loader by its own header runs: rc=%d %r" % (rc, err))
    # one world (7.4.5): a loader on a host path, the shape of a Nix or --dynamic-linker binary, is refused (F4-1, O4-2)
    if not ctx.libc:
        return "musl's libc is its loader; the host-path loader case needs libc.so.6 beside one"
    hostlib = os.path.join(ctx.work, "hostworld")
    os.makedirs(hostlib, exist_ok=True)
    for f, v in ((ctx.ldso_name, ctx.interp), ("libc.so.6", ctx.libc)):
        shutil.copy2(ctx.payload(v), os.path.join(hostlib, f))
    src = hello_source(ctx)
    world = os.path.join(ctx.work, "world")
    rc, out, err = run([wrapper(ctx, GCC), "-O1", src, "-o", world, "-Wl,--dynamic-linker=" + os.path.join(hostlib, ctx.ldso_name), "-Wl,-rpath," + hostlib], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, err)
    rc, out, err = inside(ctx, world)
    expect(rc == 127 and "does not have" in err and hostlib in err, "a host-path loader must be refused: rc=%d %r %r" % (rc, out, err))
    rc, out, err = run([wrapper(ctx, "sh"), "-c", world], cwd=ctx.work, env=ctx.env)
    expect(rc == 127 and "does not have" in err, "the same from the can's shell: rc=%d %r" % (rc, err))


@test
def prune_and_check_with_logs(ctx):
    """10.3 and 10.4 take files: the dynamic check reads CAN_LOG files a workload wrote; prune keeps what the logs
    touched plus the libraries kept ELF files need and drops the rest, and the pruned can still compiles."""
    log = os.path.join(ctx.work, "prune.log")
    if os.path.exists(log):
        os.remove(log)
    src = hello_source(ctx)
    rc, out, err = run([wrapper(ctx, GCC), "-O1", src, "-o", os.path.join(ctx.work, "hello-prune")], cwd=ctx.work, env=dict(ctx.env, CAN_LOG=log))
    expect(rc == 0, err)
    rc, out, err = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "check", ctx.can, log])
    expect(rc == 0 and "0 errors" in out and "dynamic check:" in out and "log lines" in out, "check with a log: " + out[-500:] + err)
    can2 = os.path.join(ctx.work, "pruned.can")
    copy_can(ctx.can, can2)
    before = sum(1 for _ in cannery.walk_files(os.path.join(can2, "root")))
    rc, out, err = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "prune", can2, log])
    expect(rc == 0 and "pruned" in out, "prune: " + out + err)
    after = sum(1 for _ in cannery.walk_files(os.path.join(can2, "root")))
    expect(after < before // 2, "pruning removed little: %d of %d files remain" % (after, before))
    expect(os.path.isdir(os.path.join(can2, "root", "usr", "share")) and os.path.exists(os.path.join(can2, "root", "etc", "passwd")), "directories and placeholders stay")
    gcc2 = os.path.join(can2, "root", ctx.vbin(GCC).lstrip("/"))
    rc, out, err = run([gcc2, "-O1", src, "-o", os.path.join(ctx.work, "hello-pruned")], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "the pruned can compiles: " + err[-500:])
    rc, out, err = inside(ctx, os.path.join(ctx.work, "hello-pruned"))
    expect(rc == 0 and out.startswith("hello "), "the output runs: %r %r" % (out, err))
    rc, out, err = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "check", can2])
    expect(rc == 0, "the pruned can passes the static check: " + out[-600:])
    return "%d of %d files kept" % (after, before)


@test
def static_check_loader_model(ctx):
    """10.3 after the review (O3-10, F3-17): DT_RPATH is inherited down the chain, ld.so.cache is read, a search
    directory the can does not own is refused; a hand-made glibc layout closes (F4-13, F4-9), a truncated ELF is an error
    by name (F4-11), a host record is applied as the opener applies it, a library a workload built in its own directory
    is a note (F4-10, O5-4); a separate debug file, whose segments carry no bytes, is not a program."""
    import elfcheck
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
    gcc = wrapper(ctx, GCC)
    built = os.path.join(src, "out")                          # built on the host side, then placed in the tree by hand:
    os.makedirs(built, exist_ok=True)                         # from inside the can the tree's real path is the read-only can
    try:
        for cmd in (["-shared", "-fPIC", "-Wl,-soname,libbar.so.1", "-o", os.path.join(built, "libbar.so.1"), "bar.c"],
                    ["-shared", "-fPIC", "-Wl,-soname,libfoo.so.1", "-o", os.path.join(built, "libfoo.so.1"), "foo.c", "-L" + built, "-l:libbar.so.1"],
                    ["-o", os.path.join(built, "prog"), "prog.c", "-L" + built, "-l:libfoo.so.1", "-Wl,-rpath-link," + built, "-Wl,--disable-new-dtags", "-Wl,-rpath,/usr/local/x/lib"],
                    ["-o", os.path.join(built, "hostprog"), "prog.c", "-L" + built, "-l:libfoo.so.1", "-Wl,-rpath-link," + built, "-Wl,-rpath,/tmp/cont-hostlib"]):
            rc, out, err = run([gcc] + cmd, cwd=src, env=ctx.env)
            expect(rc == 0, err)
        rc, out, err = run([wrapper(ctx, "objcopy"), "--only-keep-debug", os.path.join(built, "prog"), os.path.join(built, "prog.debug")], cwd=src, env=ctx.env)
        expect(rc == 0, "objcopy: " + err)
        shutil.copy2(os.path.join(built, "prog.debug"), os.path.join(x, "prog.debug"))   # as /usr/lib/debug holds them: an empty PT_INTERP
        for f in ("libbar.so.1", "libfoo.so.1"):
            shutil.copy2(os.path.join(built, f), os.path.join(base, f))
        for f in ("prog", "hostprog"):
            shutil.copy2(os.path.join(built, f), os.path.join(x, f))
        rep = elfcheck.static_check(ctx.can, cannery.owned(ctx.can), cannery.data_prefixes(ctx.can))
        bad = [e for e in rep.errors if "/usr/local/x/prog" in e or ("libfoo" in e and "hostprog" not in e)]
        expect(not bad, "RPATH inheritance: " + "; ".join(bad))
        debug = [e for e in rep.errors if "prog.debug" in e]
        expect(not debug, "a separate debug file is not a program: %r" % debug)
        expect(any("hostprog" in e and "does not own" in e for e in rep.errors), "a host RPATH must be refused (F3-17): %r" % rep.errors[:3])
        cache = elfcheck.read_cache(elfcheck.Tree(ctx.root))
        if ctx.ldso_cache:
            expect(cache and "libc.so.6" in cache and cache["libc.so.6"][0].endswith("/libc.so.6"), "ld.so.cache parsed: %r" % (list(cache.items())[:2] if cache else cache))
    finally:
        shutil.rmtree(x, ignore_errors=True)
        if made_local:
            os.rmdir(os.path.dirname(x))                      # the shared can is left as it was (17)
    # F4-13: a hand-made tree with the loader at /usr/lib64 and no ld.so.cache closes; the loader satisfies its own
    # soname and its default directories come from the loader itself. F4-9: without /lib the host's would be searched.
    if not ctx.libc:
        return "no libc.so.6 in the tree (musl): the hand-made glibc layout is not made"
    hand2 = os.path.join(ctx.work, "hand2.can")
    shutil.rmtree(hand2, ignore_errors=True)
    libdir = os.path.dirname(ctx.vreal(ctx.libc)).lstrip("/")           # where the tree keeps libc: usr/lib/<triplet>, or usr/lib64
    for d in ("usr/" + ctx.ldso_dir, libdir, "usr/bin", "etc"):
        os.makedirs(os.path.join(hand2, "root", d), exist_ok=True)
    for top in ("lib", "lib64", "lib32"):                               # the tree's own top-level links, as the loader's defaults expect
        if os.path.islink(os.path.join(ctx.root, top)):
            os.symlink(os.readlink(os.path.join(ctx.root, top)), os.path.join(hand2, "root", top))
    shutil.copy2(ctx.payload(ctx.interp), os.path.join(hand2, "root", "usr", ctx.ldso_dir, ctx.ldso_name))   # the loader where PT_INTERP names it
    shutil.copy2(ctx.payload(ctx.libc), os.path.join(hand2, "root", libdir, "libc.so.6"))
    shutil.copy2(ctx.payload("true"), os.path.join(hand2, "root", "usr", "bin", "true"))
    rc, out, err = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "wrap", hand2])
    expect(rc == 0, "a tree with the loader in /usr/lib64 and no cache must close (F4-13): " + out[-500:])
    rc, out, err = run([os.path.join(hand2, "root", "usr", "bin", "true")], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "and run: %r" % err)
    top = ctx.libc.split("/")[1]                                        # the top-level link libc is reached through: lib, or lib64
    os.remove(os.path.join(hand2, "root", top))
    rep = elfcheck.static_check(hand2, cannery.owned(hand2), [])
    expect(any((os.path.dirname(ctx.libc) in e_ and "does not own" in e_) or (ctx.ldso_dir == top and "loader" in e_) for e_ in rep.errors),
           "a tree without /%s searches the host's (F4-9): %r" % (top, rep.errors[:3]))
    os.symlink(os.readlink(os.path.join(ctx.root, top)), os.path.join(hand2, "root", top))
    shutil.rmtree(os.path.join(hand2, "root", "etc"))
    os.makedirs(os.path.join(hand2, "root", "etc"))
    rep = elfcheck.static_check(hand2, cannery.owned(hand2), [])
    expect(any("/etc is the host's" in e_ for e_ in rep.errors), "a tree without /etc would read the host's ld.so.cache (F4-9): %r" % rep.errors[:3])
    # a truncated ELF is an error by name, not a traceback (F4-11)
    bad = os.path.join(hand2, "root", "usr", "bin", "broken")
    with open(bad, "wb") as f:
        f.write(b"\x7fELF\x02\x01\x01\x00garbage")
    os.chmod(bad, 0o755)
    rep = elfcheck.static_check(hand2, cannery.owned(hand2), [])
    expect(any("broken" in e_ and ("malformed" in e_ or "not ELF64" in e_) for e_ in rep.errors), "a truncated ELF must be reported by name: %r" % rep.errors[:3])
    # a host record takes a path back from the tree by the opener's longest prefix (8.1): over the loader's directory
    # it leaves the can no loader the opener will take, and the check must say so rather than read the tree alone
    with open(os.path.join(hand2, ".can", "manifest"), "w") as f:
        f.write('can 1\n\nhost "/usr/%s"\n' % ctx.ldso_dir)
    rep = elfcheck.static_check(hand2, cannery.owned(hand2), [])
    expect(any("/usr/bin/true wants interpreter" in e_ and "does not own" in e_ for e_ in rep.errors), "a host record over the loader: %r" % rep.errors[:3])
    # F4-10: a library the workload built in its own directory is a note, not an error
    bld = os.path.join(ctx.work, "bld")
    os.makedirs(bld, exist_ok=True)
    with open(os.path.join(bld, "foo.c"), "w") as f:
        f.write("int foo(void) { return 42; }\n")
    with open(os.path.join(bld, "usefoo.c"), "w") as f:
        f.write('#include <stdio.h>\nint foo(void); int main(void) { printf("%d\\n", foo()); return 0; }\n')
    gcc = wrapper(ctx, GCC)
    rc, out, err = run([gcc, "-shared", "-fPIC", "-o", "libfoo.so", "foo.c"], cwd=bld, env=ctx.env)
    rc2, out, err2 = run([gcc, "usefoo.c", "-L.", "-lfoo", "-Wl,-rpath,$ORIGIN", "-o", "usefoo"], cwd=bld, env=ctx.env)
    expect(rc == 0 and rc2 == 0, err + err2)
    log = os.path.join(ctx.work, "bld.log")
    if os.path.exists(log):
        os.remove(log)
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "./usefoo"], cwd=bld, env=dict(ctx.env, CAN_LOG=log))
    expect(out == "42\n", "usefoo: %r %r" % (out, err))
    rc, out, err = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "check", ctx.can, log])
    expect(rc == 0 and "working directory" in out and "0 errors" in out.splitlines()[-1], "a build-directory library is a note, not an error (F4-10): " + out[-500:])
    # review O5-4: the same library, in a directory the host owns by rule 3, opened by a workload run from /: the check
    # must still report it (nothing is claimed from /), where a run from that directory would note it as the build's own
    import tempfile
    tmp = tempfile.mkdtemp(prefix="cont-bld-", dir="/tmp")
    try:
        for f in ("libfoo.so", "usefoo"):
            shutil.copy2(os.path.join(bld, f), os.path.join(tmp, f))
        log2 = os.path.join(ctx.work, "bld-root.log")
        rc, out, err = run([wrapper(ctx, "sh"), "-c", "%s/usefoo" % tmp], cwd="/", env=dict(ctx.env, CAN_LOG=log2))
        expect(out == "42\n", "usefoo from /: %r %r" % (out, err))
        rc, out, err = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "check", ctx.can, log2])
        expect(rc != 0 and "library opened on the host" in out and tmp + "/libfoo.so" in out, "a workload run from / must not excuse a host library: " + out[-500:])
        # and a run from that directory, the host's by rule 3 with nothing to claim, notes it as the build's own
        log3 = os.path.join(ctx.work, "bld-tmp.log")
        rc, out, err = run([wrapper(ctx, "sh"), "-c", "./usefoo"], cwd=tmp, env=dict(ctx.env, CAN_LOG=log3))
        expect(out == "42\n", "usefoo from its /tmp directory: %r %r" % (out, err))
        rc, out, err = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "check", ctx.can, log3])
        expect(rc == 0 and "working directory" in out and "0 errors" in out.splitlines()[-1], "a build directory under /tmp is a note, not an error: " + out[-500:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@test
def readlink_bad_buffer(ctx):
    """7.5.6: an unwritable readlink buffer answers EFAULT, not SIGSEGV (review O3-1)."""
    src = os.path.join(ctx.work, "rl.c")
    with open(src, "w") as f:
        f.write('#include <unistd.h>\n#include <errno.h>\n#include <stdio.h>\nint main(int c, char **v) { for (int i = 1; i < c; i++) { errno = 0; long r = readlink(v[i], (char *)8, 64); printf("%ld %d\\n", r, errno); } return 0; }\n')
    exe = os.path.join(ctx.work, "rl")
    rc, out, err = run([wrapper(ctx, GCC), "-O1", src, "-o", exe], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, err)
    lib = "/lib" if os.path.islink(os.path.join(ctx.root, "lib")) else ctx.vbin("sh")   # a link in the tree; a directory would be EINVAL before the copy
    rc, out, err = inside(ctx, exe, [lib, "/proc/self/exe", ctx.vbin("sh"), "/nonexistent"])
    expect(rc == 0 and out == "-1 14\n-1 14\n-1 14\n-1 2\n", "bad buffer: rc=%d %r %r" % (rc, out, err))


@test
def host_symlink_into_usr(ctx):
    lnk = os.path.join(ctx.work, "lnk")
    if os.path.lexists(lnk):
        os.remove(lnk)
    os.symlink("/usr/share", lnk)
    rc, out, err = run([wrapper(ctx, "cat"), os.path.join(lnk, "cont-test-marker")], cwd=ctx.work, env=ctx.env)
    expect(out == "marker\n", "host symlink into /usr resolves in the can: %r %r" % (out, err))


@test
def ld_so(ctx):
    ld = ctx.interp
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "%s --list %s" % (ld, ctx.vbin(GCC))], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and (ctx.musl or "libc.so.6 => %s" % ctx.libc in out) and ctx.root not in out, "ld.so --list: %r %r" % (out, err))
    if ctx.musl:
        return "musl's loader has no --verify"
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "%s --verify %s" % (ld, ctx.vbin(GCC))], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "ld.so --verify rc=%d" % rc)
    rc, out, err = run([os.path.join(ctx.root, ctx.interp.lstrip("/")), "--verify", ctx.vbin(GCC)], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "ld.so run by its real path from the host: rc=%d %r" % (rc, err))


@test
def nested_and_log(ctx):
    log = os.path.join(ctx.work, "can.log")
    if os.path.exists(log):
        os.remove(log)
    rc, out, err = run([wrapper(ctx, "sh"), "-c", GCC + " --version"], cwd=ctx.work, env=dict(ctx.env, CAN_LOG=log))
    expect(rc == 0 and out.strip(), out + err)
    text = open(log).read()
    expect("opener 0 boundary " + ctx.sh_exe in text and "opener 0 inside " + ctx.vreal(ctx.vbin(GCC)) in text, "log: " + text[:400])


@test
def sigsys_blocked_at_launch(ctx):
    def block():
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGSYS})
    rc, out, err = run([wrapper(ctx, GCC), "--version"], cwd=ctx.work, env=ctx.env, preexec=block)
    expect(rc == 0 and out.strip(), "launch with SIGSYS blocked: rc=%d %r" % (rc, err))


@test
def kill_sys(ctx):
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "kill -SYS $$"], cwd=ctx.work, env=ctx.env)
    expect(rc == -signal.SIGSYS, "kill -SYS: rc=%d %r" % (rc, err))


@test
def origin(ctx):
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "origin_main"), cwd=ctx.work)
    expect(rc == 0 and out == "origin 42\n", "RUNPATH=$ORIGIN: %r %r" % (out, err))


@test
def gconv_and_locale(ctx):
    notes = []
    if os.path.exists(wrapper(ctx, "iconv")):
        p = subprocess.run([wrapper(ctx, "iconv"), "-f", "utf-8", "-t", "cp1252"], input="caf\xe9".encode(), env=ctx.env, cwd=ctx.work, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        expect(p.returncode == 0 and p.stdout == b"caf\xe9", "iconv via gconv: rc=%d %r %r" % (p.returncode, p.stdout, p.stderr))
    else:
        notes.append("no iconv in the tree")
    if os.path.isdir(os.path.join(ctx.root, "usr", "lib", "locale", "C.utf8")):
        rc, out, err = run([wrapper(ctx, "wc"), "-m"], cwd=ctx.work, env=dict(ctx.env, LC_ALL="C.UTF-8"), inp="caf\xe9".encode())
        expect(out.strip() == "4", "wc -m under C.UTF-8: %r" % out)
    else:
        notes.append("no C.utf8 locale in the tree")
    return "; ".join(notes)


@test
def cannery_check(ctx):
    rc, out, err = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "check", ctx.can])
    expect(rc == 0 and "0 wrapper problems" in out and "0 errors" in out, out + err)
    rc, out, err = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "fmt", "--check", os.path.join(ctx.can, ".can", "manifest")])
    expect(rc == 0, "manifest not canonical: " + out + err)


@test
def mixed_tree_refused(ctx):
    """10.3: a tree whose ELF files name two loaders is refused by the static check, which reads the loaders from
    the files; nothing declares one."""
    import elfcheck
    mixed = os.path.join(ctx.work, "mixed.can")
    d = os.path.join(mixed, "root")
    os.makedirs(os.path.join(d, "usr", "bin"), exist_ok=True)
    src = open(ctx.payload("true"), "rb").read()
    interp = ctx.interp.encode() + b"\0"
    i = src.index(interp)
    other = (ctx.other_interp.encode() + b"\0").ljust(len(interp), b"\0")
    with open(os.path.join(d, "usr", "bin", "true"), "wb") as f:
        f.write(src[:i] + other + src[i + len(interp):])
    with open(os.path.join(d, "usr", "bin", "false"), "wb") as f:
        f.write(src)
    for n in ("true", "false"):
        os.chmod(os.path.join(d, "usr", "bin", n), 0o755)
    os.symlink(ctx.interp, os.path.join(d, "usr", "bin", "ld-glibc"))   # so that one loader resolves
    os.makedirs(os.path.join(d, ctx.ldso_dir), exist_ok=True)
    shutil.copy2(ctx.payload(ctx.interp), os.path.join(d, ctx.interp.lstrip("/")))
    os.makedirs(os.path.dirname(os.path.join(d, ctx.other_interp.lstrip("/"))), exist_ok=True)   # the other loader's directory
    shutil.copy2(ctx.payload(ctx.interp), os.path.join(d, ctx.other_interp.lstrip("/")))
    rep = elfcheck.static_check(mixed, ["/usr", "/lib", "/lib64"], [])
    expect(any("mixes loaders" in e for e in rep.errors), "a tree with two loaders was not refused: %r" % rep.errors[:4])


@test
def rust(ctx):
    rustc = shutil.which("rustc") or shutil.which("rustc", path=os.path.expanduser("~/.cargo/bin"))
    if not rustc:
        return "no rustc"
    if ctx.musl:
        return "the host's rustc targets glibc; the can has musl"
    exe = os.path.join(ctx.progs, "rs")
    rc, out, err = run([rustc, "-O", "-o", exe, os.path.join(ctx.work, "src", "rs.rs")], cwd=ctx.work)
    expect(rc == 0, "rustc: " + err[-600:])
    rc, out, err = inside(ctx, exe)
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def openat2_resolve(ctx):
    """7.4.3: openat2 in the can's world. RESOLVE_IN_ROOT and RESOLVE_BENEATH scope the walk to the descriptor's
    directory, RESOLVE_NO_SYMLINKS refuses the tree's own links as a bind mount would, magic links are refused by
    the scoped flags, RESOLVE_NO_XDEV refuses the can-to-host crossing, the read-only rule holds, and the struct's
    own rules answer EINVAL before any lookup. Skips on a kernel without openat2."""
    d = os.path.join(ctx.work, "o2host")
    os.makedirs(d, exist_ok=True)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "openat2"), [d])
    if rc == 3:
        return "no openat2 on this kernel (5.6 and later)"
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def openat2_xdev(ctx):
    """13 item 22, 7.4.3: an openat2 whose walk never touches the can is re-issued as given with its resolve flags, so
    the kernel enforces RESOLVE_NO_XDEV across the host's own mounts, and the other flags, on host-only walks. The
    kernel's answers come from this harness itself, natively, for the same cases with the same descriptors (bwrap
    rebuilds /dev and cannot be the oracle for the host's mounts); the walks that touch the can assert the crossing
    rule. Skips on a kernel without openat2."""
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
    NO_XDEV, NO_MAGIC, NO_SYMLINKS, BENEATH, IN_ROOT = 1, 2, 4, 8, 16
    RD, DIR = os.O_RDONLY, os.O_RDONLY | os.O_DIRECTORY
    dev, proc, hd = (os.open(x, os.O_PATH | os.O_DIRECTORY) for x in ("/dev", "/proc", d))
    cases = [("no_xdev cwd to .", -100, ".", DIR, NO_XDEV), ("no_xdev cwd to sub", -100, "sub", DIR, NO_XDEV), ("no_xdev cwd to ..", -100, "..", DIR, NO_XDEV),
             ("no_xdev /dev fd to null", dev, "null", RD, NO_XDEV), ("no_xdev /dev fd to shm", dev, "shm", DIR, NO_XDEV), ("no_xdev /dev fd to ..", dev, "..", DIR, NO_XDEV),
             ("no_xdev /proc fd to self/status", proc, "self/status", RD, NO_XDEV), ("no_xdev host fd to file", hd, "file", RD, NO_XDEV),
             ("no_symlinks host fd to lnk", hd, "lnk", RD, NO_SYMLINKS), ("no_symlinks host fd to file", hd, "file", RD, NO_SYMLINKS),
             ("no_magiclinks /proc fd to self/status", proc, "self/status", RD, NO_MAGIC), ("no_magiclinks /proc fd to version", proc, "version", RD, NO_MAGIC),
             ("beneath host fd to sub", hd, "sub", DIR, BENEATH), ("beneath host fd to ..", hd, "..", DIR, BENEATH), ("beneath host fd to sub/..", hd, "sub/..", DIR, BENEATH),
             ("in_root host fd to /etc/passwd", hd, "/etc/passwd", RD, IN_ROOT), ("in_root host fd to ../../../file", hd, "../../../file", RD, IN_ROOT),
             ("in_root /dev fd to /null", dev, "/null", RD, IN_ROOT), ("beneath|no_xdev /dev fd to shm", dev, "shm", DIR, BENEATH | NO_XDEV)]
    here = os.getcwd()
    os.chdir(d)                                                            # the AT_FDCWD cases start where the program started them
    try:
        bad = []
        for label, dfd, path, flags, resolve in cases:
            how = (ctypes.c_ulonglong * 3)(flags, 0, resolve)
            r = libc.syscall(437, dfd, path.encode(), how, 24)
            native = "ret=0 errno=0" if r >= 0 else "ret=-1 errno=%d" % ctypes.get_errno()
            if r >= 0:
                os.close(r)
            if got.get(label) != native:
                bad.append("%s: the can says %s, the kernel says %s" % (label, got.get(label), native))
    finally:
        os.chdir(here)
        for fd in (dev, proc, hd):
            os.close(fd)
    expect(not bad, "; ".join(bad))
    crossing = {"no_xdev cwd to /dev/null": "ret=-1 errno=18", "no_xdev cwd to /dev/shm": "ret=-1 errno=18", "no_xdev cwd to /proc/self/status": "ret=-1 errno=18",
                "no_xdev cwd to /usr/share (can)": "ret=0 errno=0", "no_xdev host fd to /dev/null (absolute)": "ret=-1 errno=18",
                "root by .. from host fd is the tree's": "yes", "no_xdev host fd to the root by ..": "ret=-1 errno=18"}   # a .. that reaches the root is the walk's (revision 16)
    bad = ["%s: %s, wanted %s" % (k, got.get(k), v) for k, v in crossing.items() if got.get(k) != v]
    expect(not bad, "the can-to-host crossing under RESOLVE_NO_XDEV: " + "; ".join(bad))


@test
def exec_identity(ctx):
    """7.4.5, 7.6: the identity a program exec'd from inside gets, as the kernel gives it: comm and AT_EXECFN from the path
    the program was exec'd by, not from argv[0]; a script's $0, AT_EXECFN and comm spelt /dev/fd/N/name relative to a
    descriptor and /dev/fd/N through one, comm then the file's own name; a close-on-exec script descriptor refused with
    ENOENT before anything runs; a header the loader cannot load ENOEXEC and a loader the can lacks ENOENT from execve
    itself, where the child used to die after a successful exec. The kernel under bwrap measured these answers
    (test/exercise.py, revision 16)."""
    d = os.path.join(ctx.work, "identhost")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "exec_identity"), [d])
    expect(rc == 0, "exec_identity: %r %r" % (out, err))
    got = dict(line.split(": ", 1) for line in out.splitlines() if ": " in line)
    want = {"abs comm": "prog2", "abs execfn": d + "/prog2", "abs argv0": "renamed", "rel comm": "prog2", "rel execfn": "prog2", "rel argv0": "renamed",
            "dfd script argv0": "/dev/fd/N/s.sh", "dfd script comm": "s.sh", "cloexec script": "ENOENT",
            "fd script argv0": "/dev/fd/N", "fd script comm": "s.sh", "fd elf comm": "prog2", "fd elf execfn": "/dev/fd/N", "fd elf argv0": "renamed",
            "elf32": "ENOEXEC", "no loader": "ENOENT"}
    bad = ["%s: got %s, the kernel says %s" % (k, got.get(k), v) for k, v in want.items() if got.get(k) != v]
    expect(not bad, "; ".join(bad))


@test
def path_length(ctx):
    """13 item 13, 7.4.4: a can-owned path whose real spelling, the root prefix and the virtual path, would not fit PATH_MAX
    is refused with ENAMETOOLONG and never cut to a shorter name, which once answered ENOENT for the cut; its parent, which
    fits, is fine. And a relative path from a working directory so deep that the two together pass PATH_MAX is
    ENAMETOOLONG too, where the kernel, walking relatively, succeeds: the stated limitation. On a private copy of the can,
    since the chain is made in the tree."""
    copy = os.path.join(ctx.work, "lengthcan")
    shutil.rmtree(copy, ignore_errors=True)
    copy_can(ctx.can, copy)
    rootlen = len(os.path.join(copy, "root"))
    if rootlen > 200:
        return "the work directory's path is too long for the window: skipped"
    base = "/usr/share/cont-deep"
    fd = os.open(os.path.join(copy, "root", base.lstrip("/")[:9]), os.O_RDONLY | os.O_DIRECTORY)   # /usr/share
    os.mkdir("cont-deep", dir_fd=fd)
    nfd = os.open("cont-deep", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd); os.close(fd); fd = nfd
    v = base
    for i in range(19):                                                # 19 components of 200: 3839 characters
        os.mkdir("a" * 200, dir_fd=fd)
        nfd = os.open("a" * 200, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd); os.close(fd); fd = nfd
        v += "/" + "a" * 200
    parent = v
    last = "b" * (PATH_MAX - rootlen - len(v) - 1)                      # a directory whose real spelling is exactly PATH_MAX long
    os.mkdir(last, dir_fd=fd)
    nfd = os.open(last, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd); os.close(fd); fd = nfd
    with os.fdopen(os.open("f", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd), "w") as f:
        f.write("deep\n")
    os.close(fd)
    deep, dfile = v + "/" + last, v + "/" + last + "/f"
    expect(len(dfile) < PATH_MAX and rootlen + len(deep) == PATH_MAX, "the window: root %d, dir %d, file %d" % (rootlen, len(deep), len(dfile)))
    # the deep working directory on the host: 14 components of 200 below the work directory, then 7 more reached relatively
    d = "d" * 200
    hostdeep = os.path.join(ctx.work, "deepcwd")
    os.makedirs(hostdeep)
    fd = os.open(hostdeep, os.O_RDONLY | os.O_DIRECTORY)
    for i in range(14):
        os.mkdir(d, dir_fd=fd)
        nfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd); os.close(fd); fd = nfd
        hostdeep = os.path.join(hostdeep, d)
    with os.fdopen(os.open("f", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd), "w") as f:
        f.write("here\n")
    rel = ""
    for i in range(7):
        os.mkdir(d, dir_fd=fd)
        nfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd); os.close(fd); fd = nfd
        rel += d + "/"
    with os.fdopen(os.open("f", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd), "w") as f:
        f.write("below\n")
    os.close(fd)
    rel += "f"
    expect(len(hostdeep) < PATH_MAX and len(hostdeep) + 1 + len(rel) > PATH_MAX, "the deep working directory: %d + %d" % (len(hostdeep), len(rel)))
    rc, out, err = run([os.path.join(copy, ".can", "opener"), os.path.join(ctx.progs, "path_length"), parent, deep, dfile, "cd:" + hostdeep, rel, "f"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "path_length: rc=%d %r %r" % (rc, out, err))
    want = ["1: stat=ok open=ok", "2: stat=ENAMETOOLONG open=ENAMETOOLONG", "3: stat=ENAMETOOLONG open=ENAMETOOLONG", "4: stat=ENAMETOOLONG open=ENAMETOOLONG", "5: stat=ok open=ok"]
    expect(out.splitlines() == want, "the parent fits, the directory at the limit and its file are ENAMETOOLONG, a relative path past PATH_MAX from a deep working directory is ENAMETOOLONG (13), a short one is fine: %r" % out)
    shutil.rmtree(copy, ignore_errors=True)


@test
def spawn_threads(ctx):
    """7.5.4: the handler under concurrency. Threads trap throughout posix_spawns from another thread, so a vfork child's
    handler runs beside the parent's and every copy from program memory names the trap's own pid, never a process-wide one
    the child overwrote; and a forked child whose traps nest, a timer's handler trapping inside a trapped stat, while every
    chunk the pool had is held by threads blocked in the parent, so the child's pool grows under nesting, which a lock
    left held by the fork would have hung (revision 16)."""
    d = os.path.join(ctx.work, "spawnhost")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "spawn_threads"), [d, ctx.vbin("true")], timeout=120)
    expect(rc == 0 and "0 failures" in out and "hung" not in out, "spawn_threads: rc=%d %r %r" % (rc, out, err))
    return out.strip().splitlines()[-1]


@test
def adversarial(ctx):
    """17.4: what a hostile program or a fuzzer would try, each case answered in microseconds. Arguments with bits above
    the word where the kernel takes an int (the probe compares the answers; this checks the buffer past the count): a readlink size of zero or minus
    one as an int once had the handler write past the program's buffer; the opener's own variables set before an exec,
    dropped; a working directory deleted under the program, its . and .. kept; an exec with no descriptor to spare, which
    the handler borrows against a soft limit and which a hard limit refuses (13); mounts and roots from inside, refused by
    the filter (7.4.2); SIGSYS ignored, handled or on a signalfd; magic links under /proc/1; interpreter loops and chains;
    an empty executable and a loader that is a directory. A second batch: a descriptor with no path handed to exec (a
    pipe or a socket is EACCES, only a regular file is run), a hard link across the boundary (EXDEV), a symlink chain
    at the kernel's limit of forty and one past it, the read-only rule from other angles (mknod, ftruncate and a
    shared writable mapping of a read-only descriptor, a device node), odd process shapes (CLONE_FS, CLONE_FILES, not
    dumpable, PER_LINUX32, a vfork child, a handler on an alternate stack), the cache saturated and a huge environment,
    io_uring and clone3 refused by the filter, and an execute-only file the loader cannot read (EACCES, a limitation).
    The kernel under bwrap measured the answers, but for the variables, the mounts, the hard limit, the filter's
    refusals and the execute-only files, which are the opener's own (revision 16, extended)."""
    d = os.path.join(ctx.work, "advhost")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "adversarial"), [d], env=dict(ctx.env, SH=ctx.vbin("sh")))
    expect(rc == 0, "adversarial: rc=%d %r %r" % (rc, out, err))
    lines = set(out.splitlines())
    want = ["readlink size 1 with upper bits: 1 byte, buffer intact", "readlink size -1 as int: EINVAL, buffer intact", "readlink size 0 as int: EINVAL, buffer intact",
            "readlinkat AT_FDCWD with upper bits: ok", "openat dfd with upper bits: ok", "utimensat host, flags upper bits only: ok", "utimensat can, flags upper bits only: EROFS",
            "faccessat2 can, flags upper bits only: ok", "newfstatat can, flags upper bits only: ok", "getcwd size all ones: ok", "getcwd size 4 with upper bits: ok",
            "renameat2 flags upper bits only: ok", "unlinkat flags upper bits only: ok", "bind can path, addrlen upper bits: EROFS", "connect can socket, addrlen upper bits: ECONNREFUSED",
            "openat2 size with upper bits: errno=7",
            "exec of a host ELF with CAN_* set: ran, exit 0", "child sees CAN_EXEC=unset CAN_EXECFN=unset CAN_COMM=unset",
            "wrapper with CAN_* set: comm=sh CAN_EXEC=unset CAN_EXECFN=unset CAN_COMM=unset",
            "deleted cwd: getcwd: ENOENT", "deleted cwd: stat .: ok", "deleted cwd: open .: ok", "deleted cwd: stat ../f: ok", "deleted cwd: mkdir x: ENOENT", "deleted cwd: open x O_CREAT: ENOENT",
            "no fd left: exec can true: ran", "no fd left: exec host ELF: ran", "no fd left: exec host script: ran", "no fd left, hard limit too: exec can true: EMFILE",
            "unshare user+mount: ok", "mount tmpfs inside: EPERM", "chroot inside: EPERM", "open_tree: ENOSYS", "mount_setattr: ENOSYS",
            "stat with SIGSYS ignored: ok", "stat with a SIGSYS handler installed: ok", "program's SIGSYS handler ran: no", "stat with SIGSYS blocked and on a signalfd: ok", "signalfd delivered a SIGSYS: no",
            "stat /proc/1/root/etc: EACCES", "stat /proc/1/root: EACCES", "lstat /proc/1/root: ok", "open /proc/1/cwd: EACCES", "readlink /proc/1/exe: EACCES",
            "exec of a script that is its own interpreter: ELOOP", "exec of a chain of 3 scripts: ran, exit 0", "exec of a chain of 4 scripts: ran, exit 0", "exec of a chain of 5 scripts: ran, exit 0", "exec of a chain of 6 scripts: ELOOP",
            "exec of a script with an empty #! line: ENOEXEC", "exec of an empty executable: ENOEXEC", "exec of an ELF whose loader is a directory: EACCES",
            # the second batch: descriptors with no path given to exec, the read-only rule from other angles, odd process shapes, saturation
            "exec with 0, 1 and 2 closed: ran, exit 0", "traps with 0, 1 and 2 closed: stat ok, open ok, readlink ok",
            "fexecve of a pipe: EACCES", "fexecve of a socket: EACCES", "fexecve of /dev/null: EACCES",   # only a regular file is exec'd (do_open_execat)
            "linkat a can file by /proc/self/fd to a host name: errno=18", "linkat a can file by empty path to a host name: errno=18",   # a link across the boundary is EXDEV
            "a chain of 40 symlinks: ok", "a chain of 41 symlinks: ELOOP", "readlink /proc/self/task/tid/exe: the program",
            "stat /proc/self/root/usr/share/cont-test-marker: ok", "a path of 4000 slashes then a can file: ok",
            "mknod a char device in the can: EROFS", "ftruncate a read-only can descriptor: EINVAL",
            "mmap PROT_WRITE MAP_SHARED of a read-only can descriptor: EACCES", "utimensat can descriptor NULL path, NOW and OMIT: EROFS",
            "open a can file O_PATH with O_WRONLY: ok", "truncate /dev/null: EINVAL",
            "unshare CLONE_FS then chdir into the can: ok, ok, getcwd /usr/share", "unshare CLONE_FILES then trap: ok, stat ok, open ok",
            "not dumpable: stat ok, readlink exe ok", "PER_LINUX32 then exec of a wrapper: ran, exit 0",
            "a vfork child that traps and exits: child ok, parent after ok", "a trap from a handler on a 16 KB alternate stack: ok",
            "io_uring_setup: ENOSYS", "clone3: ENOSYS",           # the filter refuses them (7.4.2); the kernel would answer EINVAL
            "openat on a descriptor of a directory renamed meanwhile: ok",
            "20000 absent can paths then a present and an absent one: 0 wrong, present ok, absent ENOENT",
            "exec of a wrapper with 50000 environment entries: ran, exit 0", "exec with a bad pointer among argv: EFAULT",
            "readlink whose write crosses into an unmapped page: EFAULT",
            "exec of an ELF with mode 0111: EACCES", "exec of a script with mode 0111: EACCES",   # the loader reads what it runs; execute-only is a limitation (13)
            "exec of a script whose interpreter is relative: ran, exit 0",
            "exec of a script whose #! has two options: one argument, the shell rejected it",   # the #! remainder is one argument, not two
            "exec of a wrapper with an empty environment: ran, exit 0"]
    if os.getuid() == 0:
        want = [w for w in want if "/proc/1" not in w and "mode 0111" not in w]   # root follows init's links and reads an execute-only file
    lacks = {"faccessat2 can, flags upper bits only: ok": "faccessat2 can, flags upper bits only: ENOSYS",   # 5.8 and later
             "unshare user+mount: ok": None}                    # a kernel or host without user namespaces: any refusal is its own
    bad = []
    for w in want:
        if w in lines:
            continue
        if w in lacks and (lacks[w] in lines if lacks[w] else any(l.startswith(w.split(": ")[0] + ": ") for l in lines)):
            continue
        bad.append(w)
    expect(not bad, "missing or different: " + "; ".join(bad) + "\n     got: " + out.strip().replace("\n", "\n          "))
    # the descriptor room the opener borrows at startup (7.4.5) is the program's again by the time it runs, through the
    # positional entry's re-exec and its exec of a wrapper alike
    import resource
    hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    rc, out, err = run([ctx.opener, ctx.vbin("sh"), "-c", "ulimit -n"], cwd=ctx.work, env=ctx.env, preexec=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (8, hard)))
    expect(out.strip() == "8", "a wrapper run through the entry under a soft limit of 8 sees %r (rc=%d %r): the borrowed room was not given back" % (out.strip(), rc, err))


@test
def fexec(ctx):
    """13 item 25, 7.4.5: exec of a descriptor that has no path. A memfd holding an ELF and an unlinked file run on the
    loader path through the child opener, which names the program by its descriptor and answers the link's text for
    /proc/self/exe as the kernel does; a script in a memfd or an unlinked file reaches its interpreter as /dev/fd/N,
    and a close-on-exec script is ENOENT, as natively. The kernel under bwrap measured these answers."""
    d = os.path.join(ctx.work, "fexechost")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "fexec"), [d])
    expect(rc == 0, "fexec: %r %r" % (out, err))
    got = dict(line.split(": ", 1) for line in out.splitlines() if ": " in line)
    want = {"memfd elf": "ret=0 errno=0 status=7 out=child ran, exe memfd:prog (deleted), argv0 fexec",
            "memfd elf cloexec": "ret=0 errno=0 status=7 out=child ran, exe memfd:prog (deleted), argv0 memfd-program",
            "unlinked elf": "ret=0 errno=0 status=7 out=child ran, exe unlinked-prog (deleted), argv0 fexec",
            "memfd script": "ret=0 errno=0 status=0 out=script ran, argv0 /dev/fd/3",
            "memfd script cloexec": "ret=-1 errno=2",
            "unlinked script": "ret=0 errno=0 status=0 out=script ran, argv0 /dev/fd/3",
            "fd with a path (control)": "ret=0 errno=0 status=7 out=child ran, exe linked-prog, argv0 fexec"}
    bad = ["%s: got %s, the kernel says %s" % (k, got.get(k), v) for k, v in want.items() if got.get(k) != v]
    expect(not bad, "; ".join(bad))


@test
def unix_socket(ctx):
    """7.4.3, 13 item 31: a sockaddr_un's path is a path. bind and connect at a path of every class answer what the
    kernel answers on a read-only bind mount (the namespace oracle measured these): a can-owned bind is EADDRINUSE
    for an existing name and EROFS otherwise, from a working directory inside the tree too; a can-owned connect is
    ENOENT, ENOTDIR or ECONNREFUSED; host paths and abstract names work; the structure's own limits are EINVAL. A
    datagram destination in sendto stays as written (13), so only its host case is asserted."""
    d = os.path.join(ctx.work, "sockhost")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "unix_socket"), [d, "/usr/share", ctx.vbin("true"), "/usr/share/cont-test.sock"])
    expect(rc == 0, "unix_socket: %r %r" % (out, err))
    got = dict(line.split(": ", 1) for line in out.splitlines() if ": " in line)
    want = {"bind host dir": "ret=0 errno=0", "bind /tmp": "ret=0 errno=0", "bind can dir": "ret=-1 errno=30",
            "bind existing can file": "ret=-1 errno=98", "bind existing can socket": "ret=-1 errno=98", "bind missing can parent": "ret=-1 errno=2",
            "bind under a can file": "ret=-1 errno=20", "bind can dir itself": "ret=-1 errno=98", "bind can dir trailing slash name": "ret=-1 errno=2",
            "bind abstract": "ret=0 errno=0", "bind relative in host cwd": "ret=0 errno=0", "bind relative in can cwd": "ret=-1 errno=30",
            "connect host listener": "ret=0 errno=0", "connect host socket no listener": "ret=-1 errno=111", "connect can file": "ret=-1 errno=111",
            "connect can socket": "ret=-1 errno=111", "connect missing can path": "ret=-1 errno=2", "connect can dir": "ret=-1 errno=111",
            "connect under a can file": "ret=-1 errno=20", "connect missing host path": "ret=-1 errno=2", "sendto host dgram": "ret=1 errno=0",
            "bind addrlen too long": "ret=-1 errno=22", "bind addrlen too short": "ret=-1 errno=22", "bind wrong family": "ret=-1 errno=22",
            "bind can path of 107 bytes": "ret=-1 errno=30", "connect can path of 107 bytes": "ret=-1 errno=2"}
    bad = ["%s: got %s, the kernel says %s" % (k, got.get(k), v) for k, v in want.items() if got.get(k) != v]
    expect(not bad, "; ".join(bad))
    expect(not os.path.exists(os.path.join(ctx.root, "usr", "share", "sock-rel")), "a relative bind from a working directory inside the tree wrote into the tree")


@test
def go_paths(ctx):
    """17.4: a Go program doing path syscalls from goroutines. Go issues syscalls raw, makes threads with clone,
    installs its own handler for every signal, SIGSYS included (7.5.2), and runs on small stacks; built static by
    go with cgo off and run inside as a host program, twice: as go links it for the machine, and from 0x10000 as its
    aarch64 linker does, an image past where the syscall page lay until revision 16 (13 item 24). Built here by the
    host's go, or taken from build/go/<machine>, where the matrix puts the ones it built for a VM without go; skips
    with the reason when there is neither."""
    go, prebuilt = tree.go_toolchain(), os.path.join(REPO, "build", "go", platform.machine())
    if go:
        try:
            exes = tree.go_build(go, ctx.progs, platform.machine(), ctx.work)
        except RuntimeError as e:
            expect(False, str(e))
    elif all(os.path.exists(os.path.join(prebuilt, n)) for n, f in tree.GO_BUILDS):   # copied under the work directory, which the
        exes = [(n, shutil.copy2(os.path.join(prebuilt, n), os.path.join(ctx.progs, n))) for n, f in tree.GO_BUILDS]   # can lets through
    else:
        return "no go toolchain (golang-go) and nothing in build/go/" + platform.machine()
    for name, exe in exes:
        if name == "go_paths_low":
            lo, hi = tree.load_span(exe)
            expect(lo < 0x3f0000 and hi > 0x3f1000, "%s spans %#x-%#x, not across 0x3f0000" % (name, lo, hi))
        rc, out, err = inside(ctx, exe)
        expect(rc == 0 and "FAIL" not in out, "%s: %s%s" % (name, out, err))


@test
def low_image(ctx):
    """13 item 24: a program whose image starts at 0x10000 and reaches past 0x3f0000, as Go's aarch64 linker lays one
    out, runs in a can; the syscall page lay at 0x3f0000 until revision 16 and such a program died unmapped. Built
    here by the can's compiler -no-pie from that address, so every can kind and both architectures run it."""
    exe = os.path.join(ctx.work, "low_image")
    rc, out, err = run([wrapper(ctx, GCC), "-O1", "-no-pie", "-Wl,-Ttext-segment=0x10000", "-o", exe, os.path.join(ctx.work, "src", "low_image.c")], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "compile from 0x10000: " + err)
    rc, out, err = inside(ctx, exe)
    expect(rc == 0 and out.startswith("text 0x") and out.rstrip().endswith("marker 0"), "a program from 0x10000 past 0x3f0000: rc=%d %r %r" % (rc, out, err))


@test
def gdb_hooks(ctx):
    """7.6, 13.1: gdb needs no manual command. The opener carries a script gdb auto-loads; a breakpoint in a
    library hits with the can's own symbols, the program's source line is known, a wrapped program's libc
    frames resolve, and the positional entry's re-exec does not confuse gdb."""
    gdb = shutil.which("gdb")
    if not gdb:
        return "no gdb"
    rc, out, err = run([gdb, "-batch", "-nx", "-ex", "python print(gdb.VERSION)"])
    if rc or not out.strip():
        return "gdb without Python"
    src = hello_source(ctx)
    exe = os.path.join(ctx.work, "hello-g")
    rc, out, err = run([wrapper(ctx, GCC), "-g", "-O0", "-o", exe, src], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "compile -g: " + err)
    base = [gdb, "-batch", "-nx", "-iex", "set auto-load safe-path /", "-iex", "set debuginfod enabled off", "-ex", "set breakpoint pending on"]
    if ctx.musl:
        return "gdb's breakpoints in a musl libc do not hit, the program's own do (13 item 1)"
    wr = "write"
    rc, out, err = run(base + ["-ex", "break main", "-ex", "break " + wr, "-ex", "run", "-ex", "bt", "-ex", "continue", "-ex", "bt", "-ex", "info auto-load python-scripts", "--args", ctx.opener, exe], cwd=ctx.work, env=ctx.env, timeout=300)
    expect(re.search(r"^Breakpoint 1, main \(.*\) at \S*hello\.c:\d+", out, re.M), "the program's own breakpoint hits with its source line: %r %r" % (out[-800:], err[-400:]))
    expect("Breakpoint 2, " in out and wr in out.split("Breakpoint 2, ", 1)[1].split("\n")[0], "a breakpoint in the can's libc hits with its name: %r %r" % (out[-800:], err[-400:]))
    expect("__libc_start" in out.split("Breakpoint 2, ", 1)[1], "the libc frames below the program resolve: %r" % out[-800:])
    expect("cont-opener.py" in out and "Python Exception" not in out and "Cannot insert" not in out, "the script loaded once and quietly: %r %r" % (out[-600:], err[-400:]))
    rc, out, err = run(base + ["-ex", "break " + wr, "-ex", "run", "-ex", "bt", "--args", wrapper(ctx, "echo"), "hi"], cwd=ctx.work, env=ctx.env, timeout=300)
    expect("Breakpoint 1, " in out and "__libc_start" in out, "a wrapped program's libc frames resolve: %r %r" % (out[-800:], err[-400:]))
    expect("Python Exception" not in out and "Cannot insert" not in out, "quiet for a wrapper: %r" % out[-600:])
    spaced = os.path.join(ctx.work, "space dir", "can")           # review O5-6: a can under a path with a space
    copy_can(ctx.can, spaced)
    rc, out, err = run(base + ["-ex", "break main", "-ex", "run", "-ex", "bt", "--args", os.path.join(spaced, ".can", "opener"), exe], cwd=ctx.work, env=ctx.env, timeout=300)
    expect(re.search(r"^Breakpoint 1, main \(.*\) at \S*hello\.c:\d+", out, re.M) and "Python Exception" not in out, "a can under a path with a space: %r %r" % (out[-600:], err[-300:]))


@test
def stat_bench(ctx):
    src = os.path.join(ctx.work, "bench.c")
    with open(src, "w") as f:
        f.write('#include <sys/stat.h>\n#include <stdio.h>\n#include <time.h>\nint main(void){struct stat st;struct timespec a,b;'
                'clock_gettime(CLOCK_MONOTONIC,&a);for(int i=0;i<100000;i++)stat("/usr/share/cont-test-marker",&st);'
                'clock_gettime(CLOCK_MONOTONIC,&b);printf("%.0f\\n",((b.tv_sec-a.tv_sec)*1e9+(b.tv_nsec-a.tv_nsec))/100000);return 0;}\n')
    exe = os.path.join(ctx.work, "bench")
    rc, out, err = run([wrapper(ctx, GCC), "-O2", src, "-o", exe], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, err)
    rc, out, err = inside(ctx, exe)
    expect(rc == 0, err)
    return "stat of a can path: %d ns per call" % int(out.strip())


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tree", default=os.environ.get("CONT_TREE"))
    ap.add_argument("--can", help="use the unwrapped root of this can as the tree")
    ap.add_argument("--work", default=os.path.join(REPO, "build", "test-work"))
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("-k", default="")
    ap.add_argument("--order", default="given", choices=["given", "reverse", "random"], help="run order; reverse and random expose tests that depend on one another")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--budget", type=float, default=30, help="seconds a test may take before it fails; the slowest takes 2 natively")
    ap.add_argument("-v", action="store_true")
    a = ap.parse_args()
    if a.can:
        a.tree = os.path.join(a.can, "root")
    if not a.tree or not os.path.isdir(a.tree):
        sys.exit("need --tree DIR (or $CONT_TREE) or --can CAN: a gcc tree to can; see README.md")
    ctx = Ctx()
    ctx.from_can = bool(a.can)
    ctx.tree = os.path.abspath(a.tree)
    ctx.work = os.path.abspath(a.work)
    # the pruned fixture (17): the source can pruned to what the suite touches, made by the first run on a can and
    # used by every later one until the can or the tests change
    fixture = None
    key = fixture_key(a.can) if a.can else None
    if key:
        fixture = os.path.join(REPO, "build", "fixtures", os.path.basename(os.path.abspath(a.can)).replace(".can", "") + "-" + key)
    logging = False
    if fixture and os.path.isdir(fixture):
        ctx.tree = os.path.join(fixture, "root")
        print("fixture: %s" % fixture)
    elif fixture:
        logging = True
        print("fixture: none yet for this can and these tests; this run makes it")
    ctx.opener_src = os.path.join(REPO, "build", "opener")
    if not os.path.exists(ctx.opener_src):
        sys.exit("build/opener missing: run make")
    if os.path.exists(ctx.work):
        shutil.rmtree(ctx.work)
    os.makedirs(ctx.work)
    ctx.env = {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/"), "LANG": "C"}
    t0 = time.time()
    make_can(ctx)
    if logging:
        ctx.env["CAN_LOG"] = os.path.join(ctx.work, "fixture.log")   # from here every in-can run of the suite's own is logged, the test programs' compile first
    compile_progs(ctx)
    ctx.shared = shared_state(ctx)
    print("can made and programs compiled in %.1fs" % (time.time() - t0))
    fails = 0
    exact = [t for t in TESTS if t.__name__ == a.k]                      # a test's own name runs it alone, spawn beside spawn_threads
    order = exact or [t for t in TESTS if not a.k or a.k in t.__name__]
    if a.order == "reverse":
        order.reverse()
    elif a.order == "random":
        import random
        seed = a.seed if a.seed is not None else int(time.time()) % 100000
        random.Random(seed).shuffle(order)
        print("random order, seed %d" % seed)
    for t in order:
        t0 = time.time()
        try:
            note = t(ctx)
            if time.time() - t0 > a.budget:                    # a test that hangs is caught by run()'s timeouts; one that crawls, here (17)
                raise AssertionError("took %.1f s, over the budget of %g s" % (time.time() - t0, a.budget))
            print("PASS %-26s %5.1fs %s" % (t.__name__, time.time() - t0, note or ""))
        except AssertionError as e:
            fails += 1
            print("FAIL %-26s %5.1fs %s" % (t.__name__, time.time() - t0, str(e).strip().replace("\n", "\n     ")))
        except Exception as e:  # noqa: BLE001
            fails += 1
            print("FAIL %-26s %5.1fs %s: %s" % (t.__name__, time.time() - t0, type(e).__name__, e))
        now = shared_state(ctx)                                # a test must leave the fixtures alone, whether it passed or not (17)
        changed = [n for n, a, b in zip(("manifest", "lock", "tree"), ctx.shared, now) if a != b]
        if "tree" in changed:
            d = sorted(set(now[2]) ^ set(ctx.shared[2]))
            changed[changed.index("tree")] = "tree: " + ", ".join(sorted(set(e[0] for e in d))[:6])
        if changed:
            print("FAIL %-26s %5.1fs the test changed the shared can: %s" % (t.__name__, time.time() - t0, ", ".join(changed)))
            fails += 1
            ctx.shared = now
    print("%d tests, %d failures" % (len(order), fails))
    if logging and not fails and not a.k:
        make_fixture(ctx, fixture)
    if not a.keep and not fails:
        shutil.rmtree(ctx.work, ignore_errors=True)
    return fails


if __name__ == "__main__":
    sys.exit(main())
