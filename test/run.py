#!/usr/bin/env python3
"""run.py — the regression suite for milestone 1a (PROPOSAL.md 17.4, the subset a single machine can run).

    test/run.py [--tree DIR | --can CAN] [--work DIR] [--keep] [-k SUBSTRING] [--order given|reverse|random]

Makes a can from TREE (default $CONT_TREE), or from the unwrapped root of an existing CAN, under WORK
(default build/test-work) with a few test files added to the tree, compiles test/progs/*.c with the can's
own gcc, and runs every named test. Needs python3 and a Debian/Ubuntu gcc tree (see README.md). Optional:
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
import signal
import stat
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "cannery"))
import build  # noqa: E402
import cannery  # noqa: E402

GCC = "x86_64-linux-gnu-gcc-13"      # Debian's name; make_can takes the tree's gcc when that one is absent (an Alpine can)
VOLATILE = ("/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run")
NR = {"open": 2, "stat": 4, "lstat": 6, "access": 21, "execve": 59, "readlink": 89, "openat": 257, "newfstatat": 262,
      "readlinkat": 267, "faccessat": 269, "faccessat2": 439, "statx": 332, "execveat": 322, "chdir": 80, "mkdir": 83,
      "mkdirat": 258, "unlink": 87, "unlinkat": 263, "rename": 82, "renameat": 264, "renameat2": 316, "link": 86,
      "linkat": 265, "symlink": 88, "symlinkat": 266}

TESTS = []


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


def copy_can(src, dst):
    """A copy of a can for a test to alter: the tree's files are hard-linked, the files under .can/ are copied,
    since a manifest or lock written through a hard link would change the shared can's (tests are independent)."""
    shutil.copytree(src, dst, symlinks=True, copy_function=cannery.link_or_copy)
    for name in os.listdir(os.path.join(dst, ".can")):
        p = os.path.join(dst, ".can", name)
        if os.path.isfile(p) and not os.path.islink(p):
            data = open(p, "rb").read()
            mode = os.stat(p).st_mode
            os.remove(p)
            with open(p, "wb") as f:
                f.write(data)
            os.chmod(p, mode)


def shared_state(ctx):
    """What every test shares and none may change: the can's manifest, its lock, its top level and the names in
    its /usr/bin, cheap enough to compare after every test."""
    can = ctx.can
    return (open(os.path.join(can, ".can", "manifest"), "rb").read(), open(os.path.join(can, ".can", "lock"), "rb").read() if os.path.exists(os.path.join(can, ".can", "lock")) else b"",
            tuple(sorted(os.listdir(ctx.root))), len(os.listdir(os.path.join(ctx.root, "usr", "bin"))))


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
    ctx.can, ctx.root, ctx.opener = can, root, os.path.join(can, ".can", "opener")
    if not os.path.exists(os.path.join(root, "usr", "bin", GCC)) and os.path.exists(os.path.join(root, "usr", "bin", "gcc")):
        GCC = "gcc"


def compile_progs(ctx):
    """The sources are copied into the work directory: with the work directory's top-level directory claimed
    for the can (8.1), only the working directory's subtree is the host's."""
    ctx.progs = os.path.join(ctx.work, "progs")
    src = os.path.join(ctx.work, "src")
    shutil.copytree(os.path.join(HERE, "progs"), src)
    os.makedirs(ctx.progs, exist_ok=True)
    gcc = wrapper(ctx, GCC)
    for name in ("ro_matrix", "signals", "threads", "spawn", "exec", "fifo", "execstack", "ljmp", "fdpress"):
        rc, out, err = run([gcc, "-O1", "-g", "-pthread", "-o", os.path.join(ctx.progs, name), os.path.join(src, name + ".c"), "-lm", "-ldl"], cwd=ctx.work, env=ctx.env)
        if rc:
            sys.exit("cannot compile %s with the can's gcc:\n%s" % (name, err))
    rc, out, err = run([gcc, "-shared", "-fPIC", "-o", os.path.join(ctx.progs, "liborigin.so"), os.path.join(src, "origin_lib.c")], cwd=ctx.work, env=ctx.env)
    rc2, out, err2 = run([gcc, "-o", os.path.join(ctx.progs, "origin_main"), os.path.join(src, "origin_main.c"), "-L" + ctx.progs, "-lorigin", "-Wl,-rpath,$ORIGIN"], cwd=ctx.work, env=ctx.env)
    if rc or rc2:
        sys.exit("cannot build the origin test:\n%s%s" % (err, err2))


# ------------------------------------------------------------------ tests
@test
def version(ctx):
    rc, out, err = run([wrapper(ctx, "gcc-13"), "--version"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and "13." in out, "gcc --version: rc=%d out=%r err=%r" % (rc, out, err))


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
    if not os.path.exists(host):
        return "no host gcc-13"
    src = hello_source(ctx)
    a, b = os.path.join(ctx.work, "h_host.o"), os.path.join(ctx.work, "h_can.o")
    run([host, "-O2", "-c", src, "-o", a], cwd=ctx.work)
    rc, out, err = run([wrapper(ctx, "gcc-13"), "-O2", "-c", src, "-o", b], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, err)
    expect(open(a, "rb").read() == open(b, "rb").read(), "objects differ")


@test
def isolation(ctx):
    if not shutil.which("strace"):
        return "no strace"
    tr = os.path.join(ctx.work, "trace")
    src = hello_source(ctx)
    names = list(NR)
    while True:                                               # an older strace may not know the newest names
        rc, out, err = run(["strace", "-f", "-s", "4096", "-o", tr, "-e", "trace=" + ",".join(names), wrapper(ctx, GCC), "-O1", src, "-o", os.path.join(ctx.work, "hello2")], cwd=ctx.work, env=ctx.env)
        m = re.search(r"invalid system call '(\w+)'", err)
        if m and m.group(1) in names:
            names.remove(m.group(1))
            continue
        break
    expect(rc == 0, "compile under strace failed: " + err)
    bad, seen = [], 0
    allowed_files = set(build.IDENTITY_FILES)
    for f in build.IDENTITY_FILES:          # the opener resolves each identity file's host symlink chain at startup
        p = f
        for _ in range(40):
            if not os.path.islink(p):
                break
            t = os.readlink(p)
            p = os.path.normpath(t if t.startswith("/") else os.path.join(os.path.dirname(p), t))
            allowed_files.add(p)
    for line in open(tr):
        m = re.match(r"^\d+\s+(\w+)\((.*)\)\s+=\s+(-?\d+)", line)
        if not m:
            continue
        name, args, res = m.group(1), m.group(2), int(m.group(3))
        if res == NR.get(name):
            continue                      # the trapped syscall the kernel skipped; the handler re-issues it
        if res < 0:
            continue
        paths = re.findall(r'"((?:[^"\\]|\\.)*)"', args)
        if name in ("execve", "execveat") and paths:
            paths = paths[:1]
        for p in paths:
            seen += 1
            p = os.path.normpath(p) if p.startswith("/") else p
            ok = (not p.startswith("/") or p.startswith(ctx.root) or p.startswith(VOLATILE) or p.startswith(ctx.work)
                  or p in allowed_files
                  or ctx.work.startswith(p + "/"))     # a directory on the way to the working directory (8.1.4)
            if not ok:
                bad.append("%s %s" % (name, p))
    expect(seen > 50, "trace looks empty (%d paths)" % seen)
    expect(not bad, "host paths touched: " + ", ".join(sorted(set(bad))[:10]))


@test
def ro_matrix(ctx):
    d = os.path.join(ctx.work, "hostdir")
    os.makedirs(d, exist_ok=True)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "ro_matrix"), [d, "/usr/bin/" + GCC])
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def coreutils_ro(ctx):
    def w(name, *args):
        return run([wrapper(ctx, name)] + list(args), cwd=ctx.work, env=ctx.env)
    rc, out, err = w("touch", "/usr/newfile"); expect(rc and "Read-only" in err, err)
    rc, out, err = w("mkdir", "-p", "/usr/lib"); expect(rc == 0, err)
    rc, out, err = w("install", "-d", "/usr/lib"); expect(rc == 0, err)
    rc, out, err = w("mkdir", "/usr/lib"); expect(rc and "exists" in err, err)
    rc, out, err = w("rm", "/usr/bin/gcc-13"); expect(rc and "Read-only" in err, err)
    rc, out, err = w("ln", "/usr/bin/" + GCC, os.path.join(ctx.work, "lnk-x")); expect(rc and "cross-device" in err, err)
    rc, out, err = w("cp", "/usr/bin/gcc-13", os.path.join(ctx.work, "gcc-copy")); expect(rc == 0, err)
    payload = os.path.join(ctx.root, "usr", "bin", ".real", GCC)
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
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "spawn"), timeout=600)
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
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "PATH=%s:/usr/bin exec %s execvp" % (ne, p)], cwd=ctx.work, env=ctx.env)
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
    expect(rc == 127 and "not an executable" in err, "noshebang direct: rc=%d %r" % (rc, err))
    rc, out, err = run([wrapper(ctx, "cont-test-exe")], cwd=ctx.work, env=ctx.env)
    expect(out == "/usr/bin/dash\n", "a wrapped script's /proc/self/exe is its interpreter (F3-22): %r %r" % (out, err))
    rc, out, err = run([wrapper(ctx, "bash"), "-c", "echo from bash"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "from bash\n", "bash starts (F3-23): rc=%d %r" % (rc, err))


@test
def identity(ctx):
    rc, out, err = run([wrapper(ctx, "cat"), "/etc/passwd"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == open("/etc/passwd").read(), "passwd differs from the host")
    rc, out, err = run([wrapper(ctx, "cat"), "/etc/hostname"], cwd=ctx.work, env=ctx.env)
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
    rc, out, err = inside(ctx, "/usr/bin/env")
    expect(rc == 0 and "CAN_EXEC" not in out, "CAN_EXEC leaked: " + out)


@test
def positional_entry(ctx):
    """7.2: `.can/opener PROGRAM ARGS...` runs PROGRAM inside the can with its own argv, cmdline and comm, by an
    absolute or a relative path; CAN_EXEC is the opener's own protocol and is never an interface."""
    rc, out, err = run([ctx.opener, "./progs/exec", "self"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "child ok argv0=./progs/exec\n", "relative program path: %r %r" % (out, err))
    rc, out, err = run([ctx.opener, "/bin/sh", "-c", "cat /proc/$$/comm; tr '\\0' '\\n' < /proc/$$/cmdline | head -1"], cwd=ctx.work, env=ctx.env)
    expect(out == "sh\n/bin/sh\n", "cmdline and comm are the program's: %r %r" % (out, err))
    rc, out, err = run([ctx.opener, "/usr/bin/env"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and "CAN_EXEC" not in out and "PATH=/usr/local/bin:/usr/bin:/bin" in out, "the boundary policy applies after the re-exec and CAN_EXEC never reaches the program: %r" % out)
    rc, out, err = run([ctx.opener], cwd=ctx.work, env=ctx.env)
    expect(rc == 127 and "PROGRAM" in err, "no program named: rc=%d %r" % (rc, err))
    rc, out, err = run([ctx.opener, "/nonexistent/prog"], cwd=ctx.work, env=ctx.env)
    expect(rc == 127 and "/nonexistent/prog" in err, "a missing program is named: %r" % err)
    rc, out, err = run([ctx.opener, "progs/../progs/exec", "self"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "child ok argv0=progs/../progs/exec\n", "argv[0] is the path as given: %r %r" % (out, err))


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
    real = os.path.join(ctx.root, "usr", "bin", "true")
    rc, out, err = run([wrapper(ctx, "ls"), real], cwd="/", env=ctx.env)
    expect(rc == 0 and out.strip() == real, "real can path from cwd /: rc=%d %r %r" % (rc, out, err))
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "cd %s && pwd && ls root/usr/bin/true" % ctx.can], cwd="/", env=ctx.env)
    expect(rc == 0 and out == "%s\nroot/usr/bin/true\n" % ctx.can, "cd into the can dir: rc=%d %r %r" % (rc, out, err))
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
    true2 = os.path.join(can2, "root", "usr", "bin", "true")
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "%s && %s/root/usr/bin/sh -c 'echo cross $0 && readlink /proc/self/exe'" % (true2, can2)], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "cross %s/root/usr/bin/sh\n/usr/bin/readlink\n" % can2, "cross-can exec: rc=%d %r %r" % (rc, out, err))
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "cd %s && root/usr/bin/x86_64-linux-gnu-gcc-13 --version | head -1" % can2], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and "13." in out, "gcc of the other can: rc=%d %r %r" % (rc, out, err))


@test
def nested_older_opener(ctx):
    """7.4.2: an older opener nested inside a newer one reuses the newer filter and answers ENOSYS for a trap
    it does not know, never re-issuing it to the host. build/opener-old is the current opener built with the
    previous filter version and without file_getattr in its handler (make builds it beside build/opener)."""
    old = os.path.join(os.path.dirname(ctx.opener_src), "opener-old")
    if not os.path.exists(old):
        return "no build/opener-old"
    src = os.path.join(ctx.work, "getattr.c")
    with open(src, "w") as f:
        f.write('#include <stdio.h>\n#include <errno.h>\n#include <string.h>\n#include <unistd.h>\n#include <fcntl.h>\n#include <sys/syscall.h>\n'
                'int main(void) { char a[24]; long r = syscall(468, AT_FDCWD, "/etc/passwd", a, sizeof a, 0);\n'
                ' printf("%ld %d\\n", r, r < 0 ? errno : 0); return 0; }\n')
    prog = os.path.join(ctx.work, "getattr")
    rc, out, err = run([wrapper(ctx, GCC), "-static", "-O0", "-o", prog, src], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "compile: " + err)
    rc, kernel, err = run([prog], cwd=ctx.work, env=ctx.env)              # the kernel's own answer, static so any host runs it
    rc, outer, err = run([wrapper(ctx, "sh"), "-c", prog], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and outer == kernel, "inside the current opener the kernel's answer comes back: kernel %r can %r %r" % (kernel, outer, err))
    can2 = os.path.join(ctx.work, "old-can")
    copy_can(ctx.can, can2)
    cannery.cmd_reopen(can2, old)
    log = os.path.join(ctx.work, "nested-old.log")
    rc, inner, err = run([wrapper(ctx, "sh"), "-c", "%s/root/usr/bin/sh -c %s" % (can2, prog)], cwd=ctx.work, env=dict(ctx.env, CAN_LOG=log))
    expect(rc == 0 and inner == "-1 38\n", "the older opener nested in the newer one answers ENOSYS (38) for the trap it does not know: %r %r" % (inner, err))
    text = open(log).read()
    expect("opener 0 inside %s" % prog in text and "trap -38 -" in text and "boundary" not in text.split("opener 0 inside", 1)[1],
           "the inner opener reused the newer filter and answered the trap itself: %r" % text[-400:])


@test
def real_root_is_the_tree(ctx):
    """The tree's real root is an alias of /: a path spelt through <can>/root/ obeys the same rules (F3-1)."""
    root = ctx.root
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "touch %s/usr/zz; echo rc=$?; rm %s/usr/bin/true; echo rc=$?; cat %s/usr/share/cont-test-marker; ls -l %s/usr/bin/sh | cut -c1 " % (root, root, root, root)], cwd="/", env=ctx.env)
    expect(out == "rc=1\nrc=1\nmarker\nl\n" and "Read-only" in err, "real-root spelling: %r %r" % (out, err))
    expect(not os.path.exists(os.path.join(root, "usr", "zz")) and os.path.exists(os.path.join(root, "usr", "bin", "true")), "the tree was written through its real path")


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
    rc, out, err = inside(ctx, p, ["vectors", "/usr/bin/true", p, hs], timeout=60)
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def proc_magic_links(ctx):
    """/dev/stdin on a pipe, process substitution and /proc/self/fd of a pipe are reachable (F3-11)."""
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
    ok = len(lines) == 2 and lines[0] == "-1 2" and lines[1].endswith(" 0") and int(lines[1].split()[0]) >= 0   # SELinux hosts label every file
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
    control = ("Package: %s\nVersion: 1\nArchitecture: amd64\nMaintainer: t\nDescription: t\n%s" % (name, control_extra)).encode()
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
    info = ("pkgname = %s\npkgver = 1.0-r0\narch = x86_64\nsize = 1\n%s" % (name, pkginfo_extra)).encode()
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
    entries = [(1000, 6, [name]), (1001, 6, ["1.0"]), (1002, 6, ["1"]), (1022, 6, ["x86_64"]), (1125, 6, ["gzip"]), (1124, 6, ["cpio"])]
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
    flags, so-called provides and file dependencies, rpmlib features and rich dependencies skipped; hard links;
    the merged-usr links; alternatives --install lines in %post synthesised; one format per can."""
    d = os.path.join(ctx.work, "rpms")
    os.makedirs(d, exist_ok=True)
    EQ, GE = 8, 12
    make_rpm(os.path.join(d, "tool-1.0-1.x86_64.rpm"), "tool",
             [("usr", "dir", None, 0o755), ("usr/bin", "dir", None, 0o755), ("usr/bin/tool-2", "file", b"#!/bin/sh\necho tool ok\n", 0o755)],
             requires=[("libfoo.so.1()(64bit)", 0, ""), ("absent-pkg", GE, "2"), ("/bin/sh", 0, ""), ("rpmlib(CompressedFileNames)", (1 << 24) | 10, "3.0.4-1"), ("(a or b)", 0, "")],
             postin="/usr/sbin/alternatives --install /usr/bin/tool tool /usr/bin/tool-2 20\n")
    make_rpm(os.path.join(d, "libfoo-1.0-1.x86_64.rpm"), "libfoo",
             [("usr", "dir", None, 0o755), ("usr/lib64", "dir", None, 0o755), ("usr/lib64/libfoo.so.1", "file", b"data\n", 0o644),
              ("usr/share", "dir", None, 0o755), ("usr/share/doc", "file", b"doc\n", 0o644)],
             provides=[("libfoo.so.1()(64bit)", 0, ""), ("libfoo", EQ, "1.0-1")])
    out = os.path.join(ctx.work, "rpm.can")
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "unpack", out, os.path.join(d, "tool-1.0-1.x86_64.rpm"), os.path.join(d, "libfoo-1.0-1.x86_64.rpm")])
    expect(rc == 0, "unpack: " + o + e)
    expect("depends: tool needs absent-pkg (>= 2), not in the set" in o, "the versioned dependency was not reported: " + o)
    expect("libfoo" not in o.replace("libfoo-1.0", "") and "/bin/sh" not in o and "rpmlib" not in o and "(a or b)" not in o, "a provide in the set, a file dependency, an rpmlib feature or a rich dependency was reported: " + o)
    root = os.path.join(out, "root")
    expect(os.readlink(os.path.join(root, "bin")) == "usr/bin" and os.readlink(os.path.join(root, "lib64")) == "usr/lib64", "the merged-usr links")
    expect(os.path.exists(os.path.join(root, "usr", "lib64", "libfoo.so.1")) and os.path.exists(os.path.join(root, "usr", "bin", "tool-2")), "payload extracted")
    expect(os.readlink(os.path.join(root, "usr", "bin", "tool")) == "/etc/alternatives/tool" and os.readlink(os.path.join(root, "etc", "alternatives", "tool")) == "/usr/bin/tool-2",
           "alternatives from %%post: %r" % os.listdir(os.path.join(root, "usr", "bin")))
    lock = cannery.load(os.path.join(out, ".can", "lock"), "lock")
    pkgs = cannery.values(lock, "pkg")
    expect([tuple(p[:3]) for p in pkgs] == [(b"libfoo", b"1.0-1", b"x86_64"), (b"tool", b"1.0-1", b"x86_64")], "pkg records: %r" % pkgs)
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "wrap", out])
    expect(rc == 0 and cannery.values(cannery.load(os.path.join(out, ".can", "lock"), "lock"), "tree"), "wrap: " + o + e)
    make_apk(os.path.join(d, "x-1.0-r0.apk"), "x", [("usr", "dir", None, 0o755)])
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "unpack", out + "2", os.path.join(d, "x-1.0-r0.apk"), os.path.join(d, "tool-1.0-1.x86_64.rpm")])
    expect(rc != 0 and "one format per can" in o + e, "a mixed set must be refused: " + o + e)


@test
def apk_unpack(ctx):
    """10.1: unpack reads .apk files by the file, with .PKGINFO's depend and provides, so: names and file
    dependencies; Alpine's directories are its own, not merged /usr; busybox's applet links are synthesised
    from /etc/busybox-paths.d as relative links; one format per can."""
    d = os.path.join(ctx.work, "apks")
    os.makedirs(d, exist_ok=True)
    make_apk(os.path.join(d, "tool-1.0-r0.apk"), "tool", [("usr", "dir", None, 0o755), ("usr/bin", "dir", None, 0o755),
                                                          ("usr/bin/tool", "file", b"#!/bin/sh\necho tool ok\n", 0o755)],
             "depend = so:libfoo.so.1\ndepend = absent-pkg>=2\ndepend = /bin/sh\n")
    make_apk(os.path.join(d, "libfoo-1.0-r0.apk"), "libfoo", [("bin", "dir", None, 0o755), ("bin/busybox", "file", b"#!/bin/true\n", 0o755),
                                                            ("etc", "dir", None, 0o755), ("etc/busybox-paths.d", "dir", None, 0o755),
                                                            ("etc/busybox-paths.d/busybox", "file", b"bin/sh\nusr/bin/tool2\n", 0o644),
                                                            ("usr", "dir", None, 0o755), ("usr/lib", "dir", None, 0o755), ("usr/lib/libfoo.so.1", "file", b"data\n", 0o644)],
             "provides = so:libfoo.so.1=1\nprovides = cmd:busybox=1.0-r0\n")
    out = os.path.join(ctx.work, "apk.can")
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "unpack", out, os.path.join(d, "tool-1.0-r0.apk"), os.path.join(d, "libfoo-1.0-r0.apk")])
    expect(rc == 0, "unpack: " + o + e)
    expect("depends: tool needs absent-pkg (>= 2), not in the set" in o, "the versioned dependency was not reported: " + o)
    expect("libfoo" not in o.replace("libfoo-1.0", "") and "/bin/sh" not in o, "a so: provides in the set or a file dependency was reported: " + o)
    root = os.path.join(out, "root")
    expect(os.path.isdir(os.path.join(root, "bin")) and not os.path.islink(os.path.join(root, "bin")), "Alpine's /bin is a directory of its own")
    expect(os.readlink(os.path.join(root, "bin", "sh")) == "busybox" and os.readlink(os.path.join(root, "usr", "bin", "tool2")) == "../../bin/busybox",
           "applet links relative to their target: %r" % os.listdir(os.path.join(root, "bin")))
    lock = cannery.load(os.path.join(out, ".can", "lock"), "lock")
    pkgs = cannery.values(lock, "pkg")
    expect([tuple(p[:3]) for p in pkgs] == [(b"libfoo", b"1.0-r0", b"x86_64"), (b"tool", b"1.0-r0", b"x86_64")], "pkg records: %r" % pkgs)
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "wrap", out])
    expect(rc == 0 and cannery.values(cannery.load(os.path.join(out, ".can", "lock"), "lock"), "tree"), "wrap: " + o + e)
    make_deb(os.path.join(d, "x.deb"), "x", [("./usr", "dir", None, 0o755)])
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "unpack", out + "2", os.path.join(d, "x.deb"), os.path.join(d, "tool-1.0-r0.apk")])
    expect(rc != 0 and "one format per can" in o + e, "a mixed set must be refused: " + o + e)


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
    the manifest and tree hashes; the closed can runs; a tree assembled by hand becomes a can by wrap alone."""
    import elfcheck
    d = os.path.join(ctx.work, "updebs")
    os.makedirs(d, exist_ok=True)
    true_bytes = open(os.path.join(ctx.root, "usr", "bin", ".real", "true"), "rb").read()
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
    expect([p[0] for p in pkgs] == [b"libfoo1", b"tool"] and pkgs[1][1] == b"1" and pkgs[1][2] == b"amd64", "pkg records: %r" % pkgs)
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
    O4-7), a manifest beyond the opener's tables (O4-9, O4-10); executables in a data prefix are left alone (O4-1)."""
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
    true_bytes = open(os.path.join(ctx.root, "usr", "bin", ".real", "true"), "rb").read()
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
    expect(rc != 0 and "300 own records" in o + e, "300 own records must be refused: " + (o + e)[-300:])
    g = hand("lim2.can", [("/usr/bin/hi", script, 0o755)], b"can 1\n\n" + b"".join(b'host "/hostpath%03d"\n' % i for i in range(40)))
    rc, o, e = run([sys.executable, cannery_py, "wrap", g])
    expect(rc != 0 and "40 host records" in o + e, "40 host records must be refused: " + (o + e)[-300:])
    can2 = os.path.join(ctx.work, "hosts30.can")
    copy_can(ctx.can, can2)
    with open(os.path.join(can2, ".can", "manifest"), "wb") as f:
        f.write(b"can 1\n\n" + b"".join(b'host "/hostpath%03d"\n' % i for i in range(30)))
    rc, out, err = run([os.path.join(can2, "root", "usr", "bin", "cat"), "/etc/hosts"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == open("/etc/hosts").read(), "30 host records leave the identity files the host's: %r %r" % (out[:80], err))
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
    rc, out, err = run([os.path.join(dp, "root", "usr", "bin", "sh"), "-c", "/opt/sysroot/bin/true; echo rc=$?"], cwd=ctx.work, env=ctx.env)
    expect("Permission denied" in out + err and "rc=126" in out, "a data prefix is never executed (O4-3): %r %r" % (out, err))


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
    cat = os.path.join(can2, "root", "usr", "bin", "cat")
    os.chmod(secret, 0)
    try:
        rc, out, err = run([cat, "/secret/file"], cwd=ctx.work, env=ctx.env)
        expect("Permission denied" in err and "No such file" not in err, "an unlistable directory must be the can's: %r" % err)
        expect("/secret" in cannery.owned(can2), "the cannery's ownership must agree")
    finally:
        os.chmod(secret, 0o755)
    press = os.path.join(ctx.progs, "fdpress")                 # built by the can's gcc: runs inside, like every built program
    rc, out, err = inside(ctx, press, ["1", cat, "/proc/self/maps"])
    expect(rc == 127 and "Too many open files" in err and ".real/libc.so.6" not in out, "with one spare descriptor the opener must fail loudly, never run the host's libc: rc=%d %r %r" % (rc, out[:200], err))
    rc, out, err = inside(ctx, press, ["4", cat, "/proc/self/maps"])
    expect(rc == 0 and ".real/libc.so.6" in out, "with four spare descriptors the can runs: rc=%d %r" % (rc, err))


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
    for name in ("with\nnewline", "back\\slash"):
        with open(os.path.join(odd, name), "w") as f:
            f.write(name)
    log2 = os.path.join(ctx.work, "odd.log")
    for name in ("with\nnewline", "back\\slash"):
        rc, out, err = run([os.path.join(can2, "root", "usr", "bin", "cat"), "/usr/share/odd/" + name], cwd=ctx.work, env=dict(ctx.env, CAN_LOG=log2))
        expect(out == name, "cat of the odd name: %r %r" % (out, err))
    lines = open(log2).read().split("\n")
    expect(any(l == "open 3 /usr/share/odd/with\\nnewline" for l in lines) and any(l == "open 3 /usr/share/odd/back\\\\slash" for l in lines), "escapes in the log: %r" % [l for l in lines if "odd" in l])
    src = hello_source(ctx)
    rc, out, err = run([os.path.join(can2, "root", "usr", "bin", GCC), "-O1", src, "-o", os.path.join(ctx.work, "hello-odd")], cwd=ctx.work, env=dict(ctx.env, CAN_LOG=log2))
    expect(rc == 0, err)
    rc, o, e = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "prune", can2, log2])
    expect(rc == 0, "prune: " + o + e)
    expect(sorted(os.listdir(odd)) == sorted(["with\nnewline", "back\\slash"]), "the odd names must survive pruning: %r" % os.listdir(odd))
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
    sh = os.path.join(can2, "root", "usr", "bin", "sh")
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
    src = open(os.path.join(ctx.root, "usr", "bin", ".real", "true"), "rb").read()
    interp = b"/lib64/ld-linux-x86-64.so.2\0"
    i = src.index(interp)
    other = b"/lib/ld-musl-x86_64.so.1\0".ljust(len(interp), b"\0")
    exe = os.path.join(ctx.work, "musl-true")
    with open(exe, "wb") as f:
        f.write(src[:i] + other + src[i + len(interp):])
    os.chmod(exe, 0o755)
    rc, out, err = inside(ctx, exe)
    expect(rc == 127 and "ld-musl" in err and "does not have" in err, "a loader the can lacks: rc=%d %r" % (rc, err))
    same = os.path.join(ctx.work, "glibc-true")
    shutil.copy2(os.path.join(ctx.root, "usr", "bin", ".real", "true"), same)
    rc, out, err = inside(ctx, same)
    expect(rc == 0, "a program naming the can's loader by its own header runs: rc=%d %r" % (rc, err))
    # one world (7.4.5): a loader on a host path, the shape of a Nix or --dynamic-linker binary, is refused (F4-1, O4-2)
    hostlib = os.path.join(ctx.work, "hostworld")
    os.makedirs(hostlib, exist_ok=True)
    for f in ("ld-linux-x86-64.so.2", "libc.so.6"):
        shutil.copy2(os.path.join(ctx.root, "usr", "lib", "x86_64-linux-gnu", ".real", f), os.path.join(hostlib, f))
    src = hello_source(ctx)
    world = os.path.join(ctx.work, "world")
    rc, out, err = run([wrapper(ctx, GCC), "-O1", src, "-o", world, "-Wl,--dynamic-linker=" + os.path.join(hostlib, "ld-linux-x86-64.so.2"), "-Wl,-rpath," + hostlib], cwd=ctx.work, env=ctx.env)
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
    gcc2 = os.path.join(can2, "root", "usr", "bin", GCC)
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
    directory the can does not own is refused, an opener in the cache is refused."""
    import elfcheck
    x = os.path.join(ctx.root, "usr", "local", "x")
    base = os.path.join(x, "lib")
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
        for f in ("libbar.so.1", "libfoo.so.1"):
            shutil.copy2(os.path.join(built, f), os.path.join(base, f))
        for f in ("prog", "hostprog"):
            shutil.copy2(os.path.join(built, f), os.path.join(x, f))
        rep = elfcheck.static_check(ctx.can, cannery.owned(ctx.can), cannery.data_prefixes(ctx.can))
        bad = [e for e in rep.errors if "/usr/local/x/prog" in e or ("libfoo" in e and "hostprog" not in e)]
        expect(not bad, "RPATH inheritance: " + "; ".join(bad))
        expect(any("hostprog" in e and "does not own" in e for e in rep.errors), "a host RPATH must be refused (F3-17): %r" % rep.errors[:3])
        cache = elfcheck.read_cache(elfcheck.Tree(ctx.root))
        expect(cache and "libc.so.6" in cache and cache["libc.so.6"][0].endswith("/libc.so.6"), "ld.so.cache parsed: %r" % (list(cache.items())[:2] if cache else cache))
    finally:
        shutil.rmtree(x, ignore_errors=True)
    # F4-13: a hand-made tree with the loader at /usr/lib64 and no ld.so.cache closes; the loader satisfies its own
    # soname and its default directories come from the loader itself. F4-9: without /lib the host's would be searched.
    lib = os.path.join(ctx.root, "usr", "lib", "x86_64-linux-gnu")
    hand2 = os.path.join(ctx.work, "hand2.can")
    shutil.rmtree(hand2, ignore_errors=True)
    for d in ("usr/lib64", "usr/lib/x86_64-linux-gnu", "usr/bin", "etc"):
        os.makedirs(os.path.join(hand2, "root", d))
    os.symlink("usr/lib64", os.path.join(hand2, "root", "lib64"))
    os.symlink("usr/lib", os.path.join(hand2, "root", "lib"))
    shutil.copy2(os.path.join(lib, ".real", "ld-linux-x86-64.so.2"), os.path.join(hand2, "root", "usr", "lib64", "ld-linux-x86-64.so.2"))
    shutil.copy2(os.path.join(lib, ".real", "libc.so.6"), os.path.join(hand2, "root", "usr", "lib", "x86_64-linux-gnu", "libc.so.6"))
    shutil.copy2(os.path.join(ctx.root, "usr", "bin", ".real", "true"), os.path.join(hand2, "root", "usr", "bin", "true"))
    rc, out, err = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "wrap", hand2])
    expect(rc == 0, "a tree with the loader in /usr/lib64 and no cache must close (F4-13): " + out[-500:])
    rc, out, err = run([os.path.join(hand2, "root", "usr", "bin", "true")], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "and run: %r" % err)
    os.remove(os.path.join(hand2, "root", "lib"))
    rep = elfcheck.static_check(hand2, cannery.owned(hand2), [])
    expect(any("/lib/x86_64-linux-gnu" in e_ and "does not own" in e_ for e_ in rep.errors), "a tree without /lib searches the host's /lib (F4-9): %r" % rep.errors[:3])
    os.symlink("usr/lib", os.path.join(hand2, "root", "lib"))
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


@test
def readlink_bad_buffer(ctx):
    """7.5.6: an unwritable readlink buffer answers EFAULT, not SIGSEGV (review O3-1)."""
    src = os.path.join(ctx.work, "rl.c")
    with open(src, "w") as f:
        f.write('#include <unistd.h>\n#include <errno.h>\n#include <stdio.h>\nint main(int c, char **v) { for (int i = 1; i < c; i++) { errno = 0; long r = readlink(v[i], (char *)8, 64); printf("%ld %d\\n", r, errno); } return 0; }\n')
    exe = os.path.join(ctx.work, "rl")
    rc, out, err = run([wrapper(ctx, GCC), "-O1", src, "-o", exe], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, err)
    rc, out, err = inside(ctx, exe, ["/lib", "/proc/self/exe", "/usr/bin/sh", "/nonexistent"])
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
    ld = "/lib64/ld-linux-x86-64.so.2"
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "%s --list /usr/bin/%s" % (ld, GCC)], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6" in out and ctx.root not in out, "ld.so --list: %r %r" % (out, err))
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "%s --verify /usr/bin/%s" % (ld, GCC)], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "ld.so --verify rc=%d" % rc)
    rc, out, err = run([os.path.join(ctx.root, "lib64", "ld-linux-x86-64.so.2"), "--verify", "/usr/bin/" + GCC], cwd=ctx.work, env=ctx.env)
    expect(rc == 0, "ld.so run by its real path from the host: rc=%d %r" % (rc, err))


@test
def nested_and_log(ctx):
    log = os.path.join(ctx.work, "can.log")
    if os.path.exists(log):
        os.remove(log)
    rc, out, err = run([wrapper(ctx, "sh"), "-c", GCC + " --version"], cwd=ctx.work, env=dict(ctx.env, CAN_LOG=log))
    expect(rc == 0 and "13." in out, out + err)
    text = open(log).read()
    expect("opener 0 boundary /usr/bin/dash" in text and "opener 0 inside /usr/bin/" + GCC in text, "log: " + text[:400])


@test
def sigsys_blocked_at_launch(ctx):
    def block():
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGSYS})
    rc, out, err = run([wrapper(ctx, "gcc-13"), "--version"], cwd=ctx.work, env=ctx.env, preexec=block)
    expect(rc == 0 and "13." in out, "launch with SIGSYS blocked: rc=%d %r" % (rc, err))


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
    src = open(os.path.join(ctx.root, "usr", "bin", ".real", "true"), "rb").read()
    interp = b"/lib64/ld-linux-x86-64.so.2\0"
    i = src.index(interp)
    other = b"/lib/ld-musl-x86_64.so.1\0".ljust(len(interp), b"\0")
    with open(os.path.join(d, "usr", "bin", "true"), "wb") as f:
        f.write(src[:i] + other + src[i + len(interp):])
    with open(os.path.join(d, "usr", "bin", "false"), "wb") as f:
        f.write(src)
    for n in ("true", "false"):
        os.chmod(os.path.join(d, "usr", "bin", n), 0o755)
    os.symlink("/lib64/ld-linux-x86-64.so.2", os.path.join(d, "usr", "bin", "ld-glibc"))   # so that one loader resolves
    os.makedirs(os.path.join(d, "lib64"))
    shutil.copy2(os.path.join(ctx.root, "lib64", "ld-linux-x86-64.so.2"), os.path.join(d, "lib64", "ld-linux-x86-64.so.2"), follow_symlinks=True)
    os.makedirs(os.path.join(d, "lib"))
    shutil.copy2(os.path.join(ctx.root, "lib64", "ld-linux-x86-64.so.2"), os.path.join(d, "lib", "ld-musl-x86_64.so.1"), follow_symlinks=True)
    rep = elfcheck.static_check(mixed, ["/usr", "/lib", "/lib64"], [])
    expect(any("mixes loaders" in e for e in rep.errors), "a tree with two loaders was not refused: %r" % rep.errors[:4])


@test
def rust(ctx):
    rustc = shutil.which("rustc") or shutil.which("rustc", path=os.path.expanduser("~/.cargo/bin"))
    if not rustc:
        return "no rustc"
    exe = os.path.join(ctx.progs, "rs")
    rc, out, err = run([rustc, "-O", "-o", exe, os.path.join(ctx.work, "src", "rs.rs")], cwd=ctx.work)
    expect(rc == 0, "rustc: " + err[-600:])
    rc, out, err = inside(ctx, exe)
    expect(rc == 0 and "FAIL" not in out, out + err)


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
    rc, out, err = run(base + ["-ex", "break main", "-ex", "break write", "-ex", "run", "-ex", "bt", "-ex", "continue", "-ex", "bt", "-ex", "info auto-load python-scripts", "--args", ctx.opener, exe], cwd=ctx.work, env=ctx.env, timeout=300)
    expect(re.search(r"^Breakpoint 1, main \(.*\) at \S*hello\.c:\d+", out, re.M), "the program's own breakpoint hits with its source line: %r %r" % (out[-800:], err[-400:]))
    expect("Breakpoint 2, " in out and "write" in out.split("Breakpoint 2, ", 1)[1].split("\n")[0], "a breakpoint in the can's libc hits with its name: %r %r" % (out[-800:], err[-400:]))
    expect("__libc_start" in out.split("Breakpoint 2, ", 1)[1], "the libc frames below the program resolve: %r" % out[-800:])
    expect("cont-opener.py" in out and "Python Exception" not in out and "Cannot insert" not in out, "the script loaded once and quietly: %r %r" % (out[-600:], err[-400:]))
    rc, out, err = run(base + ["-ex", "break write", "-ex", "run", "-ex", "bt", "--args", wrapper(ctx, "echo"), "hi"], cwd=ctx.work, env=ctx.env, timeout=300)
    expect("Breakpoint 1, " in out and "__libc_start" in out, "a wrapped program's libc frames resolve: %r %r" % (out[-800:], err[-400:]))
    expect("Python Exception" not in out and "Cannot insert" not in out, "quiet for a wrapper: %r" % out[-600:])


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
    ctx.opener_src = os.path.join(REPO, "build", "opener")
    if not os.path.exists(ctx.opener_src):
        sys.exit("build/opener missing: run make")
    if os.path.exists(ctx.work):
        shutil.rmtree(ctx.work)
    os.makedirs(ctx.work)
    ctx.env = {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/"), "LANG": "C"}
    t0 = time.time()
    make_can(ctx)
    compile_progs(ctx)
    ctx.shared = shared_state(ctx)
    print("can made and programs compiled in %.1fs" % (time.time() - t0))
    fails = 0
    order = [t for t in TESTS if not a.k or a.k in t.__name__]
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
            print("PASS %-26s %5.1fs %s" % (t.__name__, time.time() - t0, note or ""))
            now = shared_state(ctx)                            # a test must leave the fixtures alone (tests are independent)
            changed = [n for n, a, b in zip(("manifest", "lock", "top level", "/usr/bin"), ctx.shared, now) if a != b]
            if changed:
                print("FAIL %-26s %5.1fs the test changed the shared can: %s" % (t.__name__, time.time() - t0, ", ".join(changed)))
                fails += 1
                ctx.shared = shared_state(ctx)
        except AssertionError as e:
            fails += 1
            print("FAIL %-26s %5.1fs %s" % (t.__name__, time.time() - t0, str(e).strip().replace("\n", "\n     ")))
        except Exception as e:  # noqa: BLE001
            fails += 1
            print("FAIL %-26s %5.1fs %s: %s" % (t.__name__, time.time() - t0, type(e).__name__, e))
    print("%d tests, %d failures" % (len(order), fails))
    if not a.keep and not fails:
        shutil.rmtree(ctx.work, ignore_errors=True)
    return fails


if __name__ == "__main__":
    sys.exit(main())
