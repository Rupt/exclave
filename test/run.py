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

GCC = "x86_64-linux-gnu-gcc-13"
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
    return os.path.join(ctx.root, "usr", "bin", name)


def inside(ctx, prog, args=(), cwd=None, env=None, inp=None, argv0=None, timeout=300):
    """Run a program by virtual/host path inside the can in loader mode (CAN_EXEC)."""
    e = dict(env if env is not None else ctx.env)
    e["CAN_EXEC"] = prog
    return run([argv0 or prog] + list(args), cwd=cwd or ctx.work, env=e, inp=inp, executable=ctx.opener, timeout=timeout)


def expect(cond, msg):
    if not cond:
        raise AssertionError(msg)


def hello_source(ctx):
    """hello.c in the work directory: a fixture any test may make, made once."""
    src = os.path.join(ctx.work, "hello.c")
    if not os.path.exists(src):
        with open(src, "w") as f:
            f.write('#include <stdio.h>\nint main(int c, char **v) { printf("hello %s %d\\n", v[0], c); return 0; }\n')
    return src


# ------------------------------------------------------------------ setup
def make_can(ctx):
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
        for name in os.listdir(root):                  # a packaged can's placeholders are recreated below
            pass
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
    manifest = os.path.join(ctx.work, "test.can")
    top = "/" + ctx.work.split("/")[1]
    lines = ['can 1']
    ctx.claim = top not in VOLATILE
    if ctx.claim:
        lines.append("own %s" % cannery.quote(top.encode()))
    with open(manifest, "w") as f:
        f.write("\n\n".join(lines) + "\n")
    cannery.cmd_wrap(can, quiet=True)
    cannery.cmd_index(can, manifest, quiet=True)
    ctx.can, ctx.root, ctx.opener = can, root, os.path.join(can, ".can", "opener")


def compile_progs(ctx):
    """The sources are copied into the work directory: with the work directory's top-level directory claimed
    for the can (8.1), only the working directory's subtree is the host's."""
    ctx.progs = os.path.join(ctx.work, "progs")
    src = os.path.join(ctx.work, "src")
    shutil.copytree(os.path.join(HERE, "progs"), src)
    os.makedirs(ctx.progs, exist_ok=True)
    gcc = wrapper(ctx, GCC)
    for name in ("ro_matrix", "signals", "threads", "spawn", "exec", "fifo", "execstack", "ljmp"):
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
    allowed_files = set(cannery.IDENTITY_FILES)
    for f in cannery.IDENTITY_FILES:          # the opener resolves each identity file's host symlink chain at startup
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
                  or p in allowed_files or p.startswith("/usr/share/zoneinfo/") or p == "/etc/localtime"
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
    if os.path.islink("/etc/localtime"):
        rc, out, err = run([wrapper(ctx, "readlink"), "/etc/localtime"], cwd=ctx.work, env=ctx.env)
        expect(out.strip() == os.readlink("/etc/localtime"), "localtime link: %r" % out)
    rc, out, err = run([wrapper(ctx, "cat"), "/etc/hostname"], cwd=ctx.work, env=ctx.env)
    expect(rc != 0 and "No such file" in err, "host /etc/hostname must be invisible: %r" % err)
    if os.path.exists("/usr/share/zoneinfo/Asia/Tokyo") and not os.path.exists(os.path.join(ctx.root, "usr/share/zoneinfo/Asia/Tokyo")):
        rc, out, err = run([wrapper(ctx, "date"), "+%Z"], cwd=ctx.work, env=dict(ctx.env, TZ="Asia/Tokyo"))
        expect(out.strip() == "JST", "TZ zone from the host: %r %r" % (out, err))


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
    rc, out, err = inside(ctx, "/usr/bin/env")
    expect(rc == 0 and "CAN_EXEC" not in out, "CAN_EXEC leaked: " + out)


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
    shutil.copytree(ctx.can, can2, symlinks=True, copy_function=cannery.link_or_copy)
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
    if not os.path.islink("/etc/localtime"):
        return "host /etc/localtime is not a symlink"
    target = os.readlink("/etc/localtime")
    resolved = os.path.normpath(os.path.join("/etc", target))
    rc, out, err = run([wrapper(ctx, "sh"), "-c", "test -L /etc/localtime && echo link; readlink /etc/localtime; head -c 4 %s; head -c 4 /etc/localtime" % resolved], cwd=ctx.work, env=ctx.env)
    expect(out == "link\n%s\nTZifTZif" % target, "identity link: %r %r" % (out, err))


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
    expect(lines == ["-1 2", "0 0"], "listxattrat sees the can, not the host: %r %r" % (out, err))


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


@test
def cannery_extraction_rules(ctx):
    """10.1 step 3 after the review: a member reached through a package's own symlink is refused (O3-8); two spellings
    of one path under merged usr conflict (O3-9); an index entry without a digest is not downloaded (O3-14)."""
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
    import repo
    r = repo.Repo("ubuntu", ["noble"], "amd64", ["main"], os.path.join(ctx.work, "cache"), "http://127.0.0.1:1/none")
    try:
        r.download({"Package": "x", "Filename": "pool/x.deb", "Size": "1"})
    except repo.RepoError as e:
        expect("no SHA256" in str(e), str(e))
    else:
        raise AssertionError("a package without a digest was fetched")


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
        idx = cannery.load(os.path.join(ctx.can, ".can", "index"), "index")
        info = cannery.index_info(idx)
        rep = elfcheck.static_check(ctx.can, info, info["data"])
        bad = [e for e in rep.errors if "/usr/local/x/prog" in e or ("libfoo" in e and "hostprog" not in e)]
        expect(not bad, "RPATH inheritance: " + "; ".join(bad))
        expect(any("hostprog" in e and "does not own" in e for e in rep.errors), "a host RPATH must be refused (F3-17): %r" % rep.errors[:3])
        cache = elfcheck.read_cache(elfcheck.Tree(ctx.root))
        expect(cache and "libc.so.6" in cache and cache["libc.so.6"][0].endswith("/libc.so.6"), "ld.so.cache parsed: %r" % (list(cache.items())[:2] if cache else cache))
    finally:
        shutil.rmtree(x, ignore_errors=True)


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
    rc, out, err = run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "fmt", "--check", os.path.join(ctx.can, ".can", "index")])
    expect(rc == 0, "index not canonical: " + out + err)


@test
def mixed_tree_refused(ctx):
    """10.3: a tree whose ELF files name two loaders is refused by the cannery."""
    d = os.path.join(ctx.work, "mixed")
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
    try:
        cannery.detect(d)
    except build.BuildError as e:
        expect("mixes loaders" in str(e), str(e))
        return
    raise AssertionError("a tree with two loaders was not refused")


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
