#!/usr/bin/env python3
"""oracle_ns.py — the namespace oracle (PROPOSAL.md 17, item 1).

The same tree runs twice: under `bwrap` with the unwrapped tree bound read-only at `/`, and under the
opener. Exit status, stdout and stderr are compared, and the read-only matrix program of test/progs is
run under bwrap so that its expectations are checked against the kernel itself rather than against the
opener. Needs user namespaces and bwrap; says so and exits 0 when it cannot run.

    test/oracle_ns.py --can CAN [--work DIR] [--keep]
"""
import argparse
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "cannery"))
import build  # noqa: E402
import cannery  # noqa: E402

GCC = "x86_64-linux-gnu-gcc-13"
IDENTITY = ["/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/host.conf", "/etc/resolv.conf", "/etc/hosts",
            "/etc/ssl/certs/ca-certificates.crt"]

# shell workloads by virtual path; $W is the host work directory, writable in both worlds
WORKLOADS = [
    "cat /etc/passwd | head -3",
    "readlink /etc/localtime; readlink /usr/bin/sh",
    "pwd; cd /usr/lib && pwd; cd gcc && pwd",
    "mkdir -p /usr/lib; echo $?; install -d /usr/lib; echo $?; mkdir /usr/lib; echo $?",
    "touch /usr/x; echo $?; touch /usr/lib/x; echo $?; rm /usr/bin/sh; echo $?; rm /usr/nonexistent; echo $?",
    "mv /usr/bin/sh $W/moved; echo $?; ln /usr/bin/dash $W/linked; echo $?; ln -s /usr/bin/dash $W/symlinked; echo $?; ln $W/hello.c /usr/newlink; echo $?",
    "cp /usr/bin/dash $W/dashcopy; echo $?; cmp /usr/bin/dash $W/dashcopy; echo $?",
    "stat -c '%s %F %a' /usr/bin/dash /usr/lib /usr/bin/sh /usr/lib/x86_64-linux-gnu/libc.so.6",
    "ls /usr/lib/gcc/x86_64-linux-gnu/13 | grep -v '^\\.real$' | head -20",
    "find /usr/lib/gcc -name '*.o' | sort | head -30",
    "cd $W && gcc-13 -O1 hello.c -o hello && ./hello a b; echo $?",
    "cd $W && gcc-13 -O0 -c hello.c -o hello.o && ls -l hello.o | cut -d' ' -f5",
    "cat /nonexistent; echo $?; cat /usr/lib; echo $?; cd /usr/bin/dash; echo $?",
    "echo x > /dev/null; echo $?; : > /tmp/oracle-file; echo $?; ls /tmp/oracle-file",
    "stat -f -c '%T' /usr; touch /usr/bin/true 2>&1; chmod 600 /usr/bin/true 2>&1; echo $?",
    "TZ=Asia/Tokyo date +%Z; date -r /etc/localtime +%Z | wc -l",
    "test -w /usr/bin/dash; echo $?; test -x /usr/bin/dash; echo $?; test -w $W; echo $?",
    "cd $W && echo '#!/bin/sh' > s.sh && echo 'echo script $1' >> s.sh && chmod +x s.sh && ./s.sh q; echo $?",
    "cd $W && ln -sf /usr/share lnk && cat lnk/../bin/../share/doc/dash/copyright | head -2",
    "getent passwd root | cut -d: -f1; hostname 2>&1 | head -1 | wc -l",
]


EXTRA_BINDS = []


def norm(text, work):
    return text.replace(work, "$W")


def run_bwrap(root, work, cmd, extra=()):
    # the work directory is bound at its own path; its top-level directory becomes a tmpfs so that bwrap can
    # make the mount point inside the read-only root (the tree ships that directory as an empty placeholder)
    top = "/" + work.split("/")[1]
    args = ["bwrap", "--ro-bind", root, "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]
    if top != "/tmp":
        args += ["--tmpfs", top]
    args += ["--bind", work, work, "--chdir", work, "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", work, "--setenv", "W", work]
    for f in IDENTITY:
        if os.path.exists(f) and os.path.lexists(os.path.join(root, f.lstrip("/"))):
            args += ["--ro-bind", f, f]
    p = subprocess.run(args + EXTRA_BINDS + list(extra) + ["/bin/sh", "-c", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)   # no "--": bwrap 0.2 rejects it
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


def run_opener(can, work, cmd, prog=None):
    env = {"PATH": "/usr/bin:/bin", "HOME": work, "W": work}
    if prog:
        env["CAN_EXEC"] = prog
        p = subprocess.run([prog] + cmd, cwd=work, env=env, executable=os.path.join(can, ".can", "opener"), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        p = subprocess.run([os.path.join(can, "root", "usr", "bin", "sh"), "-c", cmd], cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--can", required=True)
    ap.add_argument("--work", default=os.path.join(REPO, "build", "oracle-work"))
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    if not shutil.which("bwrap"):
        print("no bwrap; the namespace oracle cannot run here")
        return 0
    if subprocess.run(["bwrap", "--ro-bind", "/", "/", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        print("bwrap cannot create namespaces here (user namespaces denied); the oracle cannot run")
        return 0
    can, work = os.path.abspath(a.can), os.path.abspath(a.work)
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)
    # an unwrapped copy of the tree for bwrap: hard links, then the payloads moved back over the wrappers
    root = os.path.join(work, "tree", "root")
    shutil.copytree(os.path.join(can, "root"), root, symlinks=True, copy_function=cannery.link_or_copy)
    build.unwrap(os.path.join(work, "tree"), log=lambda *x: None)
    with open(os.path.join(root, "usr", "share", "cont-test-marker"), "w") as f:
        f.write("marker\n")
    # /etc/localtime: a bind of the host's file would hide its link text, which the opener reports (8.4);
    # the copy gets a symlink with the host's text and, if the tree lacks zoneinfo, the host's zoneinfo bound
    lt = os.path.join(root, "etc", "localtime")
    if os.path.islink("/etc/localtime"):
        if os.path.lexists(lt):
            os.remove(lt)
        os.symlink(os.readlink("/etc/localtime"), lt)
    zi = os.path.join(root, "usr", "share", "zoneinfo")
    if not os.path.isdir(zi) and os.path.isdir("/usr/share/zoneinfo"):
        os.makedirs(zi)
        EXTRA_BINDS.extend(["--ro-bind", "/usr/share/zoneinfo", "/usr/share/zoneinfo"])
    with open(os.path.join(work, "hello.c"), "w") as f:
        f.write('#include <stdio.h>\nint main(int c, char **v) { printf("hello %d\\n", c); return 0; }\n')
    fails = 0
    # 1. the read-only matrix against the kernel: the same program, the same expectations, a real read-only bind
    gcc = os.path.join(can, "root", "usr", "bin", GCC)
    prog = os.path.join(work, "ro_matrix")
    r = subprocess.run([gcc, "-O1", "-o", prog, os.path.join(HERE, "progs", "ro_matrix.c")], cwd=work, env={"PATH": "/usr/bin:/bin"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode:
        sys.exit("cannot compile ro_matrix with the can's gcc: " + r.stderr.decode(errors="replace"))
    hostdir = os.path.join(work, "hostdir")
    os.makedirs(hostdir, exist_ok=True)
    rc, out, err = run_bwrap(root, work, "%s %s /usr/bin/dash" % (prog, hostdir))
    # under bwrap there is no wrapper, so the redirect line of the program is not meaningful there
    bad = [l for l in out.splitlines() if l.startswith("FAIL") and "wrapper" not in l]
    if bad or "ro_matrix:" not in out:
        fails += 1
        print("FAIL read-only matrix under the kernel's read-only bind:\n     " + "\n     ".join(bad or [err.strip() or out.strip()]))
    else:
        print("PASS read-only matrix: the kernel agrees with every expectation of 8.2 (%s)" % out.strip().splitlines()[-1])
    # 2. workloads twice
    for cmd in WORKLOADS:
        shown = cmd.replace("$W", "$W")
        for f in ("moved", "linked", "symlinked", "dashcopy", "hello", "hello.o", "s.sh", "lnk"):
            p = os.path.join(work, f)
            if os.path.lexists(p):
                os.remove(p)
        b = run_bwrap(root, work, cmd)
        for f in ("moved", "linked", "symlinked", "dashcopy", "hello", "hello.o", "s.sh", "lnk"):
            p = os.path.join(work, f)
            if os.path.lexists(p):
                os.remove(p)
        o = run_opener(can, work, cmd)
        bn = (b[0], norm(b[1], work), norm(re.sub(r"^[^:]*/(sh|dash): ", "sh: ", b[2], flags=re.M), work))
        on = (o[0], norm(o[1], work), norm(re.sub(r"^[^:]*/(sh|dash): ", "sh: ", o[2], flags=re.M), work))
        # the opener names programs by their real path when the host invoked them; bwrap by the virtual one
        if bn == on:
            print("PASS %s" % shown[:70])
        else:
            fails += 1
            print("FAIL %s\n     bwrap : rc=%d out=%r err=%r\n     opener: rc=%d out=%r err=%r" % (shown[:70], bn[0], bn[1][:300], bn[2][:200], on[0], on[1][:300], on[2][:200]))
    print("%d workloads, %d failures" % (len(WORKLOADS) + 1, fails))
    if not a.keep and not fails:
        shutil.rmtree(work, ignore_errors=True)
    return fails


if __name__ == "__main__":
    sys.exit(main())
