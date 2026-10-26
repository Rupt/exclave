"""bench.py — the performance table (DESIGN.md 13 item 2, 16). Best of three, native against the exclave.

    test/bench.py --exclave EXCLAVE [--sqlite PATH] [--work DIR] [--launcher LAUNCHER]

The exclave must contain gcc-13; the host's /usr/bin/gcc-13, else its gcc, gives the native column.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
GCC = "x86_64-linux-gnu-gcc-13"

STAT_C = r"""
#include <sys/stat.h>
#include <stdio.h>
#include <time.h>
int main(int c, char **v) { struct stat st; struct timespec a, b; const char *p = v[1]; int n = 200000;
  clock_gettime(CLOCK_MONOTONIC, &a); for (int i = 0; i < n; i++) stat(p, &st); clock_gettime(CLOCK_MONOTONIC, &b);
  printf("%.0f\n", ((b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec)) / n); return 0; }
"""
CALLS_C = r"""
#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e9 + t.tv_nsec; }
int main(int c, char **v) { int n = 200000; char buf[PATH_MAX]; double a = now();
  if (v[1][0] == 'g') for (int i = 0; i < 20 * n; i++) syscall(SYS_getppid);
  else for (int i = 0; i < n; i++) if (!realpath(v[2], buf)) return 1;
  printf("%.0f\n", (now() - a) / (v[1][0] == 'g' ? 20 * n : n)); return 0; }
"""
SPAWN_C = r"""
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
extern char **environ;
int main(void) { struct timespec a, b; int n = 300; char *av[] = { "true", 0 };
  clock_gettime(CLOCK_MONOTONIC, &a);
  for (int i = 0; i < n; i++) { pid_t p; if (posix_spawn(&p, "/usr/bin/true", 0, 0, av, environ)) return 1; int st; waitpid(p, &st, 0); }
  clock_gettime(CLOCK_MONOTONIC, &b); printf("%.0f\n", ((b.tv_sec - a.tv_sec) * 1e6 + (b.tv_nsec - a.tv_nsec) / 1e3) / n); return 0; }
"""

SPAWN100K_C = r"""
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
extern char **environ;
static long rss(void) { FILE *f = fopen("/proc/self/status", "r"); char l[256]; long v = -1; while (f && fgets(l, 256, f)) if (!strncmp(l, "VmRSS:", 6)) v = atol(l + 6); if (f) fclose(f); return v; }
int main(void) { struct timespec a, b; int n = 100000; char *av[] = { "true", 0 };
  long r0 = rss(); clock_gettime(CLOCK_MONOTONIC, &a);
  for (int i = 0; i < n; i++) { pid_t p; if (posix_spawn(&p, "/usr/bin/true", 0, 0, av, environ)) return 1; int st; waitpid(p, &st, 0); }
  clock_gettime(CLOCK_MONOTONIC, &b); long r1 = rss();
  printf("%.1f s, RSS %+ld kB\n", (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9, r1 - r0); return 0; }
"""


def run(cmd, cwd, env=None, executable=None):
    return subprocess.run(cmd, cwd=cwd, env=env, executable=executable, capture_output=True)


def best(fn, n=3):
    return min(fn() for _ in range(n))


def timed(cmd, cwd, env, executable=None):
    t = time.time()
    p = run(cmd, cwd, env, executable)
    if p.returncode:
        msg = "failed: {}\n{}".format(cmd, p.stderr.decode(errors="replace")[-400:])
        raise SystemExit(msg)
    return time.time() - t


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exclave", required=True)
    ap.add_argument("--sqlite", help="sqlite3.c amalgamation for the compute-bound compile")
    ap.add_argument("--work", default=os.path.join(REPO, "build", "bench-work"))
    ap.add_argument(
        "--launcher",
        default=os.path.join(REPO, "build", "launcher"),
        help="the launcher to measure (default: the build)",
    )
    a = ap.parse_args()
    work = os.path.abspath(a.work)
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)
    import tree

    ex = tree.fresh_exclave(
        os.path.abspath(a.exclave),
        os.path.join(work, "exclave"),
        launcher=os.path.abspath(a.launcher),
    )  # a copy relinked with the build (17)
    cgcc, hgcc = (
        os.path.join(ex, "tree", "usr", "bin", GCC),
        shutil.which("gcc-13") or shutil.which("gcc"),
    )
    launcher = os.path.join(ex, ".exclave", "launcher")
    env = {"PATH": "/usr/bin:/bin"}
    rows = []

    def native(prog, *args):
        return run([prog, *list(args)], work, env).stdout.decode().strip()

    def inside(prog, *args):
        return run([launcher, prog, *list(args)], work, env).stdout.decode().strip()

    for name, src in (
        ("statb", STAT_C),
        ("callsb", CALLS_C),
        ("spawnb", SPAWN_C),
        ("spawn100k", SPAWN100K_C),
    ):
        with open(os.path.join(work, name + ".c"), "w") as f:
            f.write(src)
        p = run(
            [cgcc, "-O2", "-o", os.path.join(work, name), os.path.join(work, name + ".c")],
            work,
            env,
        )
        if p.returncode:
            raise SystemExit(p.stderr.decode())
    statb, spawnb = os.path.join(work, "statb"), os.path.join(work, "spawnb")
    rows.append(
        (
            "stat(), three-component exclave path, ns per call",
            best(lambda: int(native(statb, "/usr/include/stdio.h"))),
            best(lambda: int(inside(statb, "/usr/include/stdio.h"))),
        )
    )
    rows.append(
        (
            "stat(), seven-component exclave path, ns per call",
            best(lambda: int(native(statb, "/usr/lib/gcc/x86_64-linux-gnu/13/include/stddef.h"))),
            best(lambda: int(inside(statb, "/usr/lib/gcc/x86_64-linux-gnu/13/include/stddef.h"))),
        )
    )
    hostfile = os.path.join(work, "statb.c")
    rows.append(
        (
            "stat(), %d-component host path, ns per call" % hostfile.count("/"),
            best(lambda: int(native(statb, hostfile))),
            best(lambda: int(inside(statb, hostfile))),
        )
    )
    rows.append(
        (
            "stat(), relative name in the working directory, %d components deep on the host, ns per call"
            % work.count("/"),
            best(lambda: int(native(statb, "statb.c"))),
            best(lambda: int(inside(statb, "statb.c"))),
        )
    )
    callsb = os.path.join(work, "callsb")
    rows.append(
        (
            "realpath() of the working directory, ns per call",
            best(lambda: int(native(callsb, "r", work))),
            best(lambda: int(inside(callsb, "r", work))),
        )
    )
    rows.append(
        (
            "getppid(), untrapped, ns per call",
            best(lambda: int(native(callsb, "g"))),
            best(lambda: int(inside(callsb, "g"))),
        )
    )
    rows.append(
        (
            "posix_spawn of /usr/bin/true, us per spawn",
            best(lambda: int(native(spawnb))),
            best(lambda: int(inside(spawnb))),
        )
    )
    spawn100k = os.path.join(
        work, "spawn100k"
    )  # 17.4: 100 000 spawns from one process, RSS before and after, one run
    rows.append(
        (
            "100 000 posix_spawns of /usr/bin/true from one process",
            native(spawn100k),
            inside(spawn100k),
        )
    )
    with open(os.path.join(work, "hello.c"), "w") as f:
        f.write('#include <stdio.h>\nint main(void) { printf("hello\\n"); return 0; }\n')

    def thirty(gcc) -> None:
        for i in range(30):
            p = run([gcc, "-O0", "hello.c", "-o", "h%d" % i], work, env)
            if p.returncode:
                raise SystemExit(p.stderr.decode())

    rows.append(
        (
            "thirty gcc -O0 hello.c, s",
            best(
                lambda: (
                    (lambda t: time.time() - t)(time.time())
                    if False
                    else _time(lambda: thirty(hgcc))
                )
            )
            if hgcc
            else None,
            best(lambda: _time(lambda: thirty(cgcc))),
        )
    )
    # a small project: 61 files, compile each, link
    proj = os.path.join(work, "proj")
    os.makedirs(proj)
    for i in range(60):
        with open(os.path.join(proj, "f%d.c" % i), "w") as f:
            f.write(
                "int f%d(int x) { int s = 0; for (int i = 0; i < x; i++) s += i * %d; return s; }\n"
                % (i, i + 1)
            )
    with open(os.path.join(proj, "main.c"), "w") as f:
        f.write(
            "".join("int f%d(int);\n" % i for i in range(60))
            + "int main(void) { int s = 0;\n"
            + "".join(" s += f%d(10);\n" % i for i in range(60))
            + " return s & 1; }\n"
        )

    def project(gcc) -> None:
        objs = []
        for i in range(61):
            src = "f%d.c" % i if i < 60 else "main.c"
            p = run([gcc, "-O1", "-c", src, "-o", src[:-2] + ".o"], proj, env)
            if p.returncode:
                raise SystemExit(p.stderr.decode())
            objs.append(src[:-2] + ".o")
        p = run([gcc, "-o", "prog", *objs], proj, env)
        if p.returncode:
            raise SystemExit(p.stderr.decode())

    rows.append(
        (
            "61-file project, -O1 -c each then link, s",
            best(lambda: _time(lambda: project(hgcc))) if hgcc else None,
            best(lambda: _time(lambda: project(cgcc))),
        )
    )
    if a.sqlite and os.path.exists(a.sqlite) and hgcc:
        rows.append(
            (
                "gcc -O2 -c sqlite3.c, s",
                best(lambda: timed([hgcc, "-O2", "-c", a.sqlite, "-o", "sq_host.o"], work, env)),
                best(lambda: timed([cgcc, "-O2", "-c", a.sqlite, "-o", "sq_exclave.o"], work, env)),
            )
        )
        same = (
            open(os.path.join(work, "sq_host.o"), "rb").read()
            == open(os.path.join(work, "sq_exclave.o"), "rb").read()
        )
        rows.append(("sqlite3.o identical", "yes" if same else "no", ""))
    if shutil.which("strace"):

        def count(gcc):
            subprocess.run(
                ["strace", "-f", "-c", "-o", "sc.txt", gcc, "-O0", "hello.c", "-o", "h_sc"],
                cwd=work,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return int(
                open(os.path.join(work, "sc.txt")).read().strip().splitlines()[-1].split()[3]
            )

        rows.append(
            (
                "syscalls for one gcc -O0 hello.c, all processes",
                count(hgcc) if hgcc else None,
                count(cgcc),
            )
        )
    print("| Workload | native | exclave |")
    print("|---|---|---|")
    for name, n, c in rows:

        def fmt(x):
            return (f"{x:.2f}" if isinstance(x, float) else str(x)) if x is not None else ""

        print(f"| {name} | {fmt(n)} | {fmt(c)} |")
    shutil.rmtree(work, ignore_errors=True)


def _time(fn):
    t = time.time()
    fn()
    return time.time() - t


if __name__ == "__main__":
    sys.exit(main())
