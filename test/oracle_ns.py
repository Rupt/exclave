"""Compare an exclave under the launcher with its tree under bwrap: the namespace oracle (17).

The same tree runs twice: under `bwrap` with the unwrapped tree bound read-only at `/`, and under
the launcher. Exit status, stdout and stderr are compared, and the read-only matrix program of
test/progs is run under bwrap so that its expectations are checked against the kernel itself rather
than against the launcher. Needs user namespaces and bwrap; says so and exits 0 when it cannot run.

    test/oracle_ns.py --exclave EXCLAVE [--work DIR] [--keep]
"""

import argparse
import dataclasses
import os
import platform
import re
import shutil
import subprocess
import sys
lazy from collections.abc import Iterable

import tree

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# the identity files the launcher answers from the host (8.4)
IDENTITY = tree.IDENTITY_FILES


@dataclasses.dataclass(frozen=True)
class Spellings:
    """The tree's own names for what the workloads use, passed to both worlds (test/tree.py)."""

    gcc: str  # the C compiler
    sh: str  # the shell's virtual path
    shx: str  # the file behind the shell
    libc: str
    sh_link: str  # the text of the shell's link, or "" when it is no link

    @classmethod
    def of(cls, root: str) -> Spellings:
        """Read the spellings from the tree at root."""
        machine = platform.machine()
        sh = tree.vbin(root, "sh")
        real_sh = os.path.join(root, sh.lstrip("/"))
        return cls(
            gcc=tree.compiler(root, machine) or f"{machine}-linux-gnu-gcc-13",
            sh=sh,
            shx=tree.resolve(root, sh),
            libc=tree.libc(root, machine),
            sh_link=os.readlink(real_sh) if os.path.islink(real_sh) else "",
        )

    def env(self) -> dict[str, str]:
        """Return the environment that names them to a workload."""
        return {
            "CC": self.gcc,
            "SH": self.sh,
            "SHX": self.shx,
            "LIBC": self.libc,
            "EXCLAVE_TEST_SH": self.sh,
            "EXCLAVE_TEST_SH_LINK": self.sh_link,
        }


# shell workloads by virtual path; $W is the host work directory, writable in both worlds
WORKLOADS = [
    "cat /etc/passwd | head -3",
    (
        "for f in /etc/resolv.conf /etc/hosts /etc/nsswitch.conf; "
        "do test -L $f && readlink $f; done; "
        "head -c 40 /etc/resolv.conf | wc -c; readlink $SH"
    ),
    "pwd; cd /usr/lib && pwd; cd gcc && pwd",
    "mkdir -p /usr/lib; echo $?; install -d /usr/lib; echo $?; mkdir /usr/lib; echo $?",
    (
        "touch /usr/x; echo $?; touch /usr/lib/x; echo $?; rm $SH; echo $?; "
        "rm /usr/nonexistent; echo $?"
    ),
    (
        "mv $SH $W/moved; echo $?; ln $SHX $W/linked; echo $?; ln -s $SHX $W/symlinked; echo $?; "
        "ln $W/hello.c /usr/newlink; echo $?"
    ),
    "cp $SHX $W/dashcopy; echo $?; cmp $SHX $W/dashcopy; echo $?",
    "stat -c '%s %F %a' $SHX $SH $LIBC; stat -c '%F %a' /usr/lib",
    "ls /usr/lib/gcc/*/* | grep -v '^\\.real$' | head -20",  # the tree's own triplet and version
    "find /usr/lib/gcc -name '*.o' | sort | head -30",
    "cd $W && $CC -O1 hello.c -o hello && ./hello a b; echo $?",
    "cd $W && $CC -O0 -c hello.c -o hello.o && ls -l hello.o | cut -d' ' -f5",
    "cat /nonexistent; echo $?; cat /usr/lib; echo $?; cd $SHX; echo $?",
    (
        f"echo x > /dev/null; echo $?; : > /tmp/oracle-file-{os.getpid()}; echo $?; "
        f"ls /tmp/oracle-file-{os.getpid()}; rm /tmp/oracle-file-{os.getpid()}"
    ),
    "stat -f -c '%T' /usr; touch /usr/bin/true 2>&1; chmod 600 /usr/bin/true 2>&1; echo $?",
    "date +%Z; TZ=Asia/Tokyo date +%Z; ls /etc/localtime 2>&1 | wc -l",
    "test -w $SHX; echo $?; test -x $SHX; echo $?; test -w $W; echo $?",
    (
        "cd $W && echo '#!/bin/sh' > s.sh && echo 'echo script $1' >> s.sh && chmod +x s.sh "
        "&& ./s.sh q; echo $?"
    ),
    "cd $W && ln -sf /usr/share lnk && cat lnk/../bin/../share/doc/dash/copyright | head -2",
    "getent passwd root | cut -d: -f1; hostname 2>&1 | head -1 | wc -l",
]


EXTRA_BINDS: list[str] = []


def norm(text: str, work: str) -> str:
    """Spell the work directory as $W."""
    return text.replace(work, "$W")


def run_bwrap(
    root: str, work: str, cmd: str, spellings: Spellings, extra: Iterable[str] = ()
) -> tuple[int, str, str]:
    """Run a shell command under bwrap with root read-only at /, where the kernel answers.

    The work directory is bound at its own path. Its top-level directory becomes a tmpfs, so that
    bwrap can make the mount point inside the read-only root, where the tree ships that directory as
    an empty placeholder.
    """
    top = "/" + work.split("/")[1]
    args = [
        "bwrap",
        "--ro-bind",
        root,
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
    ]
    if top != "/tmp":
        args += ["--tmpfs", top]
    args += [
        "--bind",
        work,
        work,
        "--chdir",
        work,
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        work,
        "--setenv",
        "W",
        work,
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "TZ",
        "UTC0",
        # the border constants of 6.2
        "--setenv",
        "SHELL",
        "/bin/sh",
    ]
    for k, v in spellings.env().items():
        args += ["--setenv", k, v]
    for f in IDENTITY:
        if os.path.exists(f) and os.path.lexists(os.path.join(root, f.lstrip("/"))):
            if os.path.islink(f):
                # the copy carries the host's link text (8.4) and the target is bound at its own
                # path: readlink and the content then agree with the launcher, which answers the
                # text and opens the host file
                t = os.path.realpath(f)
                args += ["--ro-bind", t, t]
            else:
                args += ["--ro-bind", f, f]
    # no "--": bwrap 0.2 rejects it; the setenv values are the whole environment
    p = subprocess.run(
        args + EXTRA_BINDS + list(extra) + ["/bin/sh", "-c", cmd],
        env={},
        capture_output=True,
        check=False,
    )
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


def run_launcher(
    ex: str, work: str, cmd: str | list[str], spellings: Spellings, prog: str | None = None
) -> tuple[int, str, str]:
    """Run a workload under the launcher: cmd by the tree's shell, or prog with arguments cmd."""
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": work,
        "W": work,
        **spellings.env(),
        # replaced at the border (6.2)
        "LANG": "en_GB.UTF-8",
        "TZ": "Asia/Tokyo",
    }
    if prog:
        p = subprocess.run(
            [os.path.join(ex, ".exclave", "launcher"), prog, *cmd],
            cwd=work,
            env=env,
            capture_output=True,
            check=False,
        )
    else:
        assert isinstance(cmd, str)
        p = subprocess.run(
            [os.path.join(ex, "tree", spellings.sh.lstrip("/")), "-c", cmd],
            cwd=work,
            env=env,
            capture_output=True,
            check=False,
        )
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--exclave", required=True)
    ap.add_argument("--work", default=os.path.join(REPO, "build", "oracle-work"))
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    if not shutil.which("bwrap"):
        print("no bwrap; the namespace oracle cannot run here")
        return 0
    if subprocess.run(
        ["bwrap", "--ro-bind", "/", "/", "true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode:
        print("bwrap cannot create namespaces here (user namespaces denied); the oracle cannot run")
        return 0
    work = os.path.abspath(args.work)
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)
    # the launcher's world: a copy relinked with the build (17)
    ex = tree.fresh_exclave(os.path.abspath(args.exclave), os.path.join(work, "exclave"))
    # an unwrapped copy of the tree for bwrap: hard links, then the originals moved back over the
    # wrappers
    root = os.path.join(work, "bare", "tree")
    shutil.copytree(os.path.join(ex, "tree"), root, symlinks=True, copy_function=tree.link_or_copy)
    tree.unwrap_tree(os.path.join(work, "bare"))
    with open(os.path.join(root, "usr", "share", "exclave-test-marker"), "w") as f:
        f.write("marker\n")
    # an identity file that is a host symlink: a bind of the host's file would hide its link text,
    # which the launcher reports (8.4); the copy gets a symlink with the host's text, and run_bwrap
    # binds the target
    for f in IDENTITY:
        p_ = os.path.join(root, f.lstrip("/"))
        if os.path.islink(f) and os.path.lexists(p_):
            os.remove(p_)
            os.symlink(os.readlink(f), p_)
            # the bind of the target needs a mount point in the read-only root
            t = os.path.realpath(f)
            tp = os.path.join(root, t.lstrip("/"))
            if not os.path.lexists(tp) and not t.startswith(("/run/", "/tmp/", "/dev/", "/proc/")):
                os.makedirs(os.path.dirname(tp), exist_ok=True)
                with open(tp, "wb"):
                    pass
    with open(os.path.join(work, "hello.c"), "w") as f:
        f.write(
            "#include <stdio.h>\n"
            'int main(int c, char **v) { printf("hello %d\\n", c); return 0; }\n'
        )
    fails = 0
    # 1. the read-only matrix against the kernel: the same program, the same expectations, a real
    # read-only bind
    sp = Spellings.of(os.path.join(ex, "tree"))
    gcc = os.path.join(ex, "tree", tree.vbin(os.path.join(ex, "tree"), sp.gcc).lstrip("/"))
    prog = os.path.join(work, "ro_matrix")
    r = subprocess.run(
        [gcc, "-O1", "-o", prog, os.path.join(HERE, "progs", "ro_matrix.c")],
        cwd=work,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        check=False,
    )
    if r.returncode:
        sys.exit(
            "cannot compile ro_matrix with the exclave's gcc: " + r.stderr.decode(errors="replace")
        )
    hostdir = os.path.join(work, "hostdir")
    os.makedirs(hostdir, exist_ok=True)
    _rc, out, err = run_bwrap(root, work, f"{prog} {hostdir} /usr/bin/dash", sp)
    # under bwrap there is no wrapper, so the redirect line of the program is not meaningful there
    bad = [line for line in out.splitlines() if line.startswith("FAIL") and "wrapper" not in line]
    if bad or "ro_matrix:" not in out:
        fails += 1
        print(
            "FAIL read-only matrix under the kernel's read-only bind:\n     "
            + "\n     ".join(bad or [err.strip() or out.strip()])
        )
    else:
        print(
            "PASS read-only matrix: the kernel agrees with every expectation of 8.2 "
            f"({out.strip().splitlines()[-1]})"
        )
    # 2. workloads twice
    for cmd in WORKLOADS:
        shown = cmd
        for f in ("moved", "linked", "symlinked", "dashcopy", "hello", "hello.o", "s.sh", "lnk"):
            p = os.path.join(work, f)
            if os.path.lexists(p):
                os.remove(p)
        b = run_bwrap(root, work, cmd, sp)
        for f in ("moved", "linked", "symlinked", "dashcopy", "hello", "hello.o", "s.sh", "lnk"):
            p = os.path.join(work, f)
            if os.path.lexists(p):
                os.remove(p)
        o = run_launcher(ex, work, cmd, sp)
        bn = (
            b[0],
            norm(b[1], work),
            norm(re.sub(r"^[^:]*/(sh|dash): ", "sh: ", b[2], flags=re.MULTILINE), work),
        )
        on = (
            o[0],
            norm(o[1], work),
            norm(re.sub(r"^[^:]*/(sh|dash): ", "sh: ", o[2], flags=re.MULTILINE), work),
        )
        # the launcher names programs by their real path when the host invoked them; bwrap by the
        # virtual one
        if bn == on:
            print(f"PASS {shown[:70]}")
        else:
            fails += 1
            print(
                f"FAIL {shown[:70]}\n"
                f"     bwrap : rc={bn[0]} out={bn[1][:300]!r} err={bn[2][:200]!r}\n"
                f"     launcher: rc={on[0]} out={on[1][:300]!r} err={on[2][:200]!r}"
            )
    print(f"{len(WORKLOADS) + 1} workloads, {fails} failures")
    if not args.keep and not fails:
        shutil.rmtree(work, ignore_errors=True)
    return fails


if __name__ == "__main__":
    sys.exit(main())
