"""Compare an exclave under the launcher with its tree under bwrap: the namespace oracle (17).

The same tree runs twice: under `bwrap` with the unwrapped tree bound read-only at `/`, and under
the launcher. Exit status, stdout and stderr are compared, a workload meant to succeed must show
under bwrap what it is meant to, so that one that fails alike in both worlds is not taken for a
pass, and the suite's path programs whose answers the kernel can give, the read-only matrix among
them, run under bwrap so that their expectations are checked against the kernel itself rather than
against the launcher. Needs user namespaces and bwrap; says so and exits 0 when it cannot run.

    test/oracle_ns.py --exclave EXCLAVE [--work DIR] [--keep]
"""

import argparse
import concurrent.futures
import dataclasses
import os
import platform
import re
import shutil
import subprocess
import sys
lazy from collections.abc import Callable, Iterable

import kernel_answers
import tree
from harness import run

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# the identity files the launcher answers from the host (8.4)
IDENTITY = tree.IDENTITY_FILES
# seconds a run of either world may take; the slowest workload, a compile, takes well under one
TIMEOUT = 60


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


def lines(out: str) -> list[str]:
    return out.splitlines()


def number(line: str) -> bool:
    """Whether line is a positive whole number, as wc prints one."""
    return line.strip().isdigit() and int(line) > 0


def has(root: str, name: str) -> bool:
    """Whether the tree has a tool of that name, in /usr/bin or /bin."""
    return os.path.lexists(os.path.join(root, tree.vbin(root, name).lstrip("/")))


# Shell workloads by virtual path, $W the host work directory, writable in both worlds, each with
# what it is meant to show when it does its job, asked of the kernel's world: a predicate on
# (stdout, the tree's root) for a workload meant to succeed, which must also exit 0 and say nothing
# on stderr, or None for one that is about failures. A workload that fails the same way in both
# worlds compares equal and tests nothing, as one on a tool or a file the tree lacks would.
WORKLOADS: list[tuple[str, Callable[[str, str], bool] | None]] = [
    (
        "cat /etc/passwd | head -3",
        lambda out, _root: len(lines(out)) == 3 and all(":" in x for x in lines(out)),
    ),
    (
        (
            "for f in /etc/resolv.conf /etc/hosts /etc/nsswitch.conf; "
            "do test -L $f && readlink $f; done; "
            "head -c 40 /etc/resolv.conf | wc -c; readlink $SH"
        ),
        lambda out, _root: any(number(x) for x in lines(out)),
    ),
    (
        "pwd; cd /usr/lib && pwd; cd gcc && pwd",
        lambda out, _root: lines(out)[1:] == ["/usr/lib", "/usr/lib/gcc"],
    ),
    ("mkdir -p /usr/lib; echo $?; install -d /usr/lib; echo $?; mkdir /usr/lib; echo $?", None),
    (
        (
            "touch /usr/x; echo $?; touch /usr/lib/x; echo $?; rm $SH; echo $?; "
            "rm /usr/nonexistent; echo $?"
        ),
        None,
    ),
    (
        (
            "mv $SH $W/moved; echo $?; ln $SHX $W/linked; echo $?; ln -s $SHX $W/symlinked; "
            "echo $?; ln $W/hello.c /usr/newlink; echo $?"
        ),
        None,
    ),
    (
        (
            "cp $SHX $W/dashcopy; echo $?; "
            'test "$(cksum < $SHX)" = "$(cksum < $W/dashcopy)"; echo $?'
        ),
        lambda out, _root: lines(out) == ["0", "0"],
    ),
    (
        "stat -c '%s %F %a' $SHX $SH $LIBC; stat -c '%F %a' /usr/lib",
        lambda out, _root: len(lines(out)) == 4,
    ),
    (
        # the tree's own triplet and version
        "ls /usr/lib/gcc/*/* | grep -v '^\\.real$' | head -20",
        lambda out, _root: any(x.endswith(".o") for x in lines(out)),
    ),
    (
        "find /usr/lib/gcc -name '*.o' | sort | head -30",
        lambda out, _root: bool(lines(out)) and all(x.endswith(".o") for x in lines(out)),
    ),
    (
        "cd $W && $CC -O1 hello.c -o hello && ./hello a b; echo $?",
        lambda out, _root: lines(out) == ["hello 3", "0"],
    ),
    (
        "cd $W && $CC -O0 -c hello.c -o hello.o && wc -c < hello.o",
        lambda out, _root: len(lines(out)) == 1 and number(out),
    ),
    ("cat /nonexistent; echo $?; cat /usr/lib; echo $?; cd $SHX; echo $?", None),
    (
        (
            f"echo x > /dev/null; echo $?; : > /tmp/oracle-file-{os.getpid()}; echo $?; "
            f"ls /tmp/oracle-file-{os.getpid()}; rm /tmp/oracle-file-{os.getpid()}"
        ),
        lambda out, _root: lines(out) == ["0", "0", f"/tmp/oracle-file-{os.getpid()}"],
    ),
    ("stat -f -c '%T' /usr; touch /usr/bin/true 2>&1; chmod 600 /usr/bin/true 2>&1; echo $?", None),
    ("date +%Z; TZ=Asia/Tokyo date +%Z; ls /etc/localtime 2>&1 | wc -l", None),
    ("test -w $SHX; echo $?; test -x $SHX; echo $?; test -w $W; echo $?", None),
    (
        (
            "cd $W && echo '#!/bin/sh' > s.sh && echo 'echo script $1' >> s.sh && chmod +x s.sh "
            "&& ./s.sh q; echo $?"
        ),
        lambda out, _root: lines(out) == ["script q", "0"],
    ),
    (
        # .. after a host link into the tree is the parent of the link's target, in the tree
        (
            "cd $W && ln -sf /usr/share lnk && "
            "head -c 4 lnk/../lib/../bin/$(basename $(command -v $CC)) | od -An -c"
        ),
        lambda out, _root: out.split()[1:4] == ["E", "L", "F"],
    ),
    (
        (
            "if command -v getent >/dev/null; then getent passwd root | cut -d: -f1; fi; "
            "hostname 2>&1 | head -1 | wc -l"
        ),
        # musl has no getent
        lambda out, root: lines(out) == (["root", "1"] if has(root, "getent") else ["1"]),
    ),
]


EXTRA_BINDS: list[str] = []


def norm(text: str, work: str) -> str:
    """Spell the work directory as $W."""
    return text.replace(work, "$W")


def run_bwrap(
    root: str,
    work: str,
    cmd: str,
    spellings: Spellings,
    extra: Iterable[str] = (),
    *,
    timeout: float | None = None,
) -> tuple[int, str, str]:
    """Run a shell command under bwrap with root read-only at /, where the kernel answers.

    The work directory is bound at its own path. Its top-level directory becomes a tmpfs, so that
    bwrap can make the mount point inside the read-only root, where the tree ships that directory as
    an empty placeholder. After timeout seconds the run is killed with its process group and
    TimeoutExpired raised.
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
    return run(args + EXTRA_BINDS + list(extra) + ["/bin/sh", "-c", cmd], env={}, timeout=timeout)


def run_launcher(
    ex: str,
    work: str,
    cmd: str | list[str],
    spellings: Spellings,
    prog: str | None = None,
    *,
    timeout: float | None = None,
) -> tuple[int, str, str]:
    """Run a workload under the launcher: cmd by the tree's shell, or prog with arguments cmd.

    After timeout seconds the run is killed with its process group and TimeoutExpired raised.
    """
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
        return run(
            [os.path.join(ex, ".exclave", "launcher"), prog, *cmd],
            cwd=work,
            env=env,
            timeout=timeout,
        )
    assert isinstance(cmd, str)
    return run(
        [os.path.join(ex, "tree", spellings.sh.lstrip("/")), "-c", cmd],
        cwd=work,
        env=env,
        timeout=timeout,
    )


def bwrap_unusable() -> str | None:
    """Why the kernel's world cannot be made here, or None: bwrap missing or namespaces denied."""
    if not shutil.which("bwrap"):
        return "no bwrap"
    if subprocess.run(
        ["bwrap", "--ro-bind", "/", "/", "true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode:
        return "bwrap cannot create namespaces here (user namespaces denied)"
    return None


def worlds(given: str, work: str) -> tuple[str, str]:
    """Make the two worlds under work from the exclave given: the launcher's and the kernel's.

    Returns the launcher's exclave, a copy relinked with the build (17), and the kernel's root, an
    unwrapped copy of its tree for run_bwrap: hard links, then the originals moved back over the
    wrappers, and the host's identity links (identity_links). The oracle itself keeps its worlds
    between runs (tree.kept_worlds); test/workloads.py makes them anew.
    """
    ex = tree.fresh_exclave(given, os.path.join(work, "exclave"))
    root = os.path.join(work, "bare", "tree")
    shutil.copytree(os.path.join(ex, "tree"), root, symlinks=True, copy_function=tree.link_or_copy)
    tree.unwrap_tree(os.path.join(work, "bare"))
    identity_links(root)
    return ex, root


def identity_links(root: str) -> None:
    """Give the kernel's root the host's link text for each identity file that is a host symlink.

    A bind of the host's file would hide the link text the launcher reports (8.4); run_bwrap binds
    the target, which needs a mount point in the read-only root. Done again on a kept root.
    """
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


# the suite's path programs whose expectations the kernel can check (17 item 4), each judged here as
# the suite judges the launcher's answers
PROGRAMS = (
    "ro_matrix",
    "openat2",
    "creat_slash",
    "slash_links",
    "open_flags",
    "unix_socket",
    "magic_links",
)


def judge(name: str, rc: int, out: str, hostdir: str) -> list[str]:
    """What the kernel answered that the suite's expectation for program name does not say.

    hostdir is the writable host directory the program was given.
    """
    if name == "ro_matrix":
        # under bwrap there is no wrapper, so the program's redirect line is not meaningful there;
        # it exits 1 on any FAIL line, the wrapper's included
        bad = [x for x in out.splitlines() if x.startswith("FAIL") and "wrapper" not in x]
        return bad or ([] if "ro_matrix:" in out and rc == (1 if "FAIL" in out else 0) else [out])
    if name == "openat2":
        # 3: the kernel has no openat2, which the suite skips on too; the pathless mode's lines
        # follow the plain mode's
        bad = [x for x in out.splitlines() if x.startswith("FAIL")]
        if rc != 3:
            bad += kernel_answers.openat2_pathless_wrong(out)
        return bad or ([] if rc in (0, 3) else [out])
    if name == "magic_links":
        wrong = kernel_answers.magic_links_wrong(
            out,
            kernel_answers.magic_links_missing(hostdir)
            | kernel_answers.link_empty_allowed(hostdir),
        )
    elif name == "open_flags":
        wrong = kernel_answers.open_flags_wrong(out, by_the_kernel=True)
    else:
        wrong = {
            "creat_slash": kernel_answers.creat_slash_wrong,
            "slash_links": kernel_answers.slash_links_wrong,
            "unix_socket": kernel_answers.unix_socket_wrong,
        }[name](out)
    return wrong or ([] if rc == 0 and out else [out])


def programs_under_the_kernel(ex: str, root: str, work: str, sp: Spellings) -> int:
    """Run PROGRAMS under bwrap, where the kernel answers, and judge them; the number that fail.

    Each is compiled with the exclave's compiler and run with the arguments the suite gives it; a
    program says nothing on stderr.
    """
    tr = os.path.join(ex, "tree")
    gcc = os.path.join(tr, tree.vbin(tr, sp.gcc).lstrip("/"))

    def build(name: str) -> str | None:
        r = subprocess.run(
            [gcc, "-O1", "-o", os.path.join(work, name), os.path.join(HERE, "progs", name + ".c")],
            cwd=work,
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True,
            check=False,
        )
        return r.stderr.decode(errors="replace") if r.returncode else None

    with concurrent.futures.ThreadPoolExecutor(4) as pool:
        for name, e in zip(PROGRAMS, pool.map(build, PROGRAMS), strict=True):
            if e is not None:
                sys.exit(f"cannot compile {name} with the exclave's compiler: {e}")
    hostdir = os.path.join(work, "hostdir")
    os.makedirs(hostdir, exist_ok=True)
    tree.socket_file(os.path.join(root, "usr", "share", "exclave-test.sock"))
    true = tree.vbin(root, "true")
    # unix_socket's: an absolute host directory in bwrap's own /tmp, short enough for sun_path, and
    # a working directory deeper than sun_path holds
    sockhost = f"/tmp/exclave-sockhost-{os.getpid()}"
    deep = os.path.join(work, "sockhost")
    deep = os.path.join(deep, "d" * max(1, 120 - len(deep)))
    os.makedirs(deep, exist_ok=True)
    cmds = {
        "ro_matrix": f"{work}/ro_matrix {hostdir} /usr/bin/dash",
        "openat2": (
            f"EXCLAVE_TEST_TRUE={true} {work}/openat2 {hostdir} && "
            f"{work}/openat2 pathless {hostdir}"
        ),
        "creat_slash": f"{work}/creat_slash {hostdir}",
        "slash_links": (
            f"mkdir -p {hostdir}/slash_links && {work}/slash_links {hostdir}/slash_links {true} "
            f"/usr/share {tree.dir_link(root)}"
        ),
        "open_flags": f"{work}/open_flags {hostdir}",
        "unix_socket": (
            f"mkdir {sockhost} && {work}/unix_socket {sockhost} /usr/share {true} "
            f"/usr/share/exclave-test.sock {deep}"
        ),
        "magic_links": (
            f"echo piped | {work}/magic_links pathless {hostdir} && "
            f"{work}/magic_links link-empty {hostdir}"
        ),
    }
    fails = 0
    for name in PROGRAMS:
        try:
            rc, out, err = run_bwrap(root, work, cmds[name], sp, timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            rc, out, err = -9, "", f"killed after {TIMEOUT} s"
        bad = judge(name, rc, out, hostdir) + ([err.strip()] if err else [])
        if bad:
            fails += 1
            print(
                f"FAIL {name} under the kernel's read-only bind (rc {rc}): the suite expects "
                "otherwise\n     " + "\n     ".join(x.strip() for x in bad)
            )
        else:
            last = out.strip().splitlines()[-1] if out.strip() else ""
            print(f"PASS {name}: the kernel agrees with the suite's expectations ({last})")
    return fails


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--exclave", required=True)
    ap.add_argument("--work", default=os.path.join(REPO, "build", "oracle-work"))
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    why = bwrap_unusable()
    if why:
        print(f"{why}; the oracle cannot run")
        return 0
    work = os.path.abspath(args.work)
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)
    # the two worlds, kept between runs (tree.kept_worlds)
    ex, root = tree.kept_worlds(os.path.abspath(args.exclave), "ns")
    identity_links(root)
    with open(os.path.join(root, "usr", "share", "exclave-test-marker"), "w") as f:
        f.write("marker\n")
    with open(os.path.join(work, "hello.c"), "w") as f:
        f.write(
            "#include <stdio.h>\n"
            'int main(int c, char **v) { printf("hello %d\\n", c); return 0; }\n'
        )
    sp = Spellings.of(os.path.join(ex, "tree"))
    # 1. the suite's path programs against the kernel: the same programs, the same expectations, a
    # real read-only bind
    fails = programs_under_the_kernel(ex, root, work, sp)
    # 2. workloads twice
    for cmd, meant in WORKLOADS:
        shown = cmd
        for f in ("moved", "linked", "symlinked", "dashcopy", "hello", "hello.o", "s.sh", "lnk"):
            p = os.path.join(work, f)
            if os.path.lexists(p):
                os.remove(p)
        try:
            b = run_bwrap(root, work, cmd, sp, timeout=TIMEOUT)
            for f in (
                "moved",
                "linked",
                "symlinked",
                "dashcopy",
                "hello",
                "hello.o",
                "s.sh",
                "lnk",
            ):
                p = os.path.join(work, f)
                if os.path.lexists(p):
                    os.remove(p)
            o = run_launcher(ex, work, cmd, sp, timeout=TIMEOUT)
        except subprocess.TimeoutExpired as e:
            fails += 1
            world = "bwrap" if e.cmd[0] == "bwrap" else "the launcher"
            print(f"FAIL {shown[:70]}\n     {world} killed after {TIMEOUT} s")
            continue
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
        # a workload meant to succeed does under the kernel, or the comparison tests nothing
        if meant is not None and (b[0] or b[2] or not meant(b[1], root)):
            fails += 1
            print(
                f"FAIL {shown[:70]}\n     bwrap does not show what the workload is meant to: "
                f"rc={bn[0]} out={bn[1][:300]!r} err={bn[2][:200]!r}"
            )
        elif bn == on:
            print(f"PASS {shown[:70]}")
        else:
            fails += 1
            print(
                f"FAIL {shown[:70]}\n"
                f"     bwrap : rc={bn[0]} out={bn[1][:300]!r} err={bn[2][:200]!r}\n"
                f"     launcher: rc={on[0]} out={on[1][:300]!r} err={on[2][:200]!r}"
            )
    print(f"{len(WORKLOADS) + len(PROGRAMS)} workloads, {fails} failures")
    if not args.keep and not fails:
        shutil.rmtree(work, ignore_errors=True)
    return fails


if __name__ == "__main__":
    sys.exit(main())
