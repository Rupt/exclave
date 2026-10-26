"""exercise.py — one program, two worlds (DESIGN.md 17): compile PROG.c with the exclave's compiler, run it under bwrap with
the unwrapped tree read-only at / (the namespace oracle's world, where the kernel answers) and under the launcher, and
print the two outputs side by side, marking the lines that differ. This is how a limitation is measured before it is
fixed: the program prints one line per case, "<case>: <answer>", and the kernel's column is the expectation.

    scripts/exercise --exclave EXCLAVE PROG.c [ARGS...]     HOSTDIR in ARGS is replaced by a fresh writable host directory

The work lives under build/exercise/<exclave>-<hashes file's hash>: a copy of the exclave relinked with build/launcher, and relinked again whenever the
build has changed since, the unwrapped tree for bwrap, both with a socket file at /usr/share/exclave-test.sock and the
suite's marker. Needs bwrap and user namespaces; says so and exits 1 when it cannot run. Exit status: the number of
lines that differ."""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "exclave"))
import oracle_ns  # noqa: E402
import tree  # noqa: E402
import exclave  # noqa: E402
import build  # noqa: E402


def setup(ex0, work):
    """A wrapped copy for the launcher and an unwrapped tree for bwrap, made once per exclave."""
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    ex = tree.fresh_exclave(
        ex0, os.path.join(work, "exclave")
    )  # a copy relinked with the build (17)
    root = os.path.join(work, "bare", "tree")
    shutil.copytree(
        os.path.join(ex, "tree"), root, symlinks=True, copy_function=exclave.link_or_copy
    )
    build.unwrap(os.path.join(work, "bare"), log=lambda *x: None)
    for r in (root, os.path.join(ex, "tree")):
        tree.socket_file(os.path.join(r, "usr", "share", "exclave-test.sock"))
        with open(os.path.join(r, "usr", "share", "exclave-test-marker"), "w") as f:
            f.write("marker\n")
    for f in oracle_ns.IDENTITY:  # as the namespace oracle: the host's link text, its target bound
        p_ = os.path.join(root, f.lstrip("/"))
        if os.path.islink(f) and os.path.lexists(p_):
            os.remove(p_)
            os.symlink(os.readlink(f), p_)
            t = os.path.realpath(f)
            tp = os.path.join(root, t.lstrip("/"))
            if not os.path.lexists(tp) and not t.startswith(("/run/", "/tmp/", "/dev/", "/proc/")):
                os.makedirs(os.path.dirname(tp), exist_ok=True)
                open(tp, "wb").close()


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--exclave", required=True)
    ap.add_argument("prog", help="a C source, compiled with the exclave's compiler")
    ap.add_argument(
        "args", nargs="*", help="arguments; HOSTDIR is replaced by a fresh writable host directory"
    )
    a = ap.parse_args()
    if (
        not shutil.which("bwrap")
        or subprocess.run(
            ["bwrap", "--ro-bind", "/", "/", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
    ):
        sys.exit("bwrap or user namespaces unavailable; the kernel's world cannot be made here")
    ex0 = os.path.abspath(a.exclave)
    key = hashlib.blake2b(
        open(os.path.join(ex0, ".exclave", "hashes"), "rb").read(), digest_size=6
    ).hexdigest()
    work = os.path.join(
        REPO, "build", "exercise", os.path.basename(ex0).replace(".exclave", "") + "-" + key
    )
    if not os.path.exists(os.path.join(work, "exclave", ".exclave", "hashes")):
        setup(ex0, work)
    elif tree.relink_if_stale(os.path.join(work, "exclave")):
        print("the build changed since this copy was made: relinked")
    ex, root = os.path.join(work, "exclave"), os.path.join(work, "bare", "tree")
    r = os.path.join(ex, "tree")
    machine = os.uname().machine
    oracle_ns.GCC = (
        tree.compiler(r, machine) or oracle_ns.GCC
    )  # the tree's spellings for both worlds
    oracle_ns.SH, oracle_ns.SHX, oracle_ns.LIBC = (
        tree.vbin(r, "sh"),
        tree.resolve(r, tree.vbin(r, "sh")),
        tree.libc(r, machine),
    )
    gcc = os.path.join(r, tree.vbin(r, oracle_ns.GCC).lstrip("/"))
    prog = os.path.join(work, os.path.basename(a.prog).rsplit(".", 1)[0])
    p = subprocess.run(
        [gcc, "-O1", "-o", prog, os.path.abspath(a.prog)],
        cwd=work,
        env={"PATH": "/usr/bin:/bin"},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if p.returncode:
        sys.exit("compile: " + p.stdout.decode(errors="replace"))
    hostdir = os.path.join(work, "hostdir")

    def fresh():
        shutil.rmtree(hostdir, ignore_errors=True)
        os.makedirs(hostdir)

    argv = [x.replace("HOSTDIR", hostdir) for x in a.args]
    fresh()
    rc_b, out_b, err_b = oracle_ns.run_bwrap(root, work, " ".join([prog] + argv))
    fresh()
    rc_o, out_o, err_o = oracle_ns.run_launcher(ex, work, argv, prog=prog)
    lb, lo = out_b.splitlines(), out_o.splitlines()
    print("%-45s | %-30s | %-30s" % ("case", "kernel (bwrap)", "launcher"))
    differ = 0
    for i in range(max(len(lb), len(lo))):
        b = lb[i] if i < len(lb) else "(missing)"
        o = lo[i] if i < len(lo) else "(missing)"
        cb, _, rb = b.partition(": ")
        co, _, ro = o.partition(": ")
        same = cb == co and rb == ro
        differ += not same
        print(
            "%-45s | %-30s | %-30s%s"
            % (cb[:45], rb, ro if co == cb else o, "" if same else "   <-- differs")
        )
    print(
        "rc: bwrap=%d launcher=%d; %d differ%s%s"
        % (
            rc_b,
            rc_o,
            differ,
            "; bwrap stderr: %r" % err_b[:200] if err_b else "",
            "; launcher stderr: %r" % err_o[:200] if err_o else "",
        )
    )
    return differ


if __name__ == "__main__":
    sys.exit(main())
