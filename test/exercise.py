#!/usr/bin/env python3
"""exercise.py — one program, two worlds (PROPOSAL.md 17): compile PROG.c with the can's compiler, run it under bwrap with
the unwrapped tree read-only at / (the namespace oracle's world, where the kernel answers) and under the opener, and
print the two outputs side by side, marking the lines that differ. This is how a limitation is measured before it is
fixed: the program prints one line per case, "<case>: <answer>", and the kernel's column is the expectation.

    test/exercise.py --can CAN PROG.c [ARGS...]     HOSTDIR in ARGS is replaced by a fresh writable host directory

The work lives under build/exercise/<can>: a copy of the can reopened with build/opener, the unwrapped tree for bwrap,
both with a socket file at /usr/share/cont-test.sock and the suite's marker. Needs bwrap and user namespaces; says so
and exits 2 when it cannot run. Exit status: the number of lines that differ."""
import argparse
import hashlib
import os
import shutil
import socket
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "cannery"))
import oracle_ns  # noqa: E402
import tree  # noqa: E402
import cannery  # noqa: E402
import build  # noqa: E402


def setup(can0, work):
    """A closed copy for the opener and an unwrapped tree for bwrap, made once per can."""
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    can = os.path.join(work, "can")
    if subprocess.run(["cp", "-al", can0, can], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        shutil.rmtree(can, ignore_errors=True)
        shutil.copytree(can0, can, symlinks=True)
    for f in os.listdir(os.path.join(can, ".can")):                      # the files under .can/ copied: reopen must not write through a link
        p = os.path.join(can, ".can", f)
        if os.path.isfile(p) and not os.path.islink(p):
            shutil.copy2(p, p + ".copy")
            os.replace(p + ".copy", p)
    subprocess.run([sys.executable, os.path.join(REPO, "cannery", "cannery.py"), "reopen", can, os.path.join(REPO, "build", "opener")],
                   check=True, stdout=subprocess.DEVNULL)
    root = os.path.join(work, "tree", "root")
    shutil.copytree(os.path.join(can, "root"), root, symlinks=True, copy_function=cannery.link_or_copy)
    build.unwrap(os.path.join(work, "tree"), log=lambda *x: None)
    for r in (root, os.path.join(can, "root")):
        sk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sk.bind(os.path.join(r, "usr", "share", "cont-test.sock"))
        sk.close()
        with open(os.path.join(r, "usr", "share", "cont-test-marker"), "w") as f:
            f.write("marker\n")
    for f in oracle_ns.IDENTITY:                                          # as the namespace oracle: the host's link text, its target bound
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
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--can", required=True)
    ap.add_argument("prog", help="a C source, compiled with the can's compiler")
    ap.add_argument("args", nargs="*", help="arguments; HOSTDIR is replaced by a fresh writable host directory")
    a = ap.parse_args()
    if not shutil.which("bwrap") or subprocess.run(["bwrap", "--ro-bind", "/", "/", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        sys.exit("bwrap or user namespaces unavailable; the kernel's world cannot be made here")
    can0 = os.path.abspath(a.can)
    key = hashlib.blake2b(open(os.path.join(can0, ".can", "lock"), "rb").read(), digest_size=6).hexdigest()
    work = os.path.join(REPO, "build", "exercise", os.path.basename(can0).replace(".can", "") + "-" + key)
    if not os.path.exists(os.path.join(work, "can", ".can", "lock")):
        setup(can0, work)
    can, root = os.path.join(work, "can"), os.path.join(work, "tree", "root")
    r = os.path.join(can, "root")
    machine = os.uname().machine
    oracle_ns.GCC = tree.compiler(r, machine) or oracle_ns.GCC             # the tree's spellings for both worlds
    oracle_ns.SH, oracle_ns.SHX, oracle_ns.LIBC = tree.vbin(r, "sh"), tree.resolve(r, tree.vbin(r, "sh")), tree.libc(r, machine)
    gcc = os.path.join(r, tree.vbin(r, oracle_ns.GCC).lstrip("/"))
    prog = os.path.join(work, os.path.basename(a.prog).rsplit(".", 1)[0])
    p = subprocess.run([gcc, "-O1", "-o", prog, os.path.abspath(a.prog)], cwd=work, env={"PATH": "/usr/bin:/bin"}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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
    rc_o, out_o, err_o = oracle_ns.run_opener(can, work, argv, prog=prog)
    lb, lo = out_b.splitlines(), out_o.splitlines()
    print("%-45s | %-30s | %-30s" % ("case", "kernel (bwrap)", "opener"))
    differ = 0
    for i in range(max(len(lb), len(lo))):
        b = lb[i] if i < len(lb) else "(missing)"
        o = lo[i] if i < len(lo) else "(missing)"
        cb, _, rb = b.partition(": ")
        co, _, ro = o.partition(": ")
        same = cb == co and rb == ro
        differ += not same
        print("%-45s | %-30s | %-30s%s" % (cb[:45], rb, ro if co == cb else o, "" if same else "   <-- differs"))
    print("rc: bwrap=%d opener=%d; %d differ%s%s" % (rc_b, rc_o, differ, "; bwrap stderr: %r" % err_b[:200] if err_b else "", "; opener stderr: %r" % err_o[:200] if err_o else ""))
    return differ


if __name__ == "__main__":
    sys.exit(main())
