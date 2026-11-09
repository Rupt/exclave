"""Run one program in two worlds, the kernel's and the launcher's, and mark where they differ (17).

Compile PROG.c with the exclave's compiler, run it under bwrap with the unwrapped tree read-only
at / (the namespace oracle's world, where the kernel answers) and under the launcher, and print the
two outputs side by side, marking the lines that differ. This is how a limitation is measured
before it is fixed: the program prints one line per case, "<case>: <answer>", and the kernel's
column is the expectation.

    scripts/exercise --exclave EXCLAVE [--cflag FLAG...] PROG.c [ARGS...]

HOSTDIR in ARGS is replaced by a fresh writable host directory.

The work lives under build/exercise/<exclave>-<hashes file's hash>: a copy of the exclave relinked
with build/launcher, and relinked again whenever the build has changed since, the unwrapped tree
for bwrap, both with a socket file at /usr/share/exclave-test.sock and the suite's marker. Needs
bwrap and user namespaces; says so and exits 1 when it cannot run. Exit status: the number of lines
that differ.
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys

import oracle_ns
import tree

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def setup(ex0: str, work: str) -> None:
    """Make a wrapped copy for the launcher and an unwrapped tree for bwrap, once per exclave."""
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    # a copy relinked with the build (17)
    ex = tree.fresh_exclave(ex0, os.path.join(work, "exclave"))
    root = os.path.join(work, "bare", "tree")
    shutil.copytree(os.path.join(ex, "tree"), root, symlinks=True, copy_function=tree.link_or_copy)
    tree.unwrap_tree(os.path.join(work, "bare"))
    for r in (root, os.path.join(ex, "tree")):
        tree.socket_file(os.path.join(r, "usr", "share", "exclave-test.sock"))
        with open(os.path.join(r, "usr", "share", "exclave-test-marker"), "w") as f:
            f.write("marker\n")
    # as the oracles: the placeholders, the host's link text, a mount point for its target
    tree.identity_links(root)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--exclave", required=True)
    ap.add_argument(
        "--cflag",
        action="append",
        default=[],
        help="a flag for the compile, as -fexceptions for unwind_frame.c; repeatable",
    )
    ap.add_argument("prog", help="a C source, compiled with the exclave's compiler")
    ap.add_argument(
        "args", nargs="*", help="arguments; HOSTDIR is replaced by a fresh writable host directory"
    )
    args = ap.parse_args()
    if (
        not shutil.which("bwrap")
        or subprocess.run(
            ["bwrap", "--ro-bind", "/", "/", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
    ):
        sys.exit("bwrap or user namespaces unavailable; the kernel's world cannot be made here")
    ex0 = os.path.abspath(args.exclave)
    with open(os.path.join(ex0, ".exclave", "hashes"), "rb") as f:
        key = hashlib.blake2b(f.read(), digest_size=6).hexdigest()
    work = os.path.join(
        REPO, "build", "exercise", os.path.basename(ex0).replace(".exclave", "") + "-" + key
    )
    if not os.path.exists(os.path.join(work, "exclave", ".exclave", "hashes")):
        setup(ex0, work)
    elif tree.relink_if_stale(os.path.join(work, "exclave")):
        print("the build changed since this copy was made: relinked")
    ex, root = os.path.join(work, "exclave"), os.path.join(work, "bare", "tree")
    r = os.path.join(ex, "tree")
    # the tree's spellings for both worlds
    sp = oracle_ns.Spellings.of(r)
    gcc = os.path.join(r, tree.vbin(r, sp.gcc).lstrip("/"))
    prog = os.path.join(work, os.path.basename(args.prog).rsplit(".", 1)[0])
    p = subprocess.run(
        [gcc, "-O1", *args.cflag, "-o", prog, os.path.abspath(args.prog)],
        cwd=work,
        env={"PATH": "/usr/bin:/bin"},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if p.returncode:
        sys.exit("compile: " + p.stdout.decode(errors="replace"))
    hostdir = os.path.join(work, "hostdir")

    def fresh() -> None:
        shutil.rmtree(hostdir, ignore_errors=True)
        os.makedirs(hostdir)

    argv = [x.replace("HOSTDIR", hostdir) for x in args.args]
    fresh()
    # the trust exerciser's world is the probe's: the identity directories with their links' target
    # directories (tree.identity_dir_binds), which would hide the tree's for any other program
    targets = os.path.basename(args.prog) == "trustdir.c"
    rc_b, out_b, err_b = oracle_ns.run_bwrap(
        root, work, " ".join([prog, *argv]), sp, identity_targets=targets
    )
    fresh()
    rc_o, out_o, err_o = oracle_ns.run_launcher(ex, work, argv, sp, prog=prog)
    lb, lo = out_b.splitlines(), out_o.splitlines()
    print(f"{'case':<45} | {'kernel (bwrap)':<30} | {'launcher':<30}")
    differ = 0
    for i in range(max(len(lb), len(lo))):
        b = lb[i] if i < len(lb) else "(missing)"
        o = lo[i] if i < len(lo) else "(missing)"
        cb, _, rb = b.partition(": ")
        co, _, ro = o.partition(": ")
        same = cb == co and rb == ro
        differ += not same
        shown = ro if co == cb else o
        mark = "" if same else "   <-- differs"
        print(f"{cb[:45]:<45} | {rb:<30} | {shown:<30}{mark}")
    eb = f"; bwrap stderr: {err_b[:200]!r}" if err_b else ""
    eo = f"; launcher stderr: {err_o[:200]!r}" if err_o else ""
    print(f"rc: bwrap={rc_b:d} launcher={rc_o:d}; {differ:d} differ{eb}{eo}")
    return differ


if __name__ == "__main__":
    sys.exit(main())
