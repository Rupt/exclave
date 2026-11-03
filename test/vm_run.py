"""Run a script beside some files in each VM of the kernel matrix (DESIGN.md 12).

    test/vm_run.py --script SH [--only NAME,...] [--work DIR] [--images DIR] [--memory MB] FILE...

For exclaves made to ship, where the matrix's suite does not apply: each x86-64 row of
test/matrix.py boots as there, the files are copied into the home directory beside the script,
`sh SCRIPT` runs from there, and its exit status and last lines are the row. The whole output of
each row goes to WORK/NAME.log. Exit status 0 when every row booted and the script exited 0.
"""

import argparse
import os
import subprocess
import sys

import matrix

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--script", required=True)
    ap.add_argument("--only")
    ap.add_argument("--work", default=os.path.join(REPO, "build", "vm-run-work"))
    ap.add_argument("--images", default=os.path.join(REPO, "build", "images"))
    ap.add_argument("--memory", type=int, default=2048)
    ap.add_argument("files", nargs="*")
    args = ap.parse_args()
    work = os.path.abspath(args.work)
    os.makedirs(work, exist_ok=True)
    key = os.path.join(work, "id_ed25519")
    if not os.path.exists(key):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
    with open(key + ".pub") as f:
        pubkey = f.read().strip()
    rows: list[tuple[str, str]] = []
    fails = 0
    for row in matrix.VMS:
        name = row.name
        if row.arch != "x86_64" or (args.only and name not in args.only.split(",")):
            continue
        vm, why = matrix.boot(row, args.images, work, pubkey, memory=args.memory)
        if vm is None:
            rows.append((name, why))
            fails += 1
            continue
        try:
            uname = vm.ssh("uname -r")[1].strip()
            for p in [*args.files, args.script]:
                vm.scp(p, os.path.basename(p))
            rc, out = vm.ssh(f"sh {os.path.basename(args.script)} 2>&1", timeout=3600)
            with open(os.path.join(work, name + ".log"), "w") as f:
                f.write(out)
            tail = " | ".join(line.strip() for line in out.strip().splitlines()[-3:])
            matrix.log(name, uname, f"rc={rc:d}", tail)
            rows.append((name, f"{uname} rc={rc:d} {tail}"))
            fails += 1 if rc else 0
        finally:
            vm.stop()
    for name, what in rows:
        print(f"{name:<14} {what}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
