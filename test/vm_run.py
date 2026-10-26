"""vm_run.py — run a script beside some files in each VM of the kernel matrix (DESIGN.md 12).

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
    ap.add_argument(
        "--images", default=os.path.join(os.path.expanduser("~"), ".cache", "exclave-images")
    )
    ap.add_argument("--memory", type=int, default=2048)
    ap.add_argument("files", nargs="*")
    a = ap.parse_args()
    work = os.path.abspath(a.work)
    os.makedirs(work, exist_ok=True)
    key = os.path.join(work, "id_ed25519")
    if not os.path.exists(key):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
    with open(key + ".pub") as f:
        pubkey = f.read().strip()
    rows: list[tuple[str, str]] = []
    fails = 0
    for name, _kernel, user, urls, family, _notes, arch in matrix.VMS:
        if arch != "x86_64" or (a.only and name not in a.only.split(",")):
            continue
        image = os.path.join(a.images, name + ".qcow2")
        if not any(matrix.fetch(u, image) for u in urls):
            rows.append((name, "image not available"))
            fails += 1
            continue
        with open(os.path.join(work, name + "-user-data"), "w") as f:
            f.write(matrix.user_data(family, pubkey))
        with open(os.path.join(work, name + "-meta-data"), "w") as f:
            f.write(f"instance-id: exclave-{name}\nlocal-hostname: {name}\n")
        subprocess.run(
            [
                "cloud-localds",
                os.path.join(work, name + "-seed.iso"),
                os.path.join(work, name + "-user-data"),
                os.path.join(work, name + "-meta-data"),
            ],
            check=True,
        )
        matrix.log("booting", name)
        vm = matrix.VM(name, image, work, user, matrix.free_port(), memory=a.memory, arch=arch)
        try:
            if not vm.wait(deadline=600):
                rows.append((name, f"did not come up (see {name}-console.log)"))
                fails += 1
                continue
            uname = vm.ssh("uname -r")[1].strip()
            for p in [*a.files, a.script]:
                vm.scp(p, os.path.basename(p))
            rc, out = vm.ssh(f"sh {os.path.basename(a.script)} 2>&1", timeout=3600)
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
