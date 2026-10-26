"""vm_run.py — run a script beside some files in each virtual machine of the kernel matrix (DESIGN.md 12).

    test/vm_run.py --script SH [--only NAME,...] [--work DIR] [--images DIR] [--memory MB] FILE...

For exclaves made to ship, where the matrix's suite does not apply: each x86-64 row of test/matrix.py boots as
there, the files are copied into the home directory beside the script, `sh SCRIPT` runs from there, and
its exit status and last lines are the row. The whole output of each row goes to WORK/NAME.log. Exit
status 0 when every row booted and the script exited 0.
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import matrix  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--script", required=True)
    ap.add_argument("--only")
    ap.add_argument("--work", default=os.path.join(REPO, "build", "vm-run-work"))
    ap.add_argument("--images", default=os.path.join(os.path.expanduser("~"), ".cache", "exclave-images"))
    ap.add_argument("--memory", type=int, default=2048)
    ap.add_argument("files", nargs="*")
    a = ap.parse_args()
    work = os.path.abspath(a.work)
    os.makedirs(work, exist_ok=True)
    key = os.path.join(work, "id_ed25519")
    if not os.path.exists(key):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
    pubkey = open(key + ".pub").read().strip()
    rows, fails = [], 0
    for name, kernel, user, urls, family, notes, arch in matrix.VMS:
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
            f.write("instance-id: exclave-%s\nlocal-hostname: %s\n" % (name, name))
        subprocess.run(["cloud-localds", os.path.join(work, name + "-seed.iso"), os.path.join(work, name + "-user-data"),
                        os.path.join(work, name + "-meta-data")], check=True)
        matrix.log("booting", name)
        vm = matrix.VM(name, image, work, user, matrix.free_port(), a.memory, arch)
        try:
            if not vm.wait(deadline=600):
                rows.append((name, "did not come up (see %s-console.log)" % name))
                fails += 1
                continue
            uname = vm.ssh("uname -r")[1].strip()
            for p in a.files + [a.script]:
                vm.scp(p, os.path.basename(p))
            rc, out = vm.ssh("sh %s 2>&1" % os.path.basename(a.script), timeout=3600)
            with open(os.path.join(work, name + ".log"), "w") as f:
                f.write(out)
            tail = " | ".join(l.strip() for l in out.strip().splitlines()[-3:])
            matrix.log(name, uname, "rc=%d" % rc, tail)
            rows.append((name, "%s rc=%d %s" % (uname, rc, tail)))
            fails += 1 if rc else 0
        finally:
            vm.stop()
    for name, what in rows:
        print("%-14s %s" % (name, what))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
