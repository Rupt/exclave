#!/usr/bin/env python3
"""matrix.py — the kernel matrix (PROPOSAL.md 12, 17 item 5): an exclave built here, run in virtual machines.

    test/matrix.py --exclave EXCLAVE [--only NAME,...] [--work DIR] [--images DIR] [--memory MB] [--arm64 --debs-arm64 DIR]
                   [--docker-profile FILE]

Each row of VMS names a distribution cloud image. The image is downloaded once, booted under QEMU with
KVM behind a copy-on-write overlay and a cloud-init seed that installs python3 and strace (and bubblewrap
where it exists), the exclave and this repository's test tree and launcher are copied in over SSH, and the
regression suite runs there; the oracles, the syscall probe and, given the profile, the Docker-profile run follow where bubblewrap works.
One VM at a time, 1 GB each, 2 GB for the emulated row. Results go to build/matrix-results.md.
"""
import argparse
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import tree  # noqa: E402

# name, expected kernel, ssh user, image URL candidates (first that downloads wins), package family, notes, arch
VMS = [
    ("centos-7", "3.10", "centos", ["https://cloud.centos.org/centos/7/images/CentOS-7-x86_64-GenericCloud-2211.qcow2"], "centos7", "EOL; yum repos moved to vault", "x86_64"),
    ("ubuntu-18.04", "4.15", "ubuntu", ["https://cloud-images.ubuntu.com/bionic/current/bionic-server-cloudimg-amd64.img"], "apt", "", "x86_64"),
    ("rocky-8", "4.18", "rocky", ["https://dl.rockylinux.org/pub/rocky/8/images/x86_64/Rocky-8-GenericCloud.latest.x86_64.qcow2"], "dnf", "", "x86_64"),
    ("ubuntu-20.04", "5.4", "ubuntu", ["https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img"], "apt", "", "x86_64"),
    ("debian-11", "5.10", "debian", ["https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-generic-amd64.qcow2"], "apt", "", "x86_64"),
    ("ubuntu-22.04", "5.15", "ubuntu", ["https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"], "apt", "", "x86_64"),
    ("debian-12", "6.1", "debian", ["https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"], "apt", "", "x86_64"),
    ("fedora", "6.x", "fedora", ["https://download.fedoraproject.org/pub/fedora/linux/releases/42/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-42-1.1.x86_64.qcow2",
                                 "https://download.fedoraproject.org/pub/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2",
                                 "https://download.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2"], "dnf", "SELinux enforcing", "x86_64"),
    ("alpine", "6.x", "alpine", ["https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/cloud/nocloud_alpine-3.21.3-x86_64-bios-cloudinit-r0.qcow2",
                                 "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/cloud/nocloud_alpine-3.20.3-x86_64-bios-cloudinit-r0.qcow2"], "apk", "musl host, busybox", "x86_64"),
    # aarch64 under TCG (12): the same suite and oracles, the arm64 launcher and exclave, ten to twenty times slower
    ("noble-arm64", "6.8", "ubuntu", ["https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"], "apt", "aarch64, TCG emulation", "aarch64"),]

PACKAGES = {"apt": ["python3", "strace", "bubblewrap"], "dnf": ["python3", "strace", "bubblewrap"], "apk": ["python3", "strace", "bubblewrap", "bash"],
            "centos7": ["python3", "strace"]}


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def fetch(url, dst, tries=4):
    """Download with resume and a length check: a connection that closes early must not leave a short image."""
    if os.path.exists(dst):
        return True
    tmp = dst + ".tmp"
    for attempt in range(tries):
        have = os.path.getsize(tmp) if os.path.exists(tmp) else 0
        log("downloading", url, "from byte %d" % have if have else "")
        try:
            headers = {"User-Agent": "exclave-matrix/0.1"}
            if have:
                headers["Range"] = "bytes=%d-" % have
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as r:
                if have and r.status != 206:
                    have = 0                                   # no resume support: start over
                total = r.headers.get("Content-Range", "").split("/")[-1] or r.headers.get("Content-Length")
                total = int(total) if total and total.isdigit() else None
                if have == 0 and r.status == 206:
                    total = None
                with open(tmp, "ab" if have else "wb") as f:
                    shutil.copyfileobj(r, f, 1 << 20)
            size = os.path.getsize(tmp)
            if total is not None and size != total:
                log("short download: %d of %d bytes, retrying" % (size, total))
                continue
            os.replace(tmp, dst)
            return True
        except Exception as e:  # noqa: BLE001
            log("failed:", e)
            if attempt == tries - 1 and os.path.exists(tmp) and os.path.getsize(tmp) == 0:
                os.remove(tmp)
    return False


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def user_data(family, pubkey):
    pk = PACKAGES[family]
    if family == "centos7":
        return "\n".join(["#cloud-config", "ssh_authorized_keys:", "  - " + pubkey, "runcmd:",
                          "  - sed -i 's/^mirrorlist=/#mirrorlist=/; s|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' /etc/yum.repos.d/CentOS-*.repo",
                          "  - yum install -y " + " ".join(pk), "  - touch /var/tmp/exclave-ready", ""])
    # apt installs the list in one transaction, so one package the mirror has dropped fails them all: Debian 11's security
    # suite, winding down after its LTS, still lists a bubblewrap whose file is gone. Each package again on its own, then
    # from the release's main suite
    retry = ["  - for p in %s; do dpkg -s $p >/dev/null 2>&1 || apt-get install -y $p || apt-get install -y $p=$(apt-cache madison $p | "
             "awk '!/security/ {print $3; exit}'); done" % " ".join(pk)] if family == "apt" else []
    return "\n".join(["#cloud-config", "ssh_authorized_keys:", "  - " + pubkey, "package_update: true", "packages:"] + ["  - " + p for p in pk]
                     + ["runcmd:"] + retry + ["  - touch /var/tmp/exclave-ready", ""])


AAVMF = "/usr/share/AAVMF"


class VM:
    def __init__(self, name, image, work, user, port, memory, arch="x86_64"):
        self.name, self.user, self.port, self.work, self.arch = name, user, port, work, arch
        self.overlay = os.path.join(work, name + ".qcow2")
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", image, "-F", "qcow2", self.overlay], check=True)
        subprocess.run(["qemu-img", "resize", "-q", self.overlay, "+8G"], check=True)   # cloud-init grows the root; some images ship 2 GB
        self.seed = os.path.join(work, name + "-seed.iso")
        self.key = os.path.join(work, "id_ed25519")
        common = ["-display", "none", "-serial", "file:" + os.path.join(work, name + "-console.log"),
                  "-drive", "file=%s,if=virtio,format=qcow2" % self.overlay,
                  "-drive", "file=%s,if=virtio,format=raw" % self.seed,
                  "-netdev", "user,id=n0,hostfwd=tcp:127.0.0.1:%d-:22" % port, "-device", "virtio-net-pci,netdev=n0"]
        if arch == "aarch64":                                   # no KVM for another architecture: TCG, and UEFI firmware, which arm64 images boot from
            varstore = os.path.join(work, name + "-vars.fd")
            shutil.copyfile(os.path.join(AAVMF, "AAVMF_VARS.fd"), varstore)
            cmd = ["qemu-system-aarch64", "-M", "virt", "-accel", "tcg", "-cpu", "max", "-m", str(max(memory, 2048)), "-smp", "4",
                   "-drive", "if=pflash,format=raw,readonly=on,file=" + os.path.join(AAVMF, "AAVMF_CODE.fd"),
                   "-drive", "if=pflash,format=raw,file=" + varstore] + common
        else:
            cmd = ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-m", str(memory), "-smp", "2"] + common
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def ssh(self, cmd, timeout=1800, quiet=False):
        p = subprocess.run(["ssh", "-p", str(self.port), "-i", self.key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                            "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10", "%s@127.0.0.1" % self.user, cmd],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        return p.returncode, p.stdout.decode(errors="replace")

    def scp(self, src, dst):
        subprocess.run(["scp", "-q", "-P", str(self.port), "-i", self.key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                        "-o", "LogLevel=ERROR", src, "%s@127.0.0.1:%s" % (self.user, dst)], check=True)

    def wait(self, deadline=600):
        t = time.time()
        while time.time() - t < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                rc, out = self.ssh("test -e /var/tmp/exclave-ready && echo ready", timeout=20)
                if "ready" in out:
                    return True
            except subprocess.TimeoutExpired:
                pass
            time.sleep(5)
        return False

    def stop(self):
        try:
            self.ssh("sudo poweroff || doas poweroff || poweroff", timeout=20)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exclave", required=True)
    ap.add_argument("--only")
    ap.add_argument("--work", default=os.path.join(REPO, "build", "matrix-work"))
    ap.add_argument("--images", default=os.path.join(os.path.expanduser("~"), ".cache", "exclave-images"))
    ap.add_argument("--memory", type=int, default=1024)
    ap.add_argument("--arm64", action="store_true", help="include the emulated aarch64 VM (slow); --only names it too")
    ap.add_argument("--debs-arm64", help="directory of arm64 .deb files the aarch64 VM makes its gcc exclave from")
    ap.add_argument("--docker-profile", help="Docker's default seccomp profile (test/inputs.sh fetches it); without it the Docker-profile run is left out")
    a = ap.parse_args()
    if not shutil.which("qemu-system-x86_64") or not shutil.which("cloud-localds"):
        sys.exit("need qemu-system-x86_64 and cloud-localds")
    ex, work = os.path.abspath(a.exclave), os.path.abspath(a.work)
    os.makedirs(work, exist_ok=True)
    os.makedirs(a.images, exist_ok=True)
    key = os.path.join(work, "id_ed25519")
    if not os.path.exists(key):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
    pubkey = open(key + ".pub").read().strip()
    # the payload: the exclave (hard links preserved by tar) and the repository's test tree, exclave, launcher and, where the
    # host has go, the Go regression's programs built for the VM's machine. For the
    # aarch64 VM the payload carries the arm64 package files and the cross-built launchers under the suite's names:
    # the exclave is unpacked and wrapped in the VM, on its own architecture (10.1).
    payloads = {}

    def payload_for(arch):
        if arch in payloads:
            return payloads[arch]
        payload = os.path.join(work, "payload-%s.tar.gz" % arch)
        if True:                                                  # packed afresh every run: a kept payload once carried a stale test tree
            log("packing the test tree for", arch)
            with tarfile.open(payload, "w:gz", compresslevel=1) as t:
                for d in ("test", "exclave", "src"):                  # src: the filter model the suite builds in the VM (filter_model)
                    t.add(os.path.join(REPO, d), arcname="repo/" + d)
                if a.docker_profile:
                    t.add(a.docker_profile, arcname="docker-seccomp.json")
                go = tree.go_toolchain()                          # the Go regression's programs, built here for the VM's machine: the VMs have no go
                if go:
                    for n, p in tree.go_build(go, os.path.join(work, "go-" + arch), arch, work):
                        t.add(p, arcname="repo/build/go/%s/%s" % (arch, n))
                if arch == "x86_64":
                    t.add(ex, arcname="ex")
                    t.add(os.path.join(REPO, "build", "launcher"), arcname="repo/build/launcher")
                    if os.path.exists(os.path.join(REPO, "build", "launcher-old")):
                        t.add(os.path.join(REPO, "build", "launcher-old"), arcname="repo/build/launcher-old")
                    if os.path.exists(os.path.join(REPO, "build", "sysroot-hello")):          # test/sysroot.py's output: runs natively on every glibc
                        t.add(os.path.join(REPO, "build", "sysroot-hello"), arcname="repo/build/sysroot-hello")
                else:
                    if not a.debs_arm64:
                        sys.exit("the aarch64 VM needs --debs-arm64 DIR, a directory of arm64 .deb files for the gcc exclave")
                    t.add(a.debs_arm64, arcname="debs")
                    t.add(os.path.join(REPO, "build", "launcher-aarch64"), arcname="repo/build/launcher")
                    if os.path.exists(os.path.join(REPO, "build", "launcher-old-aarch64")):
                        t.add(os.path.join(REPO, "build", "launcher-old-aarch64"), arcname="repo/build/launcher-old")
        payloads[arch] = payload
        return payload
    results = []
    for name, kernel, user, urls, family, notes, arch in VMS:
        if a.only and name not in a.only.split(","):
            continue
        if arch != "x86_64" and not a.arm64 and not (a.only and name in a.only.split(",")):
            continue                                              # the emulated rows run only when asked: ten to twenty times slower
        slow = 10 if arch != "x86_64" else 1
        payload = payload_for(arch)
        image = os.path.join(a.images, name + ".qcow2")
        if not any(fetch(u, image) for u in urls):
            results.append((name, kernel, "image not available", "", notes))
            continue
        seed = os.path.join(work, name + "-seed.iso")
        with open(os.path.join(work, name + "-user-data"), "w") as f:
            f.write(user_data(family, pubkey))
        with open(os.path.join(work, name + "-meta-data"), "w") as f:
            f.write("instance-id: exclave-%s\nlocal-hostname: %s\n" % (name, name))
        subprocess.run(["cloud-localds", seed, os.path.join(work, name + "-user-data"), os.path.join(work, name + "-meta-data")], check=True)
        port = free_port()
        log("booting", name)
        vm = VM(name, image, work, user, port, a.memory, arch)
        try:
            if not vm.wait(deadline=600 * slow):
                results.append((name, kernel, "did not come up (see %s-console.log)" % name, "", notes))
                continue
            rc, uname = vm.ssh("uname -r")
            uname = uname.strip()
            log(name, "kernel", uname)
            vm.scp(payload, "payload.tar.gz")
            rc, out = vm.ssh("mkdir -p m && cd m && tar xzf ../payload.tar.gz && echo unpacked", timeout=600 * slow)
            if "unpacked" not in out:
                results.append((name, uname, "cannot unpack: " + out[-200:], "", notes))
                continue
            if arch != "x86_64":                                  # the exclave is made here, on its own architecture (10.1)
                rc, out = vm.ssh("cd m && python3 repo/exclave/exclave.py unpack ex debs/*.deb 2>&1 | tail -3 && python3 repo/exclave/exclave.py wrap ex 2>&1 | tail -3", timeout=3600 * slow)
                log(name, "exclave:", " | ".join(l.strip() for l in out.splitlines()[-3:]))
                if "ex is wrapped" not in out:
                    results.append((name, uname, "cannot make the exclave: " + out[-300:].replace("\n", " | "), "", notes))
                    continue
            else:                                                 # the exclave given carries the launcher that made it: the row tests the checkout's
                rc, out = vm.ssh("cd m && python3 repo/exclave/exclave.py relink ex repo/build/launcher 2>&1 | tail -1", timeout=600 * slow)
                if "relinked" not in out:
                    results.append((name, uname, "cannot relink the exclave: " + out[-200:].replace("\n", " | "), "", notes))
                    continue
            rc, out = vm.ssh("cd m && python3 repo/test/run.py --exclave $PWD/ex --work $PWD/work --budget %d 2>&1" % (60 * slow), timeout=2400 * slow)
            with open(os.path.join(work, name + "-suite.log"), "w") as f:
                f.write(out)
            suite = [l for l in out.splitlines() if "tests," in l]
            suite = suite[-1] if suite else "suite did not finish: " + out[-300:].replace("\n", " | ")
            fails = [l for l in out.splitlines() if l.startswith("FAIL")]
            log(name, suite)
            for f in fails:
                log(name, f[:200])
            # 12, 17.4: a noexec mount, made as root. Natively the shell answers EACCES; the launcher's loader cannot map
            # a program there and says so; an exclave's shell answers EACCES as the kernel would (7.4.5).
            rc, out = vm.ssh("S=sudo; command -v sudo >/dev/null 2>&1 || S=doas; echo 'int main(void){return 0;}' > nx.c && "
                             "m/ex/tree/usr/bin/$(uname -m)-linux-gnu-gcc-13 -o nxprog nx.c && $S mkdir -p /mnt/nx && $S mount -t tmpfs -o noexec tmpfs /mnt/nx && "
                             "$S cp nxprog /mnt/nx/prog && $S chmod 755 /mnt/nx/prog && mount | grep -q '/mnt/nx .*noexec' || { echo noexec setup failed; exit 0; }; "
                             "/mnt/nx/prog >/dev/null 2>&1; a=$?; m/ex/.exclave/launcher /mnt/nx/prog >/dev/null 2>&1; b=$?; "
                             "m/ex/tree/usr/bin/sh -c /mnt/nx/prog >/dev/null 2>&1; c=$?; $S umount /mnt/nx; echo noexec native=$a launcher=$b inside=$c", timeout=120)
            noexec = [l for l in out.splitlines() if l.startswith("noexec ")]
            noexec = noexec[-1] if noexec else "noexec: " + out[-120:].replace("\n", " | ")
            log(name, noexec)
            notes = (notes + "; " if notes else "") + noexec
            # 9: an output built inside the gcc exclave against an older glibc's sysroot (test/sysroot.py) runs natively here
            rc, out = vm.ssh("if test -x m/repo/build/sysroot-hello; then o=$(m/repo/build/sysroot-hello 2>&1); r=$?; echo \"sysroot-rc=$r $o\"; else echo no-sysroot-hello; fi; "
                             "ldd --version 2>&1 | head -1", timeout=60)
            sysroot = " ".join(l.strip() for l in out.splitlines() if l.strip())
            ok = "sysroot-rc=0 hello from a sysroot build" in sysroot or "no-sysroot-hello" in sysroot or "musl libc" in sysroot   # a glibc program has no loader on a musl host (9)
            log(name, "sysroot output:", sysroot, "" if ok else "FAIL")
            notes += "; sysroot: " + sysroot + ("" if ok else " FAIL")
            if not ok:
                fails.append("FAIL sysroot output did not run natively: " + sysroot)
            oracle = ""
            # Ubuntu 24.04 images deny unprivileged user namespaces through AppArmor (kernel.apparmor_restrict_unprivileged_userns);
            # the VM is the matrix's own, so it lifts the sysctl where it exists, as the reference machine's permitted session does
            rc, out = vm.ssh("S=sudo; command -v sudo >/dev/null 2>&1 || S=doas; $S sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0 2>/dev/null; "
                             "cd m && bwrap --ro-bind / / true 2>&1 && echo bwrap-ok")
            if "bwrap-ok" in out:
                rc, out = vm.ssh("cd m && python3 repo/test/oracle_resolve.py --exclave $PWD/ex --work $PWD/rw 2>&1 | tail -30; echo ====; "
                                 "python3 repo/test/oracle_ns.py --exclave $PWD/ex --work $PWD/nw 2>&1 | tail -40; echo ====; "
                                 "python3 repo/test/oracle_syscalls.py --exclave $PWD/ex --work $PWD/sw --show 5000 2>&1 | tail -20000; echo ====; "
                                 + ("python3 repo/test/docker_profile.py --exclave $PWD/ex --profile $PWD/docker-seccomp.json --work $PWD/dw 2>&1 | tail -20"
                                    if a.docker_profile else "echo 'docker profile: not given'"), timeout=2400 * slow)
                with open(os.path.join(work, name + "-oracles.log"), "w") as f:
                    f.write(out)
                keep = [l.strip() for l in out.splitlines() if ("paths:" in l or "workloads," in l or "cases over" in l or l.startswith("PASS exclave") or l.startswith("FAIL exclave") or "cannot run" in l or "docker profile:" in l)]
                oracle = " / ".join(keep) or out[-300:].replace("\n", " | ")
                log(name, oracle)
            else:
                oracle = "no user namespaces"
            results.append((name, uname, suite + ("; " + "; ".join(f[:80] for f in fails[:4]) if fails else ""), oracle, notes))
        except Exception as e:  # noqa: BLE001
            results.append((name, kernel, "error: %s" % e, "", notes))
        finally:
            vm.stop()
    out = ["| VM | kernel | suite | oracles | notes |", "|---|---|---|---|---|"] + ["| %s | %s | %s | %s | %s |" % r for r in results]
    text = "\n".join(out) + "\n"
    print(text)
    with open(os.path.join(REPO, "build", "matrix-results.md"), "w") as f:
        f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
