"""Run an exclave built here in virtual machines, one per kernel (DESIGN.md 12, 17 item 5).

    scripts/matrix --exclave EXCLAVE [--only NAME,...] [--work DIR] [--images DIR] [--memory MB]
                   [--jobs N] [--arm64 --debs-arm64 DIR] [--docker-profile FILE]

Each row of VMS names a distribution cloud image. The image is downloaded once, booted under QEMU
with KVM behind a copy-on-write overlay and a cloud-init seed that installs strace (and bubblewrap
where it exists), the exclave, the pinned Python built for the VM's machine and libc, and this
repository's test tree and launcher are copied in over SSH, and the regression suite runs there;
the oracles, the syscall probe and, given the profile, the Docker-profile run follow where
bubblewrap works. Three VMs at a time (--jobs), 1 GB each, 2 GB for the emulated row. Results go to
build/matrix-results.md. The exit status is 1 when any row failed: its image could not be fetched,
its VM did not boot, or its suite, its sysroot check or one of its oracles failed.
"""

import argparse
import concurrent.futures
import contextlib
import dataclasses
import io
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request

import tree

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
UV = os.path.join(REPO, ".uv", "bin", "uv")
PYDIR = f"python{sys.version_info[0]}.{sys.version_info[1]}"


@dataclasses.dataclass(frozen=True)
class VmRow:
    """A VM of the matrix."""

    name: str
    kernel: str  # the kernel the image is expected to boot
    user: str  # the image's SSH user
    urls: list[str]  # image URL candidates: the first that downloads wins
    family: str  # the package family, a key of PACKAGES
    notes: str
    arch: str


VMS: list[VmRow] = [
    VmRow(
        name="centos-7",
        kernel="3.10",
        user="centos",
        urls=["https://cloud.centos.org/centos/7/images/CentOS-7-x86_64-GenericCloud-2211.qcow2"],
        family="centos7",
        notes="EOL; yum repos moved to vault",
        arch="x86_64",
    ),
    VmRow(
        name="ubuntu-18.04",
        kernel="4.15",
        user="ubuntu",
        urls=["https://cloud-images.ubuntu.com/bionic/current/bionic-server-cloudimg-amd64.img"],
        family="apt",
        notes="",
        arch="x86_64",
    ),
    VmRow(
        name="rocky-8",
        kernel="4.18",
        user="rocky",
        urls=[
            "https://dl.rockylinux.org/pub/rocky/8/images/x86_64/Rocky-8-GenericCloud.latest.x86_64.qcow2"
        ],
        family="dnf",
        notes="",
        arch="x86_64",
    ),
    VmRow(
        name="ubuntu-20.04",
        kernel="5.4",
        user="ubuntu",
        urls=["https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img"],
        family="apt",
        notes="",
        arch="x86_64",
    ),
    VmRow(
        name="debian-11",
        kernel="5.10",
        user="debian",
        urls=[
            "https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-generic-amd64.qcow2"
        ],
        family="apt",
        notes="",
        arch="x86_64",
    ),
    VmRow(
        name="ubuntu-22.04",
        kernel="5.15",
        user="ubuntu",
        urls=["https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"],
        family="apt",
        notes="",
        arch="x86_64",
    ),
    VmRow(
        name="debian-12",
        kernel="6.1",
        user="debian",
        urls=[
            "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"
        ],
        family="apt",
        notes="",
        arch="x86_64",
    ),
    VmRow(
        name="fedora",
        kernel="6.x",
        user="fedora",
        urls=[
            "https://download.fedoraproject.org/pub/fedora/linux/releases/42/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-42-1.1.x86_64.qcow2",
            "https://download.fedoraproject.org/pub/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2",
            "https://download.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2",
        ],
        family="dnf",
        notes="SELinux enforcing",
        arch="x86_64",
    ),
    VmRow(
        name="alpine",
        kernel="6.x",
        user="alpine",
        urls=[
            "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/cloud/nocloud_alpine-3.21.3-x86_64-bios-cloudinit-r0.qcow2",
            "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/cloud/nocloud_alpine-3.20.3-x86_64-bios-cloudinit-r0.qcow2",
        ],
        family="apk",
        notes="musl host, busybox",
        arch="x86_64",
    ),
    # aarch64 under TCG (12): the same suite and oracles, the arm64 launcher and exclave, ten to
    # twenty times slower
    VmRow(
        name="noble-arm64",
        kernel="6.8",
        user="ubuntu",
        urls=["https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"],
        family="apt",
        notes="aarch64, TCG emulation",
        arch="aarch64",
    ),
]

# what a VM installs for the oracles; Python is not among them: the pinned one, which
# pinned_python makes, is in the payload
PACKAGES: dict[str, list[str]] = {
    "apt": ["strace", "bubblewrap"],
    "dnf": ["strace", "bubblewrap"],
    "apk": ["strace", "bubblewrap", "bash"],
    "centos7": ["strace"],
}


@dataclasses.dataclass(frozen=True)
class Row:
    """A row of the results table, and whether it records a failure."""

    vm: str
    kernel: str
    suite: str
    oracles: str
    notes: str
    failed: bool


def log(*words: object) -> None:
    print(time.strftime("%H:%M:%S"), *words, flush=True)


def fetch(url: str, dst: str, tries: int = 4) -> bool:
    """Download with resume and a length check.

    A connection that closes early must not leave a short image.
    """
    if os.path.exists(dst):
        return True
    tmp = dst + ".tmp"
    for attempt in range(tries):
        have = os.path.getsize(tmp) if os.path.exists(tmp) else 0
        log("downloading", url, f"from byte {have:d}" if have else "")
        try:
            headers = {"User-Agent": "exclave-matrix/0.1"}
            if have:
                headers["Range"] = f"bytes={have:d}-"
            req = urllib.request.Request(url, headers=headers)  # noqa: S310 -- VMS's https URLs
            with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310 -- VMS's https URLs
                if have and r.status != 206:
                    have = 0  # no resume support: start over
                total = r.headers.get("Content-Range", "").split("/")[-1] or r.headers.get(
                    "Content-Length"
                )
                total = int(total) if total and total.isdigit() else None
                if have == 0 and r.status == 206:
                    total = None
                with open(tmp, "ab" if have else "wb") as f:
                    shutil.copyfileobj(r, f, 1 << 20)
            size = os.path.getsize(tmp)
            if total is not None and size != total:
                log(f"short download: {size:d} of {total:d} bytes, retrying")
                continue
            os.replace(tmp, dst)
            return True  # noqa: TRY300 -- a failed rename is logged and retried like a download
        except Exception as e:  # noqa: BLE001 -- any failure is logged and the download retried
            log("failed:", e)
            if attempt == tries - 1 and os.path.exists(tmp) and os.path.getsize(tmp) == 0:
                os.remove(tmp)
    return False


def oracle_step(script: str, opts: str, lines: int) -> str:
    """A shell step that runs an oracle on the VM's exclave and keeps its last lines.

    The last line kept is the oracle's exit status, which the pipe through tail would otherwise
    lose.
    """
    return (
        f"{{ $PWD/python/bin/python3 repo/test/{script} --exclave $PWD/ex {opts} 2>&1; "
        f'echo "oracle exit status $?"; }} | tail -{lines:d}'
    )


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def pinned_python(arch: str, libc: str) -> str:
    """The tree of the pinned Python, the version running this, built for a VM's machine and libc.

    Installed by the repository's uv into its own Python directory (scripts/lib.sh), so a VM runs
    the suite on the same Python as the reference machine whatever python3 its distribution has, or
    none. glibc builds need only glibc 2.17.
    """
    v = sys.version_info
    name = f"cpython-{v[0]:d}.{v[1]:d}.{v[2]:d}-linux-{arch}-{libc}"
    subprocess.run([UV, "python", "install", "--no-bin", "--quiet", name], check=True)
    tree_ = os.path.join(
        os.environ.get("UV_PYTHON_INSTALL_DIR", os.path.join(REPO, ".uv", "python")), name
    )
    if not os.path.isdir(tree_):
        sys.exit(f"uv installed {name} but it is not at {tree_}")
    return tree_


def without_tk(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    """Tarfile filter: Tcl/Tk, which nothing here imports, stays out of the payload."""
    base = os.path.basename(info.name)
    return (
        None
        if base.startswith(("libtcl", "libtk", "_tkinter", "tcl9", "tk9"))
        or base in ("tkinter", "idlelib", "turtledemo")
        else info
    )


def user_data(family: str, pubkey: str) -> str:
    pk = PACKAGES[family]
    if family == "centos7":
        return "\n".join(
            [
                "#cloud-config",
                "ssh_authorized_keys:",
                "  - " + pubkey,
                "runcmd:",
                (
                    "  - sed -i 's/^mirrorlist=/#mirrorlist=/; "
                    "s|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' "
                    "/etc/yum.repos.d/CentOS-*.repo"
                ),
                "  - yum install -y " + " ".join(pk),
                "  - touch /var/tmp/exclave-ready",
                "",
            ]
        )
    # apt installs the list in one transaction, so one package the mirror has dropped fails them
    # all: Debian 11's security suite, winding down after its LTS, still lists a bubblewrap whose
    # file is gone. Each package again on its own, then from the release's main suite
    retry = (
        [
            "  - for p in {}; do dpkg -s $p >/dev/null 2>&1 || apt-get install -y $p || "
            "apt-get install -y $p=$(apt-cache madison $p | "
            "awk '!/security/ {{print $3; exit}}'); done".format(" ".join(pk))
        ]
        if family == "apt"
        else []
    )
    return "\n".join(
        [
            "#cloud-config",
            "ssh_authorized_keys:",
            "  - " + pubkey,
            "package_update: true",
            "packages:",
        ]
        + ["  - " + p for p in pk]
        + ["runcmd:"]
        + retry
        + ["  - touch /var/tmp/exclave-ready", ""]
    )


AAVMF = "/usr/share/AAVMF"


class VM:
    def __init__(
        self, name: str, image: str, work: str, user: str, port: int, *, memory: int, arch: str
    ) -> None:
        self.name, self.user, self.port, self.work, self.arch = name, user, port, work, arch
        self.overlay = os.path.join(work, name + ".qcow2")
        subprocess.run(
            ["qemu-img", "create", "-q", "-f", "qcow2", "-b", image, "-F", "qcow2", self.overlay],
            check=True,
        )
        # cloud-init grows the root; some images ship 2 GB
        subprocess.run(["qemu-img", "resize", "-q", self.overlay, "+8G"], check=True)
        self.seed = os.path.join(work, name + "-seed.iso")
        self.key = os.path.join(work, "id_ed25519")
        common = [
            "-display",
            "none",
            "-serial",
            "file:" + os.path.join(work, name + "-console.log"),
            "-drive",
            f"file={self.overlay},if=virtio,format=qcow2",
            "-drive",
            f"file={self.seed},if=virtio,format=raw",
            "-netdev",
            f"user,id=n0,hostfwd=tcp:127.0.0.1:{port:d}-:22",
            "-device",
            "virtio-net-pci,netdev=n0",
        ]
        # no KVM for another architecture: TCG, and UEFI firmware, which arm64 images boot from
        if arch == "aarch64":
            varstore = os.path.join(work, name + "-vars.fd")
            shutil.copyfile(os.path.join(AAVMF, "AAVMF_VARS.fd"), varstore)
            cmd = [
                "qemu-system-aarch64",
                "-M",
                "virt",
                "-accel",
                "tcg",
                "-cpu",
                "max",
                "-m",
                str(max(memory, 2048)),
                "-smp",
                "4",
                "-drive",
                "if=pflash,format=raw,readonly=on,file=" + os.path.join(AAVMF, "AAVMF_CODE.fd"),
                "-drive",
                "if=pflash,format=raw,file=" + varstore,
                *common,
            ]
        else:
            cmd = [
                "qemu-system-x86_64",
                "-enable-kvm",
                "-cpu",
                "host",
                "-m",
                str(memory),
                "-smp",
                "2",
                *common,
            ]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def ssh(self, cmd: str, timeout: float = 1800) -> tuple[int, str]:
        p = subprocess.run(
            [
                "ssh",
                "-p",
                str(self.port),
                "-i",
                self.key,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "ConnectTimeout=10",
                f"{self.user}@127.0.0.1",
                cmd,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return p.returncode, p.stdout.decode(errors="replace")

    def scp(self, src: str, dst: str) -> None:
        subprocess.run(
            [
                "scp",
                "-q",
                "-P",
                str(self.port),
                "-i",
                self.key,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "LogLevel=ERROR",
                src,
                f"{self.user}@127.0.0.1:{dst}",
            ],
            check=True,
        )

    def wait(self, deadline: float = 600) -> bool:
        t = time.time()
        while time.time() - t < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                _rc, out = self.ssh("test -e /var/tmp/exclave-ready && echo ready", timeout=20)
                if "ready" in out:
                    return True
            except subprocess.TimeoutExpired:
                pass
            time.sleep(5)
        return False

    def stop(self) -> None:
        with contextlib.suppress(Exception):
            self.ssh("sudo poweroff || doas poweroff || poweroff", timeout=20)
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--exclave", required=True)
    ap.add_argument("--only")
    ap.add_argument("--work", default=os.path.join(REPO, "build", "matrix-work"))
    ap.add_argument(
        "--images", default=os.path.join(os.path.expanduser("~"), ".cache", "exclave-images")
    )
    ap.add_argument("--memory", type=int, default=1024)
    ap.add_argument(
        "--jobs", type=int, default=3, help="VMs at a time (default 3: 1 GB each, 2 GB emulated)"
    )
    ap.add_argument(
        "--arm64",
        action="store_true",
        help="include the emulated aarch64 VM (slow); --only names it too",
    )
    ap.add_argument(
        "--debs-arm64",
        help="directory of arm64 .deb files the aarch64 VM makes its gcc exclave from",
    )
    ap.add_argument(
        "--docker-profile",
        help="Docker's default seccomp profile (scripts/inputs fetches it); "
        "without it the Docker-profile run is left out",
    )
    args = ap.parse_args()
    if not shutil.which("qemu-system-x86_64") or not shutil.which("cloud-localds"):
        sys.exit("need qemu-system-x86_64 and cloud-localds")
    ex, work = os.path.abspath(args.exclave), os.path.abspath(args.work)
    os.makedirs(work, exist_ok=True)
    os.makedirs(args.images, exist_ok=True)
    key = os.path.join(work, "id_ed25519")
    if not os.path.exists(key):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
    with open(key + ".pub") as f:
        pubkey = f.read().strip()
    # the payload: the exclave (hard links preserved by tar) and the repository's test tree,
    # exclave, launcher and, where the host has go, the Go regression's programs built for the VM's
    # machine. For the aarch64 VM the payload carries the arm64 package files and the cross-built
    # launchers under the suite's names: the exclave is unpacked and wrapped in the VM, on its own
    # architecture (10.1).
    payloads: dict[tuple[str, str], str] = {}

    def payload_for(arch: str, libc: str) -> str:
        if (arch, libc) in payloads:
            return payloads[arch, libc]
        payload = os.path.join(work, f"payload-{arch}-{libc}.tar.gz")
        # packed afresh every run, so the VMs never test a stale tree
        log("packing the test tree for", arch)
        with tarfile.open(payload, "w:gz", compresslevel=1) as t:
            # src: the filter model the suite builds in the VM (filter_model); src and tool: the
            # sources the suite's fixture is stamped with
            for d in ("test", "unpack", "src", "tool"):
                t.add(os.path.join(REPO, d), arcname="repo/" + d)
            # the text the launcher carries, which exclave_readme compares
            t.add(os.path.join(REPO, "LICENSE"), arcname="repo/LICENSE")
            t.add(pinned_python(arch, libc), arcname="python", filter=without_tk)
            # the unpack package installed into that Python as uv sync installs it here, in
            # editable form: a .pth naming the checkout, relative to site-packages
            pth = b"../../../../repo\n"
            info = tarfile.TarInfo(f"python/lib/{PYDIR}/site-packages/_exclave.pth")
            info.size = len(pth)
            t.addfile(info, io.BytesIO(pth))
            if args.docker_profile:
                t.add(args.docker_profile, arcname="docker-seccomp.json")
            # the Go regression's programs, built here for the VM's machine: the VMs have no go
            go = tree.go_toolchain()
            if go:
                for n, p in tree.go_build(go, os.path.join(work, "go-" + arch), arch, work):
                    t.add(p, arcname=f"repo/build/go/{arch}/{n}")
            if arch == "x86_64":
                t.add(ex, arcname="ex")
                t.add(os.path.join(REPO, "build", "launcher"), arcname="repo/build/launcher")
                t.add(os.path.join(REPO, "build", "exclave"), arcname="repo/build/exclave")
                if os.path.exists(os.path.join(REPO, "build", "launcher-old")):
                    t.add(
                        os.path.join(REPO, "build", "launcher-old"),
                        arcname="repo/build/launcher-old",
                    )
                # test/sysroot.py's output: runs natively on every glibc
                if os.path.exists(os.path.join(REPO, "build", "sysroot-hello")):
                    t.add(
                        os.path.join(REPO, "build", "sysroot-hello"),
                        arcname="repo/build/sysroot-hello",
                    )
            else:
                if not args.debs_arm64:
                    sys.exit(
                        "the aarch64 VM needs --debs-arm64 DIR, "
                        "a directory of arm64 .deb files for the gcc exclave"
                    )
                t.add(args.debs_arm64, arcname="debs")
                t.add(
                    os.path.join(REPO, "build", "launcher-aarch64"), arcname="repo/build/launcher"
                )
                t.add(os.path.join(REPO, "build", "exclave-aarch64"), arcname="repo/build/exclave")
                if os.path.exists(os.path.join(REPO, "build", "launcher-old-aarch64")):
                    t.add(
                        os.path.join(REPO, "build", "launcher-old-aarch64"),
                        arcname="repo/build/launcher-old",
                    )
        payloads[arch, libc] = payload
        return payload

    start_lock = threading.Lock()

    def run_row(row: VmRow) -> Row:
        """One VM's row: boot, copy in, run the suite and the oracles, stop."""
        name, arch, notes = row.name, row.arch, row.notes
        slow = 10 if arch != "x86_64" else 1
        payload = payload_for(arch, "musl" if row.family == "apk" else "gnu")
        image = os.path.join(args.images, name + ".qcow2")

        def failure(kernel: str, why: str) -> Row:
            return Row(name, kernel, why, "", notes, failed=True)

        if not any(fetch(u, image) for u in row.urls):
            return failure(row.kernel, "image not available")
        seed = os.path.join(work, name + "-seed.iso")
        with open(os.path.join(work, name + "-user-data"), "w") as f:
            f.write(user_data(row.family, pubkey))
        with open(os.path.join(work, name + "-meta-data"), "w") as f:
            f.write(f"instance-id: exclave-{name}\nlocal-hostname: {name}\n")
        subprocess.run(
            [
                "cloud-localds",
                seed,
                os.path.join(work, name + "-user-data"),
                os.path.join(work, name + "-meta-data"),
            ],
            check=True,
        )
        with start_lock:
            port = free_port()
            log("booting", name)
            vm = VM(name, image, work, row.user, port, memory=args.memory, arch=arch)
        try:
            if not vm.wait(deadline=600 * slow):
                return failure(row.kernel, f"did not come up (see {name}-console.log)")
            _rc, uname = vm.ssh("uname -r")
            uname = uname.strip()
            log(name, "kernel", uname)
            vm.scp(payload, "payload.tar.gz")
            _rc, out = vm.ssh(
                "mkdir -p m && cd m && tar xzf ../payload.tar.gz && echo unpacked",
                timeout=600 * slow,
            )
            if "unpacked" not in out:
                return failure(uname, "cannot unpack: " + out[-200:])
            if arch != "x86_64":  # the exclave is made here, on its own architecture (10.1)
                _rc, out = vm.ssh(
                    "cd m && $PWD/python/bin/python3 -m unpack ex debs/*.deb "
                    "2>&1 | tail -3 && "
                    "repo/build/exclave wrap ex 2>&1 | tail -3",
                    timeout=3600 * slow,
                )
                log(name, "exclave:", " | ".join(x.strip() for x in out.splitlines()[-3:]))
                if "ex is wrapped" not in out:
                    return failure(
                        uname, "cannot make the exclave: " + out[-300:].replace("\n", " | ")
                    )
            else:
                # the exclave given carries the launcher that made it: the row tests the checkout's
                _rc, out = vm.ssh(
                    "cd m && repo/build/exclave relink ex repo/build/launcher 2>&1 | tail -1",
                    timeout=600 * slow,
                )
                if "relinked" not in out:
                    return failure(
                        uname, "cannot relink the exclave: " + out[-200:].replace("\n", " | ")
                    )
            suite_rc, out = vm.ssh(
                "cd m && $PWD/python/bin/python3 repo/test/run.py --exclave $PWD/ex "
                f"--work $PWD/work --budget {60 * slow:d} 2>&1",
                timeout=2400 * slow,
            )
            with open(os.path.join(work, name + "-suite.log"), "w") as f:
                f.write(out)
            suites = [x for x in out.splitlines() if "tests," in x]
            suite = (
                suites[-1] if suites else "suite did not finish: " + out[-300:].replace("\n", " | ")
            )
            fails = [x for x in out.splitlines() if x.startswith("FAIL")]
            log(name, suite)
            for f in fails:
                log(name, f[:200])
            # 12, 17.4: a noexec mount, made as root. Natively the shell answers EACCES; the
            # launcher's loader cannot map a program there and says so; an exclave's shell answers
            # EACCES as the kernel would (7.4.5).
            _rc, out = vm.ssh(
                "S=sudo; command -v sudo >/dev/null 2>&1 || S=doas; "
                "echo 'int main(void){return 0;}' > nx.c && "
                "m/ex/tree/usr/bin/$(uname -m)-linux-gnu-gcc-13 -o nxprog nx.c && "
                "$S mkdir -p /mnt/nx && $S mount -t tmpfs -o noexec tmpfs /mnt/nx && "
                "$S cp nxprog /mnt/nx/prog && $S chmod 755 /mnt/nx/prog && "
                "mount | grep -q '/mnt/nx .*noexec' || { echo noexec setup failed; exit 0; }; "
                "/mnt/nx/prog >/dev/null 2>&1; a=$?; "
                "m/ex/.exclave/launcher /mnt/nx/prog >/dev/null 2>&1; b=$?; "
                "m/ex/tree/usr/bin/sh -c /mnt/nx/prog >/dev/null 2>&1; c=$?; $S umount /mnt/nx; "
                "echo noexec native=$a launcher=$b inside=$c",
                timeout=120,
            )
            noexecs = [x for x in out.splitlines() if x.startswith("noexec ")]
            noexec = noexecs[-1] if noexecs else "noexec: " + out[-120:].replace("\n", " | ")
            log(name, noexec)
            notes = (notes + "; " if notes else "") + noexec
            # 9: an output built inside the gcc exclave against an older glibc's sysroot
            # (test/sysroot.py) runs natively here
            _rc, out = vm.ssh(
                "if test -x m/repo/build/sysroot-hello; then "
                "o=$(m/repo/build/sysroot-hello 2>&1); r=$?; "
                'echo "sysroot-rc=$r $o"; else echo no-sysroot-hello; fi; '
                "ldd --version 2>&1 | head -1",
                timeout=60,
            )
            sysroot = " ".join(x.strip() for x in out.splitlines() if x.strip())
            # a glibc program has no loader on a musl host (9)
            ok = (
                "sysroot-rc=0 hello from a sysroot build" in sysroot
                or "no-sysroot-hello" in sysroot
                or "musl libc" in sysroot
            )
            log(name, "sysroot output:", sysroot, "" if ok else "FAIL")
            notes += "; sysroot: " + sysroot + ("" if ok else " FAIL")
            if not ok:
                fails.append("FAIL sysroot output did not run natively: " + sysroot)
            oracle, oracle_failed = "", False
            # Ubuntu 24.04 images deny unprivileged user namespaces through AppArmor
            # (kernel.apparmor_restrict_unprivileged_userns); the VM is the matrix's own, so it
            # lifts the sysctl where it exists, as the reference machine's permitted session does
            _rc, out = vm.ssh(
                "S=sudo; command -v sudo >/dev/null 2>&1 || S=doas; "
                "$S sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0 2>/dev/null; "
                "cd m && bwrap --ro-bind / / true 2>&1 && echo bwrap-ok"
            )
            if "bwrap-ok" in out:
                steps = [
                    oracle_step("oracle_resolve.py", "--work $PWD/rw", 30),
                    oracle_step("oracle_ns.py", "--work $PWD/nw", 40),
                    oracle_step("oracle_syscalls.py", "--work $PWD/sw --show 5000", 20000),
                ]
                if args.docker_profile:
                    profile = "--profile $PWD/docker-seccomp.json --work $PWD/dw"
                    steps.append(oracle_step("docker_profile.py", profile, 20))
                skipped = (
                    "" if args.docker_profile else "; echo ====; echo 'docker profile: not given'"
                )
                _rc, out = vm.ssh(
                    "cd m && " + "; echo ====; ".join(steps) + skipped, timeout=2400 * slow
                )
                # an oracle that failed, or one whose status line never came, fails the row
                statuses = re.findall(r"^oracle exit status (\d+)$", out, re.MULTILINE)
                oracle_failed = len(statuses) != len(steps) or any(s != "0" for s in statuses)
                with open(os.path.join(work, name + "-oracles.log"), "w") as f:
                    f.write(out)
                keep = [
                    x.strip()
                    for x in out.splitlines()
                    if (
                        "paths:" in x
                        or "workloads," in x
                        or "cases over" in x
                        or x.startswith(("PASS exclave", "FAIL exclave"))
                        or "cannot run" in x
                        or "docker profile:" in x
                    )
                ]
                oracle = " / ".join(keep) or out[-300:].replace("\n", " | ")
                log(name, oracle)
            else:
                oracle = "no user namespaces"
            return Row(
                name,
                uname,
                suite + ("; " + "; ".join(f[:80] for f in fails[:4]) if fails else ""),
                oracle,
                notes,
                failed=bool(suite_rc or fails or oracle_failed),
            )
        except Exception as e:  # noqa: BLE001 -- a row's failure is reported in its row
            return failure(row.kernel, f"error: {e}")
        finally:
            vm.stop()

    only = args.only.split(",") if args.only else []
    rows = [
        r
        for r in VMS
        if (not only or r.name in only)
        # the emulated rows run only when asked: ten to twenty times slower
        and (r.arch == "x86_64" or args.arm64 or r.name in only)
    ]
    # packed before the VMs start, once each, so no two rows pack at once
    for arch, libc in {(r.arch, "musl" if r.family == "apk" else "gnu") for r in rows}:
        payload_for(arch, libc)
    # several VMs at a time, each with its own overlay, seed and port; the table keeps VMS's order
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(run_row, rows))
    table = ["| VM | kernel | suite | oracles | notes |", "|---|---|---|---|---|"] + [
        f"| {r.vm} | {r.kernel} | {r.suite} | {r.oracles} | {r.notes} |" for r in results
    ]
    text = "\n".join(table) + "\n"
    print(text)
    with open(os.path.join(REPO, "build", "matrix-results.md"), "w") as f:
        f.write(text)
    return 1 if any(r.failed for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
