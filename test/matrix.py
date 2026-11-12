"""Run an exclave built here in virtual machines, one per kernel (DESIGN.md 12, 17 item 5).

    scripts/matrix --exclave EXCLAVE... [--only NAME,...] [--work DIR] [--images DIR] [--memory MB]
                   [--jobs N] [--arm64] [--docker-profile FILE]

Each row of VMS names a distribution cloud image. The image is downloaded once, booted under QEMU
with KVM behind a copy-on-write overlay and a cloud-init seed that installs strace and zstd (and
bubblewrap where it exists), the exclave of the row's machine (one --exclave per machine the rows
need, each told by its launcher: scripts/inputs makes gcc13.exclave and gcc13-arm64.exclave), the
pinned Python built for the VM's machine and libc, and this repository's test tree and launcher are
copied in over SSH, and the regression suite runs there. For this machine's rows the exclave goes
in as a release of it, made here by scripts/release, which the VM first takes as the README has a
consumer take it (RECIPE), the exclave it unpacks then the row's;
the oracles, the syscall probe and, given the profile, the Docker-profile run follow where
bubblewrap works. One VM at a time, or --jobs N, 1 GB each, 2 GB for the emulated row, so that the
machine stays usable. Results go to build/matrix-results.md. The exit status is 1 when any row
failed: its image could not be fetched, its VM did not boot, or its suite, the release's recipe,
its sysroot check or one of its oracles failed.
"""

import argparse
import concurrent.futures
import contextlib
import dataclasses
import io
import os
import platform
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
MACHINE = platform.machine()
# ELF e_machine to the name uname gives it, for the launcher an exclave carries
MACHINES = {62: "x86_64", 183: "aarch64"}


def built(name: str, arch: str) -> str:
    """scripts/build's output NAME for arch: build/NAME here, build/NAME-ARCH for another."""
    return os.path.join(REPO, "build", name if arch == MACHINE else f"{name}-{arch}")


def launcher_machine(ex: str) -> str:
    """The machine of the launcher an exclave carries, from its ELF header (10.1)."""
    with open(os.path.join(ex, ".exclave", "launcher"), "rb") as f:
        head = f.read(20)
    machine = MACHINES.get(int.from_bytes(head[18:20], "little")) if len(head) == 20 else None
    if machine is None:
        sys.exit(f"{ex}: its launcher is not one of a machine the matrix knows")
    return machine


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
    kernel_package: str = ""  # a kernel to install and reboot into, for a row on another page size
    image: str = ""  # the name the row's image is kept under, when another row shares it


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
            # a release past its end of life moves from download. to archives.fedoraproject.org
            "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2",
            "https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2",
            "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/42/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-42-1.1.x86_64.qcow2",
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
    # the newest kernel a distribution's cloud image boots (12.1): 7.3 in October 2026
    VmRow(
        name="ubuntu-26.10",
        kernel="7.3",
        user="ubuntu",
        urls=[
            "https://cloud-images.ubuntu.com/stonking/current/stonking-server-cloudimg-amd64.img"
        ],
        family="apt",
        notes="the newest kernel",
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
    # the same image booted into Ubuntu's 64 KB-page kernel (13 item 43): cloud-init installs it
    # and reboots, and the ready mark is made only under 64 KB pages
    VmRow(
        name="noble-arm64-64k",
        kernel="6.8 with 64 KB pages",
        user="ubuntu",
        urls=["https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"],
        family="apt",
        notes="aarch64, TCG emulation, 64 KB pages",
        arch="aarch64",
        kernel_package="linux-image-generic-64k",
        image="noble-arm64",
    ),
]

# what a VM installs for the oracles, and zstd for the release's recipe, which unpacks a .tar.zst;
# Python is not among them: the pinned one, which pinned_python makes, is in the payload. CentOS 7
# has zstd only in EPEL, which user_data adds from Fedora's archive of it
PACKAGES: dict[str, list[str]] = {
    "apt": ["strace", "bubblewrap", "zstd"],
    "dnf": ["strace", "bubblewrap", "zstd"],
    "apk": ["strace", "bubblewrap", "bash", "zstd"],
    "centos7": ["strace"],
}
EPEL7 = "https://dl.fedoraproject.org/pub/archive/epel"


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


def boot(
    row: VmRow,
    images: str,
    work: str,
    pubkey: str,
    *,
    memory: int,
    lock: threading.Lock | None = None,
) -> tuple[VM | None, str]:
    """The row's VM, booted and answering ssh, or None and why not.

    The image is fetched into `images` if it is not there, seeded with the key, and started under
    `lock` where several rows start at once; an aarch64 row under emulation is given ten times the
    wait. The caller stops the VM.
    """
    name = row.name
    image = os.path.join(images, (row.image or name) + ".qcow2")
    if not any(fetch(u, image) for u in row.urls):
        return None, "image not available"
    seed = os.path.join(work, name + "-seed.iso")
    with open(os.path.join(work, name + "-user-data"), "w") as f:
        f.write(user_data(row.family, pubkey, row.kernel_package))
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
    with lock or contextlib.nullcontext():
        port = free_port()
        log("booting", name)
        vm = VM(name, image, work, row.user, port, memory=memory, arch=row.arch)
    slow = 10 if row.arch != "x86_64" else 1
    # a kernel to install and reboot into takes the emulated VM most of its allowance
    if not vm.wait(deadline=600 * slow * (2 if row.kernel_package else 1)):
        vm.stop()
        with open(vm.qemu_log, errors="replace") as f:
            said = " | ".join(f.read()[-300:].split())
        return None, f"did not come up (see {name}-console.log)" + (f": {said}" if said else "")
    return vm, ""


def user_data(family: str, pubkey: str, kernel_package: str = "") -> str:
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
                (
                    "  - printf '[epel]\\nname=EPEL 7, archived\\n"
                    f"baseurl={EPEL7}/7/x86_64/\\ngpgcheck=1\\n"
                    "gpgkey=https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-7\\n' "
                    "> /etc/yum.repos.d/epel-archive.repo"
                ),
                "  - yum install -y zstd",
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
    # with a kernel to boot into, the first boot installs it and reboots, and every boot marks the
    # VM ready only once its pages are 64 KB (bootcmd runs on every boot, runcmd on the first).
    # The kernel is the versioned image the meta-package names, without recommendations: the
    # meta-package also brings linux-firmware, hundreds of megabytes that take the emulated VM
    # a quarter of an hour to unpack and a second initramfs to build, for devices it has not
    ready = ["  - touch /var/tmp/exclave-ready"]
    bootcmd: list[str] = []
    if kernel_package:
        # a YAML single-quoted item: the colon and the backslashes stay as written
        pick = 'sed -n "s/^ *Depends: \\(linux-image-[0-9][^ ]*\\)/\\1/p" | head -1'
        ready = [
            (
                f"  - 'image=$(apt-cache depends {kernel_package} | {pick}); "
                'apt-get install -y --no-install-recommends "$image"\''
            ),
            "  - reboot",
        ]
        mark = 'test "$(getconf PAGESIZE)" = 65536 && touch /var/tmp/exclave-ready; true'
        bootcmd = ["bootcmd:", f"  - [sh, -c, '{mark}']"]
    return "\n".join(
        [
            "#cloud-config",
            "ssh_authorized_keys:",
            "  - " + pubkey,
            "package_update: true",
            "packages:",
        ]
        + ["  - " + p for p in pk]
        + bootcmd
        + ["runcmd:"]
        + retry
        + ready
        + [""]
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
        self.varstore: str | None = None
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
            # no option ROM: the VM boots from its disk, never the network, and the ROM is a
            # package of its own (ipxe-qemu) that a bare QEMU install lacks
            "-device",
            "virtio-net-pci,netdev=n0,romfile=",
        ]
        # no KVM for another architecture: TCG, and UEFI firmware, which arm64 images boot from; the
        # translated code's cache is capped at 256 MB, since its default of 1 GiB fills over the
        # suite and, beside the guest's memory, ran the reference machine out of memory
        if arch == "aarch64":
            varstore = self.varstore = os.path.join(work, name + "-vars.fd")
            shutil.copyfile(os.path.join(AAVMF, "AAVMF_VARS.fd"), varstore)
            cmd = [
                "qemu-system-aarch64",
                "-M",
                "virt",
                "-accel",
                "tcg,tb-size=256",
                "-cpu",
                "max",
                "-m",
                str(max(memory, 2048)),
                # emulated vCPUs beyond the host's cores only contend with each other
                "-smp",
                str(min(4, os.cpu_count() or 1)),
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
        # QEMU's own output, kept beside the console log: a VM that never comes up says why there
        self.qemu_log = os.path.join(work, name + "-qemu.log")
        with open(self.qemu_log, "wb") as out:
            self.proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT)

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
        """Power the VM off and remove its disks.

        The overlay grows to gigabytes over a row and says nothing afterwards that the console log
        and the row's logs do not; the image stays.
        """
        with contextlib.suppress(Exception):
            self.ssh("sudo poweroff || doas poweroff || poweroff", timeout=20)
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        for f in (self.overlay, self.seed, self.varstore):
            if f:
                with contextlib.suppress(FileNotFoundError):
                    os.remove(f)


def pack_payload(
    work: str,
    arch: str,
    libc: str,
    exclave: str,
    *,
    commit: str,
    docker_profile: str | None = None,
    release: str | None = None,
) -> str:
    """The payload a VM of arch and libc unpacks: the test tree, the pinned Python and the builds.

    It carries the repository's test, src and tool, the pinned Python built for the VM, the
    launchers and the command built here for arch, the Go regression's programs, and the exclave,
    or, given release (make_release's directory) for this machine, the release that holds it.
    """
    payload = os.path.join(work, f"payload-{arch}-{libc}.tar.gz")
    # packed afresh every run, so the VMs never test a stale tree
    log("packing the test tree for", arch)
    with tarfile.open(payload, "w:gz", compresslevel=1) as t:
        # src and tool: the sources the suite's fixture is stamped with
        for d in ("test", "src", "tool"):
            t.add(os.path.join(REPO, d), arcname="repo/" + d)
        # the text the launcher carries, which exclave_readme compares
        t.add(os.path.join(REPO, "LICENSE"), arcname="repo/LICENSE")
        # what scripts/reproduce copies and runs, and the commit it names, without a checkout
        for f in ("scripts/build", "scripts/lib.sh", "scripts/reproduce", "VERSION"):
            t.add(os.path.join(REPO, f), arcname="repo/" + f)
        info = tarfile.TarInfo("repo/COMMIT")
        info.size = len(commit) + 1
        t.addfile(info, io.BytesIO(commit.encode() + b"\n"))
        t.add(pinned_python(arch, libc), arcname="python", filter=without_tk)
        if docker_profile:
            t.add(docker_profile, arcname="docker-seccomp.json")
        # the Go regression's programs, built here for the VM's machine: the VMs have no go
        go = tree.go_toolchain()
        if go:
            for n, p in tree.go_build(go, os.path.join(work, "go-" + arch), arch, work):
                t.add(p, arcname=f"repo/build/go/{arch}/{n}")
            fwd = tree.go_build_cgo(go, os.path.join(work, "go-" + arch), arch, work)
            if fwd:
                t.add(fwd, arcname=f"repo/build/go/{arch}/go_fwd")
        if arch == MACHINE and release:
            out = os.path.join(release, "out")
            for f in sorted(os.listdir(out)):
                t.add(os.path.join(out, f), arcname="rel/" + f)
            t.add(os.path.join(release, "key.pub"), arcname="releaser.pub")
        else:
            t.add(exclave, arcname="ex")
        t.add(built("launcher", arch), arcname="repo/build/launcher")
        t.add(built("exclave", arch), arcname="repo/build/exclave")
        if os.path.exists(built("launcher-old", arch)):
            t.add(built("launcher-old", arch), arcname="repo/build/launcher-old")
        # test/sysroot.py's output: runs natively on every glibc of its machine
        if arch == MACHINE and os.path.exists(os.path.join(REPO, "build", "sysroot-hello")):
            t.add(os.path.join(REPO, "build", "sysroot-hello"), arcname="repo/build/sysroot-hello")
    return payload


def make_release(ex: str, reproduced_command: str, work: str) -> str | None:
    """A release of a copy of ex as scripts/release makes one (10.5), signed with a key made here.

    The copy is wrapped with the launcher scripts/reproduce built, by the command built from it,
    as the README has a releaser do. Returns the directory holding the release, `out/`, and the
    public key, `key.pub`, or None when the release could not be made.
    """
    rel = os.path.join(work, "release")
    shutil.rmtree(rel, ignore_errors=True)
    os.makedirs(rel)
    key = os.path.join(rel, "key")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
    copy = tree.copy_exclave(ex, os.path.join(rel, "src", os.path.basename(ex)))
    for cmd in (
        [reproduced_command, "relink", copy],
        [os.path.join(REPO, "scripts", "release"), key, os.path.join(rel, "out"), ex, copy],
    ):
        p = subprocess.run(cmd, capture_output=True, check=False)
        if p.returncode:
            log("the release was not made:", (p.stdout + p.stderr).decode()[-300:])
            return None
    return rel


# The README's recipe for taking a release, run in a VM in the directory holding the release's
# files, for the exclave NAME. Each line it prints is `recipe STEP: ANSWER`. What an old host lacks
# is its answer, not a failure: an ssh-keygen without -Y, and a tar without --zstd, where the
# recipe's portable form pipes zstd into tar; a host with no zstd at all is unpacked by the
# matrix's own Python, so that its suite still runs, and says so.
RECIPE = r"""
say() { echo "recipe $*"; }
echo "exclave-release $(cat ../releaser.pub)" >allowed_signers
if ! command -v ssh-keygen >/dev/null 2>&1; then say 'signature: no ssh-keygen'
elif ssh-keygen -Y verify -f allowed_signers -I exclave-release -n exclave -s SHA256SUMS.sig \
    <SHA256SUMS >sig.out 2>&1; then say 'signature: verified'
elif grep -q 'option -- .\{0,1\}Y' sig.out; then
    say "signature: no ssh-keygen -Y, $(ssh -V 2>&1 | cut -d, -f1)"
else say "signature: FAIL $(tail -1 sig.out)"; fi
if sha256sum -c SHA256SUMS >sums.out 2>&1; then say 'sums: ok'
else say "sums: FAIL $(grep -v ': OK$' sums.out | head -1)"; fi
if tar --help 2>&1 | grep -q -- --zstd; then
    tar --zstd -xf NAME.tar.zst && say 'unpack: tar --zstd' || say 'unpack: FAIL'
elif command -v zstd >/dev/null 2>&1; then
    zstd -dcq NAME.tar.zst | tar -xf - && say 'unpack: zstd -dc | tar' || say 'unpack: FAIL'
elif ../python/bin/python3 -c 'import sys, tarfile
tarfile.open(sys.argv[1]).extractall(filter="fully_trusted")' NAME.tar.zst; then
    say "unpack: no zstd, unpacked by the matrix's Python"
else say 'unpack: FAIL'; fi
chmod +x exclave
if ./exclave check NAME >check.out 2>&1; then say 'check: ok'
else say "check: FAIL $(tail -1 check.out)"; fi
v=$(./exclave version 2>&1)
case $v in "exclave "*) say "version: $v" ;; *) say "version: FAIL $v" ;; esac
o=$(NAME/tree/usr/bin/sh -c 'echo from inside' 2>&1)
if [ "$o" = 'from inside' ]; then say 'program: ok'; else say "program: FAIL $o"; fi
"""


def take_release(answers: str) -> tuple[str, list[str]]:
    """The recipe's answers as the row's note, and its failures.

    An answer an old host gives for want of a tool is recorded, not failed; every other step must
    pass on every row.
    """
    found = dict(re.findall(r"^recipe (\w+): (.*)$", answers, re.MULTILINE))
    steps = ("signature", "sums", "unpack", "check", "version", "program")
    fails = [
        f"FAIL recipe {k}: {found.get(k, 'no answer: ' + answers[-120:])}"
        for k in steps
        if k not in found or found[k].startswith("FAIL")
    ]
    note = "recipe: " + ", ".join(
        found[k] for k in ("signature", "unpack") if k in found and not found[k].startswith("FAIL")
    )
    return note + ("" if fails else ", sums, check, version and a program pass"), fails


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--exclave",
        action="append",
        required=True,
        help="the gcc exclave of one machine, wrapped with its launcher; once per machine",
    )
    ap.add_argument("--only")
    ap.add_argument("--work", default=os.path.join(REPO, "build", "matrix-work"))
    ap.add_argument("--images", default=os.path.join(REPO, "build", "images"))
    ap.add_argument("--memory", type=int, default=1024)
    ap.add_argument(
        "--jobs", type=int, default=1, help="VMs at a time (default 1: 1 GB each, 2 GB emulated)"
    )
    ap.add_argument(
        "--arm64",
        action="store_true",
        help="include the emulated aarch64 VM (slow); --only names it too",
    )
    ap.add_argument(
        "--docker-profile",
        help="Docker's default seccomp profile (scripts/inputs fetches it); "
        "without it the Docker-profile run is left out",
    )
    args = ap.parse_args()
    only = args.only.split(",") if args.only else []
    rows = [
        r
        for r in VMS
        if (not only or r.name in only)
        # the emulated rows run only when asked: ten to twenty times slower
        and (r.arch == "x86_64" or args.arm64 or r.name in only)
    ]
    for prog in ["cloud-localds", *sorted({"qemu-system-" + r.arch for r in rows})]:
        if not shutil.which(prog):
            sys.exit(f"need {prog}")
    exclaves: dict[str, str] = {}  # machine to its gcc exclave, told by the launcher it carries
    for given in args.exclave:
        exclaves[launcher_machine(os.path.abspath(given))] = os.path.abspath(given)
    for row in rows:
        if row.arch not in exclaves:
            sys.exit(f"row {row.name} needs an {row.arch} exclave: give it with --exclave")
    work = os.path.abspath(args.work)
    os.makedirs(work, exist_ok=True)
    os.makedirs(args.images, exist_ok=True)
    key = os.path.join(work, "id_ed25519")
    if not os.path.exists(key):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
    with open(key + ".pub") as f:
        pubkey = f.read().strip()
    # the payload: the row's machine's exclave (hard links preserved by tar), the repository's
    # test tree, the launchers and command built here for that machine, and, where the host has
    # go, the Go regression's programs built for it
    payloads: dict[tuple[str, str], str] = {}

    # 10.5: the launcher built inside this machine's exclave here, which each VM of the same
    # machine builds again inside its copy and must match byte for byte; the command, built from
    # it by the pinned Go, is listed after it, and the VMs, with no Go, build the launcher alone
    reproduced: list[str] = []
    if MACHINE in exclaves:
        p = subprocess.run(
            [
                os.path.join(REPO, "scripts", "reproduce"),
                exclaves[MACHINE],
                os.path.join(work, "reproduce"),
            ],
            capture_output=True,
            check=False,
        )
        reproduced = p.stdout.decode().split() if p.returncode == 0 else []
        if not reproduced:
            log(
                "scripts/reproduce failed here; the rows do not compare builds:",
                p.stderr.decode()[-200:],
            )
    # 10.5: a release of this machine's exclave, which each row of the machine takes as the README
    # has a consumer take it; the exclave the release's archive holds is then the row's exclave, so
    # the payload carries the exclave once
    release = (
        make_release(exclaves[MACHINE], os.path.join(work, "reproduce", "build", "exclave"), work)
        if reproduced
        else None
    )
    commit = (
        subprocess.run(
            ["git", "-C", REPO, "describe", "--always", "--dirty", "--exclude=*"],
            capture_output=True,
            check=False,
        )
        .stdout.decode()
        .strip()
    )

    def payload_for(arch: str, libc: str) -> str:
        if (arch, libc) not in payloads:
            payloads[arch, libc] = pack_payload(
                work,
                arch,
                libc,
                exclaves[arch],
                commit=commit,
                docker_profile=args.docker_profile,
                release=release if arch == MACHINE else None,
            )
        return payloads[arch, libc]

    start_lock = threading.Lock()

    def run_row(row: VmRow) -> Row:
        """One VM's row: boot, copy in, run the suite and the oracles, stop."""
        name, arch, notes = row.name, row.arch, row.notes
        slow = 10 if arch != "x86_64" else 1
        payload = payload_for(arch, "musl" if row.family == "apk" else "gnu")

        def failure(kernel: str, why: str) -> Row:
            return Row(name, kernel, why, "", notes, failed=True)

        vm, why = boot(row, args.images, work, pubkey, memory=args.memory, lock=start_lock)
        if vm is None:
            return failure(row.kernel, why)
        try:
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
            recipe_fails: list[str] = []
            if arch == MACHINE and release:
                # the release taken as a consumer takes it; what it unpacked is the row's exclave
                exname = os.path.basename(exclaves[arch])
                _rc, out = vm.ssh(
                    "cd m/rel && " + RECIPE.replace("NAME", exname) + f"mv {exname} ../ex",
                    timeout=600 * slow,
                )
                with open(os.path.join(work, name + "-recipe.log"), "w") as f:
                    f.write(out)
                recipe, recipe_fails = take_release(out)
                log(name, recipe)
                for f in recipe_fails:
                    log(name, f[:200])
                notes = (notes + "; " if notes else "") + recipe
            elif arch == MACHINE:
                notes = (notes + "; " if notes else "") + "recipe: no release made here"
                recipe_fails = ["FAIL no release was made here"]
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
            fails = [x for x in out.splitlines() if x.startswith("FAIL")] + recipe_fails
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
            if arch == MACHINE and reproduced:
                # 10.5: the exclave's own toolchain builds the same launcher on this kernel's host
                _rc, out = vm.ssh(
                    "cd m && sh repo/scripts/reproduce $PWD/ex $PWD/repro 2>&1 | tail -1",
                    timeout=600 * slow,
                )
                same = out.split()[:2] == reproduced[:2]
                log(name, "reproduced:", "the same bytes" if same else "DIFFER " + out[-200:])
                notes += "; reproduced" if same else "; reproduce DIFFERS"
                if not same:
                    fails.append("FAIL the build inside the exclave differs: " + out[-200:])
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
                    oracle_step("oracle_ns.py", "--work $PWD/nw", 400),
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
                # (77: it said it cannot run on this kernel, test/harness.py)
                oracle_failed = len(statuses) != len(steps) or any(
                    s not in ("0", "77") for s in statuses
                )
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
