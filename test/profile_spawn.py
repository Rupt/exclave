"""Profile a spawn's kernel side with kernel symbols, natively and through the launcher (16.4).

    scripts/profile-spawn --exclave EXCLAVE [--row NAME] [--images DIR] [--work DIR] [--out DIR]
                          [--rounds N] [--spawns N] [--memory MB]
    scripts/profile-spawn --local --exclave EXCLAVE [...]
    scripts/profile-spawn --analyse [--out DIR] [--spawns N]

The reference machine withholds kernel addresses from an unprivileged user (kernel.kptr_restrict),
so the profile runs in one x86-64 VM of the matrix (test/matrix.py's rows and boot), by default
ubuntu-26.10, whose kernel is the nearest of the rows to the reference machine's. The VM gets the
matrix's payload, installs linux-tools for its kernel, sets kernel.kptr_restrict=0 and
kernel.perf_event_paranoid=-1 as root and relinks the exclave with the payload's launcher; then this
file runs there with --guest. The spawn loop is test/bench.py's, SPAWN_C, a posix_spawn of
/usr/bin/true and its waitpid, with --spawns spawns a run. Each of --rounds rounds runs it natively
and through the launcher, the order swapped every round so both sides see the same pace (16.9):
plain for the time and the page faults, under `perf stat` for the counts, and under `perf record
-g` with a fixed period. `strace -f -c` counts each side's syscalls once. The reports come back to
--out (build/profile): the per-symbol self and inclusive tables of each side, their difference per
spawn, the counts, and the conditions. The VM is stopped and its overlay removed at the end, on an
error, on SIGTERM or SIGINT, and when the file stop appears in --work.

--local runs the guest's part on this machine, on a copy of the exclave relinked with
build/launcher, and analyses it the same way: a test of the pipeline, without kernel symbols where
the machine withholds them.

--analyse writes profile.md again from the files of a run in --out.
"""

import argparse
import collections
import contextlib
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
lazy from collections.abc import Callable

import bench
import matrix
import tree

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SIDES = ("native", "launcher")
# the period of a sample: cycles where the VM has a PMU, else nanoseconds of cpu-clock
PERIODS = {"cycles": 200003, "cpu-clock": 50000}
# kernel functions whose inclusive share says where a spawn's kernel time goes, by stage
ANCHORS: list[tuple[str, list[str]]] = [
    ("syscall entry", ["entry_SYSCALL_64_after_hwframe", "do_syscall_64"]),
    ("process creation", ["kernel_clone", "copy_process", "dup_mm", "dup_mmap"]),
    (
        "exec",
        [
            "__x64_sys_execve",
            "do_execveat_common",
            "bprm_execve",
            "exec_binprm",
            "load_elf_binary",
            "begin_new_exec",
            "exec_mmap",
            "setup_arg_pages",
            "elf_load",
            "elf_map",
            "copy_strings",
        ],
    ),
    (
        "mappings",
        [
            "__x64_sys_mmap",
            "ksys_mmap_pgoff",
            "vm_mmap_pgoff",
            "do_mmap",
            "mmap_region",
            "__x64_sys_munmap",
            "__x64_sys_mprotect",
            "do_mprotect_pkey",
            "do_vmi_munmap",
        ],
    ),
    (
        "page faults",
        [
            "asm_exc_page_fault",
            "exc_page_fault",
            "do_user_addr_fault",
            "handle_mm_fault",
            "do_anonymous_page",
            "do_fault",
            "do_wp_page",
            "filemap_map_pages",
            "clear_page_erms",
            "copy_mc_enhanced_fast_string",
            "copy_page",
        ],
    ),
    (
        "seccomp",
        [
            "__x64_sys_seccomp",
            "do_seccomp",
            "seccomp_set_mode_filter",
            "seccomp_prepare_filter",
            "bpf_prog_create_from_user",
            "bpf_prepare_filter",
            "bpf_migrate_filter",
            "bpf_int_jit_compile",
            "seccomp_cache_prepare",
            "__secure_computing",
            "__seccomp_filter",
            "seccomp_run_filters",
            "populate_seccomp_data",
        ],
    ),
    (
        "signals",
        [
            "force_sig_seccomp",
            "force_sig_info_to_task",
            "arch_do_signal_or_restart",
            "get_signal",
            "x64_setup_rt_frame",
            "setup_rt_frame",
            "__x64_sys_rt_sigreturn",
            "restore_sigcontext",
            "__x64_sys_rt_sigaction",
            "__x64_sys_rt_sigprocmask",
            "copy_fpstate_to_sigframe",
            "fpu__restore_sig",
            "__fpu_restore_sig",
        ],
    ),
    (
        "paths and files",
        [
            "__x64_sys_openat",
            "do_sys_openat2",
            "do_filp_open",
            "path_openat",
            "__x64_sys_newfstatat",
            "vfs_fstatat",
            "__x64_sys_newfstat",
            "__x64_sys_readlink",
            "__x64_sys_getdents64",
            "iterate_dir",
            "__x64_sys_read",
            "ksys_read",
            "__x64_sys_close",
            "__x64_sys_faccessat",
            "__x64_sys_openat2",
            "link_path_walk",
            "filename_lookup",
            "__x64_sys_process_vm_readv",
            "__x64_sys_getcwd",
        ],
    ),
    (
        "exit",
        ["__x64_sys_exit_group", "do_exit", "do_group_exit", "exit_mmap", "mmput", "release_task"],
    ),
    (
        "wait and scheduling",
        [
            "__x64_sys_wait4",
            "do_wait",
            "schedule",
            "__schedule",
            "finish_task_switch.isra.0",
            "finish_task_switch",
        ],
    ),
]


def log(*words: object) -> None:
    print(time.strftime("%H:%M:%S"), *words, flush=True)


def run(
    cmd: list[str], cwd: str | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, check=False)


# --- the guest's part: the measurement ------------------------------------------------------------


def compile_spawn(ex: str, out: str, name: str, spawns: int, true: str) -> str:
    """bench.SPAWN_C with `spawns` spawns a run of `true`, built by the exclave's gcc."""
    plain, path = "int n = 300;", '"/usr/bin/true"'
    if plain not in bench.SPAWN_C or path not in bench.SPAWN_C:
        sys.exit("test/bench.py's SPAWN_C no longer says what it spawns and how often")
    src = os.path.join(out, name + ".c")
    with open(src, "w") as f:
        f.write(bench.SPAWN_C.replace(plain, f"int n = {spawns:d};").replace(path, f'"{true}"'))
    prog = os.path.join(out, name)
    gcc = os.path.join(ex, "tree", "usr", "bin", bench.GCC)
    p = run([gcc, "-O2", "-o", prog, src], cwd=out, env={"PATH": "/usr/bin:/bin"})
    if p.returncode:
        sys.exit(f"cannot build {name}: {p.stderr[-400:]}")
    return prog


def event_works(perf: str, events: str) -> bool:
    p = run([perf, "stat", "-x,", "-e", events, "--", "/usr/bin/true"])
    return (
        p.returncode == 0 and "<not supported>" not in p.stderr and "<not counted>" not in p.stderr
    )


def guest(args: argparse.Namespace) -> None:
    """Measure both sides into args.out: timings, perf stat, perf reports, strace counts."""
    ex, out, perf = os.path.abspath(args.exclave), os.path.abspath(args.out), args.perf
    os.makedirs(os.path.join(out, "raw"), exist_ok=True)
    # both sides spawn the same program, the exclave's GNU true: inside by its name, natively as its
    # original on the host's own loader and libc, whatever the host's /usr/bin/true is
    true = os.path.join(ex, "tree", "usr", "bin", ".real", "true")
    strace_n = 100
    prog = {
        (side, n): compile_spawn(ex, out, f"spawn-{side}-{n:d}", n, t)
        for side, t in (("native", true), ("launcher", "/usr/bin/true"))
        for n in (args.spawns, strace_n)
    }
    launcher = os.path.join(ex, ".exclave", "launcher")
    env = {"PATH": "/usr/bin:/bin"}
    cmd = {
        "native": [prog["native", args.spawns]],
        "launcher": [launcher, prog["launcher", args.spawns]],
    }
    pmu = event_works(perf, "cycles")
    ev = "cycles" if pmu else "cpu-clock"
    stat_events = ["task-clock", "page-faults", "context-switches"]
    if pmu:
        stat_events += ["cycles:u", "cycles:k", "instructions:u", "instructions:k"]
    for tp in ("raw_syscalls:sys_enter", "signal:signal_deliver"):
        if event_works(perf, tp):
            stat_events.append(tp)
    cond = [
        f"event {ev}, period {PERIODS[ev]:d}, PMU {'available' if pmu else 'absent'}",
        f"rounds {args.rounds:d}, spawns a run {args.spawns:d}, strace spawns {strace_n:d}",
        f"perf stat events {','.join(stat_events)}",
        "perf " + run([perf, "--version"]).stdout.strip(),
        "uname " + " ".join(platform.uname()),
        (
            f"native spawns {true}; the host's /usr/bin/true is "
            f"{os.path.realpath('/usr/bin/true')}, "
            f"{os.path.getsize(os.path.realpath('/usr/bin/true')):d} bytes"
        ),
    ]
    for f in ("kernel/kptr_restrict", "kernel/perf_event_paranoid"):
        with open("/proc/sys/" + f) as fh:
            cond.append(f"{f.replace('/', '.')} {fh.read().strip()}")
    with open("/proc/cpuinfo") as fh:
        cpu = next((x.split(":", 1)[1].strip() for x in fh if x.startswith("model name")), "?")
    cond.append(f"cpu {cpu}, {os.cpu_count()} online")
    with open("/proc/meminfo") as fh:
        cond.append(fh.readline().strip())
    with open(os.path.join(out, "guest-conditions.txt"), "w") as f:
        f.write("\n".join(cond) + "\n")
    times: dict[str, list[str]] = {s: [] for s in SIDES}
    for r in range(args.rounds):
        order = SIDES if r % 2 == 0 else SIDES[::-1]
        for side in order:
            us = run(cmd[side], cwd=out, env=env).stdout.strip()
            faults = run([*cmd[side], "f"], cwd=out, env=env).stdout.strip()
            times[side].append(f"{us} {faults}")
            log("round", r, side, us, "us a spawn,", faults, "faults")
        for side in order:
            st = os.path.join(out, "raw", f"{side}-{r:d}.stat")
            p = run(
                [perf, "stat", "-x,", "-o", st, "-e", ",".join(stat_events), "--", *cmd[side]],
                cwd=out,
                env=env,
            )
            if p.returncode:
                sys.exit(f"perf stat failed: {p.stderr[-400:]}")
        for side in order:
            data = os.path.join(out, "raw", f"{side}-{r:d}.data")
            p = run(
                [
                    perf,
                    "record",
                    "-q",
                    "-g",
                    "-e",
                    ev,
                    "-c",
                    str(PERIODS[ev]),
                    "-o",
                    data,
                    "--",
                    *cmd[side],
                ],
                cwd=out,
                env=env,
            )
            if p.returncode:
                sys.exit(f"perf record failed: {p.stderr[-400:]}")
            reports = {
                "self": ["--no-children", "--sort", "sym", "-F", "period,sym"],
                "children": ["--children", "--sort", "sym", "-F", "overhead_children,overhead,sym"],
                "dso": ["--no-children", "--sort", "dso", "-F", "period,dso"],
            }
            for kind, opts in reports.items():
                p = run(
                    [
                        perf,
                        "report",
                        "-i",
                        data,
                        "--stdio",
                        "-g",
                        "none",
                        "--percent-limit",
                        "0",
                        *opts,
                    ]
                )
                # perf report answers 0 to a field it does not know
                if p.returncode or "# Event count" not in p.stdout:
                    sys.exit(f"perf report failed: {p.stderr[-400:]}")
                with open(os.path.join(out, "raw", f"{side}-{r:d}.{kind}"), "w") as f:
                    f.write(p.stdout)
            os.remove(data)
    with open(os.path.join(out, "times.txt"), "w") as f:
        for side in SIDES:
            f.write(f"{side} " + " | ".join(times[side]) + "\n")
    if shutil.which("strace"):
        for side, c in (
            ("native", [prog["native", strace_n]]),
            ("launcher", [launcher, prog["launcher", strace_n]]),
        ):
            so = os.path.join(out, f"strace-{side}.txt")
            run(["strace", "-f", "-c", "-o", so, *c], cwd=out, env=env)


# --- the analysis, here ---------------------------------------------------------------------------

Table = dict[str, float]


def parse_self(text: str) -> Table:
    """A self report's period by symbol (`[k] name` or `[.] name`)."""
    t: Table = collections.defaultdict(float)
    for line in text.splitlines():
        m = re.match(r"\s*(\d+)\s+(.+?)\s*$", line)
        if m and not line.lstrip().startswith("#"):
            t[m.group(2)] += float(m.group(1))
    return t


def event_count(text: str) -> float:
    m = re.search(r"^# Event count \(approx\.\): (\d+)", text, re.MULTILINE)
    return float(m.group(1)) if m else 0.0


def parse_children(text: str) -> Table:
    """A children report's inclusive period by symbol, its percentage of the event count."""
    total = event_count(text)
    t: Table = collections.defaultdict(float)
    for line in text.splitlines():
        m = re.match(r"\s*([\d.]+)%\s+([\d.]+)%\s+(.+?)\s*$", line)
        if m and not line.lstrip().startswith("#"):
            # perf marks a function [k] or [.] by no rule a reader can use in this report, one entry
            # each, so the bare name is the key
            t[re.sub(r"^\[.\] ", "", m.group(3))] += float(m.group(1)) / 100 * total
    return t


def parse_stat(text: str) -> Table:
    t: Table = {}
    for line in text.splitlines():
        f = line.split(",")
        if len(f) >= 3 and f[2] and not line.startswith("#"):
            value = f[0].strip()
            if re.fullmatch(r"[\d.]+", value):
                # task-clock in nanoseconds, whatever unit perf chose
                t[f[2]] = float(value) * {"msec": 1e6, "usec": 1e3, "sec": 1e9}.get(f[1], 1.0)
    return t


def parse_strace(text: str) -> Table:
    t: Table = {}
    for line in text.splitlines():
        f = line.split()
        # % time, seconds, usecs/call, calls, [errors], syscall
        if len(f) >= 5 and re.fullmatch(r"[\d.]+", f[0]) and f[-1] != "total":
            t[f[-1]] = float(f[3])
    return t


def side_sum(raw: str, side: str, kind: str, parse: Callable[[str], Table]) -> tuple[Table, int]:
    total: Table = collections.defaultdict(float)
    n = 0
    for name in sorted(os.listdir(raw)):
        if name.startswith(side + "-") and name.endswith("." + kind):
            with open(os.path.join(raw, name)) as f:
                for k, v in parse(f.read()).items():
                    total[k] += v
            n += 1
    return total, n


def analyse(out: str, spawns: int) -> str:
    """Write profile.md in out from the files of a run, and return it."""
    raw = os.path.join(out, "raw")
    stats = {s: side_sum(raw, s, "stat", parse_stat) for s in SIDES}
    rounds = stats["native"][1]
    if not rounds or stats["launcher"][1] != rounds:
        sys.exit(f"{raw}: the rounds of the two sides do not match")
    per = rounds * spawns

    def stat(side: str, key: str) -> float:
        return stats[side][0].get(key, 0.0) / per

    # the cycles a microsecond of task-clock gives, to put the profile's periods in time
    cyc = sum(stat(s, "cycles:u") + stat(s, "cycles:k") for s in SIDES)
    clock_ns = sum(stat(s, "task-clock") for s in SIDES)
    ghz = cyc / clock_ns if cyc and clock_ns else 0.0
    unit = "kcycles" if ghz else "us"
    scale = 1000.0  # kcycles from cycles, microseconds from nanoseconds

    def fmt(v: float) -> str:
        return f"{v / scale:.2f}"

    lines: list[str] = ["# Spawn profile, native against the launcher", ""]
    lines += ["## Conditions", ""]
    for name in ("host-conditions.txt", "guest-conditions.txt"):
        with open(os.path.join(out, name)) as f:
            lines += [f"- {x.strip()}" for x in f if x.strip()]
    if ghz:
        lines.append(f"- {ghz:.2f} cycles a nanosecond of task-clock over both sides")
    lines += ["", "## Plain runs (us a spawn, page faults a process), by round", ""]
    with open(os.path.join(out, "times.txt")) as f:
        lines += [f"- {x.strip()}" for x in f]
    lines += [
        "",
        "## perf stat, a spawn, mean over the rounds",
        "",
        "| count | native | launcher | ratio |",
        "|---|---|---|---|",
    ]
    for key in sorted(set(stats["native"][0]) | set(stats["launcher"][0])):
        a, b = stat("native", key), stat("launcher", key)
        lines.append(f"| {key} | {a:,.1f} | {b:,.1f} | {b / a if a else 0:.2f} |")

    selfs = {s: side_sum(raw, s, "self", parse_self)[0] for s in SIDES}
    kids = {s: side_sum(raw, s, "children", parse_children)[0] for s in SIDES}
    dsos = {s: side_sum(raw, s, "dso", parse_self)[0] for s in SIDES}
    # perf names each process's anonymous executable memory, the launcher's syscall page, by its tid
    for d in dsos.values():
        for k in [k for k in d if k.startswith("[JIT] tid ")]:
            d["[JIT] the syscall page and other anonymous code"] = d.get(
                "[JIT] the syscall page and other anonymous code", 0
            ) + d.pop(k)

    def kernel_total(side: str) -> float:
        return sum(v for k, v in selfs[side].items() if k.startswith("[k]"))

    def all_total(side: str) -> float:
        return sum(selfs[side].values())

    lines += [
        "",
        f"## Profile totals, {unit} a spawn",
        "",
        "| | native | launcher | difference |",
        "|---|---|---|---|",
    ]
    for label, fn in (("kernel", kernel_total), ("all", all_total)):
        a, b = fn("native") / per, fn("launcher") / per
        lines.append(f"| {label} | {fmt(a)} | {fmt(b)} | {fmt(b - a)} |")
    lines += [
        "",
        f"## By object (self), {unit} a spawn",
        "",
        "| object | native | launcher | difference |",
        "|---|---|---|---|",
    ]
    keys = sorted(
        set(dsos["native"]) | set(dsos["launcher"]),
        key=lambda k: -(dsos["launcher"].get(k, 0) - dsos["native"].get(k, 0)),
    )
    for k in keys:
        a, b = dsos["native"].get(k, 0) / per, dsos["launcher"].get(k, 0) / per
        if max(a, b) >= 0.5 * scale:
            lines.append(f"| `{k}` | {fmt(a)} | {fmt(b)} | {fmt(b - a)} |")
    lines += [
        "",
        f"## Kernel stages, inclusive, {unit} a spawn (overlapping)",
        "",
        "| stage | function | native | launcher | difference |",
        "|---|---|---|---|---|",
    ]
    for stage, funcs in ANCHORS:
        for fn in funcs:
            a, b = (kids["native"].get(fn, 0) / per, kids["launcher"].get(fn, 0) / per)
            if a or b:
                lines.append(f"| {stage} | `{fn}` | {fmt(a)} | {fmt(b)} | {fmt(b - a)} |")
    for title, tables, limit in (("self", selfs, 60), ("inclusive", kids, 80)):
        lines += [
            "",
            f"## Symbols by difference, {title}, {unit} a spawn (the first {limit:d})",
            "",
            "| symbol | native | launcher | difference |",
            "|---|---|---|---|",
        ]
        keys = sorted(
            set(tables["native"]) | set(tables["launcher"]),
            key=lambda k: -abs(tables["launcher"].get(k, 0) - tables["native"].get(k, 0)),
        )
        for k in keys[:limit]:
            a, b = tables["native"].get(k, 0) / per, tables["launcher"].get(k, 0) / per
            lines.append(f"| `{k}` | {fmt(a)} | {fmt(b)} | {fmt(b - a)} |")
    for side in SIDES:
        lines += [
            "",
            f"## Symbols of the {side} side, self, the first 40",
            "",
            "| symbol | share | per spawn |",
            "|---|---|---|",
        ]
        tot = all_total(side)
        for k, v in sorted(selfs[side].items(), key=lambda kv: -kv[1])[:40]:
            lines.append(f"| `{k}` | {100 * v / tot:.1f}% | {fmt(v / per)} |")
    sc = {}
    for side in SIDES:
        p = os.path.join(out, f"strace-{side}.txt")
        if os.path.exists(p):
            with open(p) as f:
                sc[side] = parse_strace(f.read())
    if len(sc) == 2:
        lines += [
            "",
            "## Syscalls a spawn, all processes (strace -f -c over 100 spawns)",
            "",
            "| syscall | native | launcher | difference |",
            "|---|---|---|---|",
        ]
        keys = sorted(
            set(sc["native"]) | set(sc["launcher"]),
            key=lambda k: -(sc["launcher"].get(k, 0) - sc["native"].get(k, 0)),
        )
        for k in keys:
            a, b = sc["native"].get(k, 0) / 100, sc["launcher"].get(k, 0) / 100
            lines.append(f"| {k} | {a:.2f} | {b:.2f} | {b - a:+.2f} |")
        lines.append(
            f"| total | {sum(sc['native'].values()) / 100:.2f} | "
            f"{sum(sc['launcher'].values()) / 100:.2f} | |"
        )
    text = "\n".join(lines) + "\n"
    with open(os.path.join(out, "profile.md"), "w") as f:
        f.write(text)
    return text


# --- the host's part: the VM ----------------------------------------------------------------------


def on_signal(signum: int, _frame: object) -> None:
    """A signal ends the run through SystemExit, so that the VM is stopped on the way out."""
    sys.exit(f"stopped by signal {signum:d}")


def stop_vm(vm: matrix.VM | None, name: str, work: str) -> None:
    """Stop the VM and remove its disks; with no VM yet, the QEMU that boot started on the overlay.

    A signal while boot waits for the VM leaves its QEMU running with nothing returned to stop it.
    """
    if vm is not None:
        vm.stop()
        return
    overlay = os.path.join(work, name + ".qcow2")
    subprocess.run(["pkill", "-f", f"^qemu-system-x86_64 .*file={overlay},"], check=False)
    time.sleep(2)
    for f in (overlay, os.path.join(work, name + "-seed.iso")):
        with contextlib.suppress(FileNotFoundError):
            os.remove(f)


def watch_stop(stop: str, done: threading.Event) -> None:
    """Send this process SIGTERM when the stop file appears, so the VM is stopped as on a signal."""
    while not done.wait(5):
        if os.path.exists(stop):
            os.kill(os.getpid(), signal.SIGTERM)
            return


def fetch_dir(vm: matrix.VM, src: str, dst: str) -> None:
    """Copy the VM's directory src into dst, through tar over ssh."""
    os.makedirs(dst, exist_ok=True)
    ssh = subprocess.Popen(
        [
            "ssh",
            "-p",
            str(vm.port),
            "-i",
            vm.key,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            f"{vm.user}@127.0.0.1",
            f"tar -C {src} -cf - .",
        ],
        stdout=subprocess.PIPE,
    )
    subprocess.run(["tar", "-C", dst, "-xf", "-"], stdin=ssh.stdout, check=True)
    if ssh.wait():
        sys.exit(f"cannot fetch {src} from the VM")


def must(vm: matrix.VM, what: str, cmd: str, mark: str, timeout: float = 1200) -> str:
    rc, out = vm.ssh(cmd, timeout=timeout)
    if mark not in out:
        sys.exit(f"{what} failed ({rc:d}): {out[-600:]}")
    return out


GUEST_SETUP = r"""
set -u
S=sudo
A="$S env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=900 install -y -q"
$A linux-tools-$(uname -r) >apt.log 2>&1 || $A linux-tools-generic >>apt.log 2>&1 || {
    tail -5 apt.log; exit 1; }
# the perf built for the kernel, wherever its package puts it, else one that runs here
for p in /usr/lib/linux-tools/$(uname -r)/perf /usr/lib/linux-tools-$(uname -r)/perf \
    $(dpkg -L linux-tools-$(uname -r) linux-tools-generic 2>/dev/null | grep '/perf$') \
    $(command -v perf); do
    [ -f "$p" ] && "$p" --version >/dev/null 2>&1 && { perf=$p; break; }
done
[ -n "${perf-}" ] || { echo no perf; tail -5 apt.log; dpkg -l 'linux-tools*' | tail -5; exit 1; }
$S sysctl -q -w kernel.kptr_restrict=0 kernel.perf_event_paranoid=-1
$S mount -o remount,mode=755 /sys/kernel/tracing 2>/dev/null
for e in raw_syscalls signal; do $S chmod -R a+rX /sys/kernel/tracing/events/$e 2>/dev/null; done
echo "perf=$perf"
"""


def host(args: argparse.Namespace) -> None:
    rows = {r.name: r for r in matrix.VMS if r.arch == "x86_64"}
    if args.row not in rows:
        sys.exit(f"no x86-64 row {args.row}: one of {', '.join(rows)}")
    row = rows[args.row]
    out, work = os.path.abspath(args.out), os.path.abspath(args.work)
    shutil.rmtree(os.path.join(out, "raw"), ignore_errors=True)
    os.makedirs(work, exist_ok=True)
    stop = os.path.join(work, "stop")
    if os.path.exists(stop):
        os.remove(stop)
    key = os.path.join(work, "id_ed25519")
    if not os.path.exists(key):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
    with open(key + ".pub") as f:
        pubkey = f.read().strip()
    commit = run(
        ["git", "-C", REPO, "describe", "--always", "--dirty", "--exclude=*"]
    ).stdout.strip()
    payload = matrix.pack_payload(
        work, "x86_64", "gnu", os.path.abspath(args.exclave), commit=commit
    )
    conditions = [
        f"row {row.name}, commit {commit}",
        "host " + " ".join(platform.uname()),
        run(["qemu-system-x86_64", "--version"]).stdout.splitlines()[0],
        f"QEMU under KVM, -cpu host, 2 vCPUs, {args.memory:d} MB",
    ]
    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(s, on_signal)
    done = threading.Event()
    threading.Thread(target=watch_stop, args=(stop, done), daemon=True).start()
    vm: matrix.VM | None = None
    try:
        vm, why = matrix.boot(row, args.images, work, pubkey, memory=args.memory)
        if vm is None:
            sys.exit(f"the VM did not boot: {why}")
        log("booted; kernel", vm.ssh("uname -r")[1].strip())
        vm.scp(payload, "payload.tar.gz")
        must(
            vm,
            "unpacking",
            "mkdir -p m && cd m && tar xzf ../payload.tar.gz && echo unpacked",
            "unpacked",
        )
        must(
            vm,
            "relinking",
            "cd m && repo/build/exclave relink ex repo/build/launcher 2>&1 | tail -1",
            "relinked",
        )
        said = must(vm, "installing perf", GUEST_SETUP, "perf=", timeout=1800)
        perf = said.rsplit("perf=", 1)[1].split()[0]
        log("perf at", perf)
        rc, said = vm.ssh(
            f"cd m && python/bin/python3 repo/test/profile_spawn.py --guest --exclave $PWD/ex "
            f"--out $PWD/out --perf {perf} --rounds {args.rounds:d} --spawns {args.spawns:d} 2>&1",
            timeout=5400,
        )
        print(said[-3000:], flush=True)
        if rc:
            sys.exit(f"the guest's run failed ({rc:d})")
        fetch_dir(vm, "m/out", out)
    finally:
        done.set()
        log("stopping the VM")
        stop_vm(vm, row.name, work)
    for f in os.listdir(out):
        if f.startswith("spawn-") and not f.endswith(".c"):
            os.remove(os.path.join(out, f))
    with open(os.path.join(out, "host-conditions.txt"), "w") as f:
        f.write("\n".join(conditions) + "\n")
    analyse(out, args.spawns)
    log("written", os.path.join(out, "profile.md"))


def local(args: argparse.Namespace) -> None:
    """The guest's part and the analysis on this machine: a test of the pipeline."""
    out, work = os.path.abspath(args.out), os.path.abspath(args.work)
    shutil.rmtree(os.path.join(out, "raw"), ignore_errors=True)
    shutil.rmtree(os.path.join(work, "exclave"), ignore_errors=True)
    os.makedirs(work, exist_ok=True)
    args.exclave = tree.fresh_exclave(os.path.abspath(args.exclave), os.path.join(work, "exclave"))
    args.out = out
    args.perf = shutil.which("perf") or sys.exit("no perf here")
    guest(args)
    with open(os.path.join(out, "host-conditions.txt"), "w") as f:
        f.write("local run on the host, " + " ".join(platform.uname()) + "\n")
    analyse(out, args.spawns)
    log("written", os.path.join(out, "profile.md"))


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--exclave", help="the gcc exclave (scripts/inputs: gcc13.exclave)")
    ap.add_argument("--row", default="ubuntu-26.10", help="the x86-64 matrix row to boot")
    ap.add_argument("--images", default=os.path.join(REPO, "build", "images"))
    ap.add_argument("--work", default=os.path.join(REPO, "build", "profile-work"))
    ap.add_argument("--out", default=os.path.join(REPO, "build", "profile"))
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--spawns", type=int, default=2000)
    ap.add_argument("--memory", type=int, default=2048)
    ap.add_argument("--local", action="store_true", help="run on this machine, without a VM")
    ap.add_argument(
        "--analyse", action="store_true", help="write profile.md again from --out's files"
    )
    ap.add_argument("--guest", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--perf", help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.analyse:
        analyse(os.path.abspath(args.out), args.spawns)
        return
    if not args.exclave:
        ap.error("--exclave is required")
    if args.guest:
        guest(args)
    elif args.local:
        local(args)
    else:
        host(args)


if __name__ == "__main__":
    main()
