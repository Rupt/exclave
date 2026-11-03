"""Check the launcher's syscall classification against the kernel's table (DESIGN.md 17 item 5).

Every syscall in the kernel's table for this machine is classified here: x86-64's unistd_64.h, or
the generic table aarch64 uses. One at or below the filter's ceiling that this file does not know
fails the test; one above it, which the running kernel is probed for, is a note, since the filter
traps it and the handler answers ENOSYS until it is classified here and the ceiling moves (7.4.2).
The launcher's trap list (src/filter.c) must equal TRAP, and its refusals must cover DENIED; the
numbers in src/sys.h's block for this machine must be the kernel's. The filter's trap set and the
syscall page must be the ones its FILTER_VERSION shipped with (SHIPPED), and every path and
descriptor syscall the filter traps must have a case in the syscall probe (test/oracle_syscalls.py).

    test/syscalls.py [unistd.h]     default: the host's table for this machine
"""

import ast
import errno
import hashlib
import os
import platform
import re
import sys
lazy import ctypes
lazy from collections.abc import Sequence

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
MACHINE = platform.machine()

# path arguments the handler translates (7.4.3)
TRAP = {
    "file_getattr",
    "file_setattr",
    "getxattrat",
    "listxattrat",
    "removexattrat",
    "setxattrat",
    "openat2",
    "bind",
    "connect",
    "access",
    "chdir",
    "chmod",
    "chown",
    "creat",
    "execve",
    "execveat",
    "faccessat",
    "faccessat2",
    "fanotify_mark",
    "fchmodat",
    "fchmodat2",
    "fchownat",
    "futimesat",
    "getcwd",
    "getxattr",
    "inotify_add_watch",
    "lchown",
    "lgetxattr",
    "link",
    "linkat",
    "listxattr",
    "llistxattr",
    "lremovexattr",
    "lsetxattr",
    "lstat",
    "mkdir",
    "mkdirat",
    "mknod",
    "mknodat",
    "newfstatat",
    "open",
    "openat",
    "readlink",
    "readlinkat",
    "removexattr",
    "rename",
    "renameat",
    "renameat2",
    "rmdir",
    "setxattr",
    "stat",
    "statfs",
    "statx",
    "symlink",
    "symlinkat",
    "truncate",
    "unlink",
    "unlinkat",
    "utime",
    "utimensat",
    "utimes",
}
# taken away by the filter: ENOSYS or EPERM (7.4.3)
DENIED = {
    "open_tree_attr",
    "acct",
    "chroot",
    "clone3",
    "fsconfig",
    "fsmount",
    "fsopen",
    "fspick",
    "io_uring_setup",
    "mount",
    "mount_setattr",
    "move_mount",
    "name_to_handle_at",
    "open_tree",
    "pivot_root",
    "umount2",
    "uselib",
}
# a path inside a struct or a name that is not a filesystem path: not translated; a datagram
# destination's sockaddr_un (sendto, sendmsg, sendmmsg) reaches the kernel untranslated, which the
# visibility rule makes harmless for /tmp, /run and /var/run and which 13 item 31 lists for exclave
# paths; bind and connect translate theirs (TRAP)
STRUCT_PATH = {
    "accept",
    "accept4",
    "bpf",
    "getpeername",
    "getsockname",
    "mq_open",
    "mq_unlink",
    "quotactl",
    "recvfrom",
    "recvmmsg",
    "recvmsg",
    "sendmmsg",
    "sendmsg",
    "sendto",
    "swapoff",
    "swapon",
}
# no path argument at all
NONPATH = {
    "listns",
    "rseq_slice_yield",
    # x86-64's uprobe trampolines' own syscalls: no arguments that name a file
    "uprobe",
    "uretprobe",
    "mseal",
    "sync_file_range2",
    "_sysctl",
    "add_key",
    "adjtimex",
    "afs_syscall",
    "alarm",
    "arch_prctl",
    "brk",
    "cachestat",
    "capget",
    "capset",
    "clock_adjtime",
    "clock_getres",
    "clock_gettime",
    "clock_nanosleep",
    "clock_settime",
    "clone",
    "close",
    "close_range",
    "copy_file_range",
    "create_module",
    "delete_module",
    "dup",
    "dup2",
    "dup3",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_ctl_old",
    "epoll_pwait",
    "epoll_pwait2",
    "epoll_wait",
    "epoll_wait_old",
    "eventfd",
    "eventfd2",
    "exit",
    "exit_group",
    "fadvise64",
    "fallocate",
    "fanotify_init",
    "fchdir",
    "fchmod",
    "fchown",
    "fcntl",
    "fdatasync",
    "fgetxattr",
    "finit_module",
    "flistxattr",
    "flock",
    "fork",
    "fremovexattr",
    "fsetxattr",
    "fstat",
    "fstatfs",
    "fsync",
    "ftruncate",
    "futex",
    "futex_requeue",
    "futex_wait",
    "futex_waitv",
    "futex_wake",
    "get_kernel_syms",
    "get_mempolicy",
    "get_robust_list",
    "get_thread_area",
    "getcpu",
    "getdents",
    "getdents64",
    "getegid",
    "geteuid",
    "getgid",
    "getgroups",
    "getitimer",
    "getpgid",
    "getpgrp",
    "getpid",
    "getpmsg",
    "getppid",
    "getpriority",
    "getrandom",
    "getresgid",
    "getresuid",
    "getrlimit",
    "getrusage",
    "getsid",
    "getsockopt",
    "gettid",
    "gettimeofday",
    "getuid",
    "init_module",
    "inotify_init",
    "inotify_init1",
    "inotify_rm_watch",
    "io_cancel",
    "io_destroy",
    "io_getevents",
    "io_pgetevents",
    "io_setup",
    "io_submit",
    "io_uring_enter",
    "io_uring_register",
    "ioctl",
    "ioperm",
    "iopl",
    "ioprio_get",
    "ioprio_set",
    "kcmp",
    "kexec_file_load",
    "kexec_load",
    "keyctl",
    "kill",
    "landlock_add_rule",
    "landlock_create_ruleset",
    "landlock_restrict_self",
    "listen",
    "listmount",
    "lookup_dcookie",
    "lseek",
    "lsm_get_self_attr",
    "lsm_list_modules",
    "lsm_set_self_attr",
    "madvise",
    "map_shadow_stack",
    "mbind",
    "membarrier",
    "memfd_create",
    "memfd_secret",
    "migrate_pages",
    "mincore",
    "mlock",
    "mlock2",
    "mlockall",
    "mmap",
    "modify_ldt",
    "move_pages",
    "mprotect",
    "mq_getsetattr",
    "mq_notify",
    "mq_timedreceive",
    "mq_timedsend",
    "mremap",
    "msgctl",
    "msgget",
    "msgrcv",
    "msgsnd",
    "msync",
    "munlock",
    "munlockall",
    "munmap",
    "nanosleep",
    "nfsservctl",
    "open_by_handle_at",
    "pause",
    "perf_event_open",
    "personality",
    "pidfd_getfd",
    "pidfd_open",
    "pidfd_send_signal",
    "pipe",
    "pipe2",
    "pkey_alloc",
    "pkey_free",
    "pkey_mprotect",
    "poll",
    "ppoll",
    "prctl",
    "pread64",
    "preadv",
    "preadv2",
    "prlimit64",
    "process_madvise",
    "process_mrelease",
    "process_vm_readv",
    "process_vm_writev",
    "pselect6",
    "ptrace",
    "putpmsg",
    "pwrite64",
    "pwritev",
    "pwritev2",
    "query_module",
    "quotactl_fd",
    "read",
    "readahead",
    "readv",
    "reboot",
    "remap_file_pages",
    "request_key",
    "restart_syscall",
    "rseq",
    "rt_sigaction",
    "rt_sigpending",
    "rt_sigprocmask",
    "rt_sigqueueinfo",
    "rt_sigreturn",
    "rt_sigsuspend",
    "rt_sigtimedwait",
    "rt_tgsigqueueinfo",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "sched_getaffinity",
    "sched_getattr",
    "sched_getparam",
    "sched_getscheduler",
    "sched_rr_get_interval",
    "sched_setaffinity",
    "sched_setattr",
    "sched_setparam",
    "sched_setscheduler",
    "sched_yield",
    "seccomp",
    "security",
    "select",
    "semctl",
    "semget",
    "semop",
    "semtimedop",
    "sendfile",
    "set_mempolicy",
    "set_mempolicy_home_node",
    "set_robust_list",
    "set_thread_area",
    "set_tid_address",
    "setdomainname",
    "setfsgid",
    "setfsuid",
    "setgid",
    "setgroups",
    "sethostname",
    "setitimer",
    "setns",
    "setpgid",
    "setpriority",
    "setregid",
    "setresgid",
    "setresuid",
    "setreuid",
    "setrlimit",
    "setsid",
    "setsockopt",
    "settimeofday",
    "setuid",
    "shmat",
    "shmctl",
    "shmdt",
    "shmget",
    "shutdown",
    "sigaltstack",
    "signalfd",
    "signalfd4",
    "socket",
    "socketpair",
    "splice",
    "statmount",
    "sync",
    "sync_file_range",
    "syncfs",
    "sysfs",
    "sysinfo",
    "syslog",
    "tee",
    "tgkill",
    "time",
    "timer_create",
    "timer_delete",
    "timer_getoverrun",
    "timer_gettime",
    "timer_settime",
    "timerfd_create",
    "timerfd_gettime",
    "timerfd_settime",
    "times",
    "tkill",
    "tuxcall",
    "umask",
    "uname",
    "unshare",
    "userfaultfd",
    "ustat",
    "vfork",
    "vhangup",
    "vmsplice",
    "vserver",
    "wait4",
    "waitid",
    "write",
    "writev",
}


# syscall numbers newer than the reference headers: name them here as the kernel gains them
EXTRA = {
    462: "mseal",
    463: "setxattrat",
    464: "getxattrat",
    465: "listxattrat",
    466: "removexattrat",
    467: "open_tree_attr",
    468: "file_getattr",
    469: "file_setattr",
    470: "listns",
    471: "rseq_slice_yield",
}
# the highest number src/filter.c classifies; anything above is trapped and answered ENOSYS by
# rule 7.4.2
HIGHEST_KNOWN = 471


# The digest of the trap set and the syscall page each filter version shipped with (7.4.2), as
# trap_digest computes it. A launcher reuses an inherited filter of its own version, so a set or a
# page changed under the same version would send a nested launcher's new trap to the host
# untranslated: a change moves FILTER_VERSION (src/common.h) and records the new digest here.
SHIPPED = {6: "98bd90f1e7eeffbb", 7: "b56b5e8d86ee308d"}


HEADERS = (
    f"usr/include/{MACHINE}-linux-gnu/asm/unistd_64.h",
    "usr/include/asm/unistd_64.h",
    "usr/include/asm-generic/unistd.h",
)


def selected_lines(text: str) -> str:
    """The header's lines as a 64-bit, non-compat build sees them.

    Only __BITS_PER_LONG and __SYSCALL_COMPAT are decided; an #ifdef on an architecture's choice
    (__ARCH_WANT_...) keeps both branches, so a form the machine does not select can appear
    (sync_file_range2) and is classified rather than pruned.
    """
    stack: list[bool | None] = []
    out: list[str] = []
    for line in text.split("\n"):
        d = line.strip()
        if d.startswith("#if"):
            cond = d.split(None, 1)[1] if " " in d else ""
            if "__BITS_PER_LONG == 32" in cond or (
                d.startswith("#ifdef") and "__SYSCALL_COMPAT" in cond
            ):
                stack.append(False)
            elif "__BITS_PER_LONG == 64" in cond or (
                d.startswith("#ifndef") and "__SYSCALL_COMPAT" in cond
            ):
                stack.append(True)
            else:
                stack.append(None)
        elif d.startswith("#else"):
            if stack[-1] is not None:
                stack[-1] = not stack[-1]
        elif d.startswith("#endif"):
            stack.pop()
        elif all(x is not False for x in stack):
            out.append(line)
    return "\n".join(out)


def parse_table(text: str) -> dict[str, int]:
    """Name to number from an x86-64 unistd_64.h, or from the generic table.

    The generic table with its __NR3264_ indirections and 32-bit-only blocks. __NR_syscalls is the
    count and arch_specific_syscall a reserved slot.
    """
    text = selected_lines(text)
    base = {n: int(v) for n, v in re.findall(r"#define __NR3264_([a-z0-9_]+)\s+(\d+)", text)}
    table = {n: int(v) for n, v in re.findall(r"#define __NR_([a-z0-9_]+)\s+(\d+)", text)}
    for n, o in re.findall(r"#define __NR_([a-z0-9_]+)\s+__NR3264_([a-z0-9_]+)", text):
        if o in base:
            table[n] = base[o]
    for n in ("syscalls", "arch_specific_syscall"):
        table.pop(n, None)
    return table


def kernel_table(path: str | None = None, roots: Sequence[str] = ("/",)) -> dict[str, int]:
    """The machine's table from a given header, else from the first root that has one.

    A gcc exclave ships linux-libc-dev, so an exclave's root can be tried before the host's.
    """
    if path is None:
        for r in roots:
            for rel in HEADERS:
                if os.path.exists(os.path.join(r, rel)):
                    path = os.path.join(r, rel)
                    break
            if path:
                break
        else:
            raise SystemExit(
                "no syscall table on the host" + (" or in the exclave" if len(roots) > 1 else "")
            )
    with open(path) as f:
        table = parse_table(f.read())
    for nr, name in EXTRA.items():
        table.setdefault(name, nr)
    return table


def running_table() -> dict[str, int]:
    """The running kernel's own table, from its headers where they are installed, else nothing.

    The userspace header lags the kernel; the kernel's own generated header names every syscall it
    has, so a new one is unclassified here, and fails, as soon as the machine boots that kernel.
    """
    arch = {"x86_64": "x86", "aarch64": "arm64"}.get(MACHINE, MACHINE)
    path = (
        f"/usr/src/linux-headers-{os.uname().release}/arch/{arch}/include/generated/uapi/asm/"
        "unistd_64.h"
    )
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return parse_table(f.read())


def kernel_probe(lo: int, hi: int) -> list[int]:
    """The numbers in [lo, hi] the running kernel implements: anything but ENOSYS.

    A userspace header lags the kernel by years, so the table must be checked against the kernel
    itself.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    present = []
    for nr in range(lo, hi + 1):
        r = libc.syscall(nr, 0, 0, 0, 0, 0, 0)
        if r < 0 and ctypes.get_errno() == errno.ENOSYS:
            continue
        present.append(nr)
    return present


def launcher_lists() -> tuple[set[str], set[str], set[str], dict[str, int]]:
    """The trap list, the refusal lists and the descriptor syscalls of src/filter.c, by name."""
    with open(os.path.join(REPO, "src", "filter.c")) as f:
        src = f.read()
    with open(os.path.join(REPO, "src", "sys.h")) as f:
        sysh = f.read()
    x86, a64 = sysh.split("#if defined(__x86_64__)", 1)[1].split("#elif defined(__aarch64__)", 1)
    block = x86 if MACHINE == "x86_64" else a64.split("#else", 1)[0]
    numbers = {n: int(v) for n, v in re.findall(r"NR_([a-z0-9_]+) = (\d+)", block)}

    def block(name: str) -> set[str]:
        m = re.search(name + r"\[\] = \{(.*?)\};", src, re.DOTALL)
        assert m, f"no {name} in src/filter.c"
        out = set()
        for tok in re.findall(r"NR_([a-z0-9_]+)|(\d+) /\* (\w+) \*/", m.group(1)):
            if tok[0]:
                out.add(tok[0])
            else:
                out.add(tok[2])
        return out

    trap = block("path_syscalls")
    denied = block("enosys_syscalls") | block("eperm_syscalls")
    fd = block("fd_syscalls")
    m = re.search(r"#define HIGHEST_KNOWN_SYSCALL (\d+)", src)
    if m and int(m.group(1)) != HIGHEST_KNOWN:
        print(
            f"FAIL src/filter.c's HIGHEST_KNOWN_SYSCALL is {m.group(1)}, "
            f"this table's is {HIGHEST_KNOWN:d}"
        )
    return trap, denied, fd, numbers


def trap_digest() -> tuple[int, str]:
    """The filter's version and the digest of what its version stands for (SHIPPED).

    That is every syscall the filter singles out, by its table in src/filter.c and by name, with
    the argument an argument trap reads; the ioctl requests it traps; and the syscall page's
    address in src/sys.h.
    """
    with open(os.path.join(REPO, "src", "filter.c")) as f:
        src = f.read()
    with open(os.path.join(REPO, "src", "common.h")) as f:
        m = re.search(r"#define FILTER_VERSION (\d+)", f.read())
        assert m, "no FILTER_VERSION in src/common.h"
        version = int(m.group(1))
    with open(os.path.join(REPO, "src", "sys.h")) as f:
        page = re.search(r"#define SC_PAGE (0x[0-9a-f]+)UL", f.read())
        assert page, "no SC_PAGE in src/sys.h"
    lines = [f"page {page.group(1)}"]
    lines += [f"ioctl {r}" for r in set(re.findall(r"\(uint32_t\)(FS_IOC_\w+)", src))]
    for table in (
        "path_syscalls",
        "fd_syscalls",
        "mask_syscalls",
        "enosys_syscalls",
        "eperm_syscalls",
        "arg_traps",
    ):
        body = re.search(table + r"\[\](?:\[2\])? = \{(.*?)\};", src, re.DOTALL)
        assert body, f"no {table} in src/filter.c"
        text = re.sub(r"^#.*$", "", body.group(1), flags=re.MULTILINE)  # every build's entries
        for nr, arg, _number, name in re.findall(
            r"NR_(\w+)(?:, (\d+)\})?|(\d+) /\* (\w+) \*/", text
        ):
            lines.append(f"{table} {nr or name}" + (f" {arg}" if arg else ""))
    blob = "".join(x + "\n" for x in sorted(lines)).encode()
    return version, hashlib.blake2b(blob, digest_size=8).hexdigest()


def probed() -> set[str]:
    """The syscalls test/oracle_syscalls.py makes cases of.

    Each is the first argument of a call of its add(), a name or the variable of a for loop over
    names.
    """
    with open(os.path.join(HERE, "oracle_syscalls.py"), "rb") as f:
        module = ast.parse(f.read())
    loops: dict[str, set[str]] = {}
    for node in ast.walk(module):
        if (
            isinstance(node, ast.For)
            and isinstance(node.target, ast.Name)
            and isinstance(node.iter, ast.Tuple | ast.List)
        ):
            loops.setdefault(node.target.id, set()).update(
                e.value
                for e in node.iter.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
            )
    names: set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "add":
            first = node.args[0] if node.args else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                names.add(first.value)
            elif isinstance(first, ast.Name):
                names |= loops.get(first.id, set())
    return names


def main() -> int:
    table = kernel_table(sys.argv[1] if len(sys.argv) > 1 else None)
    running = running_table()
    for name, nr in running.items():
        table.setdefault(name, nr)
    if running:
        print(
            f"note: the running kernel's headers name {len(running):d} syscalls, the highest "
            f"{max(running.values()):d}"
        )
    fails = 0
    known = TRAP | DENIED | STRUCT_PATH | NONPATH
    for name in sorted(table, key=lambda n: table[n]):
        if name not in known:
            print(f"FAIL unclassified syscall {table[name]:d} {name}: is it path-taking?")
            fails += 1
    absent = sorted(known - set(table))
    if absent:
        print(
            f"note: {len(absent):d} names classified here are not in this kernel's table "
            f"(forms the other architecture has): {' '.join(absent)}"
        )
    by_nr = {v: k for k, v in table.items()}
    top = max(table.values())
    for nr in kernel_probe(top + 1, top + 64):
        name = by_nr.get(nr, f"unknown-{nr:d}")
        if name in known:
            continue
        if nr > HIGHEST_KNOWN:
            print(
                f"note: the kernel implements syscall {nr:d} ({name}), above the filter's table: "
                "trapped, answered ENOSYS"
            )
        else:
            print(
                f"FAIL the kernel implements syscall {nr:d} ({name}), "
                "which this table does not classify"
            )
            fails += 1
    for name, nr in table.items():
        if nr <= HIGHEST_KNOWN and name not in known:
            print(f"FAIL unclassified syscall {nr:d} {name} below the filter's ceiling")
            fails += 1
    trap, denied, fd, numbers = launcher_lists()
    trap_fixed = {"newfstatat" if n == "fstatat" else n for n in trap}
    for n in sorted(TRAP - trap_fixed):
        print(f"FAIL path syscall {n} is not in the launcher's trap list")
        fails += 1
    for n in sorted(trap_fixed - TRAP):
        print(f"FAIL the launcher traps {n}, which this table does not call path-taking")
        fails += 1
    for n in sorted(DENIED - denied):
        print(f"FAIL {n} should be refused by the filter")
        fails += 1
    for n in sorted(TRAP | DENIED):
        if n in table and n in numbers and numbers[n] != table[n]:
            print(f"FAIL {n}: launcher number {numbers[n]:d}, kernel {table[n]:d}")
            fails += 1
    version, digest = trap_digest()
    if SHIPPED.get(version) != digest:
        print(
            f"FAIL the trap set or the syscall page is not the one filter version {version:d} "
            f"shipped with ({SHIPPED.get(version, 'none recorded')}; the sources give {digest}): "
            "move FILTER_VERSION and record the new digest in SHIPPED (7.4.2)"
        )
        fails += 1
    for n in sorted((TRAP | fd) - probed()):
        print(f"FAIL the filter traps {n}, which has no case in the syscall probe")
        fails += 1
    names = set(table)
    print(
        f"{len(table):d} syscalls in the table: {len(TRAP & names):d} trapped, "
        f"{len(DENIED & names):d} refused, {len(STRUCT_PATH & names):d} with paths in structs, "
        f"{len(NONPATH & names):d} without paths; {fails:d} failures"
    )
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
