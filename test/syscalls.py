#!/usr/bin/env python3
"""syscalls.py — the path-syscall table test (PROPOSAL.md 17, item 5).

Every syscall in the kernel's table for this machine is classified here: x86-64's unistd_64.h, or the
generic table aarch64 uses. One at or below the filter's ceiling that this file does not know fails the test;
one above it, which the running kernel is probed for, is a note, since the filter traps it and the handler
answers ENOSYS until it is classified here and the ceiling moves (7.4.2). The launcher's trap list (src/filter.c) must equal
TRAP, and its refusals must cover DENIED; the numbers in src/sys.h's block for this machine must be the
kernel's.

    test/syscalls.py [unistd.h]     default: the host's table for this machine
"""
import os
import platform
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
MACHINE = platform.machine()

# path arguments the handler translates (7.4.3)
TRAP = set(['file_getattr', 'file_setattr', 'getxattrat', 'listxattrat', 'removexattrat', 'setxattrat', 'openat2', 'bind', 'connect'] + ['access', 'chdir', 'chmod', 'chown', 'creat', 'execve', 'execveat', 'faccessat', 'faccessat2', 'fanotify_mark', 'fchmodat', 'fchmodat2', 'fchownat', 'futimesat', 'getcwd', 'getxattr', 'inotify_add_watch', 'lchown', 'lgetxattr', 'link', 'linkat', 'listxattr', 'llistxattr', 'lremovexattr', 'lsetxattr', 'lstat', 'mkdir', 'mkdirat', 'mknod', 'mknodat', 'newfstatat', 'open', 'openat', 'readlink', 'readlinkat', 'removexattr', 'rename', 'renameat', 'renameat2', 'rmdir', 'setxattr', 'stat', 'statfs', 'statx', 'symlink', 'symlinkat', 'truncate', 'unlink', 'unlinkat', 'utime', 'utimensat', 'utimes'])
# taken away by the filter: ENOSYS or EPERM (7.4.3)
DENIED = set(['open_tree_attr'] + ['acct', 'chroot', 'clone3', 'fsconfig', 'fsmount', 'fsopen', 'fspick', 'io_uring_setup', 'mount', 'mount_setattr', 'move_mount', 'name_to_handle_at', 'open_tree', 'pivot_root', 'umount2', 'uselib'])
# a path inside a struct or a name that is not a filesystem path: not translated; a datagram destination's
# sockaddr_un (sendto, sendmsg, sendmmsg) reaches the kernel untranslated, which the visibility rule makes
# harmless for /tmp, /run and /var/run and which 13 item 31 lists for exclave paths; bind and connect
# translate theirs (TRAP)
STRUCT_PATH = set(['accept', 'accept4', 'bpf', 'getpeername', 'getsockname', 'mq_open', 'mq_unlink', 'quotactl', 'recvfrom', 'recvmmsg', 'recvmsg', 'sendmmsg', 'sendmsg', 'sendto', 'swapoff', 'swapon'])
# no path argument at all
NONPATH = set(['listns', 'mseal', 'sync_file_range2'] + ['_sysctl', 'add_key', 'adjtimex', 'afs_syscall', 'alarm', 'arch_prctl', 'brk', 'cachestat', 'capget', 'capset', 'clock_adjtime', 'clock_getres', 'clock_gettime', 'clock_nanosleep', 'clock_settime', 'clone', 'close', 'close_range', 'copy_file_range', 'create_module', 'delete_module', 'dup', 'dup2', 'dup3', 'epoll_create', 'epoll_create1', 'epoll_ctl', 'epoll_ctl_old', 'epoll_pwait', 'epoll_pwait2', 'epoll_wait', 'epoll_wait_old', 'eventfd', 'eventfd2', 'exit', 'exit_group', 'fadvise64', 'fallocate', 'fanotify_init', 'fchdir', 'fchmod', 'fchown', 'fcntl', 'fdatasync', 'fgetxattr', 'finit_module', 'flistxattr', 'flock', 'fork', 'fremovexattr', 'fsetxattr', 'fstat', 'fstatfs', 'fsync', 'ftruncate', 'futex', 'futex_requeue', 'futex_wait', 'futex_waitv', 'futex_wake', 'get_kernel_syms', 'get_mempolicy', 'get_robust_list', 'get_thread_area', 'getcpu', 'getdents', 'getdents64', 'getegid', 'geteuid', 'getgid', 'getgroups', 'getitimer', 'getpgid', 'getpgrp', 'getpid', 'getpmsg', 'getppid', 'getpriority', 'getrandom', 'getresgid', 'getresuid', 'getrlimit', 'getrusage', 'getsid', 'getsockopt', 'gettid', 'gettimeofday', 'getuid', 'init_module', 'inotify_init', 'inotify_init1', 'inotify_rm_watch', 'io_cancel', 'io_destroy', 'io_getevents', 'io_pgetevents', 'io_setup', 'io_submit', 'io_uring_enter', 'io_uring_register', 'ioctl', 'ioperm', 'iopl', 'ioprio_get', 'ioprio_set', 'kcmp', 'kexec_file_load', 'kexec_load', 'keyctl', 'kill', 'landlock_add_rule', 'landlock_create_ruleset', 'landlock_restrict_self', 'listen', 'listmount', 'lookup_dcookie', 'lseek', 'lsm_get_self_attr', 'lsm_list_modules', 'lsm_set_self_attr', 'madvise', 'map_shadow_stack', 'mbind', 'membarrier', 'memfd_create', 'memfd_secret', 'migrate_pages', 'mincore', 'mlock', 'mlock2', 'mlockall', 'mmap', 'modify_ldt', 'move_pages', 'mprotect', 'mq_getsetattr', 'mq_notify', 'mq_timedreceive', 'mq_timedsend', 'mremap', 'msgctl', 'msgget', 'msgrcv', 'msgsnd', 'msync', 'munlock', 'munlockall', 'munmap', 'nanosleep', 'nfsservctl', 'open_by_handle_at', 'pause', 'perf_event_open', 'personality', 'pidfd_getfd', 'pidfd_open', 'pidfd_send_signal', 'pipe', 'pipe2', 'pkey_alloc', 'pkey_free', 'pkey_mprotect', 'poll', 'ppoll', 'prctl', 'pread64', 'preadv', 'preadv2', 'prlimit64', 'process_madvise', 'process_mrelease', 'process_vm_readv', 'process_vm_writev', 'pselect6', 'ptrace', 'putpmsg', 'pwrite64', 'pwritev', 'pwritev2', 'query_module', 'quotactl_fd', 'read', 'readahead', 'readv', 'reboot', 'remap_file_pages', 'request_key', 'restart_syscall', 'rseq', 'rt_sigaction', 'rt_sigpending', 'rt_sigprocmask', 'rt_sigqueueinfo', 'rt_sigreturn', 'rt_sigsuspend', 'rt_sigtimedwait', 'rt_tgsigqueueinfo', 'sched_get_priority_max', 'sched_get_priority_min', 'sched_getaffinity', 'sched_getattr', 'sched_getparam', 'sched_getscheduler', 'sched_rr_get_interval', 'sched_setaffinity', 'sched_setattr', 'sched_setparam', 'sched_setscheduler', 'sched_yield', 'seccomp', 'security', 'select', 'semctl', 'semget', 'semop', 'semtimedop', 'sendfile', 'set_mempolicy', 'set_mempolicy_home_node', 'set_robust_list', 'set_thread_area', 'set_tid_address', 'setdomainname', 'setfsgid', 'setfsuid', 'setgid', 'setgroups', 'sethostname', 'setitimer', 'setns', 'setpgid', 'setpriority', 'setregid', 'setresgid', 'setresuid', 'setreuid', 'setrlimit', 'setsid', 'setsockopt', 'settimeofday', 'setuid', 'shmat', 'shmctl', 'shmdt', 'shmget', 'shutdown', 'sigaltstack', 'signalfd', 'signalfd4', 'socket', 'socketpair', 'splice', 'statmount', 'sync', 'sync_file_range', 'syncfs', 'sysfs', 'sysinfo', 'syslog', 'tee', 'tgkill', 'time', 'timer_create', 'timer_delete', 'timer_getoverrun', 'timer_gettime', 'timer_settime', 'timerfd_create', 'timerfd_gettime', 'timerfd_settime', 'times', 'tkill', 'tuxcall', 'umask', 'uname', 'unshare', 'userfaultfd', 'ustat', 'vfork', 'vhangup', 'vmsplice', 'vserver', 'wait4', 'waitid', 'write', 'writev'])


# syscall numbers newer than the reference headers: name them here as the kernel gains them (review O3-5)
EXTRA = {462: "mseal", 463: "setxattrat", 464: "getxattrat", 465: "listxattrat", 466: "removexattrat", 467: "open_tree_attr",
         468: "file_getattr", 469: "file_setattr", 470: "listns"}
# the highest number src/filter.c classifies; anything above is trapped and answered ENOSYS by rule 7.4.2
HIGHEST_KNOWN = 470


HEADERS = ("usr/include/%s-linux-gnu/asm/unistd_64.h" % MACHINE, "usr/include/asm/unistd_64.h", "usr/include/asm-generic/unistd.h")


def selected_lines(text):
    """The header's lines as a 64-bit, non-compat build sees them. Only __BITS_PER_LONG and __SYSCALL_COMPAT
    are decided; an #ifdef on an architecture's choice (__ARCH_WANT_...) keeps both branches, so a form the
    machine does not select can appear (sync_file_range2) and is classified rather than pruned."""
    stack, out = [], []
    for line in text.split("\n"):
        d = line.strip()
        if d.startswith("#if"):
            cond = d.split(None, 1)[1] if " " in d else ""
            if "__BITS_PER_LONG == 32" in cond or (d.startswith("#ifdef") and "__SYSCALL_COMPAT" in cond):
                stack.append(False)
            elif "__BITS_PER_LONG == 64" in cond or (d.startswith("#ifndef") and "__SYSCALL_COMPAT" in cond):
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


def parse_table(text):
    """Name to number from an x86-64 unistd_64.h, or from the generic table with its __NR3264_ indirections
    and 32-bit-only blocks. __NR_syscalls is the count and arch_specific_syscall a reserved slot."""
    text = selected_lines(text)
    base = dict((n, int(v)) for n, v in re.findall(r"#define __NR3264_([a-z0-9_]+)\s+(\d+)", text))
    table = dict((n, int(v)) for n, v in re.findall(r"#define __NR_([a-z0-9_]+)\s+(\d+)", text))
    for n, o in re.findall(r"#define __NR_([a-z0-9_]+)\s+__NR3264_([a-z0-9_]+)", text):
        if o in base:
            table[n] = base[o]
    for n in ("syscalls", "arch_specific_syscall"):
        table.pop(n, None)
    return table


def kernel_table(path=None, roots=("/",)):
    """The machine's table from a given header, else from the first root that has one (a gcc exclave ships
    linux-libc-dev, so an exclave's root can be tried before the host's)."""
    if path is None:
        for r in roots:
            for rel in HEADERS:
                if os.path.exists(os.path.join(r, rel)):
                    path = os.path.join(r, rel)
                    break
            if path:
                break
        else:
            raise SystemExit("no syscall table on the host" + (" or in the exclave" if len(roots) > 1 else ""))
    table = parse_table(open(path).read())
    for nr, name in EXTRA.items():
        table.setdefault(name, nr)
    return table


def kernel_probe(lo, hi):
    """The numbers in [lo, hi] the running kernel implements: anything but ENOSYS. A userspace header lags
    the kernel by years, so the table must be checked against the kernel itself (review O3-5)."""
    import ctypes
    import errno
    libc = ctypes.CDLL(None, use_errno=True)
    present = []
    for nr in range(lo, hi + 1):
        r = libc.syscall(nr, 0, 0, 0, 0, 0, 0)
        if r < 0 and ctypes.get_errno() == errno.ENOSYS:
            continue
        present.append(nr)
    return present


def launcher_lists():
    """The trap list and the refusal lists of src/filter.c, by name."""
    src = open(os.path.join(REPO, "src", "filter.c")).read()
    sysh = open(os.path.join(REPO, "src", "sys.h")).read()
    x86, a64 = sysh.split("#if defined(__x86_64__)", 1)[1].split("#elif defined(__aarch64__)", 1)
    block = x86 if MACHINE == "x86_64" else a64.split("#else", 1)[0]
    numbers = dict((n, int(v)) for n, v in re.findall(r"NR_([a-z0-9_]+) = (\d+)", block))

    def block(name):
        m = re.search(name + r"\[\] = \{(.*?)\};", src, re.S)
        out = set()
        for tok in re.findall(r"NR_([a-z0-9_]+)|(\d+) /\* (\w+) \*/", m.group(1)):
            if tok[0]:
                out.add(tok[0])
            else:
                out.add(tok[2])
        return out
    trap = block("path_syscalls")
    denied = block("enosys_syscalls") | block("eperm_syscalls")
    m = re.search(r"#define HIGHEST_KNOWN_SYSCALL (\d+)", src)
    if m and int(m.group(1)) != HIGHEST_KNOWN:
        print("FAIL src/filter.c's HIGHEST_KNOWN_SYSCALL is %s, this table's is %d" % (m.group(1), HIGHEST_KNOWN))
    return trap, denied, numbers


def main():
    table = kernel_table(sys.argv[1] if len(sys.argv) > 1 else None)
    fails = 0
    known = TRAP | DENIED | STRUCT_PATH | NONPATH
    for name in sorted(table, key=table.get):
        if name not in known:
            print("FAIL unclassified syscall %d %s: is it path-taking?" % (table[name], name))
            fails += 1
    absent = sorted(known - set(table))
    if absent:
        print("note: %d names classified here are not in this kernel's table (forms the other architecture has): %s" % (len(absent), " ".join(absent)))
    by_nr = dict((v, k) for k, v in table.items())
    top = max(table.values())
    for nr in kernel_probe(top + 1, top + 64):
        name = by_nr.get(nr, "unknown-%d" % nr)
        if name in known:
            continue
        if nr > HIGHEST_KNOWN:
            print("note: the kernel implements syscall %d (%s), above the filter's table: trapped, answered ENOSYS" % (nr, name))
        else:
            print("FAIL the kernel implements syscall %d (%s), which this table does not classify" % (nr, name))
            fails += 1
    for name, nr in table.items():
        if nr <= HIGHEST_KNOWN and name not in known:
            print("FAIL unclassified syscall %d %s below the filter's ceiling" % (nr, name))
            fails += 1
    trap, denied, numbers = launcher_lists()
    trap_fixed = {"newfstatat" if n == "fstatat" else n for n in trap}
    for n in sorted(TRAP - trap_fixed):
        print("FAIL path syscall %s is not in the launcher's trap list" % n)
        fails += 1
    for n in sorted(trap_fixed - TRAP):
        print("FAIL the launcher traps %s, which this table does not call path-taking" % n)
        fails += 1
    for n in sorted(DENIED - denied):
        print("FAIL %s should be refused by the filter" % n)
        fails += 1
    for n in sorted(TRAP | DENIED):
        if n in table and n in numbers and numbers[n] != table[n]:
            print("FAIL %s: launcher number %d, kernel %d" % (n, numbers[n], table[n]))
            fails += 1
    print("%d syscalls in the table: %d trapped, %d refused, %d with paths in structs, %d without paths; %d failures"
          % (len(table), len(TRAP & set(table)), len(DENIED & set(table)), len(STRUCT_PATH & set(table)), len(NONPATH & set(table)), fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
