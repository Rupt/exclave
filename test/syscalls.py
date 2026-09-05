#!/usr/bin/env python3
"""syscalls.py — the path-syscall table test (PROPOSAL.md 17, item 5).

Every syscall in the kernel's x86-64 table is classified here. A syscall the kernel adds that this file
does not know fails the test, so a new path-taking syscall is noticed rather than discovered. The opener's
trap list (src/filter.c) must equal TRAP, and its refusals must cover DENIED.

    test/syscalls.py [unistd_64.h]     default: the host's asm/unistd_64.h
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# path arguments the handler translates (7.4.3)
TRAP = set(['access', 'chdir', 'chmod', 'chown', 'creat', 'execve', 'execveat', 'faccessat', 'faccessat2', 'fanotify_mark', 'fchmodat', 'fchmodat2', 'fchownat', 'futimesat', 'getcwd', 'getxattr', 'inotify_add_watch', 'lchown', 'lgetxattr', 'link', 'linkat', 'listxattr', 'llistxattr', 'lremovexattr', 'lsetxattr', 'lstat', 'mkdir', 'mkdirat', 'mknod', 'mknodat', 'newfstatat', 'open', 'openat', 'readlink', 'readlinkat', 'removexattr', 'rename', 'renameat', 'renameat2', 'rmdir', 'setxattr', 'stat', 'statfs', 'statx', 'symlink', 'symlinkat', 'truncate', 'unlink', 'unlinkat', 'utime', 'utimensat', 'utimes'])
# taken away by the filter: ENOSYS, EPERM, or deferred to milestone 1c (7.4.3)
DENIED = set(['acct', 'chroot', 'clone3', 'fsconfig', 'fsmount', 'fsopen', 'fspick', 'io_uring_setup', 'mount', 'mount_setattr', 'move_mount', 'name_to_handle_at', 'open_tree', 'openat2', 'pivot_root', 'umount2', 'uselib'])
# a path inside a struct or a name that is not a filesystem path: not translated; sockaddr_un paths reach
# the kernel untranslated, which the visibility rule makes harmless for /tmp, /run and /var/run and which
# section 13 lists for can-owned paths
STRUCT_PATH = set(['accept', 'accept4', 'bind', 'bpf', 'connect', 'getpeername', 'getsockname', 'mq_open', 'mq_unlink', 'quotactl', 'recvfrom', 'recvmmsg', 'recvmsg', 'sendmmsg', 'sendmsg', 'sendto', 'swapoff', 'swapon'])
# no path argument at all
NONPATH = set(['_sysctl', 'add_key', 'adjtimex', 'afs_syscall', 'alarm', 'arch_prctl', 'brk', 'cachestat', 'capget', 'capset', 'clock_adjtime', 'clock_getres', 'clock_gettime', 'clock_nanosleep', 'clock_settime', 'clone', 'close', 'close_range', 'copy_file_range', 'create_module', 'delete_module', 'dup', 'dup2', 'dup3', 'epoll_create', 'epoll_create1', 'epoll_ctl', 'epoll_ctl_old', 'epoll_pwait', 'epoll_pwait2', 'epoll_wait', 'epoll_wait_old', 'eventfd', 'eventfd2', 'exit', 'exit_group', 'fadvise64', 'fallocate', 'fanotify_init', 'fchdir', 'fchmod', 'fchown', 'fcntl', 'fdatasync', 'fgetxattr', 'finit_module', 'flistxattr', 'flock', 'fork', 'fremovexattr', 'fsetxattr', 'fstat', 'fstatfs', 'fsync', 'ftruncate', 'futex', 'futex_requeue', 'futex_wait', 'futex_waitv', 'futex_wake', 'get_kernel_syms', 'get_mempolicy', 'get_robust_list', 'get_thread_area', 'getcpu', 'getdents', 'getdents64', 'getegid', 'geteuid', 'getgid', 'getgroups', 'getitimer', 'getpgid', 'getpgrp', 'getpid', 'getpmsg', 'getppid', 'getpriority', 'getrandom', 'getresgid', 'getresuid', 'getrlimit', 'getrusage', 'getsid', 'getsockopt', 'gettid', 'gettimeofday', 'getuid', 'init_module', 'inotify_init', 'inotify_init1', 'inotify_rm_watch', 'io_cancel', 'io_destroy', 'io_getevents', 'io_pgetevents', 'io_setup', 'io_submit', 'io_uring_enter', 'io_uring_register', 'ioctl', 'ioperm', 'iopl', 'ioprio_get', 'ioprio_set', 'kcmp', 'kexec_file_load', 'kexec_load', 'keyctl', 'kill', 'landlock_add_rule', 'landlock_create_ruleset', 'landlock_restrict_self', 'listen', 'listmount', 'lookup_dcookie', 'lseek', 'lsm_get_self_attr', 'lsm_list_modules', 'lsm_set_self_attr', 'madvise', 'map_shadow_stack', 'mbind', 'membarrier', 'memfd_create', 'memfd_secret', 'migrate_pages', 'mincore', 'mlock', 'mlock2', 'mlockall', 'mmap', 'modify_ldt', 'move_pages', 'mprotect', 'mq_getsetattr', 'mq_notify', 'mq_timedreceive', 'mq_timedsend', 'mremap', 'msgctl', 'msgget', 'msgrcv', 'msgsnd', 'msync', 'munlock', 'munlockall', 'munmap', 'nanosleep', 'nfsservctl', 'open_by_handle_at', 'pause', 'perf_event_open', 'personality', 'pidfd_getfd', 'pidfd_open', 'pidfd_send_signal', 'pipe', 'pipe2', 'pkey_alloc', 'pkey_free', 'pkey_mprotect', 'poll', 'ppoll', 'prctl', 'pread64', 'preadv', 'preadv2', 'prlimit64', 'process_madvise', 'process_mrelease', 'process_vm_readv', 'process_vm_writev', 'pselect6', 'ptrace', 'putpmsg', 'pwrite64', 'pwritev', 'pwritev2', 'query_module', 'quotactl_fd', 'read', 'readahead', 'readv', 'reboot', 'remap_file_pages', 'request_key', 'restart_syscall', 'rseq', 'rt_sigaction', 'rt_sigpending', 'rt_sigprocmask', 'rt_sigqueueinfo', 'rt_sigreturn', 'rt_sigsuspend', 'rt_sigtimedwait', 'rt_tgsigqueueinfo', 'sched_get_priority_max', 'sched_get_priority_min', 'sched_getaffinity', 'sched_getattr', 'sched_getparam', 'sched_getscheduler', 'sched_rr_get_interval', 'sched_setaffinity', 'sched_setattr', 'sched_setparam', 'sched_setscheduler', 'sched_yield', 'seccomp', 'security', 'select', 'semctl', 'semget', 'semop', 'semtimedop', 'sendfile', 'set_mempolicy', 'set_mempolicy_home_node', 'set_robust_list', 'set_thread_area', 'set_tid_address', 'setdomainname', 'setfsgid', 'setfsuid', 'setgid', 'setgroups', 'sethostname', 'setitimer', 'setns', 'setpgid', 'setpriority', 'setregid', 'setresgid', 'setresuid', 'setreuid', 'setrlimit', 'setsid', 'setsockopt', 'settimeofday', 'setuid', 'shmat', 'shmctl', 'shmdt', 'shmget', 'shutdown', 'sigaltstack', 'signalfd', 'signalfd4', 'socket', 'socketpair', 'splice', 'statmount', 'sync', 'sync_file_range', 'syncfs', 'sysfs', 'sysinfo', 'syslog', 'tee', 'tgkill', 'time', 'timer_create', 'timer_delete', 'timer_getoverrun', 'timer_gettime', 'timer_settime', 'timerfd_create', 'timerfd_gettime', 'timerfd_settime', 'times', 'tkill', 'tuxcall', 'umask', 'uname', 'unshare', 'userfaultfd', 'ustat', 'vfork', 'vhangup', 'vmsplice', 'vserver', 'wait4', 'waitid', 'write', 'writev'])


def kernel_table(path):
    return dict((n, int(v)) for n, v in re.findall(r"__NR_([a-z0-9_]+) (\d+)", open(path).read()))


def opener_lists():
    """The trap list and the refusal lists of src/filter.c, by name."""
    src = open(os.path.join(REPO, "src", "filter.c")).read()
    sysh = open(os.path.join(REPO, "src", "sys.h")).read()
    numbers = dict((n, int(v)) for n, v in re.findall(r"NR_([a-z0-9_]+) = (\d+)", sysh))
    numbers["pread64"] = 17

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
    return trap, denied, numbers


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/usr/include/x86_64-linux-gnu/asm/unistd_64.h"
    table = kernel_table(path)
    fails = 0
    known = TRAP | DENIED | STRUCT_PATH | NONPATH
    for name in sorted(table, key=table.get):
        if name not in known:
            print("FAIL unclassified syscall %d %s: is it path-taking?" % (table[name], name))
            fails += 1
    for name in sorted(known - set(table)):
        print("note: %s is classified here but not in this kernel's table" % name)
    trap, denied, numbers = opener_lists()
    trap_fixed = {"newfstatat" if n == "fstatat" else n for n in trap}
    for n in sorted(TRAP - trap_fixed):
        print("FAIL path syscall %s is not in the opener's trap list" % n)
        fails += 1
    for n in sorted(trap_fixed - TRAP):
        print("FAIL the opener traps %s, which this table does not call path-taking" % n)
        fails += 1
    for n in sorted(DENIED - denied):
        print("FAIL %s should be refused by the filter" % n)
        fails += 1
    for n in sorted(TRAP | DENIED):
        if n in table and n in numbers and numbers[n] != table[n]:
            print("FAIL %s: opener number %d, kernel %d" % (n, numbers[n], table[n]))
            fails += 1
    print("%d syscalls in the table: %d trapped, %d refused, %d with paths in structs, %d without paths; %d failures"
          % (len(table), len(TRAP & set(table)), len(DENIED & set(table)), len(STRUCT_PATH & set(table)), len(NONPATH & set(table)), fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
