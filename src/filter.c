/* filter.c — the seccomp filter (PROPOSAL.md 7.4.2).
 *
 * One classic-BPF program, installed once at the can boundary and inherited
 * by every descendant. The opener's own syscalls are recognised by their
 * instruction address: all of them are issued from the syscall page, which
 * every opener maps at the same fixed address, so the filter stays valid
 * across execve and under any filter a program stacks on top. A register
 * marker would leak into any signal handler that interrupts an opener
 * syscall; an address cannot.
 */
#include "common.h"

struct sock_filter { uint16_t code; uint8_t jt, jf; uint32_t k; };
struct sock_fprog { unsigned short len; struct sock_filter *filter; };

#define LD_ABS  0x20      /* BPF_LD | BPF_W | BPF_ABS */
#define JEQ_K   0x15      /* BPF_JMP | BPF_JEQ | BPF_K */
#define JSET_K  0x45
#define RET_K   0x06
#define AND_K   0x54      /* BPF_ALU | BPF_AND | BPF_K */
#define JGT_K   0x25      /* BPF_JMP | BPF_JGT | BPF_K */
#define HIGHEST_KNOWN_SYSCALL 469      /* file_setattr, 6.17; test/syscalls.py probes the running kernel above it */
#define OFF_NR   0
#define OFF_ARCH 4
#define OFF_IP   8
#define OFF_ARG(i) (16 + 8 * (i))          /* low word; high word at +4 */

#define PROBE_ERRNO(v) (0x800u | (unsigned)(v))   /* 7.4.2: the probe answer, an errno the kernel can carry */

static struct sock_filter prog[1024];
static int np;

static void emit(uint16_t code, uint8_t jt, uint8_t jf, uint32_t k)
{
    if (np >= (int)(sizeof prog / sizeof prog[0])) die("filter too large", 0, 0);
    prog[np].code = code; prog[np].jt = jt; prog[np].jf = jf; prog[np].k = k; np++;
}
static void ret(uint32_t action) { emit(RET_K, 0, 0, action); }
/* "if nr == n then <action>" as a two-instruction pair; A must hold nr */
static void on_nr(int n, uint32_t action) { emit(JEQ_K, 0, 1, (uint32_t)n); ret(action); }
/* "if nr == n and arg i != 0 then TRAP" ; A holds nr on entry and on exit */
static void on_nr_arg_nonzero(int n, int i)
{
    emit(JEQ_K, 0, 6, (uint32_t)n);
    emit(LD_ABS, 0, 0, OFF_ARG(i));          /* low */
    emit(JEQ_K, 0, 2, 0);
    emit(LD_ABS, 0, 0, OFF_ARG(i) + 4);      /* high */
    emit(JEQ_K, 1, 0, 0);
    ret(SECCOMP_RET_TRAP);
    emit(LD_ABS, 0, 0, OFF_NR);
}

/* the path syscalls the handler translates (7.4.1) */
const int path_syscalls[] = {
    NR_open, NR_stat, NR_lstat, NR_access, NR_execve, NR_truncate, NR_getcwd, NR_chdir, NR_rename, NR_mkdir,
    NR_rmdir, NR_creat, NR_link, NR_unlink, NR_symlink, NR_readlink, NR_chmod, NR_chown, NR_lchown, NR_utime,
    NR_mknod, NR_statfs, NR_setxattr, NR_lsetxattr, NR_getxattr, NR_lgetxattr, NR_listxattr, NR_llistxattr,
    NR_removexattr, NR_lremovexattr, NR_utimes, NR_inotify_add_watch, NR_openat, NR_mkdirat, NR_mknodat,
    NR_fchownat, NR_futimesat, NR_newfstatat, NR_unlinkat, NR_renameat, NR_linkat, NR_symlinkat, NR_readlinkat,
    NR_fchmodat, NR_faccessat, NR_utimensat, NR_renameat2, NR_execveat, NR_statx, NR_faccessat2, NR_fchmodat2,
    NR_fanotify_mark, NR_setxattrat, NR_getxattrat, NR_listxattrat, NR_removexattrat,
#ifndef CONT_TEST_OLD
    NR_file_getattr, NR_file_setattr,                     /* version 2's additions: absent from build/opener-old's filter and handler alike */
#endif
};
const int n_path_syscalls = sizeof path_syscalls / sizeof path_syscalls[0];

/* descriptor syscalls that could change a can file's attributes (8.2) or need a read-only answer */
static const int fd_syscalls[] = { NR_fchmod, NR_fchown, NR_fsetxattr, NR_fremovexattr, NR_fstatfs };
/* signal-mask syscalls the handler scrubs (7.5.2) */
static const int mask_syscalls[] = { NR_rt_sigprocmask, NR_rt_sigsuspend };
/* closed rather than emulated in milestone 1a: each would bypass or confuse translation */
static const int enosys_syscalls[] = { NR_clone3, NR_io_uring_setup, NR_openat2, NR_name_to_handle_at, NR_uselib,
    428 /* open_tree */, 429 /* move_mount */, 430 /* fsopen */, 431 /* fsconfig */, 432 /* fsmount */, 433 /* fspick */, NR_mount_setattr,
    NR_open_tree_attr };
static const int eperm_syscalls[] = { NR_chroot, NR_acct, NR_pivot_root, NR_mount, NR_umount2 };
/* the hot path: answered before anything else is examined */
static const int fast_allow[] = { NR_read, NR_write, NR_close, NR_fstat, NR_lseek, NR_mmap, NR_mprotect, NR_munmap,
    12 /* brk */, NR_rt_sigreturn, NR_pread64, 202 /* futex */, 28 /* madvise */, NR_getpid, 228 /* clock_gettime */,
    NR_exit_group, NR_exit, NR_wait4, NR_getdents64, NR_fcntl, NR_dup, NR_dup2, NR_dup3, 293 /* pipe2 */,
    NR_clone, NR_fork, 58 /* vfork */, 20 /* writev */, 19 /* readv */, 218 /* set_tid_address */, 273 /* set_robust_list */,
    302 /* prlimit64 */, 318 /* getrandom */, 334 /* rseq */, 158 /* arch_prctl */, 204 /* sched_getaffinity */ };

static void build(void)
{
    np = 0;
    emit(LD_ABS, 0, 0, OFF_ARCH);
    emit(JEQ_K, 1, 0, AUDIT_ARCH_X86_64); ret(SECCOMP_RET_KILL_PROCESS);
    emit(LD_ABS, 0, 0, OFF_NR);
    emit(JSET_K, 0, 1, X32_SYSCALL_BIT); ret(SECCOMP_RET_KILL_PROCESS);
    /* the probe: uname with MAGIC as its argument answers the filter version */
    emit(JEQ_K, 0, 5, NR_uname);
    emit(LD_ABS, 0, 0, OFF_ARG(0)); emit(JEQ_K, 0, 3, (uint32_t)MAGIC);
    emit(LD_ABS, 0, 0, OFF_ARG(0) + 4); emit(JEQ_K, 0, 1, (uint32_t)(MAGIC >> 32));
    ret(SECCOMP_RET_ERRNO | PROBE_ERRNO(FILTER_VERSION));
    /* the opener's own syscalls: issued from the syscall page */
    emit(LD_ABS, 0, 0, OFF_IP + 4); emit(JEQ_K, 0, 4, (uint32_t)(SC_PAGE >> 32));
    emit(LD_ABS, 0, 0, OFF_IP); emit(AND_K, 0, 0, ~0xfffu); emit(JEQ_K, 0, 1, (uint32_t)SC_PAGE);
    ret(SECCOMP_RET_ALLOW);
    emit(LD_ABS, 0, 0, OFF_NR);
    for (unsigned i = 0; i < sizeof fast_allow / sizeof fast_allow[0]; i++) on_nr(fast_allow[i], SECCOMP_RET_ALLOW);
    for (int i = 0; i < n_path_syscalls; i++) on_nr(path_syscalls[i], SECCOMP_RET_TRAP);
    for (unsigned i = 0; i < sizeof fd_syscalls / sizeof fd_syscalls[0]; i++) on_nr(fd_syscalls[i], SECCOMP_RET_TRAP);
    for (unsigned i = 0; i < sizeof mask_syscalls / sizeof mask_syscalls[0]; i++) on_nr(mask_syscalls[i], SECCOMP_RET_TRAP);
    on_nr_arg_nonzero(NR_rt_sigaction, 1);                  /* installs trap for the mask scrub; queries report the truth */
    on_nr_arg_nonzero(NR_ppoll, 3);
    on_nr_arg_nonzero(NR_pselect6, 5);
    on_nr_arg_nonzero(NR_epoll_pwait, 4);
    on_nr_arg_nonzero(NR_epoll_pwait2, 4);
    on_nr_arg_nonzero(NR_io_pgetevents, 5);
    /* ioctl: only the two chattr requests are trapped (8.2) */
    emit(JEQ_K, 0, 5, NR_ioctl);
    emit(LD_ABS, 0, 0, OFF_ARG(1));
    emit(JEQ_K, 1, 0, (uint32_t)FS_IOC_SETFLAGS);
    emit(JEQ_K, 0, 1, (uint32_t)FS_IOC_FSSETXATTR);
    ret(SECCOMP_RET_TRAP);
    emit(LD_ABS, 0, 0, OFF_NR);
    /* a program's own sandbox is refused (7.4.2): seccomp(2) except the availability query, prctl(PR_SET_SECCOMP) */
    emit(JEQ_K, 0, 3, NR_seccomp);
    emit(LD_ABS, 0, 0, OFF_ARG(0)); emit(JEQ_K, 1, 0, SECCOMP_GET_ACTION_AVAIL);
    ret(SECCOMP_RET_ERRNO | ENOSYS);
    emit(LD_ABS, 0, 0, OFF_NR);
    emit(JEQ_K, 0, 3, NR_prctl);
    emit(LD_ABS, 0, 0, OFF_ARG(0)); emit(JEQ_K, 0, 1, PR_SET_SECCOMP);
    ret(SECCOMP_RET_ERRNO | ENOSYS);
    emit(LD_ABS, 0, 0, OFF_NR);
    for (unsigned i = 0; i < sizeof enosys_syscalls / sizeof enosys_syscalls[0]; i++) on_nr(enosys_syscalls[i], SECCOMP_RET_ERRNO | ENOSYS);
    for (unsigned i = 0; i < sizeof eperm_syscalls / sizeof eperm_syscalls[0]; i++) on_nr(eperm_syscalls[i], SECCOMP_RET_ERRNO | EPERM);
    /* a syscall newer than this filter knows is trapped, and the handler answers ENOSYS (7.4.2, review O3-5):
     * a future path-taking syscall must not reach the host untranslated */
    emit(JGT_K, 0, 1, HIGHEST_KNOWN_SYSCALL); ret(SECCOMP_RET_TRAP);
    ret(SECCOMP_RET_ALLOW);
}

/* 0: no filter of ours; otherwise the newest inherited filter's version */
int filter_probe(void)
{
    long r = __sc6_raw(NR_uname, (long)MAGIC, 0, 0, 0, 0, 0);   /* raw: the page would have it allowed */
    if (r < 0 && ((-r) & ~0xffL) == 0x800) return (int)((-r) & 0xff);
    return 0;
}

void filter_install(void)
{
    build();
    struct sock_fprog fp = { (unsigned short)np, prog };
    if (sys_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) die("PR_SET_NO_NEW_PRIVS failed", 0, 0);
    long r = SC3(NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fp);
    if (r == -ENOSYS) r = sys_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (unsigned long)&fp, 0, 0);   /* kernels before 3.17 */
    if (r < 0) die("cannot install the seccomp filter", 0, r);
}
