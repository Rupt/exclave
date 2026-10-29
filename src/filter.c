/* filter.c — the seccomp filter (DESIGN.md 7.4.2).
 *
 * One classic-BPF program, installed at the border, or over an older version's, and inherited
 * by every descendant. The launcher's own syscalls are recognised by their
 * instruction address: all of them are issued from the syscall page, which
 * every launcher maps at the same fixed address, so the filter stays valid
 * across execve and under any filter a program stacks on top. A register
 * marker would leak into any signal handler that interrupts a launcher
 * syscall; an address cannot.
 */
#include "common.h"

struct sock_filter {
    uint16_t code;
    uint8_t jt, jf;
    uint32_t k;
};
struct sock_fprog {
    unsigned short len;
    struct sock_filter *filter;
};

#define LD_ABS 0x20      /* BPF_LD | BPF_W | BPF_ABS */
#define JEQ_K 0x15      /* BPF_JMP | BPF_JEQ | BPF_K */
#if defined(__x86_64__)
#define JSET_K 0x45      /* BPF_JMP | BPF_JSET | BPF_K: the x32 bit's test */
#endif
#define RET_K 0x06
#define AND_K 0x54      /* BPF_ALU | BPF_AND | BPF_K */
/* rseq_slice_yield, in 7.0's table; test/syscalls.py reads the running kernel's table and probes it above this */
#define HIGHEST_KNOWN_SYSCALL 471
#define OFF_NR 0
#define OFF_ARCH 4
#define OFF_IP 8
#define OFF_ARG(i) (16U + 8U * (unsigned)(i)) /* low word; high word at +4 */

#define PROBE_ERRNO(v) (0x800U | (unsigned)(v)) /* 7.4.2: the probe answer, an errno the kernel can carry */

static struct sock_filter prog[1024];
static int np;

static void emit(uint16_t code, uint8_t jt, uint8_t jf, uint32_t k)
{
    if (np >= (int)(sizeof prog / sizeof prog[0])) die("filter too large", 0, 0);
    prog[np].code = code;
    prog[np].jt = jt;
    prog[np].jf = jf;
    prog[np].k = k;
    np++;
}
static void ret(uint32_t action) { emit(RET_K, 0, 0, action); }
/* "if nr == n then <action>" as a two-instruction pair; A must hold nr. An n below 0, a syscall this architecture
 * lacks, emits nothing. */
static void on_nr(int n, uint32_t action)
{
    if (n < 0) return;
    emit(JEQ_K, 0, 1, (uint32_t)n);
    ret(action);
}
/* the path syscalls the handler translates (7.4.3) */
const int path_syscalls[] = {
    NR_open,
    NR_stat,
    NR_lstat,
    NR_access,
    NR_execve,
    NR_truncate,
    NR_getcwd,
    NR_chdir,
    NR_rename,
    NR_mkdir,
    NR_rmdir,
    NR_creat,
    NR_link,
    NR_unlink,
    NR_symlink,
    NR_readlink,
    NR_chmod,
    NR_chown,
    NR_lchown,
    NR_utime,
    NR_mknod,
    NR_statfs,
    NR_setxattr,
    NR_lsetxattr,
    NR_getxattr,
    NR_lgetxattr,
    NR_listxattr,
    NR_llistxattr,
    NR_removexattr,
    NR_lremovexattr,
    NR_utimes,
    NR_inotify_add_watch,
    NR_openat,
    NR_mkdirat,
    NR_mknodat,
    NR_fchownat,
    NR_futimesat,
    NR_newfstatat,
    NR_unlinkat,
    NR_renameat,
    NR_linkat,
    NR_symlinkat,
    NR_readlinkat,
    NR_fchmodat,
    NR_faccessat,
    NR_utimensat,
    NR_renameat2,
    NR_execveat,
    NR_statx,
    NR_faccessat2,
    NR_fchmodat2,
    NR_fanotify_mark,
    NR_setxattrat,
    NR_getxattrat,
    NR_listxattrat,
    NR_removexattrat,
    NR_file_getattr,
    NR_file_setattr,
    NR_openat2,
#ifndef EXCLAVE_TEST_OLD
    /* version 4's addition: absent from build/launcher-old's filter and handler alike */
    NR_bind,
    NR_connect,
#endif
};
const int n_path_syscalls = sizeof path_syscalls / sizeof path_syscalls[0];

/* descriptor syscalls that could change an exclave file's attributes (8.2) or need a read-only answer */
static const int fd_syscalls[] = {NR_fchmod, NR_fchown, NR_fsetxattr, NR_fremovexattr, NR_fstatfs};
/* signal-mask syscalls the handler scrubs (7.5.2) */
static const int mask_syscalls[] = {NR_rt_sigprocmask, NR_rt_sigsuspend};
/* refused with ENOSYS rather than emulated (7.4.3): each would bypass or confuse translation */
static const int enosys_syscalls[] = {NR_clone3,        NR_io_uring_setup,   NR_name_to_handle_at,
                                      NR_uselib,        428 /* open_tree */, 429 /* move_mount */,
                                      430 /* fsopen */, 431 /* fsconfig */,  432 /* fsmount */,
                                      433 /* fspick */, NR_mount_setattr,    NR_open_tree_attr};
static const int eperm_syscalls[] = {NR_chroot, NR_acct, NR_pivot_root, NR_mount, NR_umount2};
/* The program has two stages (7.4.2). The first answers by the number alone: a binary tree over the numbers, whose leaf
 * is ALLOW for every number the rule does not single out at or below the ceiling, so that the kernel's action cache
 * (5.11) proves those calls allowed and skips the filter for them, and a kernel without the cache runs a dozen
 * instructions rather than the whole rule. The other leaves join the second stage, the rule in its order: the
 * arguments that can only allow (an ioctl that is not chattr, a query of a signal action, a wait without a mask, a
 * prctl that is not seccomp's, the availability query, an ordinary uname) and the probe, then the syscall page, then
 * the refusals, and every other number traps: the path syscalls, the descriptor and mask calls, an install that
 * carries a mask, the chattr requests, and anything above the ceiling. test/filter_test.c checks the program against
 * the rule written out on its own, and that every number the rule does not single out is allowed by number alone. */
#define JGE_K 0x35 /* BPF_JMP | BPF_JGE | BPF_K */
#define JA 0x05 /* BPF_JMP | BPF_JA: a 32-bit offset, where a conditional jump's is 8 bits */

/* installs trap for the mask scrub (7.5.2); queries report the truth */
static const int arg_traps[][2] = {{NR_rt_sigaction, 1}, {NR_ppoll, 3},        {NR_pselect6, 5},
                                   {NR_epoll_pwait, 4},  {NR_epoll_pwait2, 4}, {NR_io_pgetevents, 5}};

static int singled(int nr)
{
    if (nr == NR_uname || nr == NR_ioctl || nr == NR_seccomp || nr == NR_prctl) return 1;
    for (int i = 0; i < n_path_syscalls; i++)
        if (path_syscalls[i] == nr) return 1;
    for (unsigned i = 0; i < sizeof fd_syscalls / sizeof fd_syscalls[0]; i++)
        if (fd_syscalls[i] == nr) return 1;
    for (unsigned i = 0; i < sizeof mask_syscalls / sizeof mask_syscalls[0]; i++)
        if (mask_syscalls[i] == nr) return 1;
    for (unsigned i = 0; i < sizeof arg_traps / sizeof arg_traps[0]; i++)
        if (arg_traps[i][0] == nr) return 1;
    for (unsigned i = 0; i < sizeof enosys_syscalls / sizeof enosys_syscalls[0]; i++)
        if (enosys_syscalls[i] == nr) return 1;
    for (unsigned i = 0; i < sizeof eperm_syscalls / sizeof eperm_syscalls[0]; i++)
        if (eperm_syscalls[i] == nr) return 1;
    return 0;
}

/* the first stage's intervals: from lo to the next interval's lo, singled out or not; the last runs past the ceiling */
static struct {
    uint32_t lo;
    int singled;
} iv[2 * (HIGHEST_KNOWN_SYSCALL + 2)];
static int niv;
static int jumps[HIGHEST_KNOWN_SYSCALL + 2], njumps; /* JA instructions to the second stage, placed when it is */

static int tree_size(int a, int b)
{
    if (b - a == 1) return 1;
    int m = (a + b) / 2, left = tree_size(a, m);
    return 1 + (left > 255) + left + tree_size(m, b);
}
static void tree(int a, int b) /* intervals a..b-1, the number in A */
{
    if (b - a == 1) {
        if (iv[a].singled) {
            jumps[njumps++] = np;
            emit(JA, 0, 0, 0);
        } else ret(SECCOMP_RET_ALLOW);
        return;
    }
    int m = (a + b) / 2, left = tree_size(a, m);
    /* the upper half past the lower, too far for 8 bits */
    if (left > 255) {
        emit(JGE_K, 0, 1, iv[m].lo);
        emit(JA, 0, 0, (uint32_t)left);
    } else emit(JGE_K, (uint8_t)left, 0, iv[m].lo);
    tree(a, m);
    tree(m, b);
}

static void build(void)
{
    np = 0;
    niv = 0;
    njumps = 0;
    emit(LD_ABS, 0, 0, OFF_ARCH);
    /* a foreign ABI (x32, arm32 compat) dies loudly (7.4.2) */
    emit(JEQ_K, 1, 0, AUDIT_ARCH_NATIVE);
    ret(SECCOMP_RET_KILL_PROCESS);
    emit(LD_ABS, 0, 0, OFF_NR);
#if defined(__x86_64__)
    emit(JSET_K, 0, 1, X32_SYSCALL_BIT);
    ret(SECCOMP_RET_KILL_PROCESS);
#endif
    /* the first stage */
    for (int nr = 0; nr <= HIGHEST_KNOWN_SYSCALL + 1; nr++) {
        int s = nr > HIGHEST_KNOWN_SYSCALL || singled(nr);
        if (!niv || iv[niv - 1].singled != s) {
            iv[niv].lo = (uint32_t)nr;
            iv[niv].singled = s;
            niv++;
        }
    }
    tree(0, niv);
    /* the second stage, the number in A: the arguments that can only allow, and the probe */
    for (int i = 0; i < njumps; i++) prog[jumps[i]].k = (uint32_t)(np - jumps[i] - 1);
    int page[16], npage = 0;
    /* only the two chattr requests are trapped (8.2) */
    emit(JEQ_K, 0, 5, NR_ioctl);
    emit(LD_ABS, 0, 0, OFF_ARG(1));
    emit(JEQ_K, 2, 0, (uint32_t)FS_IOC_SETFLAGS);
    emit(JEQ_K, 1, 0, (uint32_t)FS_IOC_FSSETXATTR);
    ret(SECCOMP_RET_ALLOW);
    page[npage++] = np;
    emit(JA, 0, 0, 0);
    for (unsigned i = 0; i < sizeof arg_traps / sizeof arg_traps[0]; i++) {
        if (arg_traps[i][0] < 0) continue; /* not on this architecture */
        emit(JEQ_K, 0, 6, (uint32_t)arg_traps[i][0]);
        emit(LD_ABS, 0, 0, OFF_ARG(arg_traps[i][1])); /* low */
        emit(JEQ_K, 0, 3, 0);
        emit(LD_ABS, 0, 0, OFF_ARG(arg_traps[i][1]) + 4); /* high */
        emit(JEQ_K, 0, 1, 0);
        ret(SECCOMP_RET_ALLOW);
        page[npage++] = np;
        emit(JA, 0, 0, 0);
    }
    /* a program's own sandbox is refused (7.4.2): prctl(PR_SET_SECCOMP), and seccomp(2) but its availability query */
    emit(JEQ_K, 0, 4, NR_prctl);
    emit(LD_ABS, 0, 0, OFF_ARG(0));
    emit(JEQ_K, 1, 0, PR_SET_SECCOMP);
    ret(SECCOMP_RET_ALLOW);
    page[npage++] = np;
    emit(JA, 0, 0, 0);
    emit(JEQ_K, 0, 4, NR_seccomp);
    emit(LD_ABS, 0, 0, OFF_ARG(0));
    emit(JEQ_K, 0, 1, SECCOMP_GET_ACTION_AVAIL);
    ret(SECCOMP_RET_ALLOW);
    page[npage++] = np;
    emit(JA, 0, 0, 0);
    /* the probe: uname with MAGIC as its argument answers the filter version, from anywhere */
    emit(JEQ_K, 0, 6, NR_uname);
    emit(LD_ABS, 0, 0, OFF_ARG(0));
    emit(JEQ_K, 0, 3, (uint32_t)MAGIC);
    emit(LD_ABS, 0, 0, OFF_ARG(0) + 4);
    emit(JEQ_K, 0, 1, (uint32_t)(MAGIC >> 32));
    ret(SECCOMP_RET_ERRNO | PROBE_ERRNO(FILTER_VERSION));
    ret(SECCOMP_RET_ALLOW);
    /* the launcher's own syscalls: issued from the syscall page */
    for (int i = 0; i < npage; i++) prog[page[i]].k = (uint32_t)(np - page[i] - 1);
    emit(LD_ABS, 0, 0, OFF_IP + 4);
    emit(JEQ_K, 0, 4, (uint32_t)(SC_PAGE >> 32));
    emit(LD_ABS, 0, 0, OFF_IP);
    emit(AND_K, 0, 0, ~0xfffU);
    emit(JEQ_K, 0, 1, (uint32_t)SC_PAGE);
    ret(SECCOMP_RET_ALLOW);
    /* the refusals; everything else that reaches here traps, and a syscall newer than this filter knows is answered
     * ENOSYS by the handler (7.4.2): a future path-taking syscall must not reach the host untranslated */
    emit(LD_ABS, 0, 0, OFF_NR);
    on_nr(NR_seccomp, SECCOMP_RET_ERRNO | ENOSYS);
    on_nr(NR_prctl, SECCOMP_RET_ERRNO | ENOSYS);
    for (unsigned i = 0; i < sizeof enosys_syscalls / sizeof enosys_syscalls[0]; i++)
        on_nr(enosys_syscalls[i], SECCOMP_RET_ERRNO | ENOSYS);
    for (unsigned i = 0; i < sizeof eperm_syscalls / sizeof eperm_syscalls[0]; i++)
        on_nr(eperm_syscalls[i], SECCOMP_RET_ERRNO | EPERM);
    ret(SECCOMP_RET_TRAP);
}

/* 0: no filter of ours; otherwise the newest inherited filter's version */
int filter_probe(void)
{
    long r = __sc6_raw(NR_uname, (long)MAGIC, 0, 0, 0, 0, 0); /* raw: the page would have it allowed */
    if (r < 0 && ((-r) & ~0xffL) == 0x800) return (int)((-r) & 0xff);
    return 0;
}

void filter_install(void)
{
    build();
    struct sock_fprog fp = {(unsigned short)np, prog};
    if (sys_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) die("PR_SET_NO_NEW_PRIVS failed", 0, 0);
    /* SPEC_ALLOW: a filter installed without it switches the process and its descendants to Speculative Store Bypass
     * Disable, forced, wherever the kernel's default is spec_store_bypass_disable=seccomp (4.17 to 5.15 and the
     * backports before), which slows compute-bound code by up to several times; an exclave is not a security boundary
     * and its programs did not ask for it (DESIGN.md 16.5). A kernel without the flag answers EINVAL. */
    long r = SC3(NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_SPEC_ALLOW, &fp);
    if (r == -EINVAL) r = SC3(NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fp);
    /* kernels before 3.17 */
    if (r == -ENOSYS) r = sys_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (unsigned long)&fp, 0, 0);
    if (r < 0) die("cannot install the seccomp filter", 0, r);
}

#ifdef HOST_TEST
/* test/filter_test.c: the built program and the lists it was built from, for the model of 7.4.2 */
const void *filter_for_test(int *n);
const int *filter_list_for_test(int which, int *n);
const void *filter_for_test(int *n)
{
    build();
    *n = np;
    return prog;
}
const int *filter_list_for_test(int which, int *n)
{
    switch (which) {
    case 0: *n = (int)(sizeof fd_syscalls / sizeof fd_syscalls[0]); return fd_syscalls;
    case 1: *n = (int)(sizeof mask_syscalls / sizeof mask_syscalls[0]); return mask_syscalls;
    case 2: *n = (int)(sizeof enosys_syscalls / sizeof enosys_syscalls[0]); return enosys_syscalls;
    default: *n = (int)(sizeof eperm_syscalls / sizeof eperm_syscalls[0]); return eperm_syscalls;
    }
}
#endif
