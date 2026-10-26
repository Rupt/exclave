/* filter_test.c — the seccomp filter against the rule of DESIGN.md 7.4.2. Built by scripts/gate's unit step.
 *
 * A classic-BPF interpreter runs the program src/filter.c builds for every syscall number up to past the ceiling,
 * from the syscall page and from elsewhere, with the arguments each conditional rule reads set and clear, and the
 * answer is compared with the rule written out here on its own. Then, as the kernel does when it builds its action
 * cache (seccomp_cache_prepare, 5.11), every number is run with only the architecture and the number known: one whose
 * answer needs neither an argument nor the instruction pointer is ALLOW for every call, and the kernel skips the filter
 * for it; every syscall the rule does not single out must be such a number (DESIGN.md 16.3). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/common.h"

struct exclave C;
void die(const char *what, const char *detail, long err)
{
    fprintf(stderr, "die: %s %s %ld\n", what, detail ? detail : "", err);
    exit(99);
}
const void *filter_for_test(int *n);
const int *filter_list_for_test(int which, int *n);

struct sock_filter {
    uint16_t code;
    uint8_t jt, jf;
    uint32_t k;
};
struct data {
    uint32_t nr, arch;
    uint64_t ip, args[6];
};
#define HIGHEST 470                                           /* src/filter.c's HIGHEST_KNOWN_SYSCALL */
#define NOT_CONST 0xffffffffU

/* the interpreter: the instructions src/filter.c emits, and nothing else. known: 0 runs on full data; 1 runs as the
 * action cache does, answering NOT_CONST at the first load of anything but the number and the architecture */
static uint32_t run(const struct sock_filter *p, int n, const struct data *d, int known, int *steps)
{
    uint32_t A = 0;
    int pc = 0;
    *steps = 0;
    while (pc < n) {
        const struct sock_filter *f = &p[pc++];
        (*steps)++;
        switch (f->code) {
        case 0x20: {                                          /* LD W ABS */
            uint32_t off = f->k;
            if (off == 0) A = d->nr;
            else if (off == 4) A = d->arch;
            else if (known) return NOT_CONST;
            else if (off == 8) A = (uint32_t)d->ip;
            else if (off == 12) A = (uint32_t)(d->ip >> 32);
            else if (off >= 16 && off < 64) {
                uint64_t v = d->args[(off - 16) / 8];
                A = (off & 4) ? (uint32_t)(v >> 32) : (uint32_t)v;
            } else {
                printf("FAIL load at offset %u\n", off);
                exit(1);
            }
            break;
        }
        case 0x54: A &= f->k; break;                          /* ALU AND K */
        case 0x05: pc += (int)f->k; break;                    /* JA */
        case 0x15: pc += A == f->k ? f->jt : f->jf; break;    /* JEQ K */
        case 0x25: pc += A > f->k ? f->jt : f->jf; break;     /* JGT K */
        case 0x35: pc += A >= f->k ? f->jt : f->jf; break;    /* JGE K */
        case 0x45: pc += (A & f->k) ? f->jt : f->jf; break;   /* JSET K */
        case 0x06: return f->k;                               /* RET K */
        default: printf("FAIL unknown instruction %#x at %d\n", f->code, pc - 1); exit(1);
        }
    }
    printf("FAIL the program runs off its end\n");
    exit(1);
}

static int in(int nr, int which)
{
    int n;
    const int *l = filter_list_for_test(which, &n);
    for (int i = 0; i < n; i++)
        if (l[i] == nr) return 1;
    return 0;
}
static int is_path(int nr)
{
    for (int i = 0; i < n_path_syscalls; i++)
        if (path_syscalls[i] == nr) return 1;
    return 0;
}
/* the mask-carrying calls: the argument that carries the mask, or -1 */
static int arg_trap(int nr)
{
    if (nr == NR_rt_sigaction) return 1;
    if (nr == NR_ppoll) return 3;
    if (nr == NR_pselect6 || nr == NR_io_pgetevents) return 5;
    if (nr == NR_epoll_pwait || nr == NR_epoll_pwait2) return 4;
    return -1;
}
/* the rule of 7.4.2, in its order of precedence */
static uint32_t rule(const struct data *d)
{
    if (d->arch != AUDIT_ARCH_NATIVE) return SECCOMP_RET_KILL_PROCESS;
#if defined(__x86_64__)
    if (d->nr & X32_SYSCALL_BIT) return SECCOMP_RET_KILL_PROCESS;
#endif
    int nr = (int)d->nr;
    if (nr == NR_uname && d->args[0] == MAGIC) return SECCOMP_RET_ERRNO | 0x800 | FILTER_VERSION;
    if ((d->ip & ~0xfffUL) == SC_PAGE) return SECCOMP_RET_ALLOW;
    if (is_path(nr) || in(nr, 0) || in(nr, 1)) return SECCOMP_RET_TRAP;
    int a = arg_trap(nr);
    if (a >= 0) return d->args[a] ? SECCOMP_RET_TRAP : SECCOMP_RET_ALLOW;
    if (nr == NR_ioctl)
        return (uint32_t)d->args[1] == (uint32_t)FS_IOC_SETFLAGS || (uint32_t)d->args[1] == (uint32_t)FS_IOC_FSSETXATTR
                   ? SECCOMP_RET_TRAP
                   : SECCOMP_RET_ALLOW;
    if (nr == NR_seccomp)
        return (uint32_t)d->args[0] == SECCOMP_GET_ACTION_AVAIL ? SECCOMP_RET_ALLOW : SECCOMP_RET_ERRNO | ENOSYS;
    if (nr == NR_prctl) return (uint32_t)d->args[0] == PR_SET_SECCOMP ? SECCOMP_RET_ERRNO | ENOSYS : SECCOMP_RET_ALLOW;
    if (in(nr, 2)) return SECCOMP_RET_ERRNO | ENOSYS;
    if (in(nr, 3)) return SECCOMP_RET_ERRNO | EPERM;
    if (d->nr > HIGHEST) return SECCOMP_RET_TRAP;
    return SECCOMP_RET_ALLOW;
}
static int singled_out(int nr)                                /* a number the rule answers by more than the number */
{
    return nr == NR_uname || is_path(nr) || in(nr, 0) || in(nr, 1) || arg_trap(nr) >= 0 || nr == NR_ioctl ||
           nr == NR_seccomp || nr == NR_prctl || in(nr, 2) || in(nr, 3) || nr > HIGHEST;
}

int main(void)
{
    int n;
    const struct sock_filter *p = filter_for_test(&n);
    int fails = 0, cases = 0, consts = 0, steps, worst_allow = 0;
    long allow_steps = 0, allows = 0;
    static const uint64_t values[] = {0,
                                      1,
                                      2,
                                      MAGIC,
                                      MAGIC & 0xffffffffU,
                                      MAGIC >> 32 << 32,
                                      SECCOMP_GET_ACTION_AVAIL,
                                      PR_SET_SECCOMP,
                                      FS_IOC_SETFLAGS,
                                      FS_IOC_FSSETXATTR,
                                      FS_IOC_SETFLAGS | 1UL << 32,
                                      1UL << 32,
                                      ~0UL};
    static const uint64_t ips[] = {
        0x401000, SC_PAGE, SC_PAGE + 0xffe, SC_PAGE + 0x1000, SC_PAGE - 1, SC_PAGE | 1UL << 32, 0x7f0000001000};
    uint32_t nrs[HIGHEST + 64];
    int nn = 0;
    for (uint32_t nr = 0; nr <= HIGHEST + 40; nr++) nrs[nn++] = nr;
    nrs[nn++] = 0x7fffffff;
    nrs[nn++] = 0xffffffff;
    nrs[nn++] = 0x40000000;
    nrs[nn++] = 0x40000001;
    for (int i = 0; i < nn; i++) {
        uint32_t nr = nrs[i];
        for (unsigned j = 0; j < sizeof ips / sizeof ips[0]; j++)
            for (int a = -1; a < 6; a++) /* every argument clear, then one argument at each value */
                for (unsigned v = 0; v < (a < 0 ? 1 : sizeof values / sizeof values[0]); v++)
                    for (int arch = 0; arch < 2; arch++) {
                        struct data d;
                        memset(&d, 0, sizeof d);
                        d.nr = nr;
                        d.arch = arch ? AUDIT_ARCH_NATIVE : 0x40000028U;
                        d.ip = ips[j];
                        if (a >= 0) d.args[a] = values[v];
                        uint32_t got = run(p, n, &d, 0, &steps), want = rule(&d);
                        cases++;
                        if (got == SECCOMP_RET_ALLOW && arch && ips[j] == 0x401000) {
                            allow_steps += steps;
                            allows++;
                            if (steps > worst_allow) worst_allow = steps;
                        }
                        if (got != want && fails++ < 20)
                            printf("FAIL nr %u arch %#x ip %#lx arg%d=%#lx: filter %#x, rule %#x\n", nr, d.arch,
                                   (unsigned long)d.ip, a, a < 0 ? 0UL : (unsigned long)values[v], got, want);
                    }
        /* the action cache's question, with the number and the architecture alone */
        if (nr <= HIGHEST) {
            struct data d;
            memset(&d, 0, sizeof d);
            d.nr = nr;
            d.arch = AUDIT_ARCH_NATIVE;
            uint32_t c = run(p, n, &d, 1, &steps);
            if (c == SECCOMP_RET_ALLOW) consts++;
            else if (!singled_out((int)nr) && fails++ < 40)
                printf("FAIL syscall %u is allowed whatever its arguments, but not by its number alone\n", nr);
        }
    }
    printf("%d instructions; %d cases, %d failures; %d of %d numbers allowed by number alone (the action cache); an "
           "allowed syscall from a program runs %.1f instructions on average, %d at most\n",
           n, cases, fails, consts, HIGHEST + 1, (double)allow_steps / (double)allows, worst_allow);
    return fails != 0;
}
