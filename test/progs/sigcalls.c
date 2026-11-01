/* sigcalls.c — the trapped signal syscalls answered in the kernel's order (DESIGN.md 7.5.2, 17 item 4): rt_sigaction,
 * rt_sigprocmask, rt_sigsuspend, ppoll, pselect6, epoll_pwait, epoll_pwait2 and io_pgetevents with a wrong set size, a
 * bad pointer, an invalid how, a signal the kernel owns, an invalid timeout, each beside another fault so that the
 * order of the kernel's checks shows (kernel/signal.c, fs/select.c, fs/eventpoll.c, fs/aio.c); a restorer the program
 * supplies, SA_RESETHAND, SA_NODEFER, unknown flag bits, act and oact the same struct. Prints one line per case,
 * "<case>: <answer>", the same in every world where the kernel is the oracle; a case the handler decides for itself
 * (a mask with SIGSYS, 13 items 20 and 23) is marked in its name. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* _NSIG / 8, the kernel's sigset_t; cast to long where it is a sixth argument, which travels on the stack */
#define SETSZ 8
#define SA_RESTORER 0x04000000

static void *bad; /* a PROT_NONE page */
static const char *en(long r) { return r >= 0 ? "ok" : strerror(errno); }
#define P(name, call)                                                                                                  \
    do {                                                                                                               \
        errno = 0;                                                                                                     \
        long r_ = (long)(call);                                                                                        \
        printf("%s: %s\n", name, en(r_));                                                                              \
    } while (0)

static volatile int hits, deepest, depth, total;
static void h_count(int s)
{
    (void)s;
    hits++;
}
/* raises itself twice more: nested under SA_NODEFER, one after another without it */
static void h_nodefer(int s)
{
    if (++depth > deepest) deepest = depth;
    if (++total < 3) raise(s);
    depth--;
}

/* the kernel's sigaction, 152 bytes on x86-64 and aarch64 alike: handler, flags, restorer, mask */
struct ksa {
    void *handler;
    unsigned long flags;
    void *restorer;
    unsigned long mask;
};
#define RAW_SIGACTION(sig, act, oact, size) syscall(SYS_rt_sigaction, sig, act, oact, size)

static volatile int restorer_ran;
/* a restorer of the program's own: rt_sigreturn (15 on x86-64, 139 on aarch64) after a mark */
extern void my_restorer(void);
#if defined(__x86_64__)
__asm__(".text\n.globl my_restorer\n.type my_restorer,@function\nmy_restorer:\n movl $1, restorer_ran(%rip)\n mov "
        "$15, %eax\n syscall\n");
#elif defined(__aarch64__)
__asm__(".text\n.globl my_restorer\n.type my_restorer,%function\nmy_restorer:\n adrp x1, restorer_ran\n add x1, x1, "
        ":lo12:restorer_ran\n mov w2, #1\n str w2, [x1]\n mov x8, #139\n svc #0\n");
#endif

static const char *status(int st)
{
    static char b[64];
    if (WIFEXITED(st)) snprintf(b, sizeof b, "exit %d", WEXITSTATUS(st));
    else if (WIFSIGNALED(st)) snprintf(b, sizeof b, "killed by %s", strsignal(WTERMSIG(st)));
    else snprintf(b, sizeof b, "status %d", st);
    return b;
}
/* run f in a child; its wait status */
static const char *in_child(void (*f)(void))
{
    pid_t p = fork();
    if (p == 0) {
        f();
        _exit(0);
    }
    int st = 0;
    waitpid(p, &st, 0);
    return status(st);
}
static void no_restorer(void)
{
    /* x86-64 needs SA_RESTORER: the kernel cannot build the frame and kills with SIGSEGV; aarch64 has the vdso's */
    struct ksa a = {(void *)h_count, SA_SIGINFO, 0, 0};
    RAW_SIGACTION(SIGUSR1, &a, 0, SETSZ);
    hits = 0; /* this delivery's count alone: exit 1 where the handler ran */
    raise(SIGUSR1);
    _exit(hits);
}

static void sigaction_cases(void)
{
    struct ksa a = {(void *)h_count, SA_RESTORER, (void *)my_restorer, 0}, o;
    sigset_t s;
    sigemptyset(&s);
    P("rt_sigaction setsize 4", RAW_SIGACTION(SIGUSR1, &a, 0, (long)4));
    P("rt_sigaction setsize 4, act bad", RAW_SIGACTION(SIGUSR1, bad, 0, (long)4));
    P("rt_sigaction sig 0", RAW_SIGACTION(0, &a, 0, (long)SETSZ));
    P("rt_sigaction sig 65", RAW_SIGACTION(65, &a, 0, (long)SETSZ));
    P("rt_sigaction sig 64 install", RAW_SIGACTION(64, &a, 0, (long)SETSZ));
    P("rt_sigaction sig 0 query", RAW_SIGACTION(0, 0, &o, (long)SETSZ));
    P("rt_sigaction sig 0, act bad", RAW_SIGACTION(0, bad, 0, (long)SETSZ));
    P("rt_sigaction SIGKILL query", RAW_SIGACTION(SIGKILL, 0, &o, (long)SETSZ));
    P("rt_sigaction SIGKILL install", RAW_SIGACTION(SIGKILL, &a, 0, (long)SETSZ));
    P("rt_sigaction SIGSTOP install", RAW_SIGACTION(SIGSTOP, &a, 0, (long)SETSZ));
    P("rt_sigaction SIGKILL, act bad", RAW_SIGACTION(SIGKILL, bad, 0, (long)SETSZ));
    P("rt_sigaction act bad", RAW_SIGACTION(SIGUSR1, bad, 0, (long)SETSZ));
    P("rt_sigaction act bad, oact bad", RAW_SIGACTION(SIGUSR1, bad, bad, (long)SETSZ));
    /* oact bad: the install is done before the old action is written */
    signal(SIGUSR1, SIG_DFL);
    P("rt_sigaction act ok, oact bad", RAW_SIGACTION(SIGUSR1, &a, bad, (long)SETSZ));
    RAW_SIGACTION(SIGUSR1, 0, &o, SETSZ);
    printf("after oact bad, the handler: %s\n", o.handler == (void *)h_count ? "installed" : "not installed");
    P("rt_sigaction act NULL, oact bad", RAW_SIGACTION(SIGUSR1, 0, bad, (long)SETSZ));
    /* the restorer the program supplied is used and reported */
    restorer_ran = 0;
    hits = 0;
    raise(SIGUSR1);
    printf("own restorer: %s, hits %d\n", restorer_ran ? "ran" : "did not run", hits);
    memset(&o, 0, sizeof o);
    RAW_SIGACTION(SIGUSR1, 0, &o, SETSZ);
    printf("own restorer reported: %s, flags %#lx\n", o.restorer == (void *)my_restorer ? "yes" : "no", o.flags);
    /* act and oact the same struct: the old action comes back in it */
    struct ksa both = {(void *)SIG_IGN, SA_RESTORER, (void *)my_restorer, 0};
    P("rt_sigaction act and oact the same", RAW_SIGACTION(SIGUSR1, &both, &both, (long)SETSZ));
    printf("the same struct holds: %s\n", both.handler == (void *)h_count   ? "the old handler"
                                          : both.handler == (void *)SIG_IGN ? "the new one"
                                                                            : "something else");
    /* unknown flag bits are dropped on x86-64 and aarch64 */
    struct ksa odd = {(void *)h_count, SA_RESTORER | 0x100000UL, (void *)my_restorer, 0};
    P("rt_sigaction unknown flag bit", RAW_SIGACTION(SIGUSR1, &odd, 0, (long)SETSZ));
    RAW_SIGACTION(SIGUSR1, 0, &o, SETSZ);
    printf("unknown flag bit reported: %s\n", o.flags & 0x100000UL ? "kept" : "dropped");
    /* SA_RESETHAND: one delivery, then the default */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h_count;
    sa.sa_flags = (int)SA_RESETHAND;
    sigaction(SIGUSR1, &sa, 0);
    hits = 0;
    raise(SIGUSR1);
    sigaction(SIGUSR1, 0, &sa);
    printf("SA_RESETHAND: hits %d, then %s\n", hits, sa.sa_handler == SIG_DFL ? "SIG_DFL" : "still handled");
    /* SA_NODEFER: the handler re-raises itself twice, three deep */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h_nodefer;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGUSR1, &sa, 0);
    deepest = depth = total = 0;
    raise(SIGUSR1);
    printf("SA_NODEFER nesting: %d deep, %d runs\n", deepest, total);
    /* without it: the re-raise waits for the handler */
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, 0);
    deepest = depth = total = 0;
    raise(SIGUSR1);
    printf("deferred nesting: %d deep, %d runs\n", deepest, total);
    signal(SIGUSR1, SIG_DFL);
    /* sa_mask comes back as written; with SIGSYS in it, scrubbed (13 item 20) */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h_count;
    sigaddset(&sa.sa_mask, SIGUSR2);
    sigaddset(&sa.sa_mask, SIGALRM);
    sigaction(SIGUSR1, &sa, 0);
    sigaction(SIGUSR1, 0, &sa);
    printf("sa_mask reported: USR2 %s, ALRM %s, HUP %s\n", sigismember(&sa.sa_mask, SIGUSR2) ? "yes" : "no",
           sigismember(&sa.sa_mask, SIGALRM) ? "yes" : "no", sigismember(&sa.sa_mask, SIGHUP) ? "yes" : "no");
    /* SIGSYS itself (13 item 23): the bad arguments are the kernel's business before the install is */
    P("rt_sigaction SIGSYS setsize 4", RAW_SIGACTION(SIGSYS, &a, 0, (long)4));
    P("rt_sigaction SIGSYS act bad", RAW_SIGACTION(SIGSYS, bad, 0, (long)SETSZ));
    P("rt_sigaction SIGSYS act ok, oact bad", RAW_SIGACTION(SIGSYS, &a, bad, (long)SETSZ));
    P("rt_sigaction SIGSYS act NULL, oact bad", RAW_SIGACTION(SIGSYS, 0, bad, (long)SETSZ));
    printf("handler without SA_RESTORER: %s\n", in_child(no_restorer));
}

static void sigprocmask_cases(void)
{
    sigset_t s, o, before;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    sigprocmask(SIG_SETMASK, 0, &before);
    P("rt_sigprocmask setsize 4", syscall(SYS_rt_sigprocmask, SIG_BLOCK, &s, 0, (long)4));
    P("rt_sigprocmask setsize 4, set bad", syscall(SYS_rt_sigprocmask, SIG_BLOCK, bad, 0, (long)4));
    P("rt_sigprocmask how 99, set NULL", syscall(SYS_rt_sigprocmask, 99, 0, &o, (long)SETSZ));
    P("rt_sigprocmask how 99, set NULL, oset NULL", syscall(SYS_rt_sigprocmask, 99, 0, 0, (long)SETSZ));
    P("rt_sigprocmask how 99", syscall(SYS_rt_sigprocmask, 99, &s, 0, (long)SETSZ));
    P("rt_sigprocmask how 99, set bad", syscall(SYS_rt_sigprocmask, 99, bad, 0, (long)SETSZ));
    P("rt_sigprocmask set bad", syscall(SYS_rt_sigprocmask, SIG_BLOCK, bad, 0, (long)SETSZ));
    P("rt_sigprocmask set bad, oset bad", syscall(SYS_rt_sigprocmask, SIG_BLOCK, bad, bad, (long)SETSZ));
    P("rt_sigprocmask set NULL, oset bad", syscall(SYS_rt_sigprocmask, SIG_BLOCK, 0, bad, (long)SETSZ));
    /* oset bad: the mask was changed before the old one could not be written */
    P("rt_sigprocmask set ok, oset bad", syscall(SYS_rt_sigprocmask, SIG_BLOCK, &s, bad, (long)SETSZ));
    sigprocmask(SIG_SETMASK, 0, &o);
    printf("after oset bad, USR1: %s\n", sigismember(&o, SIGUSR1) ? "blocked" : "not blocked");
    sigprocmask(SIG_SETMASK, &before, 0);
    /* set and oset the same: the old mask comes back */
    sigset_t same;
    sigemptyset(&same);
    sigaddset(&same, SIGUSR2);
    sigprocmask(SIG_BLOCK, &s, 0); /* USR1 blocked now */
    P("rt_sigprocmask set and oset the same", syscall(SYS_rt_sigprocmask, SIG_BLOCK, &same, &same, (long)SETSZ));
    printf("the same set holds: USR1 %s, USR2 %s\n", sigismember(&same, SIGUSR1) ? "yes" : "no",
           sigismember(&same, SIGUSR2) ? "yes" : "no");
    sigprocmask(SIG_SETMASK, 0, &o);
    printf("blocked after it: USR1 %s, USR2 %s\n", sigismember(&o, SIGUSR1) ? "yes" : "no",
           sigismember(&o, SIGUSR2) ? "yes" : "no");
    sigprocmask(SIG_SETMASK, &before, 0);
    /* SIGKILL and SIGSTOP are dropped from a set without error */
    sigemptyset(&s);
    sigaddset(&s, SIGKILL);
    sigaddset(&s, SIGSTOP);
    sigaddset(&s, SIGHUP);
    P("rt_sigprocmask block KILL, STOP, HUP", syscall(SYS_rt_sigprocmask, SIG_SETMASK, &s, 0, (long)SETSZ));
    sigprocmask(SIG_SETMASK, 0, &o);
    printf("blocked: KILL %s, STOP %s, HUP %s\n", sigismember(&o, SIGKILL) ? "yes" : "no",
           sigismember(&o, SIGSTOP) ? "yes" : "no", sigismember(&o, SIGHUP) ? "yes" : "no");
    sigprocmask(SIG_SETMASK, &before, 0);
}

static void sigsuspend_cases(void)
{
    sigset_t s;
    sigfillset(&s);
    P("rt_sigsuspend setsize 4", syscall(SYS_rt_sigsuspend, &s, (long)4));
    P("rt_sigsuspend setsize 4, set bad", syscall(SYS_rt_sigsuspend, bad, (long)4));
    P("rt_sigsuspend set bad", syscall(SYS_rt_sigsuspend, bad, (long)SETSZ));
    P("rt_sigsuspend set NULL", syscall(SYS_rt_sigsuspend, 0, (long)SETSZ));
}

static void wait_cases(void)
{
    struct timespec zero = {0, 0}, invalid = {0, -1};
    sigset_t s;
    sigemptyset(&s);
    struct pollfd pf = {-1, 0, 0};
    /* ppoll: the timeout is read and checked, then the mask, then the descriptors */
    P("ppoll mask NULL, setsize 4", syscall(SYS_ppoll, &pf, 1, &zero, 0, (long)4));
    P("ppoll setsize 4", syscall(SYS_ppoll, &pf, 1, &zero, &s, (long)4));
    P("ppoll setsize 4, mask bad", syscall(SYS_ppoll, &pf, 1, &zero, bad, (long)4));
    P("ppoll mask bad", syscall(SYS_ppoll, &pf, 1, &zero, bad, (long)SETSZ));
    P("ppoll timeout bad", syscall(SYS_ppoll, &pf, 1, bad, &s, (long)SETSZ));
    P("ppoll timeout bad, mask bad", syscall(SYS_ppoll, &pf, 1, bad, bad, (long)SETSZ));
    P("ppoll timeout bad, setsize 4", syscall(SYS_ppoll, &pf, 1, bad, &s, (long)4));
    P("ppoll timeout invalid", syscall(SYS_ppoll, &pf, 1, &invalid, &s, (long)SETSZ));
    P("ppoll timeout invalid, mask bad", syscall(SYS_ppoll, &pf, 1, &invalid, bad, (long)SETSZ));
    P("ppoll timeout invalid, setsize 4", syscall(SYS_ppoll, &pf, 1, &invalid, &s, (long)4));
    P("ppoll fds bad", syscall(SYS_ppoll, bad, 1, &zero, &s, (long)SETSZ));
    P("ppoll fds bad, mask bad", syscall(SYS_ppoll, bad, 1, &zero, bad, (long)SETSZ));
    P("ppoll nfds huge", syscall(SYS_ppoll, &pf, 1UL << 30, &zero, &s, (long)SETSZ));
    P("ppoll nfds huge, mask bad", syscall(SYS_ppoll, &pf, 1UL << 30, &zero, bad, (long)SETSZ));
    P("ppoll nfds huge, setsize 4", syscall(SYS_ppoll, &pf, 1UL << 30, &zero, &s, (long)4));
    /* pselect6: the {mask, size} pair is read first, then the timeout, the mask, then n */
    struct {
        const sigset_t *p;
        size_t n;
    } pk = {&s, SETSZ}, pk4 = {&s, 4}, pknull4 = {0, 4}, pkbad = {(const sigset_t *)bad, SETSZ},
      pkbad4 = {(const sigset_t *)bad, 4};
    P("pselect6 pack bad", syscall(SYS_pselect6, 0, 0, 0, 0, &zero, bad));
    P("pselect6 pack bad, timeout bad", syscall(SYS_pselect6, 0, 0, 0, 0, bad, bad));
    P("pselect6 pack bad, n -1", syscall(SYS_pselect6, -1, 0, 0, 0, &zero, bad));
    P("pselect6 mask NULL, size 4", syscall(SYS_pselect6, 0, 0, 0, 0, &zero, &pknull4));
    P("pselect6 size 4", syscall(SYS_pselect6, 0, 0, 0, 0, &zero, &pk4));
    P("pselect6 size 4, mask bad", syscall(SYS_pselect6, 0, 0, 0, 0, &zero, &pkbad4));
    P("pselect6 mask bad", syscall(SYS_pselect6, 0, 0, 0, 0, &zero, &pkbad));
    P("pselect6 timeout bad", syscall(SYS_pselect6, 0, 0, 0, 0, bad, &pk));
    P("pselect6 timeout bad, mask bad", syscall(SYS_pselect6, 0, 0, 0, 0, bad, &pkbad));
    P("pselect6 timeout bad, size 4", syscall(SYS_pselect6, 0, 0, 0, 0, bad, &pk4));
    P("pselect6 timeout invalid", syscall(SYS_pselect6, 0, 0, 0, 0, &invalid, &pk));
    P("pselect6 timeout invalid, mask bad", syscall(SYS_pselect6, 0, 0, 0, 0, &invalid, &pkbad));
    P("pselect6 timeout invalid, size 4", syscall(SYS_pselect6, 0, 0, 0, 0, &invalid, &pk4));
    P("pselect6 n -1", syscall(SYS_pselect6, -1, 0, 0, 0, &zero, &pk));
    P("pselect6 n -1, mask bad", syscall(SYS_pselect6, -1, 0, 0, 0, &zero, &pkbad));
    P("pselect6 n -1, size 4", syscall(SYS_pselect6, -1, 0, 0, 0, &zero, &pk4));
    P("pselect6 fds bad", syscall(SYS_pselect6, 1, bad, 0, 0, &zero, &pk));
    P("pselect6 fds bad, mask bad", syscall(SYS_pselect6, 1, bad, 0, 0, &zero, &pkbad));
    /* epoll_pwait: the mask, then maxevents, the events pointer, the descriptor */
    int ep = epoll_create1(0);
    struct epoll_event ev;
    P("epoll_pwait mask NULL, setsize 4, epfd -1", syscall(SYS_epoll_pwait, -1, &ev, 1, 0, 0, (long)4));
    P("epoll_pwait setsize 4, epfd -1", syscall(SYS_epoll_pwait, -1, &ev, 1, 0, &s, (long)4));
    P("epoll_pwait mask bad, epfd -1", syscall(SYS_epoll_pwait, -1, &ev, 1, 0, bad, (long)SETSZ));
    P("epoll_pwait mask bad, maxevents 0", syscall(SYS_epoll_pwait, ep, &ev, 0, 0, bad, (long)SETSZ));
    P("epoll_pwait maxevents 0", syscall(SYS_epoll_pwait, ep, &ev, 0, 0, &s, (long)SETSZ));
    P("epoll_pwait events bad", syscall(SYS_epoll_pwait, ep, bad, 1, 0, &s, (long)SETSZ));
    P("epoll_pwait events bad, epfd -1", syscall(SYS_epoll_pwait, -1, bad, 1, 0, &s, (long)SETSZ));
    P("epoll_pwait epfd -1", syscall(SYS_epoll_pwait, -1, &ev, 1, 0, &s, (long)SETSZ));
    P("epoll_pwait epfd not epoll", syscall(SYS_epoll_pwait, 0, &ev, 1, 0, &s, (long)SETSZ));
    P("epoll_pwait ok, no events", syscall(SYS_epoll_pwait, ep, &ev, 1, 0, &s, (long)SETSZ));
    /* epoll_pwait2: the timeout first */
    P("epoll_pwait2 timeout bad", syscall(SYS_epoll_pwait2, ep, &ev, 1, bad, &s, (long)SETSZ));
    P("epoll_pwait2 timeout bad, mask bad", syscall(SYS_epoll_pwait2, ep, &ev, 1, bad, bad, (long)SETSZ));
    P("epoll_pwait2 timeout bad, setsize 4", syscall(SYS_epoll_pwait2, ep, &ev, 1, bad, &s, (long)4));
    P("epoll_pwait2 timeout invalid", syscall(SYS_epoll_pwait2, ep, &ev, 1, &invalid, &s, (long)SETSZ));
    P("epoll_pwait2 timeout invalid, mask bad", syscall(SYS_epoll_pwait2, ep, &ev, 1, &invalid, bad, (long)SETSZ));
    P("epoll_pwait2 timeout invalid, setsize 4", syscall(SYS_epoll_pwait2, ep, &ev, 1, &invalid, &s, (long)4));
    P("epoll_pwait2 mask NULL, setsize 4, epfd -1", syscall(SYS_epoll_pwait2, -1, &ev, 1, &zero, 0, (long)4));
    P("epoll_pwait2 mask bad, epfd -1", syscall(SYS_epoll_pwait2, -1, &ev, 1, &zero, bad, (long)SETSZ));
    P("epoll_pwait2 ok, no events", syscall(SYS_epoll_pwait2, ep, &ev, 1, &zero, &s, (long)SETSZ));
    close(ep);
    /* io_pgetevents: the {mask, size} pair, then the timeout, the mask, then the context */
    struct {
        const sigset_t *p;
        size_t n;
    } ak = {&s, SETSZ}, ak4 = {&s, 4}, aknull4 = {0, 4}, akbad = {(const sigset_t *)bad, SETSZ};
    char evs[64];
    P("io_pgetevents pack bad", syscall(SYS_io_pgetevents, 0, 0, 1, evs, &zero, bad));
    P("io_pgetevents pack bad, timeout bad", syscall(SYS_io_pgetevents, 0, 0, 1, evs, bad, bad));
    P("io_pgetevents mask NULL, size 4, ctx 0", syscall(SYS_io_pgetevents, 0, 0, 1, evs, &zero, &aknull4));
    P("io_pgetevents size 4, ctx 0", syscall(SYS_io_pgetevents, 0, 0, 1, evs, &zero, &ak4));
    P("io_pgetevents mask bad, ctx 0", syscall(SYS_io_pgetevents, 0, 0, 1, evs, &zero, &akbad));
    P("io_pgetevents timeout bad, mask bad", syscall(SYS_io_pgetevents, 0, 0, 1, evs, bad, &akbad));
    P("io_pgetevents timeout bad, size 4", syscall(SYS_io_pgetevents, 0, 0, 1, evs, bad, &ak4));
    /* io_pgetevents never checks its timeout: the mask's fault answers */
    P("io_pgetevents timeout invalid, mask bad", syscall(SYS_io_pgetevents, 0, 0, 1, evs, &invalid, &akbad));
    P("io_pgetevents timeout invalid, ctx 0", syscall(SYS_io_pgetevents, 0, 0, 1, evs, &invalid, &ak));
    P("io_pgetevents ctx 0", syscall(SYS_io_pgetevents, 0, 0, 1, evs, &zero, &ak));
}

int main(void)
{
    bad = mmap(0, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    setvbuf(stdout, 0, _IOLBF, 0);
    sigaction_cases();
    sigprocmask_cases();
    sigsuspend_cases();
    wait_cases();
    return 0;
}
