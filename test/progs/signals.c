/* signals.c — the signal regressions of DESIGN.md 7.5: SIGSYS is never blocked, handlers with full masks trap, the
 * program's mask is otherwise honoured. Prints FAIL lines; exit 1 on any. */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>

static int fails;
static volatile int hits;
static unsigned long sigblk(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char l[256];
    unsigned long v = 0;
    while (f && fgets(l, sizeof l, f))
        if (!strncmp(l, "SigBlk:", 7)) v = strtoul(l + 7, 0, 16);
    if (f) fclose(f);
    return v;
}
static void h_stat(int s)
{
    struct stat st;
    (void)s;
    if (stat("/usr/share/exclave-test-marker", &st) == 0) hits++;
}
static void h_exe(int s)
{
    char b[256];
    (void)s;
    if (readlink("/proc/self/exe", b, 255) > 0) hits++;
}

/* one of the three waits that carry a mask, 20 ms with mask; epoll through syscall, since the suite's pruned tree may
 * lack <sys/epoll.h>, and so with the kernel's eight-byte mask */
static int wait_with(int which, const sigset_t *mask)
{
    struct timespec ts = {0, 20000000};
    if (which == 0) return pselect(0, 0, 0, 0, &ts, mask);
    if (which == 1) {
        struct pollfd p = {-1, 0, 0};
        return ppoll(&p, 1, &ts, mask);
    }
    int ep = (int)syscall(SYS_epoll_create1, 0);
    char events[64];
    int rc = (int)syscall(SYS_epoll_pwait, ep, events, 1, 20, mask, 8), e = errno;
    close(ep);
    errno = e;
    return rc;
}

int main(void)
{
    struct stat st;
    /* 1. blocking SIGSYS is silently refused; USR1 is honoured; oldset does not mention SIGSYS */
    sigset_t s, o;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    sigaddset(&s, SIGSYS);
    sigprocmask(SIG_BLOCK, &s, &o);
    if (stat("/usr/share", &st)) {
        fails++;
        printf("FAIL stat with SIGSYS 'blocked'\n");
    }
    unsigned long m = sigblk();
    if (!(m & (1UL << (SIGUSR1 - 1)))) {
        fails++;
        printf("FAIL USR1 not blocked\n");
    }
    if (m & (1UL << (SIGSYS - 1))) { fails++, printf("FAIL SIGSYS blocked in SigBlk %lx\n", m); }
    if (sigismember(&o, SIGSYS)) {
        fails++;
        printf("FAIL oldset has SIGSYS\n");
    }
    sigfillset(&s);
    sigprocmask(SIG_SETMASK, &s, 0);
    if (stat("/usr/share", &st)) {
        fails++;
        printf("FAIL stat under fillset\n");
    }
    if (sigblk() & (1UL << (SIGSYS - 1))) {
        fails++;
        printf("FAIL SIGSYS blocked after SETMASK fillset\n");
    }
    sigprocmask(SIG_SETMASK, &o, 0);
    /* 2. a sigfillset handler touching a path */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h_stat;
    sigfillset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, 0);
    hits = 0;
    raise(SIGUSR1);
    if (hits != 1) {
        fails++;
        printf("FAIL fillset handler: hits=%d\n", hits);
    }
    /* 3. SA_ONSTACK handler trapping (nested inside a trapped syscall is fifo.c's business) */
    static char stk[65536];
    stack_t ss = {stk, 0, sizeof stk};
    sigaltstack(&ss, 0);
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h_exe;
    sa.sa_flags = SA_ONSTACK;
    sigfillset(&sa.sa_mask);
    sigaction(SIGUSR2, &sa, 0);
    hits = 0;
    raise(SIGUSR2);
    if (hits != 1) {
        fails++;
        printf("FAIL SA_ONSTACK handler: hits=%d\n", hits);
    }
    /* 4. pselect, ppoll and epoll_pwait hand their mask to the kernel: with SIGUSR1 blocked and pending, a full mask
     * keeps it blocked, so the wait times out and no handler runs, and an empty one lets it in, EINTR and one run of
     * the handler, which traps; the process survives a trap afterwards */
    {
        static const char *const waits[] = {"pselect", "ppoll", "epoll_pwait"};
        sigset_t full, empty, usr1, before;
        sigfillset(&full);
        sigemptyset(&empty);
        sigemptyset(&usr1);
        sigaddset(&usr1, SIGUSR1);
        for (int i = 0; i < 3; i++) {
            sigprocmask(SIG_BLOCK, &usr1, &before);
            hits = 0;
            raise(SIGUSR1);
            errno = 0;
            int rc = wait_with(i, &full);
            if (rc != 0 || hits != 0) {
                fails++;
                printf("FAIL %s with a full mask: rc=%d errno=%d hits=%d\n", waits[i], rc, errno, hits);
            }
            errno = 0;
            rc = wait_with(i, &empty);
            if (rc != -1 || errno != EINTR || hits != 1) {
                fails++;
                printf("FAIL %s with an empty mask: rc=%d errno=%d hits=%d\n", waits[i], rc, errno, hits);
            }
            sigprocmask(SIG_SETMASK, &before, 0);
        }
    }
    if (stat("/usr/share", &st)) {
        fails++;
        printf("FAIL stat after pselect/ppoll\n");
    }
    if (sigblk() & (1UL << (SIGSYS - 1))) {
        fails++;
        printf("FAIL SIGSYS blocked after waits\n");
    }
    /* 5. sigsuspend with a full mask minus ALRM, woken by an interval timer whose handler traps */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h_stat;
    sigaction(SIGALRM, &sa, 0);
    struct itimerval it = {{0, 0}, {0, 30000}};
    setitimer(ITIMER_REAL, &it, 0);
    sigfillset(&s);
    sigdelset(&s, SIGALRM);
    hits = 0;
    errno = 0;
    int rc = sigsuspend(&s);
    if (rc != -1 || errno != EINTR || hits != 1) {
        fails++;
        printf("FAIL sigsuspend rc=%d errno=%d hits=%d\n", rc, errno, hits);
    }
    /* 6. the program cannot take SIGSYS for itself; installation looks successful and traps keep working */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h_stat;
    struct sigaction old;
    if (sigaction(SIGSYS, &sa, &old) != 0) {
        fails++;
        printf("FAIL sigaction(SIGSYS)\n");
    }
    if (old.sa_handler == h_stat || old.sa_handler == SIG_DFL) {
        fails++;
        printf("FAIL old SIGSYS action should be the launcher's handler\n");
    }
    if (sigaction(SIGSYS, 0, &old) != 0 || old.sa_handler == h_stat) {
        fails++;
        printf("FAIL SIGSYS query after ignored install\n");
    }
    if (stat("/usr/share", &st)) {
        fails++;
        printf("FAIL stat after sigaction(SIGSYS)\n");
    }
    printf("signals: %d failures\n", fails);
    return fails ? 1 : 0;
}
