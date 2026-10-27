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
    /* 4. pselect and ppoll with a full mask time out normally, and the process survives a trap afterwards */
    sigfillset(&s);
    {
        struct timespec ts = {0, 20000000};
        fd_set r;
        FD_ZERO(&r);
        FD_SET(0, &r);
        int rc = pselect(1, 0, 0, 0, &ts, &s);
        if (rc != 0) {
            fails++;
            printf("FAIL pselect rc=%d errno=%d\n", rc, errno);
        }
    }
    {
        struct timespec ts = {0, 20000000};
        struct pollfd p = {-1, 0, 0};
        int rc = ppoll(&p, 1, &ts, &s);
        if (rc != 0) {
            fails++;
            printf("FAIL ppoll rc=%d errno=%d\n", rc, errno);
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
