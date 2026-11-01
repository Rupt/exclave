/* sigstack.c — the alternate signal stack under the launcher (DESIGN.md 7.5.3, 13 item 30): a handler that traps on
 * an alternate stack of each size from MINSIGSTKSZ to 16 KB, above a guard page; a handler without SA_ONSTACK, and so
 * on the main stack natively, that arrives during a trapped call and uses 5 KB of stack beside an 8 KB alternate
 * stack; SS_AUTODISARM, sigaltstack queried and changed inside a handler, traps nested on the alternate stack and from
 * a handler on the main stack while one is set. Prints one line per case, "<case>: <answer>", the same in every world
 * where the kernel is the oracle; a case that may crash runs in a child and reports its wait status. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SS_AUTODISARM
#define SS_AUTODISARM (1U << 31) /* 4.7 */
#endif

static volatile int hits, inner_stat, inner_rearm, inner_stat2;
static volatile unsigned inner_flags;

static const char *flags_name(unsigned f)
{
    static char b[64];
    if (f == 0) return "0";
    b[0] = 0;
    if (f & SS_ONSTACK) strcat(b, "SS_ONSTACK ");
    if (f & SS_DISABLE) strcat(b, "SS_DISABLE ");
    if (f & SS_AUTODISARM) strcat(b, "SS_AUTODISARM ");
    if (f & ~(SS_ONSTACK | SS_DISABLE | SS_AUTODISARM)) strcat(b, "other ");
    b[strlen(b) - 1] = 0;
    return b;
}
static const char *status(int st)
{
    static char b[64];
    if (WIFEXITED(st)) snprintf(b, sizeof b, "exit %d", WEXITSTATUS(st));
    else if (WIFSIGNALED(st)) snprintf(b, sizeof b, "killed by %s", strsignal(WTERMSIG(st)));
    else snprintf(b, sizeof b, "status %d", st);
    return b;
}
/* an alternate stack of size bytes at the top of a mapping, a PROT_NONE guard page below it */
static void *guarded(size_t size)
{
    size_t rounded = (size + 4095) & ~(size_t)4095;
    char *m = mmap(0, rounded + 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return 0;
    mprotect(m, 4096, PROT_NONE);
    return m + 4096 + rounded - size;
}
static int arm(void *sp, size_t size, int flags) /* 0, or errno: ENOMEM for a size under MINSIGSTKSZ */
{
    stack_t ss = {sp, flags, size};
    return sigaltstack(&ss, 0) ? errno : 0;
}
static void handler_with(int sig, void (*h)(int), int flags)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h;
    sa.sa_flags = flags;
    sigaction(sig, &sa, 0);
}

static void h_trap(int s)
{
    struct stat st;
    (void)s;
    if (syscall(SYS_newfstatat, AT_FDCWD, "/usr/share/exclave-test-marker", &st, 0) == 0) hits++;
}
static void h_nothing(int s)
{
    (void)s;
    hits++;
}
static void h_query(int s)
{
    stack_t o;
    (void)s;
    sigaltstack(0, &o);
    inner_flags = (unsigned)o.ss_flags;
    struct stat st;
    inner_stat = stat("/usr/share/exclave-test-marker", &st) == 0;
    /* a change from inside: refused on the stack in use, allowed once it is disarmed */
    static char other[65536];
    stack_t n = {other, 0, sizeof other};
    inner_rearm = sigaltstack(&n, 0) == 0 ? 0 : errno;
    inner_stat2 = stat("/usr/share", &st) == 0;
}
static void h_usr2(int s)
{
    (void)s;
    struct stat st;
    if (stat("/usr/share", &st) == 0) hits += 10;
}
static void h_nested(int s)
{
    (void)s;
    struct stat st;
    if (stat("/usr/share/exclave-test-marker", &st) == 0) hits++;
    raise(SIGUSR2);
}
/* a handler that uses 5 KB of stack: natively on the main stack, where the signal lands */
static void h_wide(int s)
{
    volatile char wide[5120];
    for (unsigned i = 0; i < sizeof wide; i += 64) wide[i] = (char)s;
    hits += wide[64] == s;
}

static void child_altstack(size_t size, int trap)
{
    void *sp = guarded(size);
    /* the kernel refuses a stack under its MINSIGSTKSZ (5 KB on aarch64, 2 KB on x86-64): exit 3 says so */
    if (arm(sp, size, 0)) _exit(3);
    handler_with(SIGUSR1, trap ? h_trap : h_nothing, SA_ONSTACK);
    raise(SIGUSR1);
    _exit(hits);
}
/* a SIGSEGV handler that reports rather than returns to the fault, which would fault again for ever */
static void h_segv(int s)
{
    (void)s;
    _exit(9);
}
static void child_wide(void)
{
    /* an 8 KB alternate stack for SIGSEGV, Rust's shape; SIGALRM's handler does not ask for it */
    void *sp = guarded(8192);
    arm(sp, 8192, 0);
    handler_with(SIGSEGV, h_segv, SA_ONSTACK);
    handler_with(SIGALRM, h_wide, 0);
    struct itimerval it = {{0, 1000}, {0, 1000}};
    setitimer(ITIMER_REAL, &it, 0);
    struct stat st;
    struct timeval t0, t1;
    gettimeofday(&t0, 0);
    /* 20 timer signals, within a second */
    do {
        stat("/usr/share/exclave-test-marker", &st);
        gettimeofday(&t1, 0);
    } while (hits < 20 && (t1.tv_sec - t0.tv_sec) * 1000000 + t1.tv_usec - t0.tv_usec < 1000000);
    it.it_value.tv_usec = it.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, 0);
    _exit(hits >= 20 ? 0 : 1);
}

int main(void)
{
    setvbuf(stdout, 0, _IOLBF, 0);
    long minsz = sysconf(_SC_MINSIGSTKSZ);
    printf("MINSIGSTKSZ: %ld bytes\n", minsz);
    /* 1. sizes: the handler on the stack does nothing, then traps (13 item 30: the handler's own frame is added) */
    static const struct {
        const char *name;
        size_t size;
    } sizes[] = {{"MINSIGSTKSZ", 0}, {"4 KB", 4096}, {"5 KB", 5120}, {"6 KB", 6144}, {"8 KB", 8192}, {"16 KB", 16384}};
    for (int trap = 0; trap < 2; trap++)
        for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
            size_t size = sizes[i].size ? sizes[i].size : (size_t)minsz;
            pid_t p = fork();
            if (p == 0) child_altstack(size, trap);
            int st = 0;
            waitpid(p, &st, 0);
            printf("alternate stack of %s, handler %s: %s\n", sizes[i].name, trap ? "traps" : "does nothing",
                   status(st));
        }
    /* 2. a 5 KB handler without SA_ONSTACK landing during traps, an 8 KB alternate stack armed for SIGSEGV: natively
     * it runs on the main stack; under the launcher a signal that lands inside the handler runs on the alternate
     * stack, where 5 KB reaches the guard page, and the SIGSEGV handler exits 9 (13 item 51) */
    {
        int fds[2];
        if (pipe(fds)) return 2;
        pid_t p = fork();
        if (p == 0) {
            close(fds[0]);
            child_wide();
        }
        close(fds[1]);
        int st = 0;
        waitpid(p, &st, 0);
        printf("5 KB handler without SA_ONSTACK during traps, 8 KB alternate stack: %s\n", status(st));
    }
    /* 3. queries and changes from inside a handler on the alternate stack, with and without SS_AUTODISARM */
    void *sp = guarded(65536);
    for (int autodisarm = 0; autodisarm < 2; autodisarm++) {
        if (arm(sp, 65536, autodisarm ? (int)SS_AUTODISARM : 0)) printf("sigaltstack of 64 KB: %s\n", strerror(errno));
        handler_with(SIGUSR1, h_query, SA_ONSTACK);
        raise(SIGUSR1);
        stack_t o;
        sigaltstack(0, &o);
        printf("%s: inside flags %s, stat %s, rearm %s, stat %s; after flags %s\n",
               autodisarm ? "SS_AUTODISARM" : "plain alternate stack", flags_name(inner_flags),
               inner_stat ? "ok" : "failed", inner_rearm ? strerror(inner_rearm) : "ok", inner_stat2 ? "ok" : "failed",
               flags_name((unsigned)o.ss_flags));
        arm(sp, 65536, 0);
    }
    /* 4. traps nested on the alternate stack: USR1's handler traps and raises USR2, whose handler traps */
    hits = 0;
    handler_with(SIGUSR1, h_nested, SA_ONSTACK);
    handler_with(SIGUSR2, h_usr2, SA_ONSTACK);
    raise(SIGUSR1);
    printf("nested handlers on the alternate stack: %s\n", hits == 11 ? "both trapped" : "FAIL");
    /* 5. a handler on the main stack while an alternate stack is armed, trapping, and raising one that is on it */
    hits = 0;
    handler_with(SIGUSR1, h_nested, 0);
    raise(SIGUSR1);
    printf("handler on the main stack beside an armed alternate stack: %s\n", hits == 11 ? "both trapped" : "FAIL");
    /* 6. the query after everything */
    stack_t o;
    sigaltstack(0, &o);
    printf("sigaltstack outside any handler: flags %s\n", flags_name((unsigned)o.ss_flags));
    return 0;
}
