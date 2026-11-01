/* clones.c — threads and clones trapping (DESIGN.md 7.5.4, 7.5.5, 17 item 4): a vfork child and a clone(CLONE_VM)
 * child trapping before they exit, on stacks from 64 KB down to 2 KB above a guard page; a thread with a 16 KB stack
 * and one with the least glibc allows; 64 threads trapping while the main thread sends each of them signals whose
 * handler traps; pthread_cancel of a thread blocked in a trapped open and of one looping over traps with asynchronous
 * cancellation; a sibling exiting while a trap blocks; exit_group and pthread_exit from a handler that interrupted a
 * blocking trap. usage: clones HOSTDIR. Prints one line per case, "<case>: <answer>", the same in every world where
 * the kernel is the oracle; a case that may crash runs in a child and reports its wait status. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char fifo[4096];
static long answers[4]; /* written by a child sharing memory, read after its wait */

static const char *status(int st)
{
    static char b[64];
    if (WIFEXITED(st)) snprintf(b, sizeof b, "exit %d", WEXITSTATUS(st));
    else if (WIFSIGNALED(st)) snprintf(b, sizeof b, "killed by %s", strsignal(WTERMSIG(st)));
    else snprintf(b, sizeof b, "status %d", st);
    return b;
}
static long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
/* the traps a child makes, by raw syscalls, since a CLONE_VM child shares the parent's TLS */
static void child_traps(void)
{
    struct stat st;
    char b[256];
    answers[0] = syscall(SYS_newfstatat, AT_FDCWD, "/usr/share/exclave-test-marker", &st, 0) == 0;
    long fd = syscall(SYS_openat, AT_FDCWD, "/usr/share/exclave-test-marker", O_RDONLY);
    answers[1] = fd >= 0;
    if (fd >= 0) syscall(SYS_close, fd);
    answers[2] = syscall(SYS_readlinkat, AT_FDCWD, "/proc/self/exe", b, sizeof b) > 0;
    answers[3] = syscall(SYS_faccessat, AT_FDCWD, "/usr/share/exclave-test-marker", R_OK) == 0;
}
static const char *three(void)
{
    static char b[64];
    snprintf(b, sizeof b, "stat %s, open %s, readlink %s, access %s", answers[0] ? "ok" : "failed",
             answers[1] ? "ok" : "failed", answers[2] ? "ok" : "failed", answers[3] ? "ok" : "failed");
    return b;
}
static int clone_child(void *arg)
{
    (void)arg;
    child_traps();
    return 0;
}
static int clone_one_trap(void *arg)
{
    struct stat st;
    (void)arg;
    return syscall(SYS_newfstatat, AT_FDCWD, "/usr/share/exclave-test-marker", &st, 0) == 0 ? 0 : 1;
}
/* a stack of size bytes at the top of a mapping with a guard page below; its top */
static void *stack_top(size_t size)
{
    size_t rounded = (size + 4095) & ~(size_t)4095;
    char *m = mmap(0, rounded + 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return 0;
    mprotect(m, 4096, PROT_NONE);
    return m + 4096 + rounded;
}

static void *thread_traps(void *arg)
{
    struct stat st;
    long n = 0;
    for (int i = 0; i < 100; i++) n += syscall(SYS_newfstatat, AT_FDCWD, "/usr/share/exclave-test-marker", &st, 0) == 0;
    *(long *)arg = n;
    return 0;
}
static volatile int stop;
static volatile long wrong, handler_fails, handler_runs;
static void h_trap(int s)
{
    struct stat st;
    (void)s;
    handler_runs++;
    if (stat("/usr/share", &st)) handler_fails++;
}
static void *busy(void *arg)
{
    struct stat st;
    char b[256];
    *(pid_t *)arg = (pid_t)syscall(SYS_gettid);
    while (!stop) {
        if (stat("/usr/share/exclave-test-marker", &st)) wrong++;
        if (readlink("/proc/self/exe", b, sizeof b) < 0) wrong++;
        if (access("/usr/share", R_OK)) wrong++;
    }
    return 0;
}
static void *blocked_open(void *arg)
{
    int fd = open((const char *)arg, O_RDONLY);
    if (fd >= 0) close(fd);
    return (void *)1;
}
static void *async_loop(void *arg)
{
    struct stat st;
    (void)arg;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0);
    for (;;) stat("/usr/share/exclave-test-marker", &st);
    return 0;
}
static void *exits(void *arg)
{
    (void)arg;
    pthread_exit((void *)2);
}
static void h_exit_group(int s) { _exit(s == SIGALRM ? 7 : 8); }
static void h_pthread_exit(int s)
{
    (void)s;
    pthread_exit((void *)3);
}
static void release(void)
{
    /* a writer for a blocked reader */
    int w = open(fifo, O_WRONLY);
    if (w >= 0) close(w);
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    setvbuf(stdout, 0, _IOLBF, 0);
    snprintf(fifo, sizeof fifo, "%s/fifo", argv[1]);
    mkfifo(fifo, 0600);
    /* 1. a vfork child trapping before it exits */
    memset(answers, 0, sizeof answers);
    pid_t c = vfork();
    if (c == 0) {
        child_traps();
        _exit(0);
    }
    int st = 0;
    waitpid(c, &st, 0);
    printf("vfork child's traps: %s, %s\n", three(), status(st));
    /* 2. clone(CLONE_VM) children on stacks of 64 KB, 8 KB, 4 KB and 2 KB above a guard page */
    static const size_t sizes[] = {65536, 8192, 4096, 2048};
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        memset(answers, 0, sizeof answers);
        void *top = stack_top(sizes[i]);
        c = clone(i ? clone_one_trap : clone_child, top, CLONE_VM | SIGCHLD, 0);
        st = 0;
        waitpid(c, &st, 0);
        if (i == 0) printf("clone(CLONE_VM) child on a 64 KB stack: %s, %s\n", three(), status(st));
        else printf("clone(CLONE_VM) child trapping on a %zu KB stack: %s\n", sizes[i] / 1024, status(st));
    }
    /* 3. clone(CLONE_VM|CLONE_VFORK) on its own stack */
    memset(answers, 0, sizeof answers);
    c = clone(clone_child, stack_top(65536), CLONE_VM | CLONE_VFORK | SIGCHLD, 0);
    st = 0;
    waitpid(c, &st, 0);
    printf("clone(CLONE_VM|CLONE_VFORK) child's traps: %s, %s\n", three(), status(st));
    /* 4. threads on small stacks */
    {
        pthread_attr_t at;
        pthread_t t;
        long n = 0;
        pthread_attr_init(&at);
        pthread_attr_setstacksize(&at, 16384);
        int e = pthread_create(&t, &at, thread_traps, &n);
        if (e == 0) pthread_join(t, 0);
        printf("thread with a 16 KB stack, 100 traps: %s\n", e ? strerror(e) : n == 100 ? "ok" : "some failed");
        n = 0;
        pthread_attr_setstacksize(&at, (size_t)PTHREAD_STACK_MIN);
        e = pthread_create(&t, &at, thread_traps, &n);
        if (e == 0) pthread_join(t, 0);
        printf("thread with the least stack, 100 traps: %s\n", e ? strerror(e) : n == 100 ? "ok" : "some failed");
        pthread_attr_destroy(&at);
    }
    /* 5. 64 threads trapping while the main thread sends each a SIGUSR1 in turn, whose handler traps, for 200 ms */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = h_trap;
        sigaction(SIGUSR1, &sa, 0);
        pthread_t t[64];
        static pid_t tids[64];
        for (int i = 0; i < 64; i++) pthread_create(&t[i], 0, busy, &tids[i]);
        usleep(20000);
        long end = now_ms() + 200, sent = 0;
        while (now_ms() < end)
            for (int i = 0; i < 64; i++)
                if (tids[i] && syscall(SYS_tgkill, getpid(), tids[i], SIGUSR1) == 0) sent++;
        stop = 1;
        for (int i = 0; i < 64; i++) pthread_join(t[i], 0);
        printf("64 threads trapping under tgkill: %ld wrong, handler traps %ld failed, signals %s\n", wrong,
               handler_fails, handler_runs ? "landed" : "none");
        signal(SIGUSR1, SIG_DFL);
    }
    /* 6. pthread_cancel: a thread blocked in a trapped open, and one looping over traps, cancelled asynchronously */
    {
        pthread_t t;
        void *r = 0;
        pthread_create(&t, 0, blocked_open, fifo);
        usleep(50000);
        pthread_cancel(t);
        pthread_join(t, &r);
        printf("pthread_cancel in a blocking trapped open: %s\n", r == PTHREAD_CANCELED ? "cancelled" : "returned");
        pthread_create(&t, 0, async_loop, 0);
        usleep(20000);
        pthread_cancel(t);
        pthread_join(t, &r);
        printf("asynchronous pthread_cancel in a trap loop: %s\n", r == PTHREAD_CANCELED ? "cancelled" : "returned");
        struct stat s2;
        printf("stat after the cancels: %s\n", stat("/usr/share", &s2) == 0 ? "ok" : "failed");
    }
    /* 7. a sibling exits while a thread blocks in a trapped open; the open then completes */
    {
        pthread_t a, b;
        void *r = 0;
        pthread_create(&a, 0, blocked_open, fifo);
        usleep(20000);
        pthread_create(&b, 0, exits, 0);
        pthread_join(b, &r);
        release();
        pthread_join(a, &r);
        printf("sibling exit during a blocking trap: %s\n", r == (void *)1 ? "open completed" : "other");
    }
    /* 8. exit_group from a handler that interrupted a blocking trapped open, in a child */
    {
        c = fork();
        if (c == 0) {
            signal(SIGALRM, h_exit_group);
            struct itimerval it = {{0, 0}, {0, 20000}};
            setitimer(ITIMER_REAL, &it, 0);
            int fd = open(fifo, O_RDONLY);
            _exit(fd >= 0 ? 5 : 6);
        }
        st = 0;
        waitpid(c, &st, 0);
        printf("exit_group from a handler inside a blocking trap: %s\n", status(st));
    }
    /* 9. pthread_exit from a handler that interrupted a thread's blocking trapped open */
    {
        signal(SIGUSR2, h_pthread_exit);
        pthread_t t;
        void *r = 0;
        pthread_create(&t, 0, blocked_open, fifo);
        usleep(50000);
        pthread_kill(t, SIGUSR2);
        pthread_join(t, &r);
        printf("pthread_exit from a handler inside a blocking trap: %s\n", r == (void *)3 ? "joined" : "other");
        struct stat s2;
        printf("stat after it: %s\n", stat("/usr/share", &s2) == 0 ? "ok" : "failed");
    }
    unlink(fifo);
    return 0;
}
