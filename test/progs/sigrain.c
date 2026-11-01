/* sigrain.c — signals arriving during trapped syscalls (DESIGN.md 7.5.3, 17 item 4): a 1 ms timer raining on loops of
 * stat, open, readlink and execve of a missing file, with and without SA_RESTART, blocked, ignored, with a handler
 * that traps, one that siglongjmps out, kill from a child process and tgkill from a sibling thread in a tight loop;
 * the restart rules of pause, sigsuspend, ppoll, pselect and a blocking open; the mask inside a handler across its
 * own traps. Every answer is a call's result, never EINTR from a call that cannot block, never a corrupted errno.
 * usage: sigrain HOSTDIR. Prints one line per case, "<case>: <answer>", the same in every world where the kernel is
 * the oracle. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile long signals, handler_fails;
static char longpath[4096];

static long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void h_count(int s)
{
    (void)s;
    signals++;
}
static void h_trap(int s)
{
    struct stat st;
    (void)s;
    signals++;
    if (stat("/usr/share/exclave-test-marker", &st)) handler_fails++;
}
static sigjmp_buf env;
static void h_jump(int s)
{
    (void)s;
    signals++;
    siglongjmp(env, 1);
}
static void timer(long us)
{
    struct itimerval it = {{0, us}, {0, us}};
    setitimer(ITIMER_REAL, &it, 0);
}
static void install(void (*h)(int), int flags)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h;
    sa.sa_flags = flags;
    sigaction(SIGALRM, &sa, 0);
}

/* one trapped call; its result classified */
static int one(int which)
{
    struct stat st;
    char b[256];
    switch (which) {
    case 0: return stat("/usr/share/exclave-test-marker", &st) == 0 ? 0 : errno;
    case 1: {
        int fd = open("/usr/share/exclave-test-marker", O_RDONLY);
        if (fd < 0) return errno;
        close(fd);
        return 0;
    }
    case 2: return readlink(longpath, b, sizeof b) < 0 ? errno : 0;
    default: {
        char *av[] = {"missing", 0};
        execve("/usr/share/exclave-missing-program", av, av + 1);
        return errno == ENOENT ? 0 : errno;
    }
    }
}
static const char *const names[] = {"stat", "open", "readlink", "execve of a missing file"};

/* a loop of the call for 50 ms: how many answered as a call that cannot block must, EINTR, other */
static void rain(const char *mode, int which)
{
    long ok = 0, eintr = 0, other = 0, end = now_ms() + 50;
    signals = 0;
    while (now_ms() < end) {
        int e = one(which);
        if (e == 0) ok++;
        else if (e == EINTR) eintr++;
        else other++;
    }
    printf("%s under SIGALRM rain, %s: %s, %ld EINTR, %ld other\n", names[which], mode, ok ? "ok" : "none ok", eintr,
           other);
}

static volatile int inside_usr1, inside_usr2, inside_hup;
static void h_mask(int sig)
{
    (void)sig;
    struct stat st2;
    sigset_t hup, cur;
    sigemptyset(&hup);
    sigaddset(&hup, SIGHUP);
    sigprocmask(SIG_BLOCK, &hup, 0);
    stat("/usr/share", &st2);
    sigprocmask(SIG_BLOCK, 0, &cur);
    inside_usr1 = sigismember(&cur, SIGUSR1);
    inside_usr2 = sigismember(&cur, SIGUSR2);
    inside_hup = sigismember(&cur, SIGHUP);
}
static pid_t main_tid;
static volatile int stop;
static void *tgkiller(void *arg)
{
    (void)arg;
    while (!stop) syscall(SYS_tgkill, getpid(), main_tid, SIGUSR1);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    setvbuf(stdout, 0, _IOLBF, 0);
    /* a long host path to a symlink: HOSTDIR/<300 a's>/link -> target */
    char dir[4096];
    snprintf(dir, sizeof dir, "%s/%s", argv[1],
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
             "aaaaaaa"
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
             "aaaaaaa");
    mkdir(dir, 0755);
    snprintf(longpath, sizeof longpath, "%.4000s/link", dir);
    if (symlink("/usr/share/exclave-test-marker", longpath)) perror("symlink");
    char fifo[4096];
    snprintf(fifo, sizeof fifo, "%s/fifo", argv[1]);
    mkfifo(fifo, 0600);

    /* 1. the timer's handler: plain, SA_RESTART, trapping, the signal blocked, ignored */
    for (int which = 0; which < 4; which++) {
        install(h_count, 0);
        timer(1000);
        rain("handler", which);
        install(h_count, SA_RESTART);
        rain("SA_RESTART", which);
        install(h_trap, 0);
        rain("handler that traps", which);
        timer(0);
    }
    printf("the trapping handler's own traps: %ld failed\n", handler_fails);
    sigset_t s, o;
    sigemptyset(&s);
    sigaddset(&s, SIGALRM);
    install(h_count, 0);
    sigprocmask(SIG_BLOCK, &s, 0);
    timer(1000);
    rain("blocked", 0);
    long seen = signals;
    timer(0);
    signals = 0;
    sigprocmask(SIG_UNBLOCK, &s, 0);
    printf("blocked throughout: %ld delivered, then %ld on unblocking\n", seen, signals);
    signal(SIGALRM, SIG_IGN);
    timer(1000);
    rain("ignored", 0);
    timer(0);
    /* 2. a handler that siglongjmps out, 20 rounds, each a stat loop under a one-shot timer */
    install(h_jump, 0);
    int jumped = 0;
    for (int i = 0; i < 20; i++) {
        if (sigsetjmp(env, 1) == 0) {
            struct itimerval it = {{0, 0}, {0, 1000}};
            setitimer(ITIMER_REAL, &it, 0);
            struct stat st;
            long end = now_ms() + 500;
            while (now_ms() < end) stat("/usr/share/exclave-test-marker", &st);
        } else jumped++;
    }
    timer(0);
    struct stat st;
    printf("siglongjmp out of the handler: %d of 20 rounds jumped, stat after %s\n", jumped,
           stat("/usr/share", &st) == 0 ? "ok" : "failed");
    /* 3. kill from a child process in a tight loop, the handler trapping */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = h_trap;
        sigaction(SIGUSR1, &sa, 0);
        handler_fails = 0;
        pid_t me = getpid(), c = fork();
        if (c == 0) {
            long end = now_ms() + 100;
            while (now_ms() < end) kill(me, SIGUSR1);
            _exit(0);
        }
        long ok = 0, bad = 0, end = now_ms() + 100;
        signals = 0;
        while (now_ms() < end)
            for (int which = 0; which < 3; which++) {
                if (one(which) == 0) ok++;
                else bad++;
            }
        waitpid(c, 0, 0);
        printf("traps under kill from a child: %s, %ld wrong, handler traps %ld failed, signals %s\n",
               ok ? "ok" : "none", bad, handler_fails, signals ? "landed" : "none");
    }
    /* 4. tgkill from a sibling thread in a tight loop: a thread-directed signal pending at the trap itself */
    {
        main_tid = (pid_t)syscall(SYS_gettid);
        handler_fails = 0;
        signals = 0;
        pthread_t t;
        pthread_create(&t, 0, tgkiller, 0);
        long ok = 0, bad = 0, end = now_ms() + 100;
        while (now_ms() < end)
            for (int which = 0; which < 4; which++) {
                if (one(which) == 0) ok++;
                else bad++;
            }
        stop = 1;
        pthread_join(t, 0);
        printf("traps under tgkill from a thread: %s, %ld wrong, handler traps %ld failed, signals %s\n",
               ok ? "ok" : "none", bad, handler_fails, signals ? "landed" : "none");
        signal(SIGUSR1, SIG_DFL);
    }
    /* 5. the restart rules: pause, sigsuspend, ppoll, pselect never restart; a blocking open does under SA_RESTART */
    {
        install(h_count, SA_RESTART);
        struct itimerval it = {{0, 0}, {0, 10000}};
        setitimer(ITIMER_REAL, &it, 0);
        errno = 0;
        int r = pause();
        printf("pause under SA_RESTART: %s\n", r == -1 && errno == EINTR ? "EINTR" : "returned");
        sigset_t none;
        sigemptyset(&none);
        setitimer(ITIMER_REAL, &it, 0);
        errno = 0;
        r = sigsuspend(&none);
        printf("sigsuspend under SA_RESTART: %s\n", r == -1 && errno == EINTR ? "EINTR" : "returned");
        struct pollfd pf = {-1, 0, 0};
        struct timespec ts = {5, 0};
        setitimer(ITIMER_REAL, &it, 0);
        errno = 0;
        r = ppoll(&pf, 1, &ts, &none);
        printf("ppoll under SA_RESTART: %s\n", r == -1 && errno == EINTR ? "EINTR" : r == 0 ? "timed out" : "returned");
        ts.tv_sec = 5;
        setitimer(ITIMER_REAL, &it, 0);
        errno = 0;
        r = pselect(0, 0, 0, 0, &ts, &none);
        printf("pselect under SA_RESTART: %s\n", r == -1 && errno == EINTR ? "EINTR"
                                                 : r == 0                  ? "timed out"
                                                                           : "returned");
        for (int restart = 1; restart >= 0; restart--) {
            install(h_count, restart ? SA_RESTART : 0);
            pid_t c = fork();
            if (c == 0) {
                usleep(100000);
                int w = open(fifo, O_WRONLY);
                if (w >= 0) close(w);
                _exit(0);
            }
            setitimer(ITIMER_REAL, &it, 0);
            errno = 0;
            int fd = open(fifo, O_RDONLY);
            int e = errno;
            printf("open of a FIFO %s: %s\n", restart ? "under SA_RESTART" : "without SA_RESTART",
                   fd >= 0 ? "ok" : strerror(e));
            /* a reader for the child's open, which has not happened yet after EINTR */
            int r2 = fd >= 0 ? -1 : open(fifo, O_RDONLY | O_NONBLOCK);
            waitpid(c, 0, 0);
            if (fd >= 0) close(fd);
            if (r2 >= 0) close(r2);
        }
    }
    /* 6. the mask inside a handler across its own traps: USR1 and sa_mask's USR2 blocked, HUP after a sigprocmask in
     * the handler, none of them after it returns */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = h_mask;
        sigaddset(&sa.sa_mask, SIGUSR2);
        sigaction(SIGUSR1, &sa, 0);
        raise(SIGUSR1);
        sigprocmask(SIG_BLOCK, 0, &o);
        printf("mask inside the handler after its traps: USR1 %s, USR2 %s, HUP %s\n", inside_usr1 ? "yes" : "no",
               inside_usr2 ? "yes" : "no", inside_hup ? "yes" : "no");
        printf("mask after the handler: USR1 %s, USR2 %s, HUP %s\n", sigismember(&o, SIGUSR1) ? "yes" : "no",
               sigismember(&o, SIGUSR2) ? "yes" : "no", sigismember(&o, SIGHUP) ? "yes" : "no");
    }
    /* 7. a path that faults: in a file mapping past its end, where a load takes SIGBUS, and one that runs off the end
     * of a mapping; the kernel's copy answers EFAULT and no signal is delivered */
    {
        char f[4096];
        snprintf(f, sizeof f, "%s/short", argv[1]);
        int fd = open(f, O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0 && write(fd, "/", 1) == 1) {
            char *m = mmap(0, 8192, PROT_READ, MAP_PRIVATE, fd, 0);
            if (m != MAP_FAILED) {
                errno = 0;
                int r = stat(m + 4096, &st);
                printf("stat with a path in a file mapping past its end: %s\n", r ? strerror(errno) : "ok");
                /* the page's last byte is a slash and the next page cannot be read */
                char *m2 = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (m2 != MAP_FAILED) {
                    memset(m2, '/', 4096);
                    mprotect(m2 + 4096, 4096, PROT_NONE);
                    errno = 0;
                    r = stat(m2 + 4000, &st);
                    printf("stat with a path running off its mapping: %s\n", r ? strerror(errno) : "ok");
                    munmap(m2, 8192);
                }
                munmap(m, 8192);
            }
            close(fd);
            unlink(f);
        }
    }
    unlink(fifo);
    unlink(longpath);
    rmdir(dir);
    return 0;
}
