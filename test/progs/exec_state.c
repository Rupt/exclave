/* exec_state.c — what a process keeps and loses across an exec (fs/exec.c's begin_new_exec, kernel/signal.c's
 * flush_signal_handlers; DESIGN.md 7.4.5, 17.4): the signal mask, ignored and handled dispositions, pending signals,
 * the alternate stack, interval timers, a POSIX timer, the umask, the working directory and root, nice, the CPU
 * affinity, the prctl settings exec keeps and clears, comm after PR_SET_NAME, and an exec made by a second thread
 * while the main thread lives, with the thread's own mask and pending signals and the main thread's. usage:
 * exec_state HOSTDIR; "exec_state --child LABEL" is the program it re-executes. Prints one line per case, "<case>:
 * <answer>", the same in every world, so the kernel under bwrap is the oracle. PR_GET_SECCOMP is left out: the
 * launcher's filter is its mechanism (7.4.2), bwrap installs none. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
static const char *yes_no(int b) { return b ? "yes" : "no"; }

static void on_term(int s) { (void)s; }

/* a field of /proc/self/status by its name */
static const char *status_field(const char *name)
{
    static char line[256];
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return "unreadable";
    size_t l = strlen(name);
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, name, l) && line[l] == ':') {
            fclose(f);
            char *s = line + l + 1;
            while (*s == ' ' || *s == '\t') s++;
            s[strcspn(s, "\n")] = 0;
            return s;
        }
    fclose(f);
    return "absent";
}

static const char *disp(int sig)
{
    struct sigaction sa;
    sigaction(sig, 0, &sa);
    return sa.sa_handler == SIG_IGN ? "SIG_IGN" : sa.sa_handler == SIG_DFL ? "SIG_DFL" : "handler";
}

static void report(const char *L, const char *hd, const char *timer_id)
{
    sigset_t m, pend;
    sigprocmask(SIG_BLOCK, 0, &m);
    sigpending(&pend);
    printf("%s SIGUSR1 blocked: %s\n", L, yes_no(sigismember(&m, SIGUSR1)));
    printf("%s SIGHUP blocked: %s\n", L, yes_no(sigismember(&m, SIGHUP)));
    printf("%s SIGSYS blocked: %s\n", L, yes_no(sigismember(&m, SIGSYS)));
    printf("%s SIGUSR1 pending: %s\n", L, yes_no(sigismember(&pend, SIGUSR1)));
    printf("%s SIGWINCH pending: %s\n", L, yes_no(sigismember(&pend, SIGWINCH)));
    printf("%s SIGALRM pending: %s\n", L, yes_no(sigismember(&pend, SIGALRM)));
    printf("%s SIGTTOU pending: %s\n", L, yes_no(sigismember(&pend, SIGTTOU)));
    printf("%s SigBlk: %s\n", L, status_field("SigBlk"));
    printf("%s SigPnd: %s\n", L, status_field("SigPnd"));
    printf("%s ShdPnd: %s\n", L, status_field("ShdPnd"));
    printf("%s SigIgn: %s\n", L, status_field("SigIgn"));
    printf("%s SigCgt: %s\n", L, status_field("SigCgt"));
    printf("%s SIGUSR2: %s\n", L, disp(SIGUSR2));
    printf("%s SIGTERM: %s\n", L, disp(SIGTERM));
    printf("%s SIGCHLD: %s\n", L, disp(SIGCHLD));
    printf("%s SIGSYS: %s\n", L, disp(SIGSYS));
    stack_t ss;
    sigaltstack(0, &ss);
    printf("%s altstack: %s\n", L, ss.ss_flags & SS_DISABLE ? "disabled" : "set");
    struct itimerval it;
    getitimer(ITIMER_REAL, &it);
    printf("%s ITIMER_REAL: %s\n", L, it.it_value.tv_sec || it.it_value.tv_usec ? "armed" : "off");
    getitimer(ITIMER_VIRTUAL, &it);
    printf("%s ITIMER_VIRTUAL: %s\n", L, it.it_value.tv_sec || it.it_value.tv_usec ? "armed" : "off");
    if (timer_id) {
        struct itimerspec ts;
        errno = 0;
        int r = timer_gettime((timer_t)(long)atoi(timer_id), &ts);
        printf("%s posix timer: %s\n", L, r == 0 ? "found" : errno == EINVAL ? "EINVAL" : strerror(errno));
    }
    mode_t u = umask(0);
    umask(u);
    printf("%s umask: %03o\n", L, u);
    char cwd[4096] = "";
    if (!getcwd(cwd, sizeof cwd)) strcpy(cwd, "?");
    printf("%s cwd is hostdir: %s\n", L, yes_no(!strcmp(cwd, hd)));
    char root[64] = "";
    ssize_t n = readlink("/proc/self/root", root, sizeof root - 1);
    root[n > 0 ? n : 0] = 0;
    printf("%s root: %s\n", L, root);
    const char *n0 = getenv("EXEC_STATE_NICE");
    printf("%s nice raised by 5: %s\n", L, n0 ? yes_no(getpriority(PRIO_PROCESS, 0) == atoi(n0) + 5) : "no parent");
    cpu_set_t cs;
    CPU_ZERO(&cs);
    sched_getaffinity(0, sizeof cs, &cs);
    printf("%s affinity one cpu: %s\n", L, yes_no(CPU_COUNT(&cs) == 1));
    printf("%s no_new_privs: %d\n", L, prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
    printf("%s dumpable: %d\n", L, prctl(PR_GET_DUMPABLE, 0, 0, 0, 0));
    int v = 0;
    prctl(PR_GET_CHILD_SUBREAPER, &v, 0, 0, 0);
    printf("%s child subreaper: %d\n", L, v);
    v = 0;
    prctl(PR_GET_PDEATHSIG, &v, 0, 0, 0);
    printf("%s pdeathsig: %d\n", L, v);
    printf("%s timerslack: %d\n", L, prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0));
    printf("%s thp disable: %d\n", L, prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0));
    printf("%s keepcaps: %d\n", L, prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0));
    v = prctl(65 /* PR_GET_MDWE */, 0, 0, 0, 0);
    printf("%s mdwe: %d\n", L, v);
    v = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0);
    printf("%s ssb: %d\n", L, v);
    char comm[32] = "";
    prctl(PR_GET_NAME, comm, 0, 0, 0);
    printf("%s PR_GET_NAME: %s\n", L, comm);
    printf("%s Threads: %s\n", L, status_field("Threads"));
    printf("%s tid is pid: %s\n", L, yes_no(syscall(SYS_gettid) == getpid()));
    printf("%s NoNewPrivs: %s\n", L, status_field("NoNewPrivs"));
}

static char self[4096], *hd;
static char *child_av[6];

/* the thread blocks SIGUSR1 and has SIGALRM pending for itself, then execs */
static void *thread(void *arg)
{
    (void)arg;
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    sigaddset(&s, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &s, 0);
    pthread_kill(pthread_self(), SIGALRM);
    execve(self, child_av, environ);
    perror("execve from thread");
    _exit(97);
}

static void run(const char *tag, void (*prep)(void), int from_thread, const char *timer_id)
{
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        if (prep) prep();
        char tg[64], ti[32];
        snprintf(tg, sizeof tg, "%s", tag);
        snprintf(ti, sizeof ti, "%s", timer_id ? timer_id : "");
        char *const av[] = {self, "--child", tg, hd, ti, 0};
        if (from_thread) {
            /* the main thread has SIGTTOU pending for itself and SIGWINCH for the process, then the thread execs */
            memcpy(child_av, av, sizeof child_av);
            sigset_t s;
            sigemptyset(&s);
            sigaddset(&s, SIGTTOU);
            sigaddset(&s, SIGWINCH);
            pthread_sigmask(SIG_BLOCK, &s, 0);
            pthread_kill(pthread_self(), SIGTTOU);
            kill(getpid(), SIGWINCH);
            pthread_t t;
            pthread_create(&t, 0, thread, 0);
            pause();
            _exit(96);
        }
        execve(self, av, environ);
        perror("execve");
        _exit(98);
    }
    int st = 0;
    waitpid(c, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st)) printf("%s: status %d signal %d\n", tag, WEXITSTATUS(st), WTERMSIG(st));
}

static timer_t tid;
static void setup(void)
{
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    sigaddset(&s, SIGHUP);
    sigaddset(&s, SIGSYS);
    sigaddset(&s, SIGWINCH);
    sigprocmask(SIG_BLOCK, &s, 0);
    raise(SIGUSR1);
    kill(getpid(), SIGWINCH);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, on_term);
    signal(SIGSYS, on_term);
    static char stk[65536];
    stack_t ss = {.ss_sp = stk, .ss_size = sizeof stk};
    sigaltstack(&ss, 0);
    struct itimerval it = {.it_value = {100, 0}};
    setitimer(ITIMER_REAL, &it, 0);
    setitimer(ITIMER_VIRTUAL, &it, 0);
    umask(027);
    if (chdir(hd)) perror(hd);
    char n0[16];
    snprintf(n0, sizeof n0, "%d", getpriority(PRIO_PROCESS, 0));
    setenv("EXEC_STATE_NICE", n0, 1);
    if (setpriority(PRIO_PROCESS, 0, atoi(n0) + 5)) perror("nice");
    /* the first CPU this process may run on, alone */
    cpu_set_t cs, one;
    CPU_ZERO(&cs);
    CPU_ZERO(&one);
    sched_getaffinity(0, sizeof cs, &cs);
    for (size_t i = 0; i < CPU_SETSIZE; i++)
        if (CPU_ISSET(i, &cs)) {
            CPU_SET(i, &one);
            break;
        }
    sched_setaffinity(0, sizeof one, &one);
    prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    prctl(PR_SET_PDEATHSIG, SIGHUP, 0, 0, 0);
    prctl(PR_SET_TIMERSLACK, 123456, 0, 0, 0);
    prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0);
    prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
    prctl(PR_SET_NAME, "renamed", 0, 0, 0);
}

int main(int argc, char **argv)
{
    if (argc >= 4 && !strcmp(argv[1], "--child")) {
        report(argv[2], argv[3], argc > 4 && argv[4][0] ? argv[4] : 0);
        return 0;
    }
    if (argc < 2) {
        fprintf(stderr, "usage: exec_state HOSTDIR\n");
        return 2;
    }
    hd = argv[1];
    /* whatever mask and dispositions the caller left (a nohup ignores SIGHUP): the cases below set their own */
    sigset_t none;
    sigemptyset(&none);
    sigprocmask(SIG_SETMASK, &none, 0);
    for (int sig = 1; sig < 32; sig++)
        if (sig != SIGKILL && sig != SIGSTOP) signal(sig, SIG_DFL);
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n < 0) {
        perror("readlink");
        return 2;
    }
    self[n] = 0;
    /* the program the cases exec: a copy in the host directory, which stays in sight after the chdir there (8.1) */
    {
        int i = open(self, O_RDONLY), o;
        snprintf(self, sizeof self, "%s/exec_state", hd);
        o = open(self, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        char b[65536];
        ssize_t r;
        if (i < 0 || o < 0) {
            perror("copy");
            return 2;
        }
        while ((r = read(i, b, sizeof b)) > 0)
            if (write(o, b, (size_t)r) != r) perror("copy");
        close(i);
        close(o);
    }
    report("plain", hd, 0);
    char id[32] = "";
    if (timer_create(CLOCK_MONOTONIC, 0, &tid) == 0) {
        struct itimerspec ts = {.it_value = {100, 0}};
        timer_settime(tid, 0, &ts, 0);
        snprintf(id, sizeof id, "%ld", (long)tid);
    }
    run("after", setup, 0, id);
    run("thread", 0, 1, 0);
    return 0;
}
