/* traceme.c — a child that asks to be traced and then execs, as gdb and strace start their inferior (DESIGN.md 7.4.5,
 * 13 item 54): by vfork, as gdb's fork_inferior does, and by fork. A traced task's trapped execve stops for its tracer
 * at the SIGSYS, before the launcher's handler runs, so a vfork child's PTRACE_TRACEME waits for its exec; a fork
 * child's does not, and its tracer's first stop after the exec is that SIGSYS. usage: traceme [PROGRAM], by default
 * /usr/bin/true. Prints one line per case, "<case>: <answer>": a wait status, "hang" when the tracer still waits
 * after five seconds, the answers of the requests, or the count of exec stops, which the launcher's second exec under a
 * debugger's start makes one more (7.6). Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char true_path[] = "/usr/bin/true", *prog = true_path;
static char sh_path[] = "/bin/sh", sh_c[] = "-c", sh_cmd[4096];
static volatile long r1, r2;
static volatile int e2;

/* the names of the signals a tracer meets here, spelt as glibc's sigabbrev_np spells them, which musl lacks */
static const char *sig_name(int s)
{
    static char num[16];
    if (s == SIGTRAP) return "TRAP";
    if (s == SIGSYS) return "SYS";
    if (s == SIGSTOP) return "STOP";
    if (s == SIGKILL) return "KILL";
    snprintf(num, sizeof num, "%d", s);
    return num;
}

static void describe(const char *name, int st)
{
    if (WIFSTOPPED(st)) printf("%s: stopped %s\n", name, sig_name(WSTOPSIG(st)));
    else if (WIFEXITED(st)) printf("%s: exited %d\n", name, WEXITSTATUS(st));
    else printf("%s: signalled %s\n", name, sig_name(WTERMSIG(st)));
}

/* the child's part: 0 the plain request and exec, 1 a second request, 2 a failed exec first, 3 no exec at all, 4 a
 * stop of its own before the exec, 5 no request, 6 the request and an exec of sh -c "exec PROGRAM", as gdb starts its
 * program through a shell */
static void child(int how)
{
    char *av[] = {prog, 0};
    if (how != 5) r1 = ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (how == 1) {
        r2 = ptrace(PTRACE_TRACEME, 0, 0, 0);
        e2 = errno;
    }
    if (how == 2) execv("/nonexistent/traceme", av);
    if (how == 3) _exit(7);
    /* kill rather than raise: musl's raise blocks signals around its tkill, a trapped rt_sigprocmask whose SIGSYS
     * would stop a traced child before its SIGSTOP */
    if (how == 4) kill(getpid(), SIGSTOP);
    if (how == 6) {
        char *sv[] = {sh_path, sh_c, sh_cmd, 0};
        execv(sh_path, sv);
    }
    execv(prog, av);
    _exit(127);
}

/* the tracer: starts the child, reports its first stop, and the one after a SIGSTOP of its own, then lets it run to
 * its end, passing every signal but the exec's SIGTRAP and that SIGSTOP; the stops after the exec are the program's,
 * under the launcher every trapped call's SIGSYS. With count, it reports the SIGTRAP stops, one per exec */
static int tracer(const char *name, int use_vfork, int how, int count)
{
    char label[96];
    pid_t p = use_vfork ? vfork() : fork();
    if (p == 0) child(how);
    if (how == 1)
        printf("%s requests: %ld, %ld %s\n", name, r1, r2, r2 < 0 ? (e2 == EPERM ? "EPERM" : strerror(e2)) : "-");
    int st, n = 0, shown = 1, traps = 0;
    waitpid(p, &st, 0);
    for (; WIFSTOPPED(st); n++) {
        if (n < shown) {
            /* past a stop of the child's own, the one the exec makes */
            if (WSTOPSIG(st) == SIGSTOP) shown++;
            snprintf(label, sizeof label, "%s %s stop", name, n ? "second" : "first");
            describe(label, st);
        }
        traps += WSTOPSIG(st) == SIGTRAP;
        int sig = WSTOPSIG(st) == SIGTRAP || WSTOPSIG(st) == SIGSTOP ? 0 : WSTOPSIG(st);
        ptrace(PTRACE_CONT, p, 0, sig);
        waitpid(p, &st, 0);
    }
    if (count) printf("%s exec stops: %d\n", name, traps);
    snprintf(label, sizeof label, "%s end", name);
    describe(label, st);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct {
        const char *name;
        int vfork, how, count;
    } cases[] = {
        {"vfork-traceme-exec", 1, 0, 1},
        {"vfork-traceme-twice", 1, 1, 0},
        {"vfork-traceme-fail-exec", 1, 2, 0},
        {"vfork-traceme-exit", 1, 3, 0},
        {"vfork-exec", 1, 5, 0},
        {"vfork-traceme-shell", 1, 6, 1},
        {"fork-traceme-exec", 0, 0, 0},
        {"fork-traceme-stop-exec", 0, 4, 0},
    };
    if (argc > 1) prog = argv[1];
    snprintf(sh_cmd, sizeof sh_cmd, "exec %s", prog);
    setvbuf(stdout, 0, _IONBF, 0);
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        pid_t t = fork();
        if (t == 0) _exit(tracer(cases[i].name, cases[i].vfork, cases[i].how, cases[i].count));
        int st = 0, done = 0;
        for (int k = 0; k < 50 && !done; k++) {
            done = waitpid(t, &st, WNOHANG) == t;
            if (!done) nanosleep(&(struct timespec){0, 100000000}, 0);
        }
        if (!done) {
            printf("%s: hang\n", cases[i].name);
            kill(t, SIGKILL);
            waitpid(t, &st, 0);
        }
    }
    return 0;
}
