/* tracer_exe.c — /proc/<pid>/exe of a traced process, read by its tracer and by another process (DESIGN.md 7.6): a
 * debugger learns what it debugs from the link at every exec, and natively it names the file the kernel exec'd.
 * usage: tracer_exe PROGRAM [ARGS...]; the child asks to be traced and execs PROGRAM, and at the stop after its exec
 * the tracer and a forked sibling that does not trace it read the link. Prints "tracer: TEXT", "other: TEXT" and the
 * child's end; exit 0 always. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static void show(const char *who, pid_t p)
{
    char link[64], text[4096];
    snprintf(link, sizeof link, "/proc/%d/exe", (int)p);
    ssize_t n = readlink(link, text, sizeof text - 1);
    if (n < 0) snprintf(text, sizeof text, "error %m");
    else text[n] = 0;
    printf("%s: %s\n", who, text);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    pid_t p = fork();
    if (p == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execv(argv[1], argv + 1);
        _exit(127);
    }
    int st;
    /* the stops before the exec's SIGTRAP are the exec's SIGSYS under the launcher (13 item 54): passed on */
    while (waitpid(p, &st, 0) == p && WIFSTOPPED(st) && WSTOPSIG(st) != SIGTRAP)
        ptrace(PTRACE_CONT, p, 0, WSTOPSIG(st));
    if (!WIFSTOPPED(st)) {
        printf("child ended before its exec stop: %#x\n", st);
        return 0;
    }
    show("tracer", p);
    pid_t o = fork();
    if (o == 0) {
        show("other", p);
        _exit(0);
    }
    waitpid(o, 0, 0);
    ptrace(PTRACE_CONT, p, 0, 0);
    while (waitpid(p, &st, 0) == p && WIFSTOPPED(st))
        ptrace(PTRACE_CONT, p, 0, WSTOPSIG(st) == SIGTRAP ? 0 : WSTOPSIG(st));
    printf("end: %s %d\n", WIFEXITED(st) ? "exited" : "signalled", WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st));
    return 0;
}
