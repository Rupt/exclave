/* shstk.c — a CET-marked program under the launcher: whether glibc gave it a shadow stack, and the handler's paths on
 * it if so (DESIGN.md 13 item 49). Prints `shstk on` or `shstk off` from /proc/self/status, then one line per case:
 * a signal handler, a thread making trapped calls, setjmp and longjmp across trapped calls, a fork and exec. */
#define _GNU_SOURCE
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t got;
static void on_usr1(int s) { got = s; }
static void *worker(void *arg)
{
    struct stat st;
    long n = 0;
    for (int i = 0; i < 1000; i++) n += stat("/usr/bin", &st) == 0;
    *(long *)arg = n;
    return 0;
}
static jmp_buf jb;
static void jump(void)
{
    struct stat st;
    stat("/etc", &st);
    longjmp(jb, 1);
}
int main(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    int on = 0;
    while (f && fgets(line, sizeof line, f))
        if (!strncmp(line, "x86_Thread_features:", 20) && strstr(line, "shstk")) on = 1;
    if (f) fclose(f);
    printf("shstk %s\n", on ? "on" : "off");
    signal(SIGUSR1, on_usr1);
    raise(SIGUSR1);
    printf("signal %s\n", got == SIGUSR1 ? "ok" : "FAIL");
    pthread_t t;
    long n = 0;
    pthread_create(&t, 0, worker, &n);
    pthread_join(t, 0);
    printf("thread %s\n", n == 1000 ? "ok" : "FAIL");
    if (!setjmp(jb)) jump();
    struct stat st;
    printf("longjmp %s\n", stat("/usr/bin", &st) == 0 ? "ok" : "FAIL");
    pid_t p = fork();
    if (p == 0) {
        execl("/bin/true", "true", (char *)0);
        _exit(127);
    }
    int ws = 0;
    waitpid(p, &ws, 0);
    printf("exec %s\n", WIFEXITED(ws) && WEXITSTATUS(ws) == 0 ? "ok" : "FAIL");
    return 0;
}
