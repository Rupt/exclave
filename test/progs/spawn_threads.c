/* spawn_threads.c — the handler under concurrency (PROPOSAL.md 7.5.4, 17.4): threads trapping while another thread
 * posix_spawns, so a vfork child's handler runs beside the parent's and the copies from program memory must stay each
 * thread's own; and a forked child whose traps nest, a timer's handler trapping inside a trapped stat, while every
 * chunk the pool had is held by threads blocked in the parent, so that the child's pool must grow under nesting.
 * usage: spawn_threads HOSTDIR PROGRAM (a program to spawn, the can's true). Prints one line per part; exit 0 when
 * both pass. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static volatile int stop, fails;
static char exe[4096];

static void *trapper(void *arg)
{
    struct stat st; char b[4096];
    while (!stop) {
        if (stat("/usr/share/cont-test-marker", &st)) { __sync_fetch_and_add(&fails, 1); continue; }
        long n = readlink("/proc/self/exe", b, sizeof b - 1);
        if (n < 0 || (size_t)n != strlen(exe) || memcmp(b, exe, (size_t)n)) __sync_fetch_and_add(&fails, 1);
    }
    return arg;
}

static volatile long ticks;
static void on_alarm(int sig) { struct stat st; (void)sig; if (stat("/usr/share", &st) == 0) ticks++; }   /* a trap inside whatever trap the timer interrupted */

static void *blocker(void *arg)                                /* holds a chunk: blocked inside the handler's re-issued open of a FIFO */
{
    int fd = open((const char *)arg, O_RDONLY);
    if (fd >= 0) close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: spawn_threads HOSTDIR PROGRAM\n"); return 2; }
    const char *host = argv[1], *prog = argv[2];
    long n = readlink("/proc/self/exe", exe, sizeof exe - 1); exe[n > 0 ? n : 0] = 0;
    /* part 1: four threads trapping throughout 200 spawns from the main thread */
    pthread_t t[4];
    for (int i = 0; i < 4; i++) pthread_create(&t[i], 0, trapper, 0);
    int spawned = 0;
    for (int i = 0; i < 200; i++) {
        pid_t pid; char *av[] = { (char *)prog, 0 };
        if (posix_spawn(&pid, prog, 0, 0, av, environ) == 0) { int st; waitpid(pid, &st, 0); spawned++; }
    }
    stop = 1;
    for (int i = 0; i < 4; i++) pthread_join(t[i], 0);
    printf("spawns beside trapping threads: %d spawned, %d failures\n", spawned, fails);
    /* part 2: eight threads hold chunks in a FIFO open; a forked child traps with a 1 ms timer whose handler traps too */
    char fifo[4096]; snprintf(fifo, sizeof fifo, "%s/fifo", host); unlink(fifo);
    if (mkfifo(fifo, 0600)) { perror("mkfifo"); return 1; }
    pthread_t b[8];
    for (int i = 0; i < 8; i++) pthread_create(&b[i], 0, blocker, fifo);
    usleep(100000);                                            /* the blockers are inside their traps */
    pid_t c = fork();
    if (c == 0) {
        signal(SIGALRM, on_alarm);
        struct itimerval it = { { 0, 1000 }, { 0, 1000 } }; setitimer(ITIMER_REAL, &it, 0);
        struct stat st; int bad = 0;
        for (int i = 0; i < 200000; i++) if (stat("/usr/share/cont-test-marker", &st)) bad++;
        it.it_value.tv_sec = it.it_value.tv_usec = 0; setitimer(ITIMER_REAL, &it, 0);
        _exit(bad ? 1 : ticks ? 0 : 3);
    }
    int st = -1;
    for (int i = 0; i < 300; i++) { if (waitpid(c, &st, WNOHANG) == c) break; usleep(100000); }   /* 30 s: a hang is a failure, not a stall */
    if (!WIFEXITED(st)) { kill(c, SIGKILL); waitpid(c, 0, 0); }
    int w = open(fifo, O_WRONLY | O_NONBLOCK); if (w >= 0) close(w);   /* releases the blockers */
    for (int i = 0; i < 8; i++) pthread_join(b[i], 0);
    unlink(fifo);
    printf("nested traps in a forked child while the pool is held: %s\n", WIFEXITED(st) && WEXITSTATUS(st) == 0 ? "ok" : WIFEXITED(st) && WEXITSTATUS(st) == 3 ? "no timer trap landed" : WIFEXITED(st) ? "a stat failed" : "hung");
    return fails == 0 && WIFEXITED(st) && WEXITSTATUS(st) != 1 && WEXITSTATUS(st) != 2 && (WEXITSTATUS(st) == 0 || WEXITSTATUS(st) == 3) ? 0 : 1;
}
