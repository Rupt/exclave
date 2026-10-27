/* spawn.c — posix_spawn (clone3 refused, vfork path), system(), threads spawning, many spawns without RSS growth,
 * a large argv. Prints FAIL lines; exit 1 on any. */
#define _GNU_SOURCE
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
static int fails;
static long rss(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char l[256];
    long v = -1;
    while (f && fgets(l, 256, f))
        if (!strncmp(l, "VmRSS:", 6)) v = atol(l + 6);
    if (f) fclose(f);
    return v;
}
static const char *TRUE = "/usr/bin/true";                 /* the tree's, by the test */
/* 0, a wait status, or 0x10000 plus posix_spawn's error, so that a failure says which */
static int spawn_true(void)
{
    pid_t p;
    char *av[] = {"true", 0};
    int e = posix_spawn(&p, TRUE, 0, 0, av, environ);
    if (e) return 0x10000 | e;
    int st;
    waitpid(p, &st, 0);
    return st;
}
static void *w(void *a)
{
    (void)a;
    for (int i = 0; i < 25; i++) {
        int r = spawn_true();
        if (r) return (void *)(long)r;
    }
    return 0;
}

int main(int argc, char **argv)
{
    pid_t pid;
    int st;
    char cmd[4096];
    if (argc > 2) TRUE = argv[2];
    char *av[] = {"sh", "-c", "exit 7", 0};
    if (posix_spawn(&pid, "/bin/sh", 0, 0, av, environ) || waitpid(pid, &st, 0) < 0 || WEXITSTATUS(st) != 7) {
        fails++;
        printf("FAIL posix_spawn sh -c\n");
    }
    /* the exclave's gcc, by the test */
    snprintf(cmd, sizeof cmd, "%s --version >/dev/null", argc > 1 ? argv[1] : "/usr/bin/x86_64-linux-gnu-gcc-13");
    if (system(cmd) != 0) {
        fails++;
        printf("FAIL system(gcc --version)\n");
    }
    pthread_t t[8];
    void *r;
    for (int i = 0; i < 8; i++) pthread_create(&t[i], 0, w, 0);
    for (int i = 0; i < 8; i++) {
        pthread_join(t[i], &r);
        if (r) {
            long v = (long)r;
            fails++;
            printf("FAIL spawning thread %d: %s %ld\n", i, v & 0x10000 ? "posix_spawn error" : "wait status",
                   v & 0xffff);
        }
    }
    for (int i = 0; i < 50; i++) spawn_true();
    long before = rss();
    for (int i = 0; i < 1000; i++)
        if (spawn_true()) {
            fails++;
            printf("FAIL spawn %d\n", i);
            break;
        }
    long after = rss();
    if (after - before > 4096) {
        fails++;
        printf("FAIL RSS grew %ld kB over 1000 spawns\n", after - before);
    }
    printf("rss before %ld kB after %ld kB\n", before, after);
    enum { N = 20000 };
    static char *big[N + 3];
    big[0] = "true";
    for (int i = 1; i <= N; i++) big[i] = "argument-number-with-some-length";
    big[N + 1] = 0;
    if (posix_spawn(&pid, TRUE, 0, 0, big, environ) || waitpid(pid, &st, 0) < 0 || st) {
        fails++;
        printf("FAIL large argv spawn\n");
    }
    printf("spawn: %d failures\n", fails);
    return fails ? 1 : 0;
}
