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
static long rss(void) { FILE *f = fopen("/proc/self/status", "r"); char l[256]; long v = -1; while (f && fgets(l, 256, f)) if (!strncmp(l, "VmRSS:", 6)) v = atol(l + 6); if (f) fclose(f); return v; }
static const char *TRUE = "/usr/bin/true";                 /* the tree's, by the test */
static int spawn_true(void) { pid_t p; char *av[] = { "true", 0 }; if (posix_spawn(&p, TRUE, 0, 0, av, environ)) return -1; int st; waitpid(p, &st, 0); return st; }
static void *w(void *a) { for (int i = 0; i < 25; i++) if (spawn_true()) return (void *)1; return 0; }

int main(int argc, char **argv)
{
    pid_t pid; int st; char cmd[4096];
    if (argc > 2) TRUE = argv[2];
    char *av[] = { "sh", "-c", "exit 7", 0 };
    if (posix_spawn(&pid, "/bin/sh", 0, 0, av, environ) || waitpid(pid, &st, 0) < 0 || WEXITSTATUS(st) != 7) { fails++; printf("FAIL posix_spawn sh -c\n"); }
    snprintf(cmd, sizeof cmd, "%s --version >/dev/null", argc > 1 ? argv[1] : "/usr/bin/x86_64-linux-gnu-gcc-13");   /* the can's gcc, by the test */
    if (system(cmd) != 0) { fails++; printf("FAIL system(gcc --version)\n"); }
    pthread_t t[8]; void *r;
    for (int i = 0; i < 8; i++) pthread_create(&t[i], 0, w, 0);
    for (int i = 0; i < 8; i++) { pthread_join(t[i], &r); if (r) { fails++; printf("FAIL spawning thread %d\n", i); } }
    for (int i = 0; i < 50; i++) spawn_true();
    long before = rss();
    for (int i = 0; i < 1000; i++) if (spawn_true()) { fails++; printf("FAIL spawn %d\n", i); break; }
    long after = rss();
    if (after - before > 4096) { fails++; printf("FAIL RSS grew %ld kB over 1000 spawns\n", after - before); }
    printf("rss before %ld kB after %ld kB\n", before, after);
    enum { N = 20000 }; static char *big[N + 3]; big[0] = "true"; for (int i = 1; i <= N; i++) big[i] = "argument-number-with-some-length"; big[N + 1] = 0;
    if (posix_spawn(&pid, TRUE, 0, 0, big, environ) || waitpid(pid, &st, 0) < 0 || st) { fails++; printf("FAIL large argv spawn\n"); }
    printf("spawn: %d failures\n", fails);
    return fails ? 1 : 0;
}
