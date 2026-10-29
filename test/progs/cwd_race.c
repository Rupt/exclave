/* cwd_race.c — relative lookups from the working directory while another thread changes it (DESIGN.md 13 item 14).
 * Four threads stat and open "x" relative to the working directory, a million lookups in all, while one thread
 * either changes directory between two that both hold x (chdir), or renames the working directory's parent back and
 * forth (rename). The kernel resolves each lookup from the directory itself, so none fails in either case; the
 * launcher reads the directory's name and walks it from the root, so a rename meanwhile can fail one. Each case stops
 * at its count or after SECONDS, whichever comes first, so that an emulated machine finishes in time. Prints one line
 * per case, `CASE ok` or `CASE F of N failed (R per million)`. argv[1]: a writable host directory. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define WORKERS 4
#define LOOKUPS 250000 /* per worker */
#define SECONDS 15

static int stop; /* the compiler's atomic builtins: no header, which a pruned fixture may lack */
static long failed, done;
static double end;

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}
static char p[4096], p2[4096 + 8], a[4096 + 16], b[4096 + 16];

static void *worker(void *arg)
{
    (void)arg;
    long f = 0, i = 0;
    for (; i < LOOKUPS && ((i & 1023) || now() < end); i++) {
        struct stat st;
        if (i & 1) {
            int fd = open("x", O_RDONLY | O_CLOEXEC);
            if (fd < 0) f++;
            else close(fd);
        } else if (stat("x", &st)) f++;
    }
    __atomic_fetch_add(&failed, f, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&done, i, __ATOMIC_SEQ_CST);
    return 0;
}

static void *changer(void *arg)
{
    int renaming = *(int *)arg;
    for (long i = 0; !__atomic_load_n(&stop, __ATOMIC_SEQ_CST); i++) {
        if (renaming) {
            if (rename(i & 1 ? p2 : p, i & 1 ? p : p2)) {
                printf("FAIL rename: %s\n", strerror(errno));
                return 0;
            }
        } else if (chdir(i & 1 ? a : b)) {
            printf("FAIL chdir: %s\n", strerror(errno));
            return 0;
        }
    }
    /* the parent back at its own name, for the cleanup */
    if (renaming && access(p, F_OK)) rename(p2, p);
    return 0;
}

static int run(const char *name, int renaming)
{
    if (chdir(a)) {
        printf("FAIL chdir %s: %s\n", a, strerror(errno));
        return 1;
    }
    __atomic_store_n(&stop, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&failed, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&done, 0, __ATOMIC_SEQ_CST);
    end = now() + SECONDS;
    pthread_t c, w[WORKERS];
    if (pthread_create(&c, 0, changer, &renaming)) return 1;
    for (int i = 0; i < WORKERS; i++)
        if (pthread_create(&w[i], 0, worker, 0)) return 1;
    for (int i = 0; i < WORKERS; i++) pthread_join(w[i], 0);
    __atomic_store_n(&stop, 1, __ATOMIC_SEQ_CST);
    pthread_join(c, 0);
    long n = __atomic_load_n(&done, __ATOMIC_SEQ_CST), f = __atomic_load_n(&failed, __ATOMIC_SEQ_CST);
    if (f) printf("%s %ld of %ld failed (%ld per million)\n", name, f, n, f * 1000000 / n);
    else printf("%s ok\n", name);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("FAIL usage: cwd_race DIR\n");
        return 1;
    }
    snprintf(p, sizeof p, "%s/cwd-race-%d", argv[1], (int)getpid());
    snprintf(p2, sizeof p2, "%s.moved", p);
    snprintf(a, sizeof a, "%s/a", p);
    snprintf(b, sizeof b, "%s/b", p);
    if (mkdir(p, 0755) || mkdir(a, 0755) || mkdir(b, 0755)) {
        printf("FAIL mkdir: %s\n", strerror(errno));
        return 1;
    }
    for (int i = 0; i < 2; i++) {
        char x[4096 + 32];
        snprintf(x, sizeof x, "%s/x", i ? b : a);
        int fd = open(x, O_WRONLY | O_CREAT, 0644);
        if (fd < 0) {
            printf("FAIL create: %s\n", strerror(errno));
            return 1;
        }
        close(fd);
    }
    int r = run("chdir", 0) | run("rename", 1);
    if (chdir("/")) return 1;
    for (int i = 0; i < 2; i++) {
        char x[4096 + 32];
        snprintf(x, sizeof x, "%s/x", i ? b : a);
        unlink(x);
    }
    rmdir(a);
    rmdir(b);
    rmdir(p);
    return r;
}
