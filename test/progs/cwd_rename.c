/* cwd_rename.c — the exerciser of DESIGN.md 13 item 14: relative lookups from the working directory while another
 * thread renames its parent back and forth. Four threads stat and open "x" relative to the working directory, a
 * million lookups in all or SECONDS, whichever comes first. The kernel resolves each lookup from the directory itself,
 * so none fails; the launcher reads the directory's name and walks it, so a rename meanwhile can fail one. Run in both
 * worlds by scripts/exercise --exclave EXCLAVE test/progs/cwd_rename.c HOSTDIR; prints one line, `rename: ok` or
 * `rename: F of N failed (R per million)`. */
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
#define SECONDS 10

static int stop;
static long failed, done;
static double end;
static char p[4096], p2[4096 + 8], a[4096 + 16];

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

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

static void *renamer(void *arg)
{
    (void)arg;
    for (long i = 0; !__atomic_load_n(&stop, __ATOMIC_SEQ_CST); i++)
        if (rename(i & 1 ? p2 : p, i & 1 ? p : p2)) {
            printf("FAIL rename: %s\n", strerror(errno));
            return 0;
        }
    /* the parent back at its own name, for the cleanup */
    if (access(p, F_OK)) rename(p2, p);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("FAIL usage: cwd_rename DIR\n");
        return 1;
    }
    snprintf(p, sizeof p, "%s/cwd-rename-%d", argv[1], (int)getpid());
    snprintf(p2, sizeof p2, "%s.moved", p);
    snprintf(a, sizeof a, "%s/a", p);
    char x[4096 + 32];
    snprintf(x, sizeof x, "%s/x", a);
    int fd;
    if (mkdir(p, 0755) || mkdir(a, 0755) || (fd = open(x, O_WRONLY | O_CREAT, 0644)) < 0) {
        printf("FAIL setup: %s\n", strerror(errno));
        return 1;
    }
    close(fd);
    if (chdir(a)) {
        printf("FAIL chdir %s: %s\n", a, strerror(errno));
        return 1;
    }
    end = now() + SECONDS;
    pthread_t c, w[WORKERS];
    if (pthread_create(&c, 0, renamer, 0)) return 1;
    for (int i = 0; i < WORKERS; i++)
        if (pthread_create(&w[i], 0, worker, 0)) return 1;
    for (int i = 0; i < WORKERS; i++) pthread_join(w[i], 0);
    __atomic_store_n(&stop, 1, __ATOMIC_SEQ_CST);
    pthread_join(c, 0);
    if (failed) printf("rename: %ld of %ld failed (%ld per million)\n", failed, done, failed * 1000000 / done);
    else printf("rename: ok\n");
    if (chdir("/")) return 1;
    unlink(x);
    rmdir(a);
    rmdir(p);
    return 0;
}
