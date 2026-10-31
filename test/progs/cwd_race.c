/* cwd_race.c — relative creates while another thread changes the working directory between the host's and the
 * exclave's (DESIGN.md 8.2, 13 item 14). One thread changes directory back and forth between HOSTDIR and /usr/share
 * while four create "cwdrace-x" relative to the working directory. Each create resolves against one directory or the
 * other, so it succeeds or answers EROFS, and the tree is never written: a lookup re-issued relative to the working
 * directory as given, which the kernel would resolve against whichever directory is current by then, writes
 * /usr/share/cwdrace-x into the tree. The creates stop once both answers have been seen COUNT times, or after
 * SECONDS, so that an emulated machine finishes in time. usage: cwd_race HOSTDIR. Prints FAIL lines and then
 * `C created, R refused, O other`; exit 1 on any FAIL. */
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
#define COUNT 1000
#define SECONDS 10

static const char *host;
static int stop, started; /* the compiler's atomic builtins: no header, which a pruned fixture may lack */
static long created, refused, other, first_errno;
static double end;

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void *changer(void *arg)
{
    (void)arg;
    for (long i = 0; !__atomic_load_n(&stop, __ATOMIC_SEQ_CST); i++) {
        if (chdir(i & 1 ? "/usr/share" : host)) {
            printf("FAIL chdir: %s\n", strerror(errno));
            exit(1);
        }
        __atomic_store_n(&started, 1, __ATOMIC_SEQ_CST);
    }
    return 0;
}

static void *worker(void *arg)
{
    (void)arg;
    while (!__atomic_load_n(&started, __ATOMIC_SEQ_CST)) {}
    for (long i = 0; !__atomic_load_n(&stop, __ATOMIC_SEQ_CST); i++) {
        int fd = open("cwdrace-x", O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
        if (fd >= 0) {
            close(fd);
            __atomic_fetch_add(&created, 1, __ATOMIC_SEQ_CST);
        } else if (errno == EROFS) __atomic_fetch_add(&refused, 1, __ATOMIC_SEQ_CST);
        else {
            long e = errno;
            if (__atomic_fetch_add(&other, 1, __ATOMIC_SEQ_CST) == 0) first_errno = e;
        }
        if ((__atomic_load_n(&created, __ATOMIC_SEQ_CST) >= COUNT &&
             __atomic_load_n(&refused, __ATOMIC_SEQ_CST) >= COUNT) ||
            ((i & 63) == 0 && now() > end))
            __atomic_store_n(&stop, 1, __ATOMIC_SEQ_CST);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("FAIL usage: cwd_race HOSTDIR\n");
        return 1;
    }
    host = argv[1];
    end = now() + SECONDS;
    pthread_t c, w[WORKERS];
    if (pthread_create(&c, 0, changer, 0)) return 1;
    for (int i = 0; i < WORKERS; i++)
        if (pthread_create(&w[i], 0, worker, 0)) return 1;
    for (int i = 0; i < WORKERS; i++) pthread_join(w[i], 0);
    pthread_join(c, 0);
    int fails = 0;
    if (other)
        fails++, printf("FAIL %ld creates answered neither success nor EROFS, the first %s\n", other,
                        strerror((int)first_errno));
    if (created < COUNT || refused < COUNT)
        fails++, printf("FAIL in %d s, fewer than %d of each answer: the race was not run\n", SECONDS, COUNT);
    struct stat st;
    int r = stat("/usr/share/cwdrace-x", &st), e = errno;
    if (r == 0) fails++, printf("FAIL /usr/share/cwdrace-x was created in the tree\n");
    else if (e != ENOENT) fails++, printf("FAIL stat /usr/share/cwdrace-x: %s\n", strerror(e));
    char x[4096 + 16];
    snprintf(x, sizeof x, "%s/cwdrace-x", host);
    unlink(x);
    printf("%ld created, %ld refused, %ld other\n", created, refused, other);
    return fails ? 1 : 0;
}
