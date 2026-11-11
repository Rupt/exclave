/* top_reach.c — the first path into a top-level directory (8.1 rule 1): whose the directory is must not depend on
 * who asks first, how many ask at once, or whether a descriptor is free when they do.
 *
 *   top_reach race ROUNDS PATH...    each round, in a fresh child, which no path has yet led anywhere: two threads
 *                                    for each PATH, released together, ask access(PATH, F_OK); every other round
 *                                    a vfork child asks first and its parent after it. One line for each PATH and
 *                                    kind, the answers seen: one answer when all agree.
 *   top_reach limit A B FILE         with the soft descriptor limit full, a path under A, a top-level directory no
 *                                    path has reached; with the hard limit full, one under B, another such, twice,
 *                                    the path under A again, FILE by its path and fstatvfs of standard input; then
 *                                    with a descriptor freed, the same three.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_PATHS 16
enum { OK, NOENT, OTHER, KINDS };
/* shared with every child: the answers seen for each path, by threads and around a vfork */
struct seen {
    int threads[MAX_PATHS][KINDS], vfork[MAX_PATHS][KINDS];
    int other_errno;
};
static struct seen *seen;
static char **paths;
static int npaths;
static pthread_barrier_t gate;

static const char *name(int e)
{
    static char b[32];
    switch (e) {
    case 0: return "ok";
    case ENOENT: return "ENOENT";
    case EMFILE: return "EMFILE";
    case ENFILE: return "ENFILE";
    case EROFS: return "EROFS";
    case EACCES: return "EACCES";
    case ENOTDIR: return "ENOTDIR";
    default: snprintf(b, sizeof b, "errno %d", e); return b;
    }
}
static int ask(const char *p) { return access(p, F_OK) == 0 ? 0 : errno; }
static void note(int (*t)[KINDS], int k, int e)
{
    int kind = e == 0 ? OK : e == ENOENT ? NOENT : OTHER;
    __sync_fetch_and_add(&t[k][kind], 1);
    if (kind == OTHER) seen->other_errno = e;
}
static void *racer(void *arg)
{
    int k = (int)(long)arg % npaths;
    pthread_barrier_wait(&gate);
    note(seen->threads, k, ask(paths[k]));
    return 0;
}
static void line(const char *what, const char *p, const int *c)
{
    if (c[OK] && !c[NOENT] && !c[OTHER]) printf("%s %s: ok\n", what, p);
    else if (c[NOENT] && !c[OK] && !c[OTHER]) printf("%s %s: ENOENT\n", what, p);
    else if (!c[OK] && !c[NOENT] && !c[OTHER]) printf("%s %s: not asked\n", what, p);
    else
        printf("%s %s: ok %d, ENOENT %d, other %d (%s)\n", what, p, c[OK], c[NOENT], c[OTHER], name(seen->other_errno));
}

static int race(int rounds)
{
    seen = mmap(0, sizeof *seen, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (seen == MAP_FAILED) return 2;
    for (int r = 0; r < rounds; r++) {
        pid_t pid = fork();
        if (pid < 0) return 2;
        if (pid == 0) {
            if (r & 1) {
                /* a vfork child asks first, in its parent's memory, and the parent after it */
                for (int k = 0; k < npaths; k++) {
                    pid_t v = vfork();
                    if (v == 0) {
                        note(seen->vfork, k, ask(paths[k]));
                        _exit(0);
                    }
                    if (v > 0) waitpid(v, 0, 0);
                    note(seen->vfork, k, ask(paths[k]));
                }
                _exit(0);
            }
            int n = 2 * npaths;
            pthread_t th[2 * MAX_PATHS];
            pthread_attr_t at;
            pthread_attr_init(&at);
            pthread_attr_setstacksize(&at, 128 * 1024);
            pthread_barrier_init(&gate, 0, (unsigned)n);
            for (int i = 0; i < n; i++)
                if (pthread_create(&th[i], &at, racer, (void *)(long)i)) _exit(3);
            for (int i = 0; i < n; i++) pthread_join(th[i], 0);
            _exit(0);
        }
        int st;
        if (waitpid(pid, &st, 0) < 0 || !WIFEXITED(st) || WEXITSTATUS(st)) {
            printf("round %d: the child failed, status %d\n", r, st);
            return 1;
        }
    }
    for (int k = 0; k < npaths; k++) line("threads", paths[k], seen->threads[k]);
    for (int k = 0; k < npaths; k++) line("vfork", paths[k], seen->vfork[k]);
    return 0;
}

static const char *readonly(int fd)
{
    struct statvfs sf;
    if (fstatvfs(fd, &sf) < 0) return name(errno);
    return (sf.f_flag & ST_RDONLY) ? "yes" : "no";
}
static int limit(const char *a, const char *b, const char *file)
{
    /* descriptors 0, 1 and 2 are open and nothing else: a limit of 3 leaves no number free */
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) < 0) return 2;
    rl.rlim_cur = 3;
    if (setrlimit(RLIMIT_NOFILE, &rl) < 0) return 2;
    printf("soft limit full, a path under the first: %s\n", name(ask(a)));
    getrlimit(RLIMIT_NOFILE, &rl);
    printf("soft limit after: %lu\n", (unsigned long)rl.rlim_cur);
    rl.rlim_max = 3;
    if (setrlimit(RLIMIT_NOFILE, &rl) < 0) return 2;
    printf("hard limit full, a path under the second: %s\n", name(ask(b)));
    printf("hard limit full, the same again: %s\n", name(ask(b)));
    printf("hard limit full, the path under the first: %s\n", name(ask(a)));
    printf("hard limit full, the file by its path: %s\n", name(ask(file)));
    printf("hard limit full, standard input's filesystem read-only: %s\n", readonly(0));
    fflush(stdout);
    close(2);
    printf("a descriptor freed, the file by its path: %s\n", name(ask(file)));
    printf("a descriptor freed, standard input's filesystem read-only: %s\n", readonly(0));
    printf("a descriptor freed, the path under the second: %s\n", name(ask(b)));
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, 0, _IOLBF, 0);
    if (argc >= 4 && strcmp(argv[1], "race") == 0 && argc - 3 <= MAX_PATHS) {
        paths = argv + 3;
        npaths = argc - 3;
        return race(atoi(argv[2]));
    }
    if (argc == 5 && strcmp(argv[1], "limit") == 0) return limit(argv[2], argv[3], argv[4]);
    fprintf(stderr, "usage: top_reach race ROUNDS PATH... | top_reach limit A B FILE\n");
    return 2;
}
