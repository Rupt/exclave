/* rename_race.c — a path relative to a descriptor while an ancestor of the descriptor's directory is renamed. The
 * kernel resolves such a path from the directory itself, whatever its name is at the moment, so every openat and
 * fstatat succeeds; the launcher re-issues a walk that never touched the exclave as given, so they succeed inside too
 * (DESIGN.md 7.4.3). argv[1]: a writable host directory. Prints FAIL lines; exit 1 on any. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define RENAMES 20000
#define LOOKUPS 200000

static char a[4096], a2[4096 + 8];

static void *renamer(void *arg)
{
    (void)arg;
    for (int i = 0; i < RENAMES; i++) {
        if (rename(a, a2) || rename(a2, a)) {
            printf("FAIL rename: %s\n", strerror(errno));
            return (void *)1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("FAIL usage: rename_race DIR\n");
        return 1;
    }
    char b[4096 + 8], x[4096 + 16];
    snprintf(a, sizeof a, "%s/race-%d", argv[1], (int)getpid());
    snprintf(a2, sizeof a2, "%s/race-%d.moved", argv[1], (int)getpid());
    snprintf(b, sizeof b, "%s/b", a);
    snprintf(x, sizeof x, "%s/x", b);
    if (mkdir(a, 0755) || mkdir(b, 0755)) {
        printf("FAIL mkdir: %s\n", strerror(errno));
        return 1;
    }
    int fd = open(x, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        printf("FAIL create: %s\n", strerror(errno));
        return 1;
    }
    close(fd);
    int dfd = open(b, O_PATH | O_DIRECTORY);
    if (dfd < 0) {
        printf("FAIL open the directory: %s\n", strerror(errno));
        return 1;
    }
    pthread_t t;
    if (pthread_create(&t, 0, renamer, 0)) {
        printf("FAIL pthread_create\n");
        return 1;
    }
    long opens = 0, stats = 0;
    for (int i = 0; i < LOOKUPS; i++) {
        int f = openat(dfd, "x", O_RDONLY);
        if (f < 0) opens++;
        else close(f);
        struct stat st;
        if (fstatat(dfd, "x", &st, 0)) stats++;
    }
    void *r;
    pthread_join(t, &r);
    if (opens || stats)
        printf("FAIL %ld of %d openat and %ld of %d fstatat failed relative to a directory whose parent was renamed\n",
               opens, LOOKUPS, stats, LOOKUPS);
    else printf("ok: %d openat and fstatat each succeeded while the parent was renamed %d times\n", LOOKUPS, RENAMES);
    unlink(x);
    rmdir(b);
    rmdir(a);
    rmdir(a2);
    return opens || stats || r ? 1 : 0;
}
