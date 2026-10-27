/* magic_links.c — a magic link to an object with no path reaches the object, as the kernel's walk does (DESIGN.md
 * 7.4.3).
 *
 * Mode "pathless DIR": for stdin (a pipe the caller gives), a pipe, a memfd, an inotify descriptor and a file unlinked
 * from DIR, stat, statx and faccessat2 through /proc/self/fd/N, and stat of /dev/stdin, must find the object fstat
 * finds; an O_TMPFILE file in DIR is linked into DIR through its magic link. Each line names a case and ends "ok", or
 * "n/a" where this kernel lacks the call, or says what differed.
 *
 * Mode "deleted-name DIR": DIR, a directory of the tree named "... (deleted)", is a path, so a descriptor on it is
 * the exclave's and creating under it answers EROFS. One line per call: its errno, or "created". */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_statx
#define SYS_statx 332
#endif
#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif
#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif

static void check(const char *name, int fd)
{
    struct stat want, got;
    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    if (fd < 0) {
        printf("%s n/a\n", name);
        return;
    }
    fstat(fd, &want);
    if (stat(link, &got) < 0) printf("%s stat errno %d\n", name, errno);
    else if (got.st_dev != want.st_dev || got.st_ino != want.st_ino)
        printf("%s stat differs: mode %o\n", name, got.st_mode);
    else printf("%s stat ok\n", name);

    /* struct statx: stx_ino at 32 */
    unsigned char sx[256];
    long r = syscall(SYS_statx, AT_FDCWD, link, 0, 0x100 /* STATX_INO */, sx);
    unsigned long long ino;
    memcpy(&ino, sx + 32, sizeof ino);
    if (r < 0 && errno == ENOSYS) printf("%s statx n/a\n", name);
    else if (r < 0) printf("%s statx errno %d\n", name, errno);
    else printf("%s statx %s\n", name, ino == (unsigned long long)want.st_ino ? "ok" : "differs");

    r = syscall(SYS_faccessat2, AT_FDCWD, link, F_OK, 0);
    if (r < 0 && errno == ENOSYS) printf("%s faccessat2 n/a\n", name);
    else printf("%s faccessat2 %s\n", name, r == 0 ? "ok" : strerror(errno));
}

static int pathless(const char *dir)
{
    char path[4096];
    struct stat in, dev;
    fstat(0, &in);
    if (stat("/dev/stdin", &dev) < 0) printf("/dev/stdin errno %d\n", errno);
    else printf("/dev/stdin %s\n", dev.st_dev == in.st_dev && dev.st_ino == in.st_ino ? "ok" : "differs");
    check("stdin", 0);

    int p[2];
    check("pipe", pipe(p) == 0 ? p[0] : -1);
    check("memfd", (int)syscall(SYS_memfd_create, "magic", 0));
    /* through syscall: the suite's pruned tree may lack <sys/inotify.h> */
    check("inotify", (int)syscall(SYS_inotify_init1, O_CLOEXEC));

    snprintf(path, sizeof path, "%s/magic-unlinked-%d", dir, (int)getpid());
    int u = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    unlink(path);
    check("unlinked", u);

    int t = open(dir, O_TMPFILE | O_WRONLY, 0644);
    if (t < 0) printf("tmpfile n/a\n");
    else {
        char link[64];
        snprintf(link, sizeof link, "/proc/self/fd/%d", t);
        snprintf(path, sizeof path, "%s/magic-linked-%d", dir, (int)getpid());
        if (linkat(AT_FDCWD, link, AT_FDCWD, path, AT_SYMLINK_FOLLOW) < 0) printf("tmpfile linkat errno %d\n", errno);
        else {
            printf("tmpfile linkat ok\n");
            unlink(path);
        }
    }
    return 0;
}

static int deleted_name(const char *dir)
{
    int d = open(dir, O_RDONLY | O_DIRECTORY);
    if (d < 0) {
        printf("open errno %d\n", errno);
        return 1;
    }
    int fd = openat(d, "written-through", O_CREAT | O_WRONLY, 0644);
    if (fd < 0) printf("create %d\n", errno);
    else printf("create created\n");
    if (mkdirat(d, "sub", 0755) < 0) printf("mkdir %d\n", errno);
    else printf("mkdir created\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "pathless")) return pathless(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "deleted-name")) return deleted_name(argv[2]);
    fprintf(stderr, "usage: magic_links pathless DIR | deleted-name DIR\n");
    return 2;
}
