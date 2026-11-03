/* dirstat.c — a directory's link count and size by every stat (DESIGN.md 8.3): upstream's tree has no .real/, so a
 * directory of the tree counts one link fewer where links count subdirectories, and on a filesystem whose directory
 * size counts entries, one entry fewer. usage: dirstat DIR...; prints "<dir> <call>: nlink=N size=S" per call.
 * Exit 0. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static void show(const char *dir, const char *call, long r, unsigned long nlink, long long size)
{
    if (r < 0) printf("%s %s: failed\n", dir, call);
    else printf("%s %s: nlink=%lu size=%lld\n", dir, call, nlink, size);
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        const char *d = argv[i];
        struct stat st;
        long r = stat(d, &st);
        show(d, "stat", r, st.st_nlink, st.st_size);
        r = lstat(d, &st);
        show(d, "lstat", r, st.st_nlink, st.st_size);
        r = syscall(SYS_newfstatat, AT_FDCWD, d, &st, 0);
        show(d, "newfstatat", r, st.st_nlink, st.st_size);
        int fd = open(d, O_RDONLY | O_DIRECTORY);
#ifdef SYS_fstat
        r = syscall(SYS_fstat, fd, &st);
        show(d, "fstat", r, st.st_nlink, st.st_size);
#endif
        r = syscall(SYS_newfstatat, fd, "", &st, AT_EMPTY_PATH);
        show(d, "newfstatat AT_EMPTY_PATH", r, st.st_nlink, st.st_size);
        struct statx sx;
        r = syscall(SYS_statx, AT_FDCWD, d, 0, STATX_NLINK | STATX_SIZE, &sx);
        show(d, "statx", r, sx.stx_nlink, (long long)sx.stx_size);
        r = syscall(SYS_statx, fd, "", AT_EMPTY_PATH, STATX_NLINK | STATX_SIZE, &sx);
        show(d, "statx AT_EMPTY_PATH", r, sx.stx_nlink, (long long)sx.stx_size);
        close(fd);
        fd = open(d, O_PATH | O_DIRECTORY);
#ifdef SYS_fstat
        r = syscall(SYS_fstat, fd, &st);
        show(d, "fstat O_PATH", r, st.st_nlink, st.st_size);
#endif
        close(fd);
    }
    return 0;
}
