/* open_flags.c — the open flags the kernel judges before the walk and the directory it wants before the read-only
 * rules (DESIGN.md 7.4.3, 17.4). build_open_flags refuses O_DIRECTORY with O_CREAT and O_TMPFILE without O_DIRECTORY
 * or write access before getname, in open and openat as in openat2, and open's O_PATH drops every companion but its
 * own; do_open and path_lookupat answer ENOTDIR for O_DIRECTORY on what is not a directory before may_open and the
 * write access a read-only mount refuses. Makes its host entries in argv[1], a writable host directory, and prints one
 * line per case: the case and the errno text, or ok. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char *answer(long fd)
{
    if (fd >= 0) {
        close((int)fd);
        return "ok";
    }
    return strerror(errno);
}

static void try(const char *what, const char *path, int flags)
{ printf("%s: %s\n", what, answer(open(path, flags, 0644))); }

static void try_at(const char *what, const char *path, int flags)
{ printf("%s: %s\n", what, answer(syscall(SYS_openat, AT_FDCWD, path, flags, 0644))); }

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: open_flags HOSTDIR\n");
        return 2;
    }
    const char *host = argv[1];
    const char *dir = "/usr/share", *file = "/usr/share/exclave-test-marker", *missing = "/usr/share/exclave-missing";
    char dangling[4096], created[4096];
    snprintf(dangling, sizeof dangling, "%s/dangling", host);
    snprintf(created, sizeof created, "%s/created", host);
    unlink(dangling);
    unlink(created);
    if (symlink("/usr/share/exclave-missing", dangling) != 0) {
        printf("symlink: %s\n", strerror(errno));
        return 2;
    }
    /* build_open_flags: before any lookup, in open and openat alike */
    try("O_DIRECTORY|O_CREAT on a directory", dir, O_RDONLY | O_DIRECTORY | O_CREAT);
    try("O_DIRECTORY|O_CREAT on a file", file, O_RDONLY | O_DIRECTORY | O_CREAT);
    try("O_DIRECTORY|O_CREAT on a missing name", missing, O_WRONLY | O_DIRECTORY | O_CREAT);
    try("O_DIRECTORY|O_CREAT with a trailing slash", "/usr/share/exclave-test-marker/",
        O_RDONLY | O_DIRECTORY | O_CREAT);
    try("O_DIRECTORY|O_CREAT on a bad pointer", (const char *)8, O_RDONLY | O_DIRECTORY | O_CREAT);
    try_at("openat O_DIRECTORY|O_CREAT on a missing name", missing, O_WRONLY | O_DIRECTORY | O_CREAT);
    printf("the missing name afterwards: %s\n", access(missing, F_OK) == 0 ? "created" : strerror(errno));
    try("O_TMPFILE without write access", dir, O_RDONLY | O_TMPFILE);
    try("O_TMPFILE with O_CREAT", dir, O_RDWR | O_TMPFILE | O_CREAT);
    try("O_TMPFILE without O_DIRECTORY", dir, O_RDWR | (O_TMPFILE & ~O_DIRECTORY));
    try("O_TMPFILE on a missing name", missing, O_RDWR | O_TMPFILE);
    try("O_TMPFILE on a file", file, O_RDWR | O_TMPFILE);
    try("O_TMPFILE on a directory", dir, O_RDWR | O_TMPFILE);
    /* open's O_PATH drops its companions (build_open_how); openat2 refuses them */
    try("O_PATH|O_DIRECTORY|O_CREAT on a directory", dir, O_PATH | O_DIRECTORY | O_CREAT);
    try("O_PATH|O_DIRECTORY|O_CREAT on a file", file, O_PATH | O_DIRECTORY | O_CREAT);
    try("O_PATH|O_DIRECTORY|O_CREAT on a missing name", missing, O_PATH | O_DIRECTORY | O_CREAT);
    /* the mode of an existing file is kept */
    {
        struct stat st;
        int fd = open(created, O_WRONLY | O_CREAT, 0600);
        if (fd >= 0) close(fd);
        fd = open(created, O_WRONLY | O_CREAT, 0);
        if (fd >= 0) close(fd);
        printf("the mode of an existing file after O_CREAT with mode 0: %s\n",
               stat(created, &st) == 0 ? (st.st_mode & 07777) == 0600 ? "kept" : "changed" : strerror(errno));
    }
    unlink(dangling);
    unlink(created);
    return 0;
}
