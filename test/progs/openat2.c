/* openat2.c — the openat2 regression of DESIGN.md 17.4: the resolve flags in the exclave's world (7.4.3).
 * usage: openat2 HOSTDIR (HOSTDIR: a writable host directory). Prints FAIL lines; exit 1 on any; exit 3 when the kernel
 * has no openat2. Spellings come from the environment: EXCLAVE_TEST_SH (a symlink in the tree), EXCLAVE_TEST_TRUE.
 *
 * Mode "pathless HOSTDIR": a scoped openat2 (RESOLVE_BENEATH, RESOLVE_IN_ROOT) from a descriptor whose file has no
 * path, a directory made in HOSTDIR and removed after it was opened, a memfd and an O_TMPFILE file in HOSTDIR, which
 * the kernel walks from the descriptor itself. One line per case, the case and the errno's name, or ok
 * (test/kernel_answers.py has the kernel's answers); exit 3 when the kernel has no openat2. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define RESOLVE_NO_XDEV 0x01
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS 0x04
#define RESOLVE_BENEATH 0x08
#define RESOLVE_IN_ROOT 0x10

struct how {
    unsigned long long flags, mode, resolve;
};
static int fails;

static long o2(int dfd, const char *path, unsigned long flags, unsigned long mode, unsigned long resolve)
{
    struct how h = {flags, mode, resolve};
    return syscall(SYS_openat2, dfd, path, &h, sizeof h);
}
#define CHECK(expr, want)                                                                                              \
    do {                                                                                                               \
        errno = 0;                                                                                                     \
        long r_ = (long)(expr);                                                                                        \
        int e_ = errno;                                                                                                \
        if ((want) == 0 ? r_ < 0 : !(r_ < 0 && e_ == (want))) {                                                        \
            fails++;                                                                                                   \
            printf("FAIL %s: got %ld errno %d (%s), wanted %s\n", #expr, r_, e_, strerror(e_),                         \
                   (want) == 0 ? "success" : strerror(want));                                                          \
        } else if (r_ >= 0) close((int)r_);                                                                            \
    } while (0)

#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif

/* the errno's name, which every libc spells alike where strerror's text is its own */
static const char *ename(int e)
{
    static char b[32];
    switch (e) {
    case ENOENT: return "ENOENT";
    case ENOTDIR: return "ENOTDIR";
    case EISDIR: return "EISDIR";
    case EEXIST: return "EEXIST";
    case EBUSY: return "EBUSY";
    case EXDEV: return "EXDEV";
    case EROFS: return "EROFS";
    case EACCES: return "EACCES";
    case EPERM: return "EPERM";
    case EINVAL: return "EINVAL";
    case ELOOP: return "ELOOP";
    case ENOTEMPTY: return "ENOTEMPTY";
    default: snprintf(b, sizeof b, "errno=%d", e); return b;
    }
}

static void answer(const char *what, long r)
{
    printf("%s: %s\n", what, r >= 0 ? "ok" : ename(errno));
    if (r >= 0) close((int)r);
}

/* a scoped open from each descriptor whose file has no path; the kernel's order: the scope's directory itself, "."
 * and "..", a name under it, an absolute path, and what is not a directory at all */
static int pathless(const char *host)
{
    char gone[4096];
    snprintf(gone, sizeof gone, "%s/gone", host);
    mkdir(gone, 0755);
    int gonefd = open(gone, O_PATH | O_DIRECTORY);
    if (gonefd < 0 || rmdir(gone) != 0) {
        printf("a removed directory: %s\n", ename(errno));
        return 2;
    }
    int memfd = (int)syscall(SYS_memfd_create, "probe", 0);
    int tmpfilefd = open(host, O_TMPFILE | O_RDWR, 0644);
    if (memfd < 0 || tmpfilefd < 0) {
        printf("a memfd and an O_TMPFILE file: %s\n", ename(errno));
        return 2;
    }
    answer("removed directory, . beneath", o2(gonefd, ".", O_RDONLY, 0, RESOLVE_BENEATH));
    answer("removed directory, . in root", o2(gonefd, ".", O_RDONLY, 0, RESOLVE_IN_ROOT));
    answer("removed directory, . with O_DIRECTORY beneath",
           o2(gonefd, ".", O_RDONLY | O_DIRECTORY, 0, RESOLVE_BENEATH));
    answer("removed directory, . with O_PATH in root", o2(gonefd, ".", O_PATH, 0, RESOLVE_IN_ROOT));
    answer("removed directory, .. beneath", o2(gonefd, "..", O_RDONLY, 0, RESOLVE_BENEATH));
    answer("removed directory, .. in root", o2(gonefd, "..", O_RDONLY, 0, RESOLVE_IN_ROOT));
    answer("removed directory, ../x beneath", o2(gonefd, "../x", O_RDONLY, 0, RESOLVE_BENEATH));
    answer("removed directory, ../x in root", o2(gonefd, "../x", O_RDONLY, 0, RESOLVE_IN_ROOT));
    answer("removed directory, x beneath", o2(gonefd, "x", O_RDONLY, 0, RESOLVE_BENEATH));
    answer("removed directory, x in root", o2(gonefd, "x", O_RDONLY, 0, RESOLVE_IN_ROOT));
    answer("removed directory, x created beneath", o2(gonefd, "x", O_WRONLY | O_CREAT, 0644, RESOLVE_BENEATH));
    answer("removed directory, / beneath", o2(gonefd, "/", O_RDONLY, 0, RESOLVE_BENEATH));
    answer("removed directory, / in root", o2(gonefd, "/", O_RDONLY, 0, RESOLVE_IN_ROOT));
    answer("removed directory, /etc/passwd in root", o2(gonefd, "/etc/passwd", O_RDONLY, 0, RESOLVE_IN_ROOT));
    answer("removed directory, empty path beneath", o2(gonefd, "", O_RDONLY, 0, RESOLVE_BENEATH));
    answer("removed directory, . written beneath", o2(gonefd, ".", O_WRONLY, 0, RESOLVE_BENEATH));
    answer("removed directory, .. written in root", o2(gonefd, "..", O_WRONLY, 0, RESOLVE_IN_ROOT));
    answer("removed directory, . created in root", o2(gonefd, ".", O_WRONLY | O_CREAT, 0644, RESOLVE_IN_ROOT));
    answer("memfd, . beneath", o2(memfd, ".", O_RDONLY, 0, RESOLVE_BENEATH));
    answer("memfd, . in root", o2(memfd, ".", O_RDONLY, 0, RESOLVE_IN_ROOT));
    answer("memfd, x beneath", o2(memfd, "x", O_RDONLY, 0, RESOLVE_BENEATH));
    answer("memfd, x in root", o2(memfd, "x", O_RDONLY, 0, RESOLVE_IN_ROOT));
    answer("memfd, x created beneath", o2(memfd, "x", O_WRONLY | O_CREAT, 0644, RESOLVE_BENEATH));
    answer("memfd, empty path beneath", o2(memfd, "", O_RDONLY, 0, RESOLVE_BENEATH));
    answer("memfd, / in root", o2(memfd, "/", O_RDONLY, 0, RESOLVE_IN_ROOT));
    answer("O_TMPFILE file, . beneath", o2(tmpfilefd, ".", O_RDONLY, 0, RESOLVE_BENEATH));
    answer("O_TMPFILE file, . in root", o2(tmpfilefd, ".", O_RDONLY, 0, RESOLVE_IN_ROOT));
    answer("O_TMPFILE file, x beneath", o2(tmpfilefd, "x", O_RDONLY, 0, RESOLVE_BENEATH));
    answer("O_TMPFILE file, x in root", o2(tmpfilefd, "x", O_RDONLY, 0, RESOLVE_IN_ROOT));
    answer("O_TMPFILE file, . with O_PATH beneath", o2(tmpfilefd, ".", O_PATH, 0, RESOLVE_BENEATH));
    int fds[2];
    if (pipe(fds) == 0) {
        answer("pipe, . beneath", o2(fds[0], ".", O_RDONLY, 0, RESOLVE_BENEATH));
        answer("pipe, x in root", o2(fds[0], "x", O_RDONLY, 0, RESOLVE_IN_ROOT));
    }
    close(gonefd);
    close(memfd);
    close(tmpfilefd);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: openat2 HOSTDIR | openat2 pathless HOSTDIR\n");
        return 2;
    }
    if (strcmp(argv[1], "pathless") == 0 && argc > 2) {
        errno = 0;
        long r0 = o2(AT_FDCWD, "/", O_RDONLY | O_DIRECTORY, 0, 0);
        if (r0 < 0 && errno == ENOSYS) {
            printf("no openat2 on this kernel\n");
            return 3;
        }
        if (r0 >= 0) close((int)r0);
        return pathless(argv[2]);
    }
    const char *host = argv[1];
    const char *sh = getenv("EXCLAVE_TEST_SH") ? getenv("EXCLAVE_TEST_SH") : "/usr/bin/sh";
    const char *truep = getenv("EXCLAVE_TEST_TRUE") ? getenv("EXCLAVE_TEST_TRUE") : "/usr/bin/true";
    errno = 0;
    long r = o2(AT_FDCWD, "/", O_RDONLY | O_DIRECTORY, 0, 0);
    if (r < 0 && errno == ENOSYS) {
        printf("no openat2 on this kernel\n");
        return 3;
    }
    if (r < 0) {
        printf("FAIL openat2 of /: %s\n", strerror(errno));
        return 1;
    }
    close((int)r);
    int usr = open("/usr", O_PATH | O_DIRECTORY), root = open("/", O_PATH | O_DIRECTORY);
    /* in root: / is the descriptor's directory; .. and absolute paths stay inside it (the tree says where true is) */
    CHECK(o2(usr, "/bin", O_RDONLY | O_DIRECTORY, 0, RESOLVE_IN_ROOT), 0);            /* /usr/bin */
    CHECK(o2(usr, "/etc/passwd", O_RDONLY, 0, RESOLVE_IN_ROOT), ENOENT);              /* /usr/etc/passwd */
    CHECK(o2(usr, "../../etc/passwd", O_RDONLY, 0, RESOLVE_IN_ROOT), ENOENT);        /* clamped at /usr */
    CHECK(o2(usr, "bin/../bin", O_RDONLY | O_DIRECTORY, 0, RESOLVE_IN_ROOT), 0);
    CHECK(o2(root, truep, O_RDONLY, 0, RESOLVE_IN_ROOT), 0);
    CHECK(o2(root, truep + 1, O_RDONLY, 0, RESOLVE_IN_ROOT), 0);
    CHECK(o2(root, "etc/passwd", O_RDONLY, 0, RESOLVE_IN_ROOT), 0);
    /* beneath: leaving the descriptor's directory is EXDEV */
    CHECK(o2(usr, "bin", O_RDONLY | O_DIRECTORY, 0, RESOLVE_BENEATH), 0);
    CHECK(o2(root, truep + 1, O_RDONLY, 0, RESOLVE_BENEATH), 0);
    CHECK(o2(usr, "../etc/passwd", O_RDONLY, 0, RESOLVE_BENEATH), EXDEV);
    CHECK(o2(usr, truep, O_RDONLY, 0, RESOLVE_BENEATH), EXDEV);
    CHECK(o2(usr, "bin/../..", O_RDONLY | O_DIRECTORY, 0, RESOLVE_BENEATH), EXDEV);
    /* no symlinks: the tree's own links count, as they would under a bind mount */
    CHECK(o2(AT_FDCWD, sh, O_RDONLY, 0, RESOLVE_NO_SYMLINKS), ELOOP);
    CHECK(o2(AT_FDCWD, sh, O_PATH | O_NOFOLLOW, 0, RESOLVE_NO_SYMLINKS), 0); /* the link itself, not followed */
    CHECK(o2(AT_FDCWD, sh, O_RDONLY, 0, 0), 0);
    /* magic links: NO_MAGICLINKS and NO_SYMLINKS refuse one with ELOOP, then the scoped flags with EXDEV
     * (nd_jump_link), for the process's exe and a descriptor alike */
    CHECK(o2(AT_FDCWD, "/proc/self/exe", O_RDONLY, 0, RESOLVE_NO_MAGICLINKS), ELOOP);
    CHECK(o2(AT_FDCWD, "/proc/self/exe", O_RDONLY, 0, RESOLVE_NO_SYMLINKS), ELOOP);
    CHECK(o2(root, "proc/self/exe", O_RDONLY, 0, RESOLVE_IN_ROOT), EXDEV);
    CHECK(o2(root, "proc/self/exe", O_RDONLY, 0, RESOLVE_BENEATH), EXDEV);
    CHECK(o2(root, "proc/self/exe", O_RDONLY, 0, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS), ELOOP);
    CHECK(o2(root, "proc/self/fd/0", O_RDONLY, 0, RESOLVE_IN_ROOT), EXDEV);
    CHECK(o2(root, "proc/self/fd/0", O_RDONLY, 0, RESOLVE_BENEATH), EXDEV);
    CHECK(o2(root, "proc/self/fd/0", O_RDONLY, 0, RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS), ELOOP);
    CHECK(o2(AT_FDCWD, "/proc/self/exe", O_RDONLY, 0, 0), 0);
    /* no xdev: the exclave and the host are different mounts; an identity file is the host's */
    CHECK(o2(root, truep + 1, O_RDONLY, 0, RESOLVE_NO_XDEV), 0);
    CHECK(o2(root, "etc/passwd", O_RDONLY, 0, RESOLVE_NO_XDEV), EXDEV);
    CHECK(o2(root, "tmp", O_RDONLY | O_DIRECTORY, 0, RESOLVE_NO_XDEV), EXDEV);
    /* the read-only rule holds through openat2 too */
    char hnew[4096];
    snprintf(hnew, sizeof hnew, "%s/o2new", host);
    unlink(hnew);
    CHECK(o2(AT_FDCWD, "/usr/share/o2new", O_WRONLY | O_CREAT, 0644, 0), EROFS);
    CHECK(o2(AT_FDCWD, hnew, O_WRONLY | O_CREAT, 0644, 0), 0);
    unlink(hnew);
    CHECK(o2(AT_FDCWD, truep, O_WRONLY, 0, 0), EROFS);
    /* the struct's rules, checked before any lookup */
    CHECK(o2(AT_FDCWD, "/nonexistent", O_RDONLY, 0, 0x100), EINVAL);
    CHECK(o2(AT_FDCWD, "/nonexistent", O_RDONLY, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT), EINVAL);
    CHECK(o2(AT_FDCWD, "/nonexistent", O_RDONLY, 0644, 0), EINVAL);
    CHECK(o2(AT_FDCWD, "/nonexistent", O_PATH | O_RDWR, 0, 0), EINVAL);
    {
        struct how h = {O_RDONLY, 0, 0};
        CHECK(syscall(SYS_openat2, AT_FDCWD, "/", &h, 16), EINVAL);
    }
    close(usr);
    close(root);
    printf("openat2: %d failures\n", fails);
    return fails ? 1 : 0;
}
