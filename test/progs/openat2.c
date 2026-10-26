/* openat2.c — the openat2 regression of DESIGN.md 17.4: the resolve flags in the exclave's world (7.4.3).
 * usage: openat2 HOSTDIR   (HOSTDIR: a writable host directory). Prints FAIL lines; exit 1 on any; exit 3 when
 * the kernel has no openat2. Spellings come from the environment: EXCLAVE_TEST_SH (a symlink in the tree), EXCLAVE_TEST_TRUE. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define RESOLVE_NO_XDEV 0x01
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS 0x04
#define RESOLVE_BENEATH 0x08
#define RESOLVE_IN_ROOT 0x10

struct how { unsigned long long flags, mode, resolve; };
static int fails;

static long o2(int dfd, const char *path, unsigned long flags, unsigned long mode, unsigned long resolve)
{
    struct how h = { flags, mode, resolve };
    return syscall(SYS_openat2, dfd, path, &h, sizeof h);
}
#define CHECK(expr, want) do { errno = 0; long r_ = (long)(expr); int e_ = errno; \
    if ((want) == 0 ? r_ < 0 : !(r_ < 0 && e_ == (want))) { fails++; printf("FAIL %s: got %ld errno %d (%s), wanted %s\n", #expr, r_, e_, strerror(e_), (want) == 0 ? "success" : strerror(want)); } \
    else if (r_ >= 0) close((int)r_); } while (0)

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: openat2 HOSTDIR\n"); return 2; }
    const char *host = argv[1];
    const char *sh = getenv("EXCLAVE_TEST_SH") ? getenv("EXCLAVE_TEST_SH") : "/usr/bin/sh";
    const char *truep = getenv("EXCLAVE_TEST_TRUE") ? getenv("EXCLAVE_TEST_TRUE") : "/usr/bin/true";
    errno = 0;
    long r = o2(AT_FDCWD, "/", O_RDONLY | O_DIRECTORY, 0, 0);
    if (r < 0 && errno == ENOSYS) { printf("no openat2 on this kernel\n"); return 3; }
    if (r < 0) { printf("FAIL openat2 of /: %s\n", strerror(errno)); return 1; }
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
    CHECK(o2(AT_FDCWD, sh, O_PATH | O_NOFOLLOW, 0, RESOLVE_NO_SYMLINKS), 0);         /* the link itself, not followed */
    CHECK(o2(AT_FDCWD, sh, O_RDONLY, 0, 0), 0);
    /* magic links */
    CHECK(o2(AT_FDCWD, "/proc/self/exe", O_RDONLY, 0, RESOLVE_NO_MAGICLINKS), ELOOP);
    CHECK(o2(root, "proc/self/exe", O_RDONLY, 0, RESOLVE_IN_ROOT), ELOOP);
    CHECK(o2(AT_FDCWD, "/proc/self/exe", O_RDONLY, 0, 0), 0);
    /* no xdev: the exclave and the host are different mounts; an identity file is the host's */
    CHECK(o2(root, truep + 1, O_RDONLY, 0, RESOLVE_NO_XDEV), 0);
    CHECK(o2(root, "etc/passwd", O_RDONLY, 0, RESOLVE_NO_XDEV), EXDEV);
    CHECK(o2(root, "tmp", O_RDONLY | O_DIRECTORY, 0, RESOLVE_NO_XDEV), EXDEV);
    /* the read-only rule holds through openat2 too */
    char hnew[4096]; snprintf(hnew, sizeof hnew, "%s/o2new", host); unlink(hnew);
    CHECK(o2(AT_FDCWD, "/usr/share/o2new", O_WRONLY | O_CREAT, 0644, 0), EROFS);
    CHECK(o2(AT_FDCWD, hnew, O_WRONLY | O_CREAT, 0644, 0), 0);
    unlink(hnew);
    CHECK(o2(AT_FDCWD, truep, O_WRONLY, 0, 0), EROFS);
    /* the struct's rules, checked before any lookup */
    CHECK(o2(AT_FDCWD, "/nonexistent", O_RDONLY, 0, 0x100), EINVAL);
    CHECK(o2(AT_FDCWD, "/nonexistent", O_RDONLY, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT), EINVAL);
    CHECK(o2(AT_FDCWD, "/nonexistent", O_RDONLY, 0644, 0), EINVAL);
    CHECK(o2(AT_FDCWD, "/nonexistent", O_PATH | O_RDWR, 0, 0), EINVAL);
    { struct how h = { O_RDONLY, 0, 0 }; CHECK(syscall(SYS_openat2, AT_FDCWD, "/", &h, 16), EINVAL); }
    close(usr); close(root);
    printf("openat2: %d failures\n", fails);
    return fails ? 1 : 0;
}
