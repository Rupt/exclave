/* rename_dots.c — a rename whose last name is "." or "..", in do_renameat2's order (DESIGN.md 7.4.3, 17.4): the parents
 * are looked up, then the two mounts compared (EXDEV), then such a name refused (EBUSY, or EEXIST for the new name
 * under RENAME_NOREPLACE), then the mount wanted writable (EROFS). usage: rename_dots HOSTDIR OTHERDIR (two writable
 * host directories; whether they lie on different mounts is the caller's to know). Prints one line per case: the
 * case and the errno's name, or ok (test/kernel_answers.py has the kernel's answers). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#define RENAME_EXCHANGE 2
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

static void try(const char *what, const char *from, const char *to, unsigned flags)
{
    long r = flags ? syscall(SYS_renameat2, AT_FDCWD, from, AT_FDCWD, to, flags) : rename(from, to);
    printf("%s: %s\n", what, r == 0 ? "ok" : ename(errno));
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: rename_dots HOSTDIR OTHERDIR\n");
        return 2;
    }
    const char *host = argv[1], *other = argv[2];
    char hdir[4096], hdot[4096], hdotdot[4096], hnew[4096], hfile[4096], hfdot[4096], hlink[4096], hldot[4096],
        hmiss[4096], onew[4096];
    snprintf(hdir, sizeof hdir, "%s/hdir", host);
    snprintf(hdot, sizeof hdot, "%s/hdir/.", host);
    snprintf(hdotdot, sizeof hdotdot, "%s/hdir/..", host);
    snprintf(hnew, sizeof hnew, "%s/hnew", host);
    snprintf(hfile, sizeof hfile, "%s/hfile", host);
    snprintf(hfdot, sizeof hfdot, "%s/hfile/.", host);
    snprintf(hlink, sizeof hlink, "%s/hlink", host);
    snprintf(hldot, sizeof hldot, "%s/hlink/..", host);
    snprintf(hmiss, sizeof hmiss, "%s/missing/.", host);
    snprintf(onew, sizeof onew, "%s/new", other);
    mkdir(hdir, 0755);
    unlink(hlink);
    close(open(hfile, O_WRONLY | O_CREAT, 0644));
    if (symlink("hdir", hlink) != 0 || access(hdir, F_OK) != 0) {
        printf("setup: %s\n", ename(errno));
        return 2;
    }
    unlink(hnew);
    unlink(onew);
    /* the other directory's mount, which may be another of the host's: EXDEV before EBUSY */
    try("hdir/. to other", hdot, onew, 0);
    try("other to hdir/.", onew, hdot, 0);
    try("hdir/.. to other", hdotdot, onew, 0);
    try("other to hdir/..", onew, hdotdot, 0);
    try("other to hdir/. noreplace", onew, hdot, RENAME_NOREPLACE);
    try("hdir/. to other exchange", hdot, onew, RENAME_EXCHANGE);
    try("hlink/.. to other", hldot, onew, 0);
    /* the same mount: EBUSY, or EEXIST for the new name under RENAME_NOREPLACE */
    try("hdir/. to hnew", hdot, hnew, 0);
    try("hnew to hdir/.", hnew, hdot, 0);
    try("hdir/.. to hnew", hdotdot, hnew, 0);
    try("hnew to hdir/.. noreplace", hnew, hdotdot, RENAME_NOREPLACE);
    try("hdir/. to hnew noreplace", hdot, hnew, RENAME_NOREPLACE);
    try("hdir/. to hnew exchange", hdot, hnew, RENAME_EXCHANGE);
    try("hlink/.. to hnew", hldot, hnew, 0);
    /* the parent lookups come first */
    try("hfile/. to hnew", hfdot, hnew, 0);
    try("hnew to hfile/.", hnew, hfdot, 0);
    try("missing/. to other", hmiss, onew, 0);
    /* the exclave's mount against the host's: EXDEV; its own: EBUSY, then EROFS */
    try("/usr/share/. to other", "/usr/share/.", onew, 0);
    try("other to /usr/share/..", onew, "/usr/share/..", 0);
    try("/usr/share/. to hnew", "/usr/share/.", hnew, 0);
    try("/usr/share/. to /usr/x", "/usr/share/.", "/usr/x", 0);
    try("/usr/x to /usr/share/.", "/usr/x", "/usr/share/.", 0);
    try("/usr/x to /usr/share/.. noreplace", "/usr/x", "/usr/share/..", RENAME_NOREPLACE);
    try("/usr/share/x to /usr/y", "/usr/share/x", "/usr/y", 0);
    try("/ to other", "/", onew, 0);
    try("/ to /usr/x", "/", "/usr/x", 0);
    /* a parent on one of the host's own mounts, /proc, against the exclave's and another of the host's */
    try("/proc/.. to /usr/x", "/proc/..", "/usr/x", 0);
    try("/proc/.. to hnew", "/proc/..", hnew, 0);
    try("hnew to /proc/..", hnew, "/proc/..", 0);
    /* the name relative to a descriptor and to the working directory */
    {
        int dfd = open(host, O_PATH | O_DIRECTORY);
        long r = syscall(SYS_renameat2, dfd, "hdir/..", AT_FDCWD, onew, 0);
        printf("hdir/.. from a descriptor to other: %s\n", r == 0 ? "ok" : ename(errno));
        r = syscall(SYS_renameat2, dfd, "hdir/.", dfd, "hnew", 0);
        printf("hdir/. from a descriptor to hnew: %s\n", r == 0 ? "ok" : ename(errno));
        close(dfd);
    }
    if (chdir(host) == 0) {
        try("hdir/. from the working directory to other", "hdir/.", onew, 0);
        try("hdir/.. from the working directory to hnew", "hdir/..", "hnew", 0);
        try(".. from the working directory to other", "..", onew, 0);
        try("hdir/./ from the working directory to hnew", "hdir/./", "hnew", 0);
    }
    printf("hnew afterwards: %s\n", access(hnew, F_OK) == 0 ? "exists" : ename(errno));
    printf("other afterwards: %s\n", access(onew, F_OK) == 0 ? "exists" : ename(errno));
    unlink(hlink);
    unlink(hfile);
    rmdir(hdir);
    return 0;
}
