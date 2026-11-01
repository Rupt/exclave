/* identity_nofollow.c — every call that does not follow the last component, and the follow calls beside them, on the
 * paths given, meant for the host identity files (DESIGN.md 8.4, 17.4): lstat, statx, open with O_NOFOLLOW, readlinkat,
 * faccessat2, lchown, fchownat, utimensat, fchmodat2, the l* and *at xattr calls, inotify_add_watch IN_DONT_FOLLOW,
 * fanotify_mark with FAN_MARK_DONT_FOLLOW, linkat of the path as the old name, renameat of it (renamed back when it
 * succeeds) and unlink, last. usage: identity_nofollow HOSTDIR PATH...; HOSTDIR is a writable directory for the new
 * names. Prints one line per case, "<path> <call>: <answer>", the same in every world, so the kernel is the oracle:
 * an answer is "ret=N errno=E" with what tells the object reached, the type lstat found, a link's text, whether a
 * watch on the path without following is the same as one following it, and the new name's kind after a link. Exit 0
 * always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#define SYS_FCHMODAT2 452 /* the same on every architecture */
#define SYS_SETXATTRAT 463
#define SYS_GETXATTRAT 464
#define SYS_LISTXATTRAT 465
#define SYS_REMOVEXATTRAT 466
#define FAN_REPORT_FID 0x200
#define FAN_MARK_ADD 1
#define FAN_MARK_DONT_FOLLOW 4
#define FAN_OPEN 0x20

static const char *path;
static int hfd;

static const char *kind(unsigned m)
{
    switch (m & S_IFMT) {
    case S_IFREG: return "reg";
    case S_IFDIR: return "dir";
    case S_IFLNK: return "lnk";
    default: return "other";
    }
}

static void say(const char *call, long r, const char *extra)
{
    int e = r < 0 ? errno : 0;
    printf("%s %s: ret=%ld errno=%d%s%s\n", path, call, r < 0 ? -1L : r, e, extra[0] ? " " : "", extra);
}

static void stat_case(const char *call, int flags)
{
    struct stat st;
    errno = 0;
    long r = fstatat(AT_FDCWD, path, &st, flags);
    say(call, r, r == 0 ? kind(st.st_mode) : "");
}

static void open_case(const char *call, int flags)
{
    struct stat st;
    errno = 0;
    int fd = open(path, flags);
    const char *x = "";
    if (fd >= 0 && fstat(fd, &st) == 0) x = kind(st.st_mode);
    say(call, fd < 0 ? -1 : 0, x);
    if (fd >= 0) close(fd);
}

static void one(const char *hostdir, int i)
{
    char buf[4096], extra[4200], newname[4200];
    struct stat st;
    struct timespec ts[2] = {{1000, 0}, {2000, 0}};
    long r;
    unsigned char xa[16] = {0}; /* struct xattr_args: value pointer, size, flags */
    stat_case("lstat", AT_SYMLINK_NOFOLLOW);
    stat_case("stat", 0);
    {
        struct {
            unsigned char raw[256];
        } sx;
        errno = 0;
        r = syscall(SYS_statx, AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &sx);
        unsigned short mode;
        memcpy(&mode, sx.raw + 28, 2); /* stx_mode */
        say("statx_nofollow", r, r == 0 ? kind(mode) : "");
    }
    open_case("open_path_nofollow", O_PATH | O_NOFOLLOW);
    open_case("open_rd_nofollow", O_RDONLY | O_NOFOLLOW);
    open_case("open_rd", O_RDONLY);
    errno = 0;
    r = readlinkat(AT_FDCWD, path, buf, sizeof buf - 1);
    if (r >= 0) buf[r] = 0;
    say("readlinkat", r < 0 ? -1 : 0, r >= 0 ? buf : "");
    errno = 0;
    say("faccessat2_w_nofollow", syscall(SYS_faccessat2, AT_FDCWD, path, W_OK, AT_SYMLINK_NOFOLLOW), "");
    errno = 0;
    say("lchown", lchown(path, getuid(), getgid()), "");
    errno = 0;
    say("fchownat_nofollow", fchownat(AT_FDCWD, path, getuid(), getgid(), AT_SYMLINK_NOFOLLOW), "");
    errno = 0;
    say("chown", chown(path, getuid(), getgid()), "");
    errno = 0;
    r = utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW);
    extra[0] = 0;
    if (r == 0 && fstatat(AT_FDCWD, path, &st, AT_SYMLINK_NOFOLLOW) == 0)
        snprintf(extra, sizeof extra, "link_mtime=%s", st.st_mtime == 2000 ? "set" : "unset");
    say("utimensat_nofollow", r, extra);
    errno = 0;
    r = utimensat(AT_FDCWD, path, ts, 0);
    extra[0] = 0;
    if (r == 0 && stat(path, &st) == 0)
        snprintf(extra, sizeof extra, "target_mtime=%s", st.st_mtime == 2000 ? "set" : "unset");
    say("utimensat", r, extra);
    errno = 0;
    say("fchmodat2_nofollow", syscall(SYS_FCHMODAT2, AT_FDCWD, path, 0644, AT_SYMLINK_NOFOLLOW), "");
    errno = 0;
    say("fchmodat", fchmodat(AT_FDCWD, path, 0644, 0), "");
    errno = 0;
    say("lsetxattr", lsetxattr(path, "user.probe", "v", 1, 0), "");
    errno = 0;
    say("setxattr", setxattr(path, "user.probe", "v", 1, 0), "");
    errno = 0;
    r = lgetxattr(path, "user.probe", buf, sizeof buf);
    say("lgetxattr", r, "");
    errno = 0;
    r = getxattr(path, "user.probe", buf, sizeof buf);
    say("getxattr", r, "");
    errno = 0;
    say("llistxattr", llistxattr(path, buf, sizeof buf), "");
    errno = 0;
    say("listxattr", listxattr(path, buf, sizeof buf), "");
    errno = 0;
    say("lremovexattr", lremovexattr(path, "user.probe"), "");
    errno = 0;
    say("removexattr", removexattr(path, "user.probe"), "");
    {
        const char *v = "v";
        unsigned long sz = 1;
        memcpy(xa, &v, sizeof v);
        memcpy(xa + 8, &sz, 4);
        errno = 0;
        say("setxattrat_nofollow", syscall(SYS_SETXATTRAT, AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, "user.probe", xa, 16),
            "");
        void *b = buf;
        sz = sizeof buf;
        memcpy(xa, &b, sizeof b);
        memcpy(xa + 8, &sz, 4);
        errno = 0;
        say("getxattrat_nofollow", syscall(SYS_GETXATTRAT, AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, "user.probe", xa, 16),
            "");
        errno = 0;
        say("listxattrat_nofollow", syscall(SYS_LISTXATTRAT, AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, buf, sizeof buf), "");
        errno = 0;
        say("removexattrat_nofollow", syscall(SYS_REMOVEXATTRAT, AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, "user.probe"),
            "");
    }
    {
        int in = inotify_init1(IN_CLOEXEC);
        errno = 0;
        int w1 = inotify_add_watch(in, path, IN_ATTRIB | IN_DONT_FOLLOW);
        int e1 = errno;
        int w2 = inotify_add_watch(in, path, IN_ATTRIB);
        errno = e1;
        say("inotify_dont_follow", w1 < 0 ? -1 : 0,
            w1 < 0     ? ""
            : w2 < 0   ? "no_follow_watch"
            : w1 == w2 ? "same_as_follow"
                       : "distinct_from_follow");
        close(in);
    }
    {
        int fan = (int)syscall(SYS_fanotify_init, FAN_REPORT_FID, O_RDONLY);
        if (fan < 0) say("fanotify_dont_follow", -1, "init_failed");
        else {
            errno = 0;
            say("fanotify_dont_follow",
                syscall(SYS_fanotify_mark, fan, FAN_MARK_ADD | FAN_MARK_DONT_FOLLOW, (unsigned long)FAN_OPEN, AT_FDCWD,
                        path),
                "");
            errno = 0;
            say("fanotify", syscall(SYS_fanotify_mark, fan, FAN_MARK_ADD, (unsigned long)FAN_OPEN, AT_FDCWD, path), "");
            close(fan);
        }
    }
    snprintf(newname, sizeof newname, "%s/lnk-%d", hostdir, i);
    errno = 0;
    r = linkat(AT_FDCWD, path, AT_FDCWD, newname, 0);
    extra[0] = 0;
    if (r == 0 && lstat(newname, &st) == 0) {
        snprintf(extra, sizeof extra, "new=%s", kind(st.st_mode));
        unlink(newname);
    }
    say("linkat", r, extra);
    snprintf(newname, sizeof newname, "%s/ren-%d", hostdir, i);
    errno = 0;
    r = renameat(AT_FDCWD, path, AT_FDCWD, newname);
    extra[0] = 0;
    if (r == 0) {
        const char *k = lstat(newname, &st) == 0 ? kind(st.st_mode) : "absent";
        const char *o = lstat(path, &st) == 0 ? kind(st.st_mode) : "absent";
        snprintf(extra, sizeof extra, "new=%s old=%s", k, o);
        renameat(AT_FDCWD, newname, AT_FDCWD, path);
    }
    say("renameat", r, extra);
    errno = 0;
    r = unlink(path);
    extra[0] = 0;
    if (r == 0) snprintf(extra, sizeof extra, "after=%s", lstat(path, &st) == 0 ? kind(st.st_mode) : "absent");
    say("unlink", r, extra);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: identity_nofollow HOSTDIR PATH...\n");
        return 2;
    }
    hfd = open(argv[1], O_RDONLY | O_DIRECTORY);
    if (hfd < 0) {
        perror(argv[1]);
        return 2;
    }
    for (int i = 2; i < argc; i++) {
        path = argv[i];
        one(argv[1], i);
    }
    return 0;
}
