/* slash_links.c — a trailing slash after a final symlink, for the calls that look the last name up in its parent
 * (DESIGN.md 7.4.3, 17.4). A create, a delete, a rename and link's new name walk the parent and look the last name up
 * in it (filename_parentat), never following a symlink there, and the slash is the call's own to judge: EEXIST for a
 * create of what exists, ENOENT for a non-directory create of what does not, ENOTDIR for rmdir and unlink of a link,
 * EADDRINUSE for bind; open with O_CREAT answers EISDIR before the lookup (lookup_fast_for_open). A plain lookup
 * follows a link that a trailing slash ends (lookup_last). usage: slash_links HOSTDIR EXFILE EXDIR [EXLINK]: a
 * writable host directory, a regular file and a directory the exclave owns, and a symlink in the tree to a directory
 * ("-" for none). Prints one line per case, "<case>: ok" or "<case>: ret=-1 errno=<e>", the same in every world, so
 * that the kernel under bwrap is the oracle for the launcher. Exit 0 always: the driver compares. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#define RENAME_EXCHANGE 2
#endif

static void show(const char *form, const char *what, long r)
{
    if (r < 0) printf("%s %s: ret=-1 errno=%d\n", form, what, errno);
    else printf("%s %s: ok\n", form, what); /* a descriptor's number is the world's own */
}

static void try_open(const char *form, const char *what, const char *path, int flags)
{
    long r = open(path, flags, 0644);
    show(form, what, r);
    if (r >= 0) close((int)r);
}

static void try_bind(const char *form, const char *path)
{
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    size_t n = strlen(path);
    if (n >= sizeof a.sun_path) {
        printf("%s bind: skipped\n", form);
        return;
    }
    memcpy(a.sun_path, path, n);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    long r = bind(s, (struct sockaddr *)&a, (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n + 1));
    show(form, "bind", r);
    close(s);
}

/* every call on one path, p ending in a slash; rel is its name relative to dfd, or NULL */
static void cases(const char *form, const char *p, int dfd, const char *rel, const char *host)
{
    char q[4096];
    show(form, "mkdir", mkdir(p, 0755));
    if (rel) show(form, "mkdirat", mkdirat(dfd, rel, 0755));
    show(form, "rmdir", rmdir(p));
    show(form, "unlink", unlink(p));
    show(form, "symlink", symlink("x", p));
    if (rel) show(form, "symlinkat", symlinkat("x", dfd, rel));
    show(form, "mknod fifo", mknod(p, S_IFIFO | 0644, 0));
    show(form, "mknod reg", mknod(p, S_IFREG | 0644, 0));
    if (rel) show(form, "mknodat fifo", mknodat(dfd, rel, S_IFIFO | 0644, 0));
    try_bind(form, p);
    try_open(form, "open creat", p, O_WRONLY | O_CREAT);
    try_open(form, "open creat excl", p, O_WRONLY | O_CREAT | O_EXCL);
    try_open(form, "open rdonly", p, O_RDONLY);
    snprintf(q, sizeof q, "%s/hfile2", host);
    show(form, "link to it", link(q, p));
    show(form, "renameat2 noreplace onto it", syscall(SYS_renameat2, AT_FDCWD, q, AT_FDCWD, p, RENAME_NOREPLACE));
    show(form, "rename onto it", rename(q, p));
    /* an exchange that succeeds is undone, so that the forms after it see the same files */
    long r = syscall(SYS_renameat2, AT_FDCWD, q, AT_FDCWD, p, RENAME_EXCHANGE);
    show(form, "renameat2 exchange with it", r);
    if (r == 0) syscall(SYS_renameat2, AT_FDCWD, q, AT_FDCWD, p, RENAME_EXCHANGE);
    snprintf(q, sizeof q, "%s/renamed", host);
    show(form, "rename it", rename(p, q));
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: slash_links HOSTDIR EXFILE EXDIR [EXLINK]\n");
        return 2;
    }
    const char *host = argv[1], *exfile = argv[2], *exdir = argv[3];
    const char *exlink = argc > 4 && strcmp(argv[4], "-") != 0 ? argv[4] : NULL;
    char p[4096];
    int fd;
    if (chdir(host) != 0) {
        perror(host);
        return 2;
    }
    /* a dangling link, a link to an exclave file, one to an exclave directory, a directory and a file */
    if (symlink("missing", "hdang") || symlink(exfile, "hlink") || symlink(exdir, "hlnkdir") || mkdir("hdir", 0755) ||
        (fd = open("hfile", O_WRONLY | O_CREAT, 0644)) < 0 || close(fd) ||
        (fd = open("hfile2", O_WRONLY | O_CREAT, 0644)) < 0 || close(fd)) {
        perror("setup");
        return 2;
    }
    int dfd = open(host, O_RDONLY | O_DIRECTORY);
    static const char *const names[] = {"hdang", "hlink", "hlnkdir", "hdir", "hfile", "absent"};
    for (size_t i = 0; i < sizeof names / sizeof *names; i++) {
        char rel[64];
        snprintf(rel, sizeof rel, "%s/", names[i]);
        snprintf(p, sizeof p, "%s/%s/", host, names[i]);
        cases(names[i], p, dfd, rel, host);
    }
    if (exlink) {
        snprintf(p, sizeof p, "%s/", exlink);
        cases("exlink", p, dfd, NULL, host);
    } else {
        printf("exlink: skipped\n");
    }
    /* the effects: what the calls left behind */
    static const char *const left[] = {"missing", "hdang",  "hlink",   "hlnkdir", "hdir",
                                       "hfile",   "hfile2", "renamed", "absent"};
    for (size_t i = 0; i < sizeof left / sizeof *left; i++) {
        struct stat st;
        printf("effect %s: %s\n", left[i],
               lstat(left[i], &st) != 0 ? "absent"
               : S_ISLNK(st.st_mode)    ? "link"
               : S_ISDIR(st.st_mode)    ? "dir"
               : S_ISREG(st.st_mode)    ? "file"
                                        : "other");
    }
    return 0;
}
