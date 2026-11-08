/* trustdir.c — the trust directory as a program inside sees it (DESIGN.md 8.4, 13 item 55): the listing of
 * /etc/ssl/certs, a subject-hash link and the .pem link it names, each by stat, lstat, readlink and open, the bundle
 * and Java's keystore in it, the directory reached through Debian's /usr/lib/ssl/certs, a .. out of the directory,
 * openat2's resolve flags on the links from the directory and from the root, getcwd and a relative open from inside
 * it, and a create, a delete and a rename in it. usage: trustdir HASH PEM [DIR NAME], a hash link and its .pem target
 * as the host's /etc/ssl/certs names them. Prints one line per case, "<case>: <answer>"; the kernel under bwrap with
 * the host's directory and its links' target directories bound at their names is the oracle
 * (tree.identity_dir_binds). With DIR and NAME, only openat2 under RESOLVE_NO_XDEV of NAME and of .. relative to DIR.
 * Exit 0 always. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define D "/etc/ssl/certs"

struct how {
    uint64_t flags, mode, resolve;
};
#define R_NO_XDEV 0x01
#define R_NO_SYMLINKS 0x04
#define R_BENEATH 0x08
#define R_IN_ROOT 0x10

static const char *en(int e)
{
    static char b[32];
    switch (e) {
    case ENOENT: return "ENOENT";
    case ENOTDIR: return "ENOTDIR";
    case EACCES: return "EACCES";
    case EROFS: return "EROFS";
    case ELOOP: return "ELOOP";
    case EXDEV: return "EXDEV";
    case EINVAL: return "EINVAL";
    case EEXIST: return "EEXIST";
    case ENOSYS: return "ENOSYS";
    default: snprintf(b, sizeof b, "errno=%d", e); return b;
    }
}

static const char *kind(mode_t m) { return S_ISDIR(m) ? "dir" : S_ISLNK(m) ? "link" : S_ISREG(m) ? "file" : "other"; }

/* the first bytes of what fd reads, printable */
static void head(const char *tag, int fd)
{
    char b[12] = {0};
    ssize_t n = read(fd, b, 11);
    for (ssize_t i = 0; i < n; i++)
        if (b[i] < 0x20 || b[i] > 0x7e) b[i] = '.';
    printf("%s: %s\n", tag, n < 0 ? en(errno) : n == 0 ? "(empty)" : b);
}

static void stat_case(const char *tag, const char *p)
{
    struct stat st;
    if (stat(p, &st)) printf("stat %s: %s\n", tag, en(errno));
    else printf("stat %s: %s size>0=%d\n", tag, kind(st.st_mode), st.st_size > 0);
    if (lstat(p, &st)) printf("lstat %s: %s\n", tag, en(errno));
    else printf("lstat %s: %s\n", tag, kind(st.st_mode));
    char t[PATH_MAX];
    ssize_t n = readlink(p, t, sizeof t - 1);
    if (n < 0) printf("readlink %s: %s\n", tag, en(errno));
    else printf("readlink %s: %.*s\n", tag, (int)n, t);
    int fd = open(p, O_RDONLY);
    if (fd < 0) printf("open %s: %s\n", tag, en(errno));
    else {
        char ot[64];
        snprintf(ot, sizeof ot, "open %s", tag);
        head(ot, fd);
        close(fd);
    }
}

static void o2f(const char *tag, int dfd, const char *p, uint64_t flags, uint64_t resolve)
{
    struct how h = {flags, 0, resolve};
    long fd = syscall(SYS_openat2, dfd, p, &h, sizeof h);
    if (fd < 0) printf("openat2 %s: %s\n", tag, en(errno));
    else {
        printf("openat2 %s: ok\n", tag);
        close((int)fd);
    }
}
static void o2(const char *tag, int dfd, const char *p, uint64_t resolve) { o2f(tag, dfd, p, O_RDONLY, resolve); }

static int cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

int main(int argc, char **argv)
{
    /* the walks openat2 scopes or refuses links in, through /etc/ssl/certs, a host link at its name to a directory
     * holding plain.pem */
    if (argc == 2 && !strcmp(argv[1], "--scoped")) {
        int rfd = open("/", O_PATH | O_DIRECTORY), efd = open("/etc", O_PATH | O_DIRECTORY);
        o2f("nosym name", AT_FDCWD, D, O_PATH, R_NO_SYMLINKS);
        o2f("nosym below", AT_FDCWD, D "/plain.pem", O_RDONLY, R_NO_SYMLINKS);
        o2f("beneath root", rfd, "etc/ssl/certs/plain.pem", O_RDONLY, R_BENEATH);
        o2f("inroot etc", efd, "ssl/certs/plain.pem", O_RDONLY, R_IN_ROOT);
        o2f("noxdev nofollow name", AT_FDCWD, D, O_PATH | O_NOFOLLOW, R_NO_XDEV);
        o2f("noxdev through", AT_FDCWD, D "/plain.pem", O_RDONLY, R_NO_XDEV);
        return 0;
    }
    if (argc < 3) {
        fprintf(stderr, "usage: trustdir HASH PEM [DIR NAME]\n");
        return 0;
    }
    /* a walk under RESOLVE_NO_XDEV relative to a directory, a host record nested in an exclave directory say: its
     * name crosses nothing, and its .. leaves its mount */
    if (argc > 4) {
        int hfd = open(argv[3], O_PATH | O_DIRECTORY);
        o2("noxdev dir name", hfd, argv[4], R_NO_XDEV);
        o2("noxdev dir dotdot", hfd, "..", R_NO_XDEV);
        return 0;
    }
    const char *hash = argv[1], *pem = argv[2];
    char hp[PATH_MAX], pp[PATH_MAX], p[PATH_MAX];
    snprintf(hp, sizeof hp, D "/%s", hash);
    snprintf(pp, sizeof pp, D "/%s", pem);

    /* the listing: its count, how many are links and absolute ones, and the first names */
    DIR *d = opendir(D);
    if (!d) printf("list: %s\n", en(errno));
    else {
        static char *names[4096];
        int n = 0, links = 0, abs = 0;
        struct dirent *e;
        while ((e = readdir(d)) && n < 4096) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            names[n++] = strdup(e->d_name);
            char t[PATH_MAX];
            snprintf(p, sizeof p, D "/%s", e->d_name);
            ssize_t k = readlink(p, t, sizeof t);
            if (k > 0) {
                links++;
                abs += t[0] == '/';
            }
        }
        closedir(d);
        qsort(names, (size_t)n, sizeof names[0], cmp);
        printf("list count: %d links %d absolute %d\n", n, links, abs);
        printf("list first: %s %s %s\n", n > 0 ? names[0] : "-", n > 1 ? names[1] : "-", n > 2 ? names[2] : "-");
        int has = 0;
        for (int i = 0; i < n; i++) has |= !strcmp(names[i], "ca-certificates.crt");
        printf("list has bundle: %d\n", has);
    }
    stat_case("dir", D);
    stat_case("hash", hp);
    stat_case("pem", pp);
    stat_case("bundle", D "/ca-certificates.crt");
    stat_case("java", D "/java/cacerts");
    stat_case("absent", D "/no-such-cert.pem");
    char *rp = realpath(D, 0);
    printf("realpath dir: %s\n", rp ? rp : en(errno));
    free(rp);

    /* Debian's OPENSSLDIR names the directory through a link in the tree */
    snprintf(p, sizeof p, "/usr/lib/ssl/certs/%s", hash);
    stat_case("libssl_hash", p);
    /* .. out of the directory, and through it */
    stat_case("cnf", "/etc/ssl/openssl.cnf");
    stat_case("dotdot_cnf", D "/../openssl.cnf");
    stat_case("dotdot_dir", D "/..");
    snprintf(p, sizeof p, D "/%s/..", hash);
    stat_case("hash_dotdot", p);
    snprintf(p, sizeof p, D "/./%s", hash);
    stat_case("dot_hash", p);

    /* openat2's resolve flags on the links */
    o2("nosym hash", AT_FDCWD, hp, R_NO_SYMLINKS);
    o2("noxdev hash", AT_FDCWD, hp, R_NO_XDEV);
    o2("noxdev dir", AT_FDCWD, D, R_NO_XDEV);
    int dfd = open(D, O_PATH | O_DIRECTORY);
    if (dfd < 0) printf("open dir: %s\n", en(errno));
    o2("beneath hash", dfd, hash, R_BENEATH);
    o2("beneath pem", dfd, pem, R_BENEATH);
    o2("inroot pem", dfd, pem, R_IN_ROOT);
    o2("inroot bundle", dfd, "ca-certificates.crt", R_IN_ROOT);
    o2("beneath dotdot", dfd, "../openssl.cnf", R_BENEATH);
    o2("noxdev rel hash", dfd, hash, R_NO_XDEV);
    o2("noxdev rel dotdot", dfd, "..", R_NO_XDEV);
    /* the root as the scope: an absolute target leaves it all the same (nd_jump_root) */
    int rfd = open("/", O_PATH | O_DIRECTORY);
    snprintf(p, sizeof p, "etc/ssl/certs/%s", pem);
    o2("beneath root pem", rfd, p, R_BENEATH);
    o2("inroot root pem", rfd, p, R_IN_ROOT);
    snprintf(p, sizeof p, "etc/ssl/certs/%s", hash);
    o2("beneath root hash", rfd, p, R_BENEATH);
    o2("beneath root bundle", rfd, "etc/ssl/certs/ca-certificates.crt", R_BENEATH);
    if (dfd >= 0) {
        snprintf(p, sizeof p, "/proc/self/fd/%d", dfd);
        char t[PATH_MAX];
        ssize_t n = readlink(p, t, sizeof t - 1);
        printf("fd link dir: %.*s\n", n < 0 ? 0 : (int)n, t);
        int fd = openat(dfd, hash, O_RDONLY);
        if (fd < 0) printf("openat hash: %s\n", en(errno));
        else {
            head("openat hash", fd);
            close(fd);
        }
    }

    /* a create in the directory: the host's answer for this user */
    int fd = open(D "/exclave-trustdir-new", O_WRONLY | O_CREAT | O_EXCL, 0644);
    printf("creat: %s\n", fd < 0 ? en(errno) : "ok");
    if (fd >= 0) {
        close(fd);
        unlink(D "/exclave-trustdir-new");
    }
    printf("unlink absent: %s\n", unlink(D "/no-such-cert.pem") ? en(errno) : "ok");
    printf("rename hash to tmp: %s\n", rename(hp, "/tmp/exclave-trustdir-x") ? en(errno) : "ok");

    /* from inside the directory */
    if (chdir(D)) printf("chdir: %s\n", en(errno));
    else {
        char c[PATH_MAX];
        printf("getcwd: %s\n", getcwd(c, sizeof c) ? c : en(errno));
        int f2 = open(hash, O_RDONLY);
        if (f2 < 0) printf("relative hash: %s\n", en(errno));
        else {
            head("relative hash", f2);
            close(f2);
        }
        struct stat st;
        printf("relative dotdot cnf: %s\n", stat("../openssl.cnf", &st) ? en(errno) : "ok");
    }
    return 0;
}
