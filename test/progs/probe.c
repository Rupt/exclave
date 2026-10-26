/* probe.c — the interpreter of the differential syscall probe (DESIGN.md 17, item 7).
 *
 * Reads cases from stdin, one per line: an id, a syscall number, then up to six encoded arguments. Each case
 * is issued through syscall(2), so that no libc wrapper stands between the case and the kernel (or the
 * launcher), and answered on stdout as "<id> ret=<r> errno=<e>[ open=<errno>][ data=<...>]". The same binary
 * runs under bwrap and under the launcher; the driver (test/oracle_syscalls.py) compares the two answers.
 *
 *   i:<decimal>          an integer, passed as a long
 *   s:<hex>              a NUL-terminated string in a fresh buffer
 *   e:<hex>              the bytes at the very end of a mapped page, the next page unmapped, no NUL
 *   n:                   a null pointer
 *   u:                   a pointer into an unmapped page
 *   f:<flags>:<hex>      a descriptor from open(path, flags), made before the call and closed after it;
 *                        -1 when the open fails, with open=<errno> in the answer
 *   b:<kind>:<size>      a writable buffer of <size> bytes, printed after the call by its kind:
 *                        link, xattr: the ret bytes as hex; cwd: the string; stat: type, permissions and
 *                        the size of a regular file or symlink; statx: the same; raw: nothing
 *   t:<s>,<ns>,<s>,<ns>  a struct timespec[2]; T: the same as struct timeval[2]; U:<s>,<s> a struct utimbuf
 *   v:<hex>,<hex>,...    a NULL-terminated vector of strings (execve's argv and envp); v: is the empty vector
 *   x:<hex>:<flags>      a struct xattr_args whose value is the bytes (setxattrat, getxattrat)
 *   I:                   a descriptor from inotify_init1(0), closed after the call
 *   k:<type>            a unix socket of that type, opened before the call (-1 when it fails)
 *   A:<hex>             a struct sockaddr_un, AF_UNIX, whose sun_path holds those bytes (at most 108, unterminated at 108)
 *   h:<flags>:<mode>:<resolve>[:<size>[:<tail>]]   a struct open_how (openat2), in a buffer of <size> bytes (24 by
 *                        default) whose byte 24 is <tail> when given: the extensible-struct rules
 *
 * execve and execveat run in a forked child (ret is the wait status: the exec'd program's exit, or
 * 100 + errno when the exec returned); a descriptor that open, openat or creat returned is closed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utime.h>
#include <stdint.h>

#ifndef SYS_open
#define SYS_open -1
#endif
#ifndef SYS_creat
#define SYS_creat -1
#endif

struct arg { long v; char kind; char *buf; size_t size; char bkind[8]; int fd; int open_errno; void *map; size_t maplen; };

static int unhex(const char *h, char *out)
{
    int n = 0;
    for (; h[0] && h[1] && h[0] != ':' && h[0] != ','; h += 2) {
        unsigned b; if (sscanf(h, "%2x", &b) != 1) return -1;
        out[n++] = (char)b;
    }
    return n;
}

static long page;

static void decode(struct arg *a, char *tok)
{
    memset(a, 0, sizeof *a); a->fd = -1;
    a->kind = tok[0];
    char *p = tok + 2;
    switch (tok[0]) {
    case 'i': a->v = strtol(p, 0, 10); break;
    case 's': { a->buf = calloc(1, strlen(p) / 2 + 2); a->size = (size_t)unhex(p, a->buf); a->v = (long)a->buf; break; }
    case 'e': { size_t n = strlen(p) / 2; a->maplen = (size_t)page * 2; a->map = mmap(0, a->maplen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                mprotect((char *)a->map + page, (size_t)page, PROT_NONE); char *at = (char *)a->map + page - n; unhex(p, at); a->v = (long)at; break; }
    case 'n': a->v = 0; break;
    case 'I': a->fd = (int)syscall(SYS_inotify_init1, 0); a->open_errno = a->fd < 0 ? errno : 0; a->v = a->fd; break;
    case 'k': a->fd = socket(AF_UNIX, (int)strtol(p, 0, 10), 0); a->open_errno = a->fd < 0 ? errno : 0; a->v = a->fd; break;
    case 'A': { a->buf = calloc(1, 4096); struct sockaddr_un *u = (struct sockaddr_un *)a->buf; u->sun_family = AF_UNIX;   /* the driver keeps the path to 108 bytes */
                a->size = (size_t)unhex(p, u->sun_path); a->v = (long)a->buf; break; }
    case 'h': { unsigned long long f = 0, m = 0, rs = 0; long size = 24, tail = -1; sscanf(p, "%llu:%llu:%llu:%ld:%ld", &f, &m, &rs, &size, &tail);
                if (size < 24) size = 24;
                a->buf = calloc(1, (size_t)size + 8); unsigned long long *h = (unsigned long long *)a->buf; h[0] = f; h[1] = m; h[2] = rs;
                if (tail >= 0 && size > 24) a->buf[24] = (char)tail;
                a->v = (long)a->buf; break; }
    case 'u': { a->maplen = (size_t)page; a->map = mmap(0, a->maplen, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); a->v = (long)a->map + 16; break; }
    case 'f': { long fl = strtol(p, &p, 10); char path[8192]; int n = unhex(p + 1, path); path[n] = 0;
                a->fd = open(path, (int)fl); a->open_errno = a->fd < 0 ? errno : 0; a->v = a->fd; break; }
    case 'b': { char *c = strchr(p, ':'); size_t k = (size_t)(c - p); if (k > 7) k = 7; memcpy(a->bkind, p, k); a->size = (size_t)strtol(c + 1, 0, 10);
                a->buf = calloc(1, a->size + 8); a->v = (long)a->buf; break; }
    case 't': { struct timespec *ts = calloc(2, sizeof *ts); sscanf(p, "%ld,%ld,%ld,%ld", &ts[0].tv_sec, &ts[0].tv_nsec, &ts[1].tv_sec, &ts[1].tv_nsec); a->buf = (char *)ts; a->v = (long)ts; break; }
    case 'T': { struct timeval *tv = calloc(2, sizeof *tv); sscanf(p, "%ld,%ld,%ld,%ld", &tv[0].tv_sec, &tv[0].tv_usec, &tv[1].tv_sec, &tv[1].tv_usec); a->buf = (char *)tv; a->v = (long)tv; break; }
    case 'U': { struct utimbuf *u = calloc(1, sizeof *u); sscanf(p, "%ld,%ld", &u->actime, &u->modtime); a->buf = (char *)u; a->v = (long)u; break; }
    case 'v': { int n = 0; char **vec = calloc(64, sizeof *vec);
                while (*p && n < 62) { char *s = calloc(1, strlen(p) / 2 + 2); unhex(p, s); vec[n++] = s; char *c = strchr(p, ','); if (!c) break; p = c + 1; }
                a->buf = (char *)vec; a->v = (long)vec; break; }
    case 'x': { struct { uint64_t value; uint32_t size, flags; } *xa = calloc(1, 16); char *val = calloc(1, strlen(p) / 2 + 2); int n = unhex(p, val);
                char *c = strchr(p, ':'); xa->value = (uint64_t)val; xa->size = (uint32_t)n; xa->flags = c ? (uint32_t)strtol(c + 1, 0, 10) : 0;
                a->buf = (char *)xa; a->v = (long)xa; break; }
    default: a->v = 0;
    }
}

static void hex(const char *b, long n)
{
    for (long i = 0; i < n; i++) printf("%02x", (unsigned char)b[i]);
}

static void show(struct arg *a, long ret)
{
    if (a->kind != 'b') return;
    if (!strcmp(a->bkind, "link") || !strcmp(a->bkind, "xattr")) { if (ret > 0 && (size_t)ret <= a->size) { printf(" data="); hex(a->buf, ret); } }
    else if (!strcmp(a->bkind, "cwd")) { if (ret > 0) { printf(" data="); hex(a->buf, ret - 1); } }
    else if (!strcmp(a->bkind, "stat") && ret == 0) {
        struct stat *st = (struct stat *)a->buf;
        printf(" data=mode=%o", (unsigned)st->st_mode);                 /* no uid: a user namespace shows root's files as nobody's */
        if (S_ISREG(st->st_mode) || S_ISLNK(st->st_mode)) printf(",size=%lld", (long long)st->st_size);
    } else if (!strcmp(a->bkind, "statx") && ret == 0) {
        unsigned char *x = (unsigned char *)a->buf; unsigned mode = x[28] | (x[29] << 8); long long size; memcpy(&size, x + 40, 8);
        printf(" data=mode=%o", mode);
        if (S_ISREG(mode) || S_ISLNK(mode)) printf(",size=%lld", size);
    }
}

#define RESOLVE_BENEATH 0x08
#define RESOLVE_IN_ROOT 0x10
#define RESOLVE_CACHED 0x20
static int scoped_uncached(const struct arg *a)                       /* an open_how whose walk is scoped and not RESOLVE_CACHED */
{
    if (a->kind != 'h' || !a->buf) return 0;
    unsigned long long rs = ((const unsigned long long *)a->buf)[2];
    return (rs & (RESOLVE_BENEATH | RESOLVE_IN_ROOT)) && !(rs & RESOLVE_CACHED);
}

int main(void)
{
    page = sysconf(_SC_PAGESIZE);
    static char line[65536];
    setvbuf(stdout, 0, _IOLBF, 0);
    while (fgets(line, sizeof line, stdin)) {
        size_t n = strlen(line); if (n && line[n - 1] == '\n') line[--n] = 0;
        if (!n || line[0] == '#') continue;
        char *save = 0, *id = strtok_r(line, " ", &save), *nrs = strtok_r(0, " ", &save);
        if (!id || !nrs) continue;
        long nr = strtol(nrs, 0, 10);
        struct arg args[6]; int na = 0; char *tok;
        while (na < 6 && (tok = strtok_r(0, " ", &save))) decode(&args[na++], tok);
        for (int i = na; i < 6; i++) { memset(&args[i], 0, sizeof args[i]); args[i].fd = -1; }
        long ret; int err = 0, opened = 0;
        for (int i = 0; i < na; i++) if (args[i].kind == 'f' && args[i].open_errno) opened = args[i].open_errno;
        if (nr == SYS_execve || nr == SYS_execveat) {
            fflush(stdout);
            pid_t pid = fork();
            if (pid == 0) {
                int dn = open("/dev/null", O_RDONLY); if (dn >= 0) { dup2(dn, 0); close(dn); }   /* a shell exec'd here must not eat the cases */
                syscall(nr, args[0].v, args[1].v, args[2].v, args[3].v, args[4].v, args[5].v); _exit(100 + (errno & 0xff));
            }
            int st = -1; waitpid(pid, &st, 0); ret = st; err = 0;
        } else {
            errno = 0;
            ret = syscall(nr, args[0].v, args[1].v, args[2].v, args[3].v, args[4].v, args[5].v);
            /* openat2(2): a scoped walk (RESOLVE_BENEATH, RESOLVE_IN_ROOT) answers EAGAIN when a rename or a mount anywhere on
             * the system raced it, and tells the caller to retry; this caller does, so the kernel's answer is the retry's.
             * RESOLVE_CACHED's EAGAIN is not a race and is not retried. */
            for (int tries = 0; nr == SYS_openat2 && ret < 0 && errno == EAGAIN && tries < 1000 && scoped_uncached(&args[2]); tries++) {
                errno = 0;
                ret = syscall(nr, args[0].v, args[1].v, args[2].v, args[3].v, args[4].v, args[5].v);
            }
            err = ret < 0 ? errno : 0;
            if (ret >= 0 && (nr == SYS_open || nr == SYS_openat || nr == SYS_creat || nr == SYS_openat2)) { close((int)ret); ret = 0; }
        }
        printf("%s ret=%ld errno=%d", id, ret, err);
        if (opened) printf(" open=%d", opened);
        for (int i = 0; i < na; i++) show(&args[i], ret);
        printf("\n");
        for (int i = 0; i < na; i++) {
            if (args[i].fd >= 0) close(args[i].fd);
            if (args[i].map) munmap(args[i].map, args[i].maplen);
            if (args[i].kind == 'v') { char **v = (char **)args[i].buf; for (int k = 0; v[k]; k++) free(v[k]); }
            if (args[i].kind == 'x') free((void *)(uintptr_t)((uint64_t *)args[i].buf)[0]);
            free(args[i].buf);
        }
    }
    return 0;
}
