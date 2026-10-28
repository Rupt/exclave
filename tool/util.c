/* util.c — what every command shares (DESIGN.md 10): a refusal, which prints one line and exits; memory that is
 * never short; a byte string that grows; a path joined; a file read whole. */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tool.h"

_Noreturn void fail(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("exclave: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

_Noreturn void fail_errno(const char *path) { fail("%s: %s", path, strerror(errno)); }

_Noreturn void fail_grammar(const char *err)
{
    fprintf(stderr, "grammar: %s\n", err);
    exit(1);
}

_Noreturn void usage(const char *line)
{
    fprintf(stderr, "usage: exclave %s\n", line);
    exit(2);
}

void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) fail("out of memory");
    return q;
}

void buf_add(struct buf *b, const void *data, size_t n)
{
    if (!n) return;
    if (!b->p || n > b->cap - b->n) { /* a buffer without memory grows, whatever its counts say */
        b->cap = b->n + n > 2 * b->cap ? b->n + n + 64 : 2 * b->cap;
        b->p = xrealloc(b->p, b->cap);
    }
    memcpy(b->p + b->n, data, n);
    b->n += n;
}

void buf_str(struct buf *b, const char *s) { buf_add(b, s, strlen(s)); }

char *path_join(const char *a, const char *b)
{
    struct buf p = {0};
    buf_str(&p, a);
    if (p.n && p.p[p.n - 1] != '/') buf_add(&p, "/", 1);
    buf_str(&p, b);
    buf_add(&p, "", 1);
    return p.p;
}

char *read_file(const char *path, size_t *n)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) fail_errno(path);
    struct buf b = {0};
    char chunk[1 << 16];
    for (;;) {
        ssize_t k = read(fd, chunk, sizeof chunk);
        if (k < 0) fail_errno(path);
        if (k == 0) break;
        buf_add(&b, chunk, (size_t)k);
    }
    close(fd);
    *n = b.n;
    buf_add(&b, "", 1);
    return b.p;
}
