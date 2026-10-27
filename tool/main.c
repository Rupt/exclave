/* main.c — the exclave command's entry: its commands, and what every one shares (DESIGN.md 10).
 *
 *     exclave hash EXCLAVE    The tree hash of 6.4. */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) fail("out of memory");
    return q;
}

void buf_add(struct buf *b, const void *data, size_t n)
{
    if (!n) return;
    if (b->n + n > b->cap) {
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

static _Noreturn void usage(const char *line)
{
    fprintf(stderr, "usage: exclave %s\n", line);
    exit(2);
}

int cmd_hash(int argc, char **argv)
{
    if (argc != 1) usage("hash EXCLAVE");
    require_exclave(argv[0], "hash");
    char *root = path_join(argv[0], "tree"), text[B2_TEXT];
    tree_hash(root, text);
    printf("%s\n", text);
    free(root);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct {
        const char *name;
        int (*run)(int, char **);
    } commands[] = {
        {"hash", cmd_hash},
    };
    if (argc < 2) usage("COMMAND ARGS...");
    for (size_t i = 0; i < sizeof commands / sizeof *commands; i++)
        if (!strcmp(argv[1], commands[i].name)) {
            int rc = commands[i].run(argc - 2, argv + 2);
            if (fflush(stdout)) fail("standard output: %s", strerror(errno));
            return rc;
        }
    fprintf(stderr, "exclave: unknown command %s\n", argv[1]);
    return 2;
}
