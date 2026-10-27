/* decompress_test.c — the command's decoders (tool/decompress.c, tool/inflate.c) as a filter, for
 * test/decompress_test.py: `decompress_test zstd|xz|gzip` reads standard input and writes what it decompresses to,
 * exit 0, or the reason to standard error, exit 1. Built by scripts/gate's unit step under ASan and UBSan. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../tool/tool.h"

/* what the decoders use of tool/main.c */
_Noreturn void fail(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
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
    if (b->n + n > b->cap) {
        b->cap = b->n + n > 2 * b->cap ? b->n + n + 64 : 2 * b->cap;
        b->p = xrealloc(b->p, b->cap);
    }
    memcpy(b->p + b->n, data, n);
    b->n += n;
}

int main(int argc, char **argv)
{
    if (argc != 2) fail("usage: decompress_test zstd|xz|gzip\n");
    struct buf in = {0}, out = {0};
    char chunk[1 << 16], why[INFLATE_WHY];
    for (ssize_t k; (k = read(0, chunk, sizeof chunk)) > 0;) buf_add(&in, chunk, (size_t)k);
    int (*decode)(const uint8_t *, size_t, struct buf *, char *) = !strcmp(argv[1], "zstd") ? unzstd
                                                                   : !strcmp(argv[1], "xz") ? unxz
                                                                                            : gunzip;
    int rc = decode((const uint8_t *)in.p, in.n, &out, why) ? 1 : 0;
    if (rc) fprintf(stderr, "%s\n", why);
    else if (out.n && fwrite(out.p, 1, out.n, stdout) != out.n) rc = 2;
    free(in.p);
    free(out.p);
    return rc;
}
