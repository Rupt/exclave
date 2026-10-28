/* main.c — the exclave command's entry: its commands, and what every one shares (DESIGN.md 10).
 *
 *     exclave check EXCLAVE [LOG...]      Wrappers, originals, the tree against its recorded hash and the static
 *                                         check; with EXCLAVE_LOG files, the dynamic check of what a workload opened.
 *     exclave format [--check] FILE...    Parse with the strict grammar and rewrite in canonical form; --check
 *                                         only reports.
 *     exclave hash EXCLAVE                The tree hash of 6.4.
 *     exclave prune EXCLAVE LOG...        Drop every file no logged workload touched (10.4).
 *     exclave relink EXCLAVE [LAUNCHER]   Replace the launcher and relink every wrapper.
 *     exclave unwrap EXCLAVE              Move every original back over its wrapper.
 *     exclave wrap EXCLAVE                Wrap an exclave: add the launcher and the placeholders where missing, check
 *                                         the manifest, the wrappers and every ELF, then wrap every executable and
 *                                         write the launcher, manifest and tree hashes to .exclave/hashes. */
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

_Noreturn void usage(const char *line)
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

/* Each file is a manifest or a hashes file by its first record, not its name (6.5). */
int cmd_format(int argc, char **argv)
{
    int check = 0, files = 0, options = 1;
    for (int i = 0; i < argc; i++) {
        size_t k = strlen(argv[i]);
        if (options && !strcmp(argv[i], "--")) options = 0;
        else if (options && k > 2 && !strncmp(argv[i], "--check", k)) /* any prefix, as argparse takes one */ check = 1;
        else if (options && argv[i][0] == '-' && argv[i][1]) usage("format [--check] FILE...");
        else argv[files++] = argv[i];
    }
    if (!files) usage("format [--check] FILE...");
    int rc = 0;
    for (int i = 0; i < files; i++) {
        size_t n;
        char *data = read_file(argv[i], &n), err[GRAMMAR_ERR];
        const char *first = data; /* the first line that is neither empty nor a comment */
        while (first < data + n && (*first == '\n' || *first == '#')) {
            const char *lf = memchr(first, '\n', (size_t)(data + n - first));
            first = lf ? lf + 1 : data + n;
        }
        enum kind kind = !strncmp(first, "hashes ", 7) ? KIND_HASHES : KIND_MANIFEST;
        struct records rs;
        if (grammar_parse(data, n, kind, &rs, err)) {
            printf("%s: %s\n", argv[i], err);
            rc = 1;
            free(data);
            continue;
        }
        struct buf canon = {0};
        grammar_dump(&rs, kind, &canon);
        records_free(&rs);
        if (canon.n != n || memcmp(canon.p, data, n) != 0) {
            if (check) {
                printf("%s: not canonical\n", argv[i]);
                rc = 1;
            } else {
                FILE *f = fopen(argv[i], "wb");
                if (!f || fwrite(canon.p, 1, canon.n, f) != canon.n || fclose(f)) fail_errno(argv[i]);
                printf("%s: rewritten\n", argv[i]);
            }
        }
        free(canon.p);
        free(data);
    }
    return rc;
}

int main(int argc, char **argv)
{
    static const struct {
        const char *name;
        int (*run)(int, char **);
    } commands[] = {
        {"check", cmd_check},   {"format", cmd_format}, {"hash", cmd_hash}, {"prune", cmd_prune},
        {"relink", cmd_relink}, {"unwrap", cmd_unwrap}, {"wrap", cmd_wrap},
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
