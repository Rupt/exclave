/* grammar.c — the strict grammar of the manifest and the hashes file (DESIGN.md 6.2, 6.4).
 *
 * Both files are lines of records: a lowercase key, then fields separated by single spaces, each a bare token or a
 * double-quoted string. grammar_parse accepts exactly one spelling of each file and grammar_dump produces it, so a
 * file that grammar_parse accepts and grammar_dump reproduces byte for byte is canonical. The launcher's own parser
 * (src/manifest.c) reads the manifest into its tables; test/grammar_test.py holds the two to the same answers. */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tool.h"

/* each key: the file it belongs to, its place in that file's order, its fields (s a string, t a token), and whether
 * it may appear once only */
static const struct {
    const char *key;
    enum kind kind;
    int order;
    const char *fields;
    int once;
} SCHEMA[] = {
    /* clang-format off */
    {"exclave",  KIND_MANIFEST, 0, "t",    1},
    {"cpu",      KIND_MANIFEST, 1, "s",    1},
    {"data",     KIND_MANIFEST, 2, "s",    0},
    {"host",     KIND_MANIFEST, 3, "s",    0},
    {"own",      KIND_MANIFEST, 4, "s",    0},
    {"hashes",   KIND_HASHES,   0, "t",    1},
    {"tool",     KIND_HASHES,   1, "s",    1},
    {"launcher", KIND_HASHES,   2, "s",    1},
    {"pkg",      KIND_HASHES,   3, "ssss", 0},
    {"manifest", KIND_HASHES,   4, "s",    1},
    {"tree",     KIND_HASHES,   5, "s",    1},
    /* clang-format on */
};
#define NSCHEMA (sizeof SCHEMA / sizeof *SCHEMA)
/* the launcher's tables (8.1): the most records of each key a manifest may carry */
static const struct {
    const char *key;
    int most;
} LIMITS[] = {{"own", 256}, {"host", 32}, {"data", 32}};
/* the most bytes a field holds, a string's decoded: a path the launcher's buffers hold, which a longer one would not
 * fit in the kernel's either (6.2) */
#define FIELD_MAX (PATH_MAX - 1)

const char *kind_name(enum kind kind) { return kind == KIND_HASHES ? "hashes" : "exclave"; }

static int schema_of(const char *key, enum kind kind)
{
    for (size_t i = 0; i < NSCHEMA; i++)
        if (SCHEMA[i].kind == kind && !strcmp(SCHEMA[i].key, key)) return (int)i;
    return -1;
}

/* the length of the well-formed UTF-8 sequence at b[i], or 0 if it is malformed: no overlong forms, no surrogates,
 * nothing above U+10FFFF (Unicode's table 3-7) */
static size_t utf8_len(const unsigned char *b, size_t i, size_t n)
{
    unsigned c = b[i];
    size_t left = n - i;
    if (c < 0x80) return 1;
    if (c < 0xC2) return 0;
    if (c < 0xE0) return left >= 2 && b[i + 1] >= 0x80 && b[i + 1] <= 0xBF ? 2 : 0;
    if (c < 0xF0) {
        if (left < 3 || b[i + 2] < 0x80 || b[i + 2] > 0xBF) return 0;
        unsigned lo = c == 0xE0 ? 0xA0 : 0x80, hi = c == 0xED ? 0x9F : 0xBF;
        return b[i + 1] >= lo && b[i + 1] <= hi ? 3 : 0;
    }
    if (c < 0xF5) {
        if (left < 4 || b[i + 2] < 0x80 || b[i + 2] > 0xBF || b[i + 3] < 0x80 || b[i + 3] > 0xBF) return 0;
        unsigned lo = c == 0xF0 ? 0x90 : 0x80, hi = c == 0xF4 ? 0x8F : 0xBF;
        return b[i + 1] >= lo && b[i + 1] <= hi ? 4 : 0;
    }
    return 0;
}

int utf8_valid(const char *s, size_t n)
{
    for (size_t i = 0; i < n;) {
        size_t k = utf8_len((const unsigned char *)s, i, n);
        if (!k) return 0;
        i += k;
    }
    return 1;
}

/* the code point of the well-formed sequence of length k at p */
static unsigned code_point(const unsigned char *p, size_t k)
{
    if (k == 1) return p[0];
    unsigned v = p[0] & (0x7FU >> k);
    for (size_t j = 1; j < k; j++) v = (v << 6) | (p[j] & 0x3FU);
    return v;
}

static int failed(char err[GRAMMAR_ERR], int line, size_t col, const char *why)
{
    snprintf(err, GRAMMAR_ERR, "line %d col %zu: %s", line, col, why);
    return -1;
}

/* the column of raw[i], counted in characters from 1 as the launcher counts it (6.2); the line is well-formed UTF-8,
 * so every byte that is not a continuation byte starts a character */
static size_t column(const unsigned char *raw, size_t i)
{
    size_t c = 1;
    for (size_t j = 0; j < i; j++) c += (raw[j] & 0xC0) != 0x80;
    return c;
}

static int is_token_char(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' ||
           c == '+' || c == '-';
}

/* the quoted string at raw[*col], its opening quote; its value into f, *col past its closing quote */
static int parse_string(const unsigned char *raw, size_t len, size_t *col, int line, struct field *f, char *err)
{
    struct buf v = {0};
    size_t c = *col + 1;
    for (;;) {
        if (c >= len) return free(v.p), failed(err, line, column(raw, c), "unterminated string");
        unsigned char ch = raw[c];
        if (ch == '"') break;
        if (ch == '\\') {
            unsigned char e = c + 1 < len ? raw[c + 1] : 0, b;
            size_t step = 2;
            if (e == '\\' || e == '"') {
                b = e;
            } else if (e == 'n' || e == 't') {
                b = e == 'n' ? '\n' : '\t';
            } else if (e == 'x') {
                static const char hex[] = "0123456789abcdef";
                const char *h1 = c + 2 < len && raw[c + 2] ? strchr(hex, raw[c + 2]) : NULL;
                const char *h2 = c + 3 < len && raw[c + 3] ? strchr(hex, raw[c + 3]) : NULL;
                if (!h1 || !h2)
                    return free(v.p), failed(err, line, column(raw, c), "\\x needs two lowercase hex digits");
                b = (unsigned char)((h1 - hex) * 16 + (h2 - hex));
                step = 4;
            } else {
                return free(v.p), failed(err, line, column(raw, c), "unknown escape");
            }
            if (v.n + 1 > FIELD_MAX) return free(v.p), failed(err, line, column(raw, c), "string too long");
            buf_add(&v, &b, 1);
            c += step;
            continue;
        }
        size_t k = utf8_len(raw, c, len);
        unsigned o = code_point(raw + c, k);
        if (o < 0x20 || (o >= 0x7F && o <= 0x9F))
            return free(v.p), failed(err, line, column(raw, c), "control character must be escaped");
        if (v.n + k > FIELD_MAX) return free(v.p), failed(err, line, column(raw, c), "string too long");
        buf_add(&v, raw + c, k);
        c += k;
    }
    buf_add(&v, "", 1); /* a NUL past the value, which may hold NULs itself */
    f->type = 's';
    f->v = v.p;
    f->n = v.n - 1;
    *col = c + 1;
    return 0;
}

static int normalised_abs(const struct field *f)
{
    const char *b = f->v;
    size_t n = f->n;
    if (!n || b[0] != '/' || memchr(b, 0, n)) return 0;
    if (n == 1) return 1;
    if (b[n - 1] == '/') return 0;
    for (size_t i = 1; i <= n;) { /* every component after the first slash */
        const char *end = memchr(b + i, '/', n - i);
        size_t k = end ? (size_t)(end - (b + i)) : n - i;
        if (k == 0 || (k == 1 && b[i] == '.') || (k == 2 && b[i] == '.' && b[i + 1] == '.')) return 0;
        i += k + 1;
    }
    return 1;
}

static int check_record(const struct record *r, enum kind kind, char *err)
{
    char why[GRAMMAR_ERR - 32];
    int s = schema_of(r->key, kind);
    if (s < 0) {
        snprintf(why, sizeof why, "unknown key %s", r->key);
        return failed(err, r->line, 1, why);
    }
    const char *want = SCHEMA[s].fields;
    int ok = r->nf == (int)strlen(want);
    for (int i = 0; ok && i < r->nf; i++) ok = r->f[i].type == want[i];
    if (!ok) {
        snprintf(why, sizeof why, "wrong field count or type for %s", r->key);
        return failed(err, r->line, 1, why);
    }
    /* every key has a field, which the schema has just checked */
    const struct field *f0 = r->nf ? &r->f[0] : NULL;
    if ((!strcmp(r->key, "own") || !strcmp(r->key, "host") || !strcmp(r->key, "data")) && f0 && !normalised_abs(f0)) {
        snprintf(why, sizeof why, "%s must be a normalised absolute path", r->key);
        return failed(err, r->line, 1, why);
    }
    if (!strcmp(r->key, "cpu") && f0 && memchr(f0->v, 0, f0->n))
        return failed(err, r->line, 1, "cpu must not contain NUL");
    return 0;
}

void records_free(struct records *rs)
{
    for (size_t i = 0; i < rs->n; i++) {
        struct record *r = &rs->r[i];
        for (int j = 0; j < r->nf; j++) free(r->f[j].v);
        free(r->f);
        free(r->key);
        free(r->comments.p);
    }
    free(rs->r);
    *rs = (struct records){0};
}

int grammar_parse(const char *text, size_t n, enum kind kind, struct records *out, char err[GRAMMAR_ERR])
{
    const unsigned char *data = (const unsigned char *)text;
    *out = (struct records){0};
    if (!n || data[n - 1] != '\n') return failed(err, 1, 1, "file must end with LF");
    if (n >= 3 && !memcmp(data, "\xef\xbb\xbf", 3)) return failed(err, 1, 1, "byte order mark");
    int line = 1;
    for (size_t i = 0; i < n;) {
        if (data[i] == '\r') return failed(err, line, 1, "CR not allowed");
        size_t k = utf8_len(data, i, n);
        if (!k) return failed(err, line, 1, "malformed UTF-8");
        if (data[i] == '\n') line++;
        i += k;
    }
    struct buf comments = {0};
    int counts[sizeof LIMITS / sizeof *LIMITS] = {0};
    size_t cap = 0;
    line = 1;
    for (size_t pos = 0; pos < n; line++) {
        const unsigned char *raw = data + pos;
        size_t len = (size_t)((const unsigned char *)memchr(raw, '\n', n - pos) - raw);
        pos += len + 1;
        if (!len) continue;
        if (raw[0] == '#') { /* kept with the record below it; a comment may hold any character */
            size_t k = len - 1;
            buf_add(&comments, &k, sizeof k);
            buf_add(&comments, raw + 1, k);
            continue;
        }
        if (out->n == cap) {
            cap = cap ? 2 * cap : 16;
            out->r = xrealloc(out->r, cap * sizeof *out->r);
        }
        struct record *r = &out->r[out->n++];
        *r = (struct record){.line = line, .comments = comments};
        comments = (struct buf){0};
        size_t col = 0;
        while (col < len &&
               (col ? (raw[col] >= 'a' && raw[col] <= 'z') || (raw[col] >= '0' && raw[col] <= '9') || raw[col] == '-'
                    : raw[col] >= 'a' && raw[col] <= 'z'))
            col++;
        if (!col) return records_free(out), failed(err, line, 1, "record must start with a lowercase key");
        r->key = xrealloc(NULL, col + 1);
        memcpy(r->key, raw, col);
        r->key[col] = 0;
        while (col < len) {
            if (raw[col] != ' ')
                return records_free(out),
                       failed(err, line, column(raw, col),
                              raw[col] == '\t' ? "tab outside a string" : "expected a single space between fields");
            col++;
            if (col >= len) return records_free(out), failed(err, line, column(raw, col), "trailing space");
            if (raw[col] == ' ') return records_free(out), failed(err, line, column(raw, col), "multiple spaces");
            r->f = xrealloc(r->f, (size_t)(r->nf + 1) * sizeof *r->f);
            struct field *f = &r->f[r->nf];
            if (raw[col] == '"') {
                if (parse_string(raw, len, &col, line, f, err)) return records_free(out), -1;
            } else {
                size_t start = col;
                while (col < len && is_token_char(raw[col])) {
                    if (col - start == FIELD_MAX)
                        return records_free(out), failed(err, line, column(raw, col), "token too long");
                    col++;
                }
                if (col == start)
                    return records_free(out), failed(err, line, column(raw, col), "expected a string or token");
                f->type = 't';
                f->v = xrealloc(NULL, col - start + 1);
                memcpy(f->v, raw + start, col - start);
                f->v[col - start] = 0;
                f->n = col - start;
            }
            r->nf++;
        }
        if (check_record(r, kind, err)) return records_free(out), -1;
        /* each record's errors in the file's order, as the launcher meets them, so the two name the same line */
        if (out->n == 1 && (strcmp(r->key, kind_name(kind)) != 0 || r->nf < 1 || strcmp(r->f[0].v, "1") != 0)) {
            char why[64];
            snprintf(why, sizeof why, "first record must be %s 1", kind_name(kind));
            return records_free(out), failed(err, line, 1, why);
        }
        for (size_t j = 0; SCHEMA[schema_of(r->key, kind)].once && j + 1 < out->n; j++)
            if (!strcmp(out->r[j].key, r->key)) {
                char why[64];
                snprintf(why, sizeof why, "duplicate %s", r->key);
                return records_free(out), failed(err, line, 1, why);
            }
        /* refused here where the launcher's tables would refuse it (8.1) */
        for (size_t l = 0; kind == KIND_MANIFEST && l < sizeof LIMITS / sizeof *LIMITS; l++)
            if (!strcmp(r->key, LIMITS[l].key) && ++counts[l] > LIMITS[l].most) {
                char why[64];
                snprintf(why, sizeof why, "more than %d %s records", LIMITS[l].most, r->key);
                return records_free(out), failed(err, line, 1, why);
            }
    }
    if (comments.n) return free(comments.p), records_free(out), failed(err, line, 1, "comment after the last record");
    if (!out->n) return failed(err, line, 1, "empty file");
    return 0;
}

/* the canonical string literal for v: printable UTF-8 as itself; backslash, double quote, newline and tab by their
 * one-letter escapes; every other control character, C1 controls byte by byte, and every malformed byte as \xHH */
void grammar_quote(struct buf *out, const char *v, size_t n)
{
    const unsigned char *b = (const unsigned char *)v;
    char x[5];
    buf_add(out, "\"", 1);
    for (size_t i = 0; i < n;) {
        size_t k = utf8_len(b, i, n);
        unsigned o = k ? code_point(b + i, k) : 0;
        if (b[i] == '\\') {
            buf_add(out, "\\\\", 2);
        } else if (b[i] == '"') {
            buf_add(out, "\\\"", 2);
        } else if (b[i] == '\n') {
            buf_add(out, "\\n", 2);
        } else if (b[i] == '\t') {
            buf_add(out, "\\t", 2);
        } else if (!k || o < 0x20 || o == 0x7F || (o >= 0x80 && o <= 0x9F)) {
            for (size_t j = 0; j < (k ? k : 1); j++) {
                snprintf(x, sizeof x, "\\x%02x", b[i + j]);
                buf_add(out, x, 4);
            }
        } else {
            buf_add(out, b + i, k);
        }
        i += k ? k : 1;
    }
    buf_add(out, "\"", 1);
}

static int field_order(const struct record *a, const struct record *b)
{
    for (int i = 0; i < a->nf && i < b->nf; i++) {
        size_t n = a->f[i].n < b->f[i].n ? a->f[i].n : b->f[i].n;
        int c = memcmp(a->f[i].v, b->f[i].v, n);
        if (c) return c;
        if (a->f[i].n != b->f[i].n) return a->f[i].n < b->f[i].n ? -1 : 1;
    }
    return (a->nf > b->nf) - (a->nf < b->nf);
}

/* the records in canonical order: by key in the file's order, then by their fields' bytes, keeping file order between
 * equals */
static const struct record **sorted_records(const struct records *rs, enum kind kind)
{
    const struct record **o = (const struct record **)xrealloc(NULL, rs->n * sizeof *o);
    for (size_t i = 0; i < rs->n; i++) o[i] = &rs->r[i];
    for (size_t i = 1; i < rs->n; i++) { /* insertion sort: stable, and a file holds few records */
        const struct record *r = o[i];
        size_t j = i;
        while (j > 0) {
            const struct record *p = o[j - 1];
            int ko = SCHEMA[schema_of(p->key, kind)].order - SCHEMA[schema_of(r->key, kind)].order;
            if (ko < 0 || (ko == 0 && field_order(p, r) <= 0)) break;
            o[j] = p;
            j--;
        }
        o[j] = r;
    }
    return o;
}

void grammar_dump(const struct records *rs, enum kind kind, struct buf *out)
{
    const struct record **o = sorted_records(rs, kind);
    for (size_t i = 0; i < rs->n; i++) {
        const struct record *r = o[i];
        if (i && strcmp(o[i - 1]->key, r->key) != 0) buf_add(out, "\n", 1);
        for (size_t c = 0; c < r->comments.n;) {
            size_t k;
            memcpy(&k, r->comments.p + c, sizeof k);
            buf_add(out, "#", 1);
            buf_add(out, r->comments.p + c + sizeof k, k);
            buf_add(out, "\n", 1);
            c += sizeof k + k;
        }
        buf_str(out, r->key);
        for (int f = 0; f < r->nf; f++) {
            buf_add(out, " ", 1);
            if (r->f[f].type == 't') buf_add(out, r->f[f].v, r->f[f].n);
            else grammar_quote(out, r->f[f].v, r->f[f].n);
        }
        buf_add(out, "\n", 1);
    }
    free((void *)o);
}
