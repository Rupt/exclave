/* tar.c — the members of a tar archive held in memory, for the .apk files unpack reads (DESIGN.md 10.1).
 *
 * It reads what Python's tarfile reads: ustar headers with their prefix, old-style directories spelt as a file with a
 * trailing slash, numbers in octal or base-256, and PAX extended headers' path, linkpath, size and mtime. An archive
 * ends at its first block of NULs, or where too little is left for a header; a header that is not one ends it too,
 * unless it is the first. GNU long names, sparse files, global PAX headers and two extended headers in a row are
 * refused, which no .apk has. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tool.h"

#define BLOCK 512

static int py_space(char c) { return c == ' ' || (c >= '\t' && c <= '\r') || (c >= 0x1c && c <= 0x1f); }

/* An integer as Python's int(s, base) reads it, s without NULs: blanks about it, a sign, for base 8 a 0o prefix, and
 * digits with single underscores between them. 0, or -1 when it is none or does not fit. */
static int py_int(const char *s, size_t n, int base, int64_t *out)
{
    while (n && py_space(*s)) s++, n--;
    while (n && py_space(s[n - 1])) n--;
    int neg = 0;
    if (n && (*s == '+' || *s == '-')) neg = *s == '-', s++, n--;
    int underscore_ok = 0;
    if (base == 8 && n >= 2 && s[0] == '0' && (s[1] == 'o' || s[1] == 'O')) s += 2, n -= 2, underscore_ok = 1;
    if (!n) return -1;
    uint64_t v = 0;
    int digits = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '_' && underscore_ok && i + 1 < n) {
            underscore_ok = 0;
            continue;
        }
        int d = s[i] - '0';
        if (d < 0 || d >= base) return -1;
        if (v > (UINT64_C(1) << 62) / (uint64_t)base) return -1;
        v = v * (uint64_t)base + (uint64_t)d;
        digits++;
        underscore_ok = 1;
    }
    if (!digits || s[n - 1] == '_') return -1;
    *out = neg ? -(int64_t)v : (int64_t)v;
    return 0;
}

/* a header's number field: base-256 when its first byte says so, else octal text up to a NUL, empty for 0 */
static int number(const uint8_t *f, size_t n, int64_t *out)
{
    if (f[0] == 0x80 || f[0] == 0xff) {
        __int128 v = 0;
        for (size_t i = 1; i < n; i++) v = v << 8 | f[i];
        if (f[0] == 0xff) v -= (__int128)1 << (8 * (n - 1));
        if (v > INT64_MAX / 4 || v < -(INT64_MAX / 4)) return -1;
        *out = (int64_t)v;
        return 0;
    }
    size_t k = 0;
    while (k < n && f[k]) k++;
    for (size_t i = 0; i < k; i++)
        if (f[i] >= 0x80) return -1;
    size_t a = 0, b = k;
    while (a < b && py_space((char)f[a])) a++;
    while (b > a && py_space((char)f[b - 1])) b--;
    if (a == b) {
        *out = 0;
        return 0;
    }
    return py_int((const char *)f + a, b - a, 8, out);
}

static char *field(const uint8_t *f, size_t n)
{
    size_t k = 0;
    while (k < n && f[k]) k++;
    char *s = xrealloc(NULL, k + 1);
    memcpy(s, f, k);
    s[k] = 0;
    return s;
}

static void rstrip_slash(char *s)
{
    size_t k = strlen(s);
    while (k && s[k - 1] == '/') s[--k] = 0;
}

static int64_t block_of(int64_t size) { return (size + BLOCK - 1) / BLOCK * BLOCK; }

int tar_regular(char type) { return type == '0' || type == 0 || type == '7'; }

/* the types tarfile knows; any other is a file whose data is skipped */
static int known(char type) { return tar_regular(type) || (type && strchr("123456", type)); }

/* whether the member's data follows its header in the archive */
static int has_data(char type) { return tar_regular(type) || !known(type); }

/* GNU's long name, long link name and sparse file */
static int gnu(char type) { return type == 'L' || type == 'K' || type == 'S'; }

enum { HEADER_OK, HEADER_END, HEADER_BAD };

/* the header at off, as tarfile's frombuf reads it */
static int header(const uint8_t *p, size_t n, size_t off, int dircheck, struct tar_member *m)
{
    if (n - off < BLOCK) return HEADER_END;
    const uint8_t *h = p + off;
    size_t zero = 0;
    while (zero < BLOCK && !h[zero]) zero++;
    if (zero == BLOCK) return HEADER_END;
    int64_t sum, mode, uid, gid, size, mtime, major, minor;
    if (number(h + 148, 8, &sum)) return HEADER_BAD;
    int64_t unsigned_sum = 256, signed_sum = 256;
    for (int i = 0; i < BLOCK; i++) {
        if (i >= 148 && i < 156) continue;
        unsigned_sum += h[i];
        signed_sum += (int8_t)h[i];
    }
    if (sum != unsigned_sum && sum != signed_sum) return HEADER_BAD;
    if (number(h + 100, 8, &mode) || number(h + 108, 8, &uid) || number(h + 116, 8, &gid) ||
        number(h + 124, 12, &size) || number(h + 136, 12, &mtime) || number(h + 329, 8, &major) ||
        number(h + 337, 8, &minor))
        return HEADER_BAD;
    (void)uid, (void)gid, (void)major, (void)minor;
    *m = (struct tar_member){.type = (char)h[156], .size = size, .mode = mode, .mtime = mtime};
    m->name = field(h, 100);
    m->linkname = field(h + 157, 100);
    char *prefix = field(h + 345, 155);
    size_t k = strlen(m->name);
    if (dircheck && m->type == 0 && k && m->name[k - 1] == '/') m->type = '5';
    if (m->type == '5') rstrip_slash(m->name);
    if (*prefix && !gnu(m->type)) {
        struct buf b = {0};
        buf_str(&b, prefix);
        buf_add(&b, "/", 1);
        buf_str(&b, m->name);
        buf_add(&b, "", 1);
        free(m->name);
        m->name = b.p;
    }
    free(prefix);
    return HEADER_OK;
}

struct pax {
    char *path, *linkpath;
    int has_size, has_mtime;
    int64_t size;
    double mtime;
};

/* A decimal number as Python's float() reads the plain spellings: a sign, digits, a point, an exponent. 0, or -1 for
 * anything else, which tarfile takes as 0. */
static int py_float(const char *s, double *out)
{
    size_t n = strlen(s);
    while (n && py_space(*s)) s++, n--;
    while (n && py_space(s[n - 1])) n--;
    if (!n || n > 64) return -1;
    char text[65];
    memcpy(text, s, n);
    text[n] = 0;
    int digits = 0;
    for (size_t i = 0; i < n; i++) {
        char c = text[i];
        if (c >= '0' && c <= '9') digits = 1;
        else if (!strchr("+-.eE", c)) return -1;
    }
    char *end;
    double v = strtod(text, &end);
    if (!digits || *end || !isfinite(v)) return -1;
    *out = v;
    return 0;
}

/* the records of an extended header, "LENGTH KEY=VALUE\n" each, in its data rounded up to blocks; 0, or -1 when one
 * is malformed */
static int pax_records(const uint8_t *d, size_t n, struct pax *x, const char **err)
{
    size_t pos = 0;
    while (pos < n && d[pos]) {
        size_t i = pos, len = 0;
        while (i < n && i - pos < 20 && d[i] >= '0' && d[i] <= '9') len = len * 10 + (size_t)(d[i++] - '0');
        if (i == pos || i >= n || d[i] != ' ') return -1;
        if (len < 5 || len > n - pos) return -1;
        size_t kv = i + 1, last = pos + len - 1;
        if (kv > last || d[last] != '\n') return -1;
        const uint8_t *eq = memchr(d + kv, '=', last - kv);
        if (!eq || eq == d + kv) return -1;
        size_t klen = (size_t)(eq - (d + kv)), vlen = last - (size_t)(eq - d) - 1;
        const char *key = (const char *)d + kv, *val = (const char *)eq + 1;
        if (memchr(val, 0, vlen) &&
            ((klen == 4 && !memcmp(key, "path", 4)) || (klen == 8 && !memcmp(key, "linkpath", 8)))) {
            *err = "a NUL in an extended header's path";
            return -2;
        }
        char *v = xrealloc(NULL, vlen + 1);
        memcpy(v, val, vlen);
        v[vlen] = 0;
        if (klen == 4 && !memcmp(key, "path", 4)) {
            free(x->path);
            x->path = v;
            v = NULL;
        } else if (klen == 8 && !memcmp(key, "linkpath", 8)) {
            free(x->linkpath);
            x->linkpath = v;
            v = NULL;
        } else if (klen == 4 && !memcmp(key, "size", 4)) {
            x->has_size = 1;
            if (memchr(val, 0, vlen) || py_int(v, vlen, 10, &x->size)) x->size = 0;
        } else if (klen == 5 && !memcmp(key, "mtime", 5)) {
            x->has_mtime = 1;
            if (memchr(val, 0, vlen) || py_float(v, &x->mtime)) x->mtime = 0;
        } else if (klen > 10 && !memcmp(key, "GNU.sparse", 10)) {
            free(v);
            *err = "a GNU sparse file";
            return -2;
        }
        free(v);
        pos += len;
    }
    return 0;
}

static void add(struct tar *t, const struct tar_member *m)
{
    t->m = xrealloc(t->m, (t->n + 1) * sizeof *t->m);
    t->m[t->n++] = *m;
}

void tar_free(struct tar *t)
{
    for (size_t i = 0; i < t->n; i++) {
        free(t->m[i].name);
        free(t->m[i].linkname);
    }
    free(t->m);
    *t = (struct tar){0};
}

static int refuse(char why[TAR_WHY], const char *what)
{
    snprintf(why, TAR_WHY, "%s", what);
    return -1;
}

int tar_read(const uint8_t *p, size_t n, struct tar *out, char why[TAR_WHY])
{
    *out = (struct tar){0};
    size_t off = 0;
    for (;;) {
        if (off > n) return refuse(why, "unexpected end of data");
        struct tar_member m;
        int r = header(p, n, off, 1, &m);
        if (r == HEADER_END && off == 0 && n - off < BLOCK) return refuse(why, n ? "truncated header" : "empty file");
        if (r == HEADER_END) return 0;
        if (r == HEADER_BAD) return off == 0 ? refuse(why, "invalid header") : 0;
        if (m.size < 0) {
            free(m.name);
            free(m.linkname);
            return refuse(why, "a negative size");
        }
        if (gnu(m.type)) {
            free(m.name);
            free(m.linkname);
            return refuse(why, "a GNU long name or sparse file, which this reader does not read");
        }
        if (m.type == 'g') {
            free(m.name);
            free(m.linkname);
            return refuse(why, "a global extended header, which this reader does not read");
        }
        if (m.type != 'x' && m.type != 'X') {
            if (m.type == '5') rstrip_slash(m.name); /* again, after the prefix */
            m.data = off + BLOCK;
            off = m.data + (has_data(m.type) ? (size_t)block_of(m.size) : 0);
            add(out, &m);
            continue;
        }
        /* an extended header: its records, then the member they describe */
        size_t xoff = off, xlen = (size_t)block_of(m.size);
        free(m.name);
        free(m.linkname);
        if (n - (xoff + BLOCK) < xlen) return refuse(why, "unexpected end of data");
        struct pax x = {0};
        const char *err = NULL;
        int pr = pax_records(p + xoff + BLOCK, xlen, &x, &err);
        if (pr) {
            free(x.path);
            free(x.linkpath);
            if (pr == -2) return refuse(why, err);
            return xoff == 0 ? refuse(why, "invalid header") : 0;
        }
        off = xoff + BLOCK + xlen;
        r = header(p, n, off, 0, &m);
        if (r != HEADER_OK) {
            free(x.path);
            free(x.linkpath);
            return refuse(why, "an extended header without a member after it");
        }
        if (gnu(m.type) || m.type == 'x' || m.type == 'X' || m.type == 'g') {
            free(x.path);
            free(x.linkpath);
            free(m.name);
            free(m.linkname);
            return refuse(why, "two extended headers in a row, which this reader does not read");
        }
        m.data = off + BLOCK;
        if (x.path) {
            free(m.name);
            m.name = x.path;
            rstrip_slash(m.name);
        }
        if (x.linkpath) {
            free(m.linkname);
            m.linkname = x.linkpath;
        }
        if (x.has_size) m.size = x.size;
        if (x.has_mtime) {
            m.mtime_float = 1;
            m.mtime_f = x.mtime;
        }
        if (m.size < 0) {
            free(m.name);
            free(m.linkname);
            return refuse(why, "a negative size");
        }
        if (m.type == '5') rstrip_slash(m.name);
        off = m.data + (has_data(m.type) ? (size_t)block_of(m.size) : 0);
        add(out, &m);
    }
}
