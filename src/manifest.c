/* manifest.c — strict parser for the manifest (PROPOSAL.md 6.2).
 *
 * No syscalls: takes a buffer, fills struct can, reports "line L col C: why".
 * Compiled into the opener and, with HOST_TEST, into test/manifest_test.c.
 * The opener enforces the lexical and typing rules, not the canonical order.
 * The manifest is the one file the opener reads: an ISA declaration and the
 * visibility overrides; everything else it needs it observes in the tree.
 */
#include "common.h"

struct cur { const unsigned char *p, *end; int line, col; };

static int fail(char *err, size_t errn, struct cur *c, const char *why)
{
    char l[24], k[24]; ltoa_(c->line, l); ltoa_(c->col, k);
    scpy(err, "line ", errn); scat(err, l, errn); scat(err, " col ", errn); scat(err, k, errn);
    scat(err, ": ", errn); scat(err, why, errn);
    return -1;
}

/* length of the well-formed UTF-8 sequence at p (Unicode Table 3-7), or 0 */
static int utf8_len(const unsigned char *p, size_t n)
{
    if (n == 0) return 0;
    unsigned char b = p[0];
    if (b < 0x80) return 1;
    if (b < 0xC2) return 0;
    if (b < 0xE0) return (n >= 2 && (p[1] & 0xC0) == 0x80) ? 2 : 0;
    if (b < 0xF0) {
        if (n < 3 || (p[2] & 0xC0) != 0x80) return 0;
        unsigned char lo = 0x80, hi = 0xBF;
        if (b == 0xE0) lo = 0xA0; else if (b == 0xED) hi = 0x9F;
        return (p[1] >= lo && p[1] <= hi) ? 3 : 0;
    }
    if (b < 0xF5) {
        if (n < 4 || (p[2] & 0xC0) != 0x80 || (p[3] & 0xC0) != 0x80) return 0;
        unsigned char lo = 0x80, hi = 0xBF;
        if (b == 0xF0) lo = 0x90; else if (b == 0xF4) hi = 0x8F;
        return (p[1] >= lo && p[1] <= hi) ? 4 : 0;
    }
    return 0;
}
/* code point of a valid sequence of length l */
static unsigned cp_of(const unsigned char *p, int l)
{
    if (l == 1) return p[0];
    if (l == 2) return ((p[0] & 0x1F) << 6) | (p[1] & 0x3F);
    if (l == 3) return ((p[0] & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
    return ((p[0] & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F);
}
static int hexval(unsigned char c) { return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1; }
static int is_token_char(unsigned char c)
{ return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '+' || c == '-'; }

/* field kinds */
enum { F_STR = 1, F_TOK = 2 };
#define MANIFEST_MAX_OWN 256
#define MANIFEST_MAX_HOST 32
struct field { int kind; const char *s; size_t n; };

/* parse one string literal starting at the opening quote; decodes into out (arena) */
static int parse_string(struct cur *c, char *err, size_t errn, struct field *f)
{
    static char dec[PATH_MAX * 2];
    size_t dn = 0;
    c->p++; c->col++;                                          /* opening quote */
    for (;;) {
        if (c->p >= c->end) return fail(err, errn, c, "unterminated string");
        unsigned char b = *c->p;
        if (b == '"') { c->p++; c->col++; break; }
        if (b == '\n') return fail(err, errn, c, "unterminated string");
        if (dn + 4 >= sizeof dec) return fail(err, errn, c, "string too long");
        if (b == '\\') {
            if (c->p + 1 >= c->end) return fail(err, errn, c, "unterminated escape");
            unsigned char e = c->p[1];
            if (e == '\\' || e == '"') { dec[dn++] = (char)e; c->p += 2; c->col += 2; continue; }
            if (e == 'n') { dec[dn++] = '\n'; c->p += 2; c->col += 2; continue; }
            if (e == 't') { dec[dn++] = '\t'; c->p += 2; c->col += 2; continue; }
            if (e == 'x') {
                if (c->p + 3 >= c->end) return fail(err, errn, c, "truncated \\x escape");
                int h = hexval(c->p[2]), l = hexval(c->p[3]);
                if (h < 0 || l < 0) return fail(err, errn, c, "\\x needs two lowercase hex digits");
                dec[dn++] = (char)(h * 16 + l); c->p += 4; c->col += 4; continue;
            }
            return fail(err, errn, c, "unknown escape");
        }
        int l = utf8_len(c->p, (size_t)(c->end - c->p));
        if (!l) return fail(err, errn, c, "malformed UTF-8 in string");
        unsigned cp = cp_of(c->p, l);
        if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F)) return fail(err, errn, c, "control character must be escaped");
        xmemcpy(dec + dn, c->p, (size_t)l); dn += (size_t)l; c->p += l; c->col += 1;
    }
    f->kind = F_STR; f->s = arena_str(dec, dn); f->n = dn;
    return 0;
}

static int parse_token(struct cur *c, char *err, size_t errn, struct field *f)
{
    const unsigned char *s = c->p;
    while (c->p < c->end && is_token_char(*c->p)) { c->p++; c->col++; }
    if (c->p == s) return fail(err, errn, c, "expected a string or token");
    f->kind = F_TOK; f->s = arena_str((const char *)s, (size_t)(c->p - s)); f->n = (size_t)(c->p - s);
    return 0;
}

static int valid_abs_path(const char *s, size_t n)
{
    if (n == 0 || s[0] != '/') return 0;
    for (size_t i = 0; i < n; i++) if (s[i] == 0) return 0;
    return 1;
}

int manifest_parse(const char *buf, size_t len, struct can *c, char *err, size_t errn)
{
    struct cur cu = { (const unsigned char *)buf, (const unsigned char *)buf + len, 1, 1 };
    struct cur *K = &cu;
    int seen_can = 0, seen_isa = 0, nrec = 0;
    int pending_comment = 0;

    if (len == 0 || buf[len - 1] != '\n') return fail(err, errn, K, "file must end with LF");
    if (len >= 3 && (unsigned char)buf[0] == 0xEF && (unsigned char)buf[1] == 0xBB && (unsigned char)buf[2] == 0xBF)
        return fail(err, errn, K, "byte order mark");
    /* whole-file UTF-8 and CR check */
    for (const unsigned char *p = K->p; p < K->end;) {
        if (*p == '\r') { K->line = 1; return fail(err, errn, K, "CR not allowed"); }
        int l = utf8_len(p, (size_t)(K->end - p));
        if (!l) return fail(err, errn, K, "malformed UTF-8");
        p += l;
    }

    while (K->p < K->end) {
        K->col = 1;
        if (*K->p == '\n') { K->p++; K->line++; continue; }            /* blank line */
        if (*K->p == '#') {                                              /* comment line */
            while (*K->p != '\n') K->p++;
            K->p++; K->line++; pending_comment = 1; continue;
        }
        /* record */
        const unsigned char *ks = K->p;
        if (!(*K->p >= 'a' && *K->p <= 'z')) return fail(err, errn, K, "record must start with a lowercase key");
        while (K->p < K->end && ((*K->p >= 'a' && *K->p <= 'z') || (*K->p >= '0' && *K->p <= '9') || *K->p == '-')) { K->p++; K->col++; }
        char key[32]; size_t kl = (size_t)(K->p - ks); if (kl >= sizeof key) return fail(err, errn, K, "key too long");
        xmemcpy(key, ks, kl); key[kl] = 0;
        struct field f[8]; int nf = 0;
        for (;;) {
            if (K->p >= K->end) return fail(err, errn, K, "missing LF");
            if (*K->p == '\n') { K->p++; break; }
            if (*K->p != ' ') return fail(err, errn, K, *K->p == '\t' ? "tab outside a string" : "expected a single space between fields");
            K->p++; K->col++;
            if (K->p >= K->end || *K->p == '\n') return fail(err, errn, K, "trailing space");
            if (*K->p == ' ') return fail(err, errn, K, "multiple spaces");
            if (nf == 8) return fail(err, errn, K, "too many fields");
            int r = (*K->p == '"') ? parse_string(K, err, errn, &f[nf]) : parse_token(K, err, errn, &f[nf]);
            if (r) return r;
            nf++;
        }
        pending_comment = 0;
        nrec++;
        /* typing */
#define WANT(n_, ...) do { int kinds[] = { __VA_ARGS__ }; if (nf != (n_)) return fail(err, errn, K, "wrong field count"); \
        for (int i = 0; i < nf; i++) if (f[i].kind != kinds[i]) return fail(err, errn, K, "wrong field type"); } while (0)
        if (xstrcmp(key, "can") == 0) {
            WANT(1, F_TOK);
            if (nrec != 1) return fail(err, errn, K, "can must be the first record");
            if (xstrcmp(f[0].s, "1") != 0) return fail(err, errn, K, "unsupported can version");
            seen_can = 1;
        } else if (nrec == 1) {
            return fail(err, errn, K, "first record must be can");
        } else if (xstrcmp(key, "isa") == 0) {
            WANT(1, F_STR); if (seen_isa++) return fail(err, errn, K, "duplicate isa");
            scpy(c->isa, f[0].s, sizeof c->isa);
        } else if (xstrcmp(key, "own") == 0) {
            WANT(1, F_STR); if (!valid_abs_path(f[0].s, f[0].n)) return fail(err, errn, K, "own must be an absolute path");
            if (c->nown >= MANIFEST_MAX_OWN) return fail(err, errn, K, "more than 256 own records");
            c->own[c->nown++] = f[0].s;
        } else if (xstrcmp(key, "host") == 0) {
            WANT(1, F_STR); if (!valid_abs_path(f[0].s, f[0].n)) return fail(err, errn, K, "host must be an absolute path");
            if (c->nhost >= MANIFEST_MAX_HOST) return fail(err, errn, K, "more than 32 host records");
            c->host[c->nhost].v = f[0].s; c->host[c->nhost].r = f[0].s; c->host[c->nhost].is_file = 0; c->nhost++;
        } else if (xstrcmp(key, "data") == 0) {
            WANT(1, F_STR); if (!valid_abs_path(f[0].s, f[0].n)) return fail(err, errn, K, "data must be an absolute path");
            if (c->ndata >= (int)(sizeof c->data / sizeof c->data[0])) return fail(err, errn, K, "more than 32 data records");
            c->data[c->ndata++] = f[0].s;                            /* never executed, never a loader (6.2); enforced in the handler and the loader */
        } else {
            return fail(err, errn, K, "unknown key");
        }
#undef WANT
    }
    if (pending_comment) return fail(err, errn, K, "comment after the last record");
    if (!seen_can) return fail(err, errn, K, "empty manifest");
    if (!seen_isa) scpy(c->isa, ARCH_ISA_DEFAULT, sizeof c->isa);      /* the baseline: a can that says nothing runs anywhere */
    return 0;
}
