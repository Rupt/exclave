/* inflate.c — gzip (RFC 1952) and DEFLATE (RFC 1951), decompression only, for the .apk files unpack reads (DESIGN.md
 * 10.1). Written from the RFCs; it accepts what zlib and Python's gzip.decompress accept: members back to back with NUL
 * bytes between them, each member's CRC-32 and length checked, a header CRC when one is flagged, and a Huffman code
 * that is complete, or a single code of length 1. */
#include <stdio.h>
#include <string.h>
#include "tool.h"

#define MAXBITS 15

struct bits {
    const uint8_t *p;
    size_t n, pos; /* the input and the next byte to load */
    uint64_t buf;  /* bits loaded and not consumed, the first in the lowest bit */
    int cnt;
    const char *err;
};

static void fill(struct bits *b)
{
    while (b->cnt <= 56 && b->pos < b->n) {
        b->buf |= (uint64_t)b->p[b->pos++] << b->cnt;
        b->cnt += 8;
    }
}

/* the next k bits, k at most 32; -1 with err set when the input ends first */
static long need(struct bits *b, int k)
{
    fill(b);
    if (b->cnt < k) {
        b->err = "the data ends inside a block";
        return -1;
    }
    long v = (long)(b->buf & ((1ULL << k) - 1));
    b->buf >>= k;
    b->cnt -= k;
    return v;
}

/* the whole bytes loaded but not consumed go back to the input, at a byte boundary */
static void unload(struct bits *b)
{
    b->buf = 0;
    b->pos -= (size_t)(b->cnt / 8);
    b->cnt = 0;
}

/* A canonical Huffman code as a table indexed by the next MAXBITS bits: each entry its symbol << 4 and its length, 0
 * where no code begins. */
struct huff {
    uint16_t t[1 << MAXBITS];
};

enum code_kind { CODES, LENS, DISTS };

/* zlib's rule: an over-subscribed set is refused, and an incomplete one too, unless it is a single code of length 1 in
 * a literal/length or distance code; a set with no codes at all builds an empty table */
static int build(struct huff *h, const uint8_t *lens, int n, enum code_kind kind)
{
    int count[MAXBITS + 1] = {0}, max = 0;
    for (int i = 0; i < n; i++) count[lens[i]]++;
    for (int k = 1; k <= MAXBITS; k++)
        if (count[k]) max = k;
    memset(h->t, 0, sizeof h->t);
    if (!max) return 0;
    int left = 1;
    for (int k = 1; k <= MAXBITS; k++) {
        left = 2 * left - count[k];
        if (left < 0) return -1;
    }
    if (left > 0 && (kind == CODES || max != 1)) return -1;
    int next[MAXBITS + 1], code = 0;
    count[0] = 0;
    for (int k = 1; k <= MAXBITS; k++) {
        code = (code + count[k - 1]) << 1;
        next[k] = code;
    }
    for (int s = 0; s < n; s++) {
        int len = lens[s];
        if (!len) continue;
        int c = next[len]++, rev = 0;
        for (int i = 0; i < len; i++) rev |= ((c >> i) & 1) << (len - 1 - i);
        for (int i = rev; i < 1 << MAXBITS; i += 1 << len) h->t[i] = (uint16_t)(s << 4 | len);
    }
    return 0;
}

/* the next symbol of the code; -1 with err set */
static int decode(struct bits *b, const struct huff *h, const char *invalid)
{
    fill(b);
    unsigned e = h->t[b->buf & ((1U << MAXBITS) - 1)];
    if (!e) {
        b->err = b->cnt < MAXBITS ? "the data ends inside a block" : invalid;
        return -1;
    }
    int len = (int)(e & 15);
    if (len > b->cnt) {
        b->err = "the data ends inside a block";
        return -1;
    }
    b->buf >>= len;
    b->cnt -= len;
    return (int)(e >> 4);
}

static void put(struct buf *out, uint8_t c)
{
    if (out->n == out->cap) {
        out->cap = out->cap ? 2 * out->cap : 1 << 16;
        out->p = xrealloc(out->p, out->cap);
    }
    out->p[out->n++] = (char)c;
}

/* RFC 1951 3.2.5: each length and distance code's base and its extra bits */
/* clang-format off */
static const uint16_t len_base[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83,
                                      99, 115, 131, 163, 195, 227, 258};
static const uint8_t len_extra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
                                      0};
static const uint16_t dist_base[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
                                       1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
static const uint8_t dist_extra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
                                       12, 12, 13, 13};
/* clang-format on */

/* one block's symbols, until its end; start is where the member's output begins, which no distance reaches before */
static int codes(struct bits *b, const struct huff *lit, const struct huff *dist, struct buf *out, size_t start)
{
    for (;;) {
        int s = decode(b, lit, "invalid literal/length code");
        if (s < 0) return -1;
        if (s < 256) {
            put(out, (uint8_t)s);
            continue;
        }
        if (s == 256) return 0;
        s -= 257;
        if (s >= 29) {
            b->err = "invalid literal/length code";
            return -1;
        }
        long extra = need(b, len_extra[s]);
        if (extra < 0) return -1;
        size_t len = len_base[s] + (size_t)extra;
        int d = decode(b, dist, "invalid distance code");
        if (d < 0) return -1;
        if (d >= 30) {
            b->err = "invalid distance code";
            return -1;
        }
        extra = need(b, dist_extra[d]);
        if (extra < 0) return -1;
        size_t back = dist_base[d] + (size_t)extra;
        if (back > out->n - start) {
            b->err = "invalid distance too far back";
            return -1;
        }
        for (size_t i = 0; i < len; i++) put(out, (uint8_t)out->p[out->n - back]);
    }
}

static struct huff lit_table, dist_table, code_table; /* 64 KB each: off the stack */

static int fixed(struct bits *b, struct buf *out, size_t start)
{
    uint8_t lens[288];
    memset(lens, 8, 144);
    memset(lens + 144, 9, 112);
    memset(lens + 256, 7, 24);
    memset(lens + 280, 8, 8);
    build(&lit_table, lens, 288, LENS);
    memset(lens, 5, 32);
    build(&dist_table, lens, 32, DISTS);
    return codes(b, &lit_table, &dist_table, out, start);
}

static int dynamic(struct bits *b, struct buf *out, size_t start)
{
    static const uint8_t order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
    long nlen = need(b, 5), ndist = need(b, 5), ncode = need(b, 4);
    if (nlen < 0 || ndist < 0 || ncode < 0) return -1;
    nlen += 257;
    ndist += 1;
    ncode += 4;
    if (nlen > 286 || ndist > 30) {
        b->err = "too many length or distance symbols";
        return -1;
    }
    uint8_t lens[286 + 30] = {0};
    for (int i = 0; i < ncode; i++) {
        long v = need(b, 3);
        if (v < 0) return -1;
        lens[order[i]] = (uint8_t)v;
    }
    if (build(&code_table, lens, 19, CODES)) {
        b->err = "invalid code lengths set";
        return -1;
    }
    memset(lens, 0, sizeof lens);
    for (long i = 0; i < nlen + ndist;) {
        int s = decode(b, &code_table, "invalid code lengths set");
        if (s < 0) return -1;
        if (s < 16) {
            lens[i++] = (uint8_t)s;
            continue;
        }
        uint8_t v = 0;
        long rep;
        if (s == 16) {
            if (!i) {
                b->err = "invalid bit length repeat";
                return -1;
            }
            v = lens[i - 1];
            rep = need(b, 2);
            rep = rep < 0 ? -1 : 3 + rep;
        } else if (s == 17) {
            rep = need(b, 3);
            rep = rep < 0 ? -1 : 3 + rep;
        } else {
            rep = need(b, 7);
            rep = rep < 0 ? -1 : 11 + rep;
        }
        if (rep < 0) return -1;
        if (i + rep > nlen + ndist) {
            b->err = "invalid bit length repeat";
            return -1;
        }
        while (rep--) lens[i++] = v;
    }
    if (!lens[256]) {
        b->err = "invalid code -- missing end-of-block";
        return -1;
    }
    if (build(&lit_table, lens, (int)nlen, LENS)) {
        b->err = "invalid literal/lengths set";
        return -1;
    }
    if (build(&dist_table, lens + nlen, (int)ndist, DISTS)) {
        b->err = "invalid distances set";
        return -1;
    }
    return codes(b, &lit_table, &dist_table, out, start);
}

/* one DEFLATE stream from b->pos to its last block, b left at the byte after it */
static int inflate(struct bits *b, struct buf *out)
{
    size_t start = out->n;
    for (;;) {
        long last = need(b, 1), type = need(b, 2);
        if (last < 0 || type < 0) return -1;
        if (type == 0) {
            b->buf >>= b->cnt % 8;
            b->cnt -= b->cnt % 8;
            unload(b);
            if (b->n - b->pos < 4) {
                b->err = "the data ends inside a block";
                return -1;
            }
            const uint8_t *q = b->p + b->pos;
            size_t len = q[0] | (size_t)q[1] << 8, nlen = q[2] | (size_t)q[3] << 8;
            if (len != (~nlen & 0xffff)) {
                b->err = "invalid stored block lengths";
                return -1;
            }
            b->pos += 4;
            if (b->n - b->pos < len) {
                b->err = "the data ends inside a block";
                return -1;
            }
            buf_add(out, b->p + b->pos, len);
            b->pos += len;
        } else if (type == 1) {
            if (fixed(b, out, start)) return -1;
        } else if (type == 2) {
            if (dynamic(b, out, start)) return -1;
        } else {
            b->err = "invalid block type";
            return -1;
        }
        if (last) {
            unload(b);
            return 0;
        }
    }
}

uint32_t crc32_update(uint32_t crc, const void *data, size_t n)
{
    static uint32_t table[256];
    if (!table[1])
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = c & 1 ? 0xedb88320U ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
    const uint8_t *p = data;
    crc = ~crc;
    while (n--) crc = table[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    return ~crc;
}

static uint32_t le32(const uint8_t *p)
{ return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

#define FHCRC 2
#define FEXTRA 4
#define FNAME 8
#define FCOMMENT 16

/* the header of the member at *pos, *pos left after it; 0, or -1 with the reason */
static int gzip_header(const uint8_t *p, size_t n, size_t *pos, const char **err)
{
    size_t i = *pos;
    if (n - i < 2 || p[i] != 0x1f || p[i + 1] != 0x8b) {
        *err = "not a gzipped file";
        return -1;
    }
    if (n - i < 10) {
        *err = "the data ends inside a gzip header";
        return -1;
    }
    if (p[i + 2] != 8) {
        *err = "unknown compression method";
        return -1;
    }
    int flag = p[i + 3];
    size_t start = i;
    i += 10;
    if (flag & FEXTRA) {
        if (n - i < 2 || n - i - 2 < (p[i] | (size_t)p[i + 1] << 8)) {
            *err = "the data ends inside a gzip header";
            return -1;
        }
        i += 2 + (p[i] | (size_t)p[i + 1] << 8);
    }
    /* a name and a comment end at a NUL, or at the end of the data, which the stream after them then finds */
    for (int f = FNAME; f <= FCOMMENT; f <<= 1)
        if (flag & f) {
            while (i < n && p[i]) i++;
            if (i < n) i++;
        }
    if (flag & FHCRC) {
        if (n - i < 2) {
            *err = "the data ends inside a gzip header";
            return -1;
        }
        if ((crc32_update(0, p + start, i - start) & 0xffff) != (p[i] | (uint32_t)p[i + 1] << 8)) {
            *err = "corrupted gzip header";
            return -1;
        }
        i += 2;
    }
    *pos = i;
    return 0;
}

int gunzip(const uint8_t *in, size_t n, struct buf *out, char why[INFLATE_WHY])
{
    size_t pos = 0;
    while (pos < n) {
        const char *err = NULL;
        if (gzip_header(in, n, &pos, &err)) {
            snprintf(why, INFLATE_WHY, "%s", err);
            return -1;
        }
        struct bits b = {in, n, pos, 0, 0, NULL};
        size_t start = out->n;
        if (inflate(&b, out)) {
            snprintf(why, INFLATE_WHY, "%s", b.err);
            return -1;
        }
        if (n - b.pos < 8) {
            snprintf(why, INFLATE_WHY, "the data ends before the end of a gzip member");
            return -1;
        }
        if (le32(in + b.pos) != crc32_update(0, out->p + start, out->n - start)) {
            snprintf(why, INFLATE_WHY, "CRC check failed");
            return -1;
        }
        if (le32(in + b.pos + 4) != (uint32_t)(out->n - start)) {
            snprintf(why, INFLATE_WHY, "incorrect length of data produced");
            return -1;
        }
        pos = b.pos + 8;
        while (pos < n && !in[pos]) pos++;
    }
    return 0;
}
