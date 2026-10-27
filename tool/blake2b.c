/* blake2b.c — BLAKE2b, written from RFC 7693 (sections 2 and 3, the constants of appendix C). */
#include <string.h>
#include "tool.h"

static const uint64_t IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

/* clang-format off */
/* the message schedule, one row per round; rounds 10 and 11 repeat rows 0 and 1 */
static const uint8_t SIGMA[10][16] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
    {11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4},
    { 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
    { 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13},
    { 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
    {12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11},
    {13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
    { 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5},
    {10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0},
};
/* clang-format on */

static uint64_t rotr(uint64_t x, unsigned n) { return (x >> n) | (x << (64 - n)); }

static uint64_t load64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static void mix(uint64_t *v, int a, int b, int c, int d, uint64_t x, uint64_t y)
{
    v[a] = v[a] + v[b] + x;
    v[d] = rotr(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];
    v[b] = rotr(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = rotr(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = rotr(v[b] ^ v[c], 63);
}

/* the compression function F of 3.2 over one block, last marking the final one */
static void compress(struct blake2b *s, int last)
{
    uint64_t v[16], m[16];
    for (int i = 0; i < 8; i++) {
        v[i] = s->h[i];
        v[i + 8] = IV[i];
    }
    v[12] ^= s->t[0];
    v[13] ^= s->t[1];
    if (last) v[14] = ~v[14];
    for (size_t i = 0; i < 16; i++) m[i] = load64(s->buf + 8 * i);
    for (int r = 0; r < 12; r++) {
        const uint8_t *z = SIGMA[r % 10];
        mix(v, 0, 4, 8, 12, m[z[0]], m[z[1]]);
        mix(v, 1, 5, 9, 13, m[z[2]], m[z[3]]);
        mix(v, 2, 6, 10, 14, m[z[4]], m[z[5]]);
        mix(v, 3, 7, 11, 15, m[z[6]], m[z[7]]);
        mix(v, 0, 5, 10, 15, m[z[8]], m[z[9]]);
        mix(v, 1, 6, 11, 12, m[z[10]], m[z[11]]);
        mix(v, 2, 7, 8, 13, m[z[12]], m[z[13]]);
        mix(v, 3, 4, 9, 14, m[z[14]], m[z[15]]);
    }
    for (int i = 0; i < 8; i++) s->h[i] ^= v[i] ^ v[i + 8];
}

static void count(struct blake2b *s, size_t n)
{
    s->t[0] += n;
    if (s->t[0] < n) s->t[1]++;
}

void b2_init(struct blake2b *s, size_t outlen)
{
    memset(s, 0, sizeof *s);
    memcpy(s->h, IV, sizeof s->h);
    s->h[0] ^= 0x01010000ULL ^ outlen; /* no key, fanout and depth 1 */
    s->outlen = outlen;
}

void b2_update(struct blake2b *s, const void *data, size_t len)
{
    const uint8_t *p = data;
    while (len) {
        if (s->n == sizeof s->buf) { /* a full block, and more to come: not the last */
            count(s, s->n);
            compress(s, 0);
            s->n = 0;
        }
        size_t k = sizeof s->buf - s->n < len ? sizeof s->buf - s->n : len;
        memcpy(s->buf + s->n, p, k);
        s->n += k;
        p += k;
        len -= k;
    }
}

void b2_final(struct blake2b *s, uint8_t *out)
{
    count(s, s->n);
    memset(s->buf + s->n, 0, sizeof s->buf - s->n);
    compress(s, 1);
    for (size_t i = 0; i < s->outlen; i++) out[i] = (uint8_t)(s->h[i / 8] >> (8 * (i % 8)));
}

void b2_text(const uint8_t digest[32], char out[B2_TEXT])
{
    static const char hex[] = "0123456789abcdef";
    memcpy(out, "b2:", 3);
    for (int i = 0; i < 32; i++) {
        out[3 + 2 * i] = hex[digest[i] >> 4];
        out[4 + 2 * i] = hex[digest[i] & 15];
    }
    out[B2_TEXT - 1] = 0;
}
