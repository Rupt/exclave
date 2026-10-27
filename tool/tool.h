/* tool.h — the exclave command (DESIGN.md 10): every module's interface.
 *
 * Ordinary C on the C library, linked statically so that the file runs with nothing beside it. Paths are bytes, as the
 * kernel has them, and every list the command prints or hashes is sorted by its bytes. A refusal prints one line,
 * "exclave: " and the reason, and exits 1; a usage error exits 2. */
#pragma once
#include <stddef.h>
#include <stdint.h>

/* BLAKE2b (RFC 7693), unkeyed, with the digest length given to b2_init: 32 for every hash the exclave format records
 * (6.4). */
struct blake2b {
    uint64_t h[8], t[2];
    uint8_t buf[128];
    size_t n, outlen;
};
void b2_init(struct blake2b *s, size_t outlen);
void b2_update(struct blake2b *s, const void *data, size_t len);
void b2_final(struct blake2b *s, uint8_t *out);
/* "b2:" and the lowercase hex of a 32-byte digest, as the hashes file writes it */
#define B2_TEXT 68
void b2_text(const uint8_t digest[32], char out[B2_TEXT]);

/* failures */
_Noreturn void fail(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
_Noreturn void fail_errno(const char *path);
void *xrealloc(void *p, size_t n);

/* a byte string that grows */
struct buf {
    char *p;
    size_t n, cap;
};
void buf_add(struct buf *b, const void *data, size_t n);
void buf_str(struct buf *b, const char *s);
/* a, then a slash unless a ends in one, then b: os.path.join's spelling, which the messages use */
char *path_join(const char *a, const char *b);

/* the exclave on disk (6.1) */
void require_exclave(const char *ex, const char *cmd);
void tree_hash(const char *root, char out[B2_TEXT]);

int cmd_hash(int argc, char **argv);
