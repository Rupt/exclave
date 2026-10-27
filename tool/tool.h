/* tool.h — the exclave command (DESIGN.md 10): every module's interface.
 *
 * Ordinary C on the C library, linked statically so that the file runs with nothing beside it. Paths are bytes, as the
 * kernel has them, and every list the command prints or hashes is sorted by its bytes. A refusal prints one line,
 * "exclave: " and the reason, and exits 1; a usage error exits 2. */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

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
/* a manifest or hashes file the grammar refuses: "grammar: " and where */
_Noreturn void fail_grammar(const char *err);
/* "usage: exclave LINE", exit 2 */
_Noreturn void usage(const char *line);
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

/* the manifest and the hashes file (6.2, 6.4): records of a key and fields, each a string (s) or a bare token (t);
 * a value is followed by a NUL it does not count, and a string's value may hold NULs of its own */
enum kind { KIND_MANIFEST, KIND_HASHES };
struct field {
    char type;
    char *v;
    size_t n;
};
struct record {
    char *key;
    struct field *f;
    int nf, line;
    struct buf comments; /* the comment lines above it, without their #: each its length, a size_t, then its bytes */
};
struct records {
    struct record *r;
    size_t n;
};
/* room for a grammar error: "line L col C: why" */
#define GRAMMAR_ERR 160
int grammar_parse(const char *text, size_t n, enum kind kind, struct records *out, char err[GRAMMAR_ERR]);
void grammar_dump(const struct records *rs, enum kind kind, struct buf *out);
void grammar_quote(struct buf *out, const char *v, size_t n);
void records_free(struct records *rs);
const char *kind_name(enum kind kind);

/* the exclave on disk (6.1) */
void require_exclave(const char *ex, const char *cmd);
void tree_hash(const char *root, char out[B2_TEXT]);

/* A directory's entries, sorted by their bytes: each its name, its lstat, and whether it is a directory as a walk
 * counts one, a link to a directory included. -1 with errno when it cannot be read. */
struct entry_info {
    char *name;
    struct stat st;
    int is_dir;
};
int list_dir(const char *path, struct entry_info **out, size_t *n);
void free_list(struct entry_info *e, size_t n);
/* Every directory under root, its own entries sorted, top-down or bottom-up: a link to a directory is listed and not
 * descended, and a directory that cannot be read is passed over with everything beneath it. rel is the directory's
 * path from root, "" for root itself. */
typedef void (*walk_fn)(const char *dir, const char *rel, struct entry_info *e, size_t n, void *ctx);
void walk_dirs(const char *root, int bottom_up, walk_fn fn, void *ctx);
int is_real_dir(const char *dir);
/* every file in a .real/ directory with no wrapper beside it, as /PATH from root, each NUL-terminated (6.1) */
void strays(const char *root, struct buf *out);
char *rel_join(const char *rel, const char *name);

/* an exclave's other files (6.1, 6.4) */
#define TOOL_VERSION "0.1.0"
void write_readme(const char *ex);
void write_hashes(const char *ex, const char *manifest_hash, int tree, int keep);
int has_tree_record(const char *ex);
int cmd_unwrap(int argc, char **argv);
int cmd_relink(int argc, char **argv);

char *read_file(const char *path, size_t *n);

int cmd_hash(int argc, char **argv);
int cmd_format(int argc, char **argv);
