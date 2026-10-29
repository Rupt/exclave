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
/* the build's version: TOOL_VERSION and the commit, which scripts/build defines; what `version` prints and the
 * hashes file's tool record says (6.4) */
#ifndef EXCLAVE_VERSION
#define EXCLAVE_VERSION TOOL_VERSION
#endif
void write_readme(const char *ex);
void write_hashes(const char *ex, const char *manifest_hash, int tree, int keep);
int has_tree_record(const char *ex);
int cmd_unwrap(int argc, char **argv);
int cmd_wrap(int argc, char **argv);
int cmd_relink(int argc, char **argv);

/* Every entry under root but a directory, a link to one included, as (real path, virtual path, lstat): each
 * directory's entries in the order of their bytes, before the directories below it, .real/ directories aside. */
typedef void (*file_fn)(const char *real, const char *v, const struct stat *st, void *ctx);
void walk_files(const char *root, file_fn fn, void *ctx);

/* a list of strings, each its own copy */
/* collections of strings (strs.c) */
struct strs {
    char **s;
    size_t n, cap;
};
void strs_add(struct strs *l, const char *s);
void strs_free(struct strs *l);
int strs_has(const struct strs *l, const char *s);
struct set {
    struct buf *k;
    size_t n, cap;
};
int set_add(struct set *s, const char *p, size_t n);
int set_has(const struct set *s, const char *p, size_t n);
void set_free(struct set *s);
/* distinct strings in the order added, with an index */
struct uniq {
    struct strs list;
    struct set index;
};
int uniq_add(struct uniq *u, const char *s);
int uniq_has(const struct uniq *u, const char *s);
void uniq_free(struct uniq *u);

/* virtual paths in the tree (6.1, 8.1) */
int under(const char *v, const char *prefix);
int under_any(const char *v, const struct strs *prefixes);
int volatile_path(const char *v);
struct ownership {
    struct strs own, host; /* the own prefixes, the manifest's own records and rule 1's top-level names; its hosts */
};
void ownership_of(const char *ex, struct ownership *o);
void ownership_free(struct ownership *o);
void owned_top(const char *ex, struct strs *out);
void data_prefixes(const char *ex, struct strs *out);
int host_owned(const char *v, const struct ownership *o);
char *tree_real(const char *root, const char *vpath);
char *tree_payload(const char *root, const char *vpath);
char *payload_path(const char *real);
char *tree_resolve(const char *root, const char *vpath, int follow_last, struct strs *links);
char *normpath(const char *p);
char *dirname_of(const char *p);
const char *basename_of(const char *p);

/* an ELF file's parts the checks read (10.3) */
struct elf_load {
    uint64_t vaddr, off, filesz;
};
struct elf {
    int type, machine, debug_only; /* debug_only: a separate debug file, whose PT_INTERP is empty */
    struct elf_load *loads;
    size_t nloads, nneeded;
    char *interp, **needed, *rpath, *runpath, *soname;
};
enum { ELF_OK, ELF_BAD, ELF_FOREIGN, ELF_OS };
#define ELF_WHY 128
/* ELF_OK; ELF_BAD or ELF_FOREIGN with the reason in why; ELF_OS with errno when the file cannot be opened */
int elf_read(const char *path, struct elf *e, char why[ELF_WHY]);
void elf_free(struct elf *e);
struct cache_entry {
    char *soname, *path;
};
struct cache {
    struct cache_entry *e;
    size_t n;
};
int read_cache(const char *root, struct cache *c);
void cache_free(struct cache *c);
int utf8_valid(const char *s, size_t n);

/* the checks (10.3) */
struct report {
    struct strs errors, warnings, statics;
    size_t seen, lines; /* the objects the static check followed; the log lines the dynamic check read */
};
void static_check(const char *ex, const struct ownership *own, const struct strs *data, struct report *rep);
void dynamic_check(const char *ex, char **logs, int nlogs, const struct ownership *own, struct report *rep);
void report_free(struct report *rep);
void print_report(const struct report *rep);
int static_report(const char *ex);
void wrapper_problems(const char *ex, const struct strs *data, struct strs *out);
void located_links(const char *ex, struct strs *out);
int cmd_check(int argc, char **argv);
/* machines (7.1): the table of those the command knows, and the exclave's, read from its launcher (10.1) */
struct machine {
    int e_machine;
    const char *uname, *triplet; /* uname -m, which glibc's loader substitutes for $PLATFORM; the multiarch triplet */
    const char *hwcaps[3];       /* the glibc-hwcaps subdirectories searched first, best first */
    int nhwcaps;
};
extern const struct machine MACHINES[2];
extern const struct machine *MACHINE; /* the exclave's launcher's; the command's own build until one is read */
void machine_of_launcher(const char *ex);
#define GLIBC_SONAME "libc.so.6"
void default_dirs(struct strs *out);
int is_payload_file(const char *root, const char *v);
int glibc_version(const char *root, int *major, int *minor);
char *relpath(const char *path, const char *base);
/* the loader's search (10.3) */
struct search {
    const char *root;
    const struct cache *cache;
    const struct strs *defaults;
    const char *interp;          /* the loader's virtual path, or NULL for a static program */
    const struct ownership *own; /* with host_hits, to find searched directories that are the host's */
    struct strs *host_hits;
};
char *find_library(const struct search *s, const char *name, const struct elf *e, const char *vpath,
                   const struct strs *rpaths);
char *loader_dirs(const char *root, const char *interp, struct strs *out);
/* an EXCLAVE_LOG file's lines (6.2): CALL RESULT PATH, the path's escapes undone */
struct log_line {
    char *what, *path;
    long result;
};
size_t read_log(const char *path, struct log_line **out);
void free_log(struct log_line *l, size_t n);
/* the host identity files (8.4) */
#define N_IDENTITY_FILES 8
extern const char *const IDENTITY_FILES[N_IDENTITY_FILES];
int cmd_prune(int argc, char **argv);

char *read_file(const char *path, size_t *n);

int cmd_hash(int argc, char **argv);
int cmd_version(int argc, char **argv);
int cmd_format(int argc, char **argv);
