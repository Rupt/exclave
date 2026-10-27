/* layout.c — an exclave's files beside its tree, the launcher, the README and the hashes file, and the two commands
 * that move wrappers and originals and nothing else: unwrap and relink (DESIGN.md 6.1, 6.4, 10.1). */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tool.h"

/* tool/blobs.S */
extern const char launcher_blob[], readme_blob[];
extern const uint64_t launcher_size, readme_size;

static int lexists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

/* data as the whole of path, created with mode, or truncated with its own */
static void write_file(const char *path, const void *data, size_t n, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) fail_errno(path);
    for (const char *p = data; n;) {
        ssize_t k = write(fd, p, n);
        if (k < 0) fail_errno(path);
        p += k;
        n -= (size_t)k;
    }
    if (close(fd)) fail_errno(path);
}

void write_readme(const char *ex)
{
    char *p = path_join(ex, "README");
    if (!lexists(p)) write_file(p, readme_blob, (size_t)readme_size, 0666);
    free(p);
}

static void hash_text(const char *data, size_t n, char out[B2_TEXT])
{
    struct blake2b s;
    uint8_t d[32];
    b2_init(&s, 32);
    b2_update(&s, data, n);
    b2_final(&s, d);
    b2_text(d, out);
}

static struct field string_field(const char *s)
{
    size_t n = strlen(s);
    char *v = xrealloc(NULL, n + 1);
    memcpy(v, s, n + 1);
    return (struct field){'s', v, n};
}

static void add_record(struct records *rs, const char *key, struct field *f, int nf)
{
    rs->r = xrealloc(rs->r, (rs->n + 1) * sizeof *rs->r);
    struct record *r = &rs->r[rs->n++];
    *r = (struct record){0};
    r->key = xrealloc(NULL, strlen(key) + 1);
    strcpy(r->key, key); /* NOLINT(clang-analyzer-security.insecureAPI.strcpy) -- sized on the line above */
    r->f = xrealloc(NULL, (size_t)nf * sizeof *r->f);
    memcpy(r->f, f, (size_t)nf * sizeof *f);
    r->nf = nf;
}

static struct records load_hashes(const char *path)
{
    struct records rs = {0};
    size_t n;
    char *data = read_file(path, &n), err[GRAMMAR_ERR];
    if (grammar_parse(data, n, KIND_HASHES, &rs, err)) fail_grammar(err);
    free(data);
    return rs;
}

static const struct record *find(const struct records *rs, const char *key)
{
    for (size_t i = 0; i < rs->n; i++)
        if (!strcmp(rs->r[i].key, key)) return &rs->r[i];
    return NULL;
}

int has_tree_record(const char *ex)
{
    char *p = path_join(ex, ".exclave/hashes");
    int has = 0;
    if (lexists(p)) {
        struct records rs = load_hashes(p);
        has = find(&rs, "tree") != NULL;
        records_free(&rs);
    }
    free(p);
    return has;
}

/* The hashes file: the hashes and tool records, the launcher's hash when the exclave is wrapped, the pkg records the
 * file holds already, then the manifest's hash and the tree hash when given. keep takes the manifest hash, and the
 * tree record if there was one, from the file as it stands, as after prune and relink. */
void write_hashes(const char *ex, const char *manifest_hash, int tree, int keep)
{
    char *path = path_join(ex, ".exclave/hashes"), *ld = path_join(ex, ".exclave/launcher");
    struct records old = {0}, rs = {0};
    if (lexists(path)) old = load_hashes(path);
    char kept[B2_TEXT + 64] = "";
    if (keep) {
        const struct record *m = find(&old, "manifest");
        if (m) snprintf(kept, sizeof kept, "%s", m->f[0].v);
        manifest_hash = m ? kept : NULL;
        tree = find(&old, "tree") != NULL;
    }
    struct field f = {'t', NULL, 1};
    f.v = xrealloc(NULL, 2);
    strcpy(f.v, "1"); /* NOLINT(clang-analyzer-security.insecureAPI.strcpy) -- two bytes, sized above */
    add_record(&rs, "hashes", &f, 1);
    f = string_field(TOOL_VERSION);
    add_record(&rs, "tool", &f, 1);
    if (manifest_hash || tree) {
        size_t n;
        char *data = read_file(ld, &n), text[B2_TEXT];
        hash_text(data, n, text);
        free(data);
        f = string_field(text);
        add_record(&rs, "launcher", &f, 1);
    }
    for (size_t i = 0; i < old.n; i++) {
        const struct record *r = &old.r[i];
        if (strcmp(r->key, "pkg") != 0) continue;
        struct field pf[4];
        for (int j = 0; j < 4; j++) {
            pf[j] = (struct field){'s', xrealloc(NULL, r->f[j].n + 1), r->f[j].n};
            memcpy(pf[j].v, r->f[j].v, r->f[j].n + 1);
        }
        add_record(&rs, "pkg", pf, 4);
    }
    if (manifest_hash) {
        f = string_field(manifest_hash);
        add_record(&rs, "manifest", &f, 1);
    }
    if (tree) {
        char *root = path_join(ex, "tree"), text[B2_TEXT];
        tree_hash(root, text);
        free(root);
        f = string_field(text);
        add_record(&rs, "tree", &f, 1);
    }
    struct buf out = {0};
    grammar_dump(&rs, KIND_HASHES, &out);
    write_file(path, out.p, out.n, 0666);
    free(out.p);
    records_free(&rs);
    records_free(&old);
    free(path);
    free(ld);
}

/* ---------------------------------------------------------------- unwrap */
static void refuse_strays(const char *ex)
{
    char *root = path_join(ex, "tree");
    struct buf s = {0};
    strays(root, &s);
    if (s.n) {
        struct buf msg = {0};
        for (size_t i = 0; i < s.n; i += strlen(s.p + i) + 1) {
            if (i) buf_str(&msg, "; ");
            buf_str(&msg, "original without wrapper: ");
            buf_str(&msg, s.p + i);
            buf_str(&msg, " (.real is reserved for originals, 6.1)");
        }
        buf_add(&msg, "", 1);
        fail("%s", msg.p);
    }
    free(s.p);
    free(root);
}

static void move_back(const char *dir, const char *rel, struct entry_info *e, size_t n, void *ctx)
{
    (void)rel;
    if (!is_real_dir(dir)) return;
    size_t *moved = ctx;
    const char *slash = strrchr(dir, '/');
    struct buf parent = {0};
    buf_add(&parent, dir, (size_t)(slash - dir));
    buf_add(&parent, "", 1);
    for (size_t i = 0; i < n; i++) {
        if (e[i].is_dir) continue;
        char *w = path_join(parent.p, e[i].name), *orig = path_join(dir, e[i].name);
        if (lexists(w) && unlink(w)) fail_errno(w);
        if (rename(orig, w)) fail_errno(orig);
        (*moved)++;
        free(w);
        free(orig);
    }
    if (rmdir(dir)) fail_errno(dir);
    free(parent.p);
}

/* Unwrap moves every original back over its wrapper, after refusing an original without one, which is not this
 * exclave's; the hashes file keeps its inputs and loses the hashes of a wrapped exclave. */
int cmd_unwrap(int argc, char **argv)
{
    if (argc != 1) usage("unwrap EXCLAVE");
    const char *ex = argv[0];
    require_exclave(ex, "unwrap");
    char *ld = path_join(ex, ".exclave/launcher"), *root = path_join(ex, "tree");
    struct stat st;
    if (stat(ld, &st)) fail_errno(ld);
    refuse_strays(ex);
    size_t moved = 0;
    walk_dirs(root, 1, move_back, &moved);
    printf("unwrapped %zu executables\n", moved);
    write_hashes(ex, NULL, 0, 0);
    free(ld);
    free(root);
    return 0;
}

/* ---------------------------------------------------------------- relink */
/* src at dst as a hard link where the filesystem allows it, and as a copy otherwise */
static void link_or_copy(const char *src, const char *dst)
{
    if (!link(src, dst)) return;
    size_t n;
    char *data = read_file(src, &n);
    struct stat st;
    if (stat(src, &st)) fail_errno(src);
    write_file(dst, data, n, st.st_mode & 07777);
    if (chmod(dst, st.st_mode & 07777)) fail_errno(dst);
    free(data);
}

struct relinking {
    const char *launcher;
    size_t n;
    struct buf strays;
};

static void relink_dir(const char *dir, const char *rel, struct entry_info *e, size_t n, void *ctx)
{
    if (!is_real_dir(dir)) return;
    struct relinking *r = ctx;
    const char *slash = strrchr(dir, '/');
    struct buf parent = {0};
    buf_add(&parent, dir, (size_t)(slash - dir));
    buf_add(&parent, "", 1);
    for (size_t i = 0; i < n; i++) {
        if (e[i].is_dir) continue;
        char *w = path_join(parent.p, e[i].name);
        if (!lexists(w)) {
            char *v = rel_join(rel, e[i].name);
            buf_add(&r->strays, "/", 1);
            buf_add(&r->strays, v, strlen(v) + 1);
            free(v);
        } else {
            struct buf tmp = {0};
            buf_str(&tmp, parent.p);
            buf_str(&tmp, "/.");
            buf_str(&tmp, e[i].name);
            buf_add(&tmp, ".exclave-relink", sizeof ".exclave-relink");
            link_or_copy(r->launcher, tmp.p);
            if (rename(tmp.p, w)) fail_errno(tmp.p);
            r->n++;
            free(tmp.p);
        }
        free(w);
    }
    free(parent.p);
}

/* Relink replaces the launcher and every wrapper with it, each wrapper in one rename, so an interruption leaves no
 * program missing; with no LAUNCHER, the one this command carries. A wrapped exclave's hashes file records the new
 * launcher and tree hashes. */
int cmd_relink(int argc, char **argv)
{
    if (argc != 1 && argc != 2) usage("relink EXCLAVE [LAUNCHER]");
    const char *ex = argv[0], *given = argc == 2 ? argv[1] : NULL;
    require_exclave(ex, "relink");
    struct stat st;
    if (given && (stat(given, &st) || !S_ISREG(st.st_mode))) fail("no launcher at %s", given);
    char *ld = path_join(ex, ".exclave/launcher"), *root = path_join(ex, "tree");
    struct buf next = {0};
    buf_str(&next, ld);
    buf_add(&next, ".new", sizeof ".new");
    if (given) {
        size_t n;
        char *data = read_file(given, &n);
        unlink(next.p);
        write_file(next.p, data, n, 0755);
        free(data);
    } else {
        unlink(next.p);
        write_file(next.p, launcher_blob, (size_t)launcher_size, 0755);
    }
    if (chmod(next.p, 0755)) fail_errno(next.p);
    struct relinking r = {next.p, 0, {0}};
    walk_dirs(root, 0, relink_dir, &r);
    if (rename(next.p, ld)) fail_errno(next.p);
    write_readme(ex);
    for (size_t i = 0; i < r.strays.n; i += strlen(r.strays.p + i) + 1)
        printf("original without wrapper, left alone: %s\n", r.strays.p + i);
    if (has_tree_record(ex)) write_hashes(ex, NULL, 0, 1);
    printf("relinked %zu wrappers to the new launcher\n", r.n);
    free(r.strays.p);
    free(next.p);
    free(ld);
    free(root);
    return 0;
}
