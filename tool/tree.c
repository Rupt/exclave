/* tree.c — an exclave's tree on disk: the refusal of a directory that is none, and the tree hash (DESIGN.md 6.1,
 * 6.4). */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tool.h"

static int is_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

void require_exclave(const char *ex, const char *cmd)
{
    char *dot_exclave = path_join(ex, ".exclave"), *can = path_join(ex, ".can"), *tree = path_join(ex, "tree");
    int has_exclave = is_dir(dot_exclave);
    /* a can, an exclave in the layout from before the project's rename, is named as one (13 item 45) */
    if (is_dir(can) && !has_exclave)
        fail("refusing: %s is a can, an exclave from before the rename, with .can/ and root/; convert it first "
             "(docs/DESIGN.md 13 item 45)",
             ex);
    if (!is_dir(tree)) fail("refusing: %s has no tree/ directory", ex);
    if (strcmp(cmd, "wrap") != 0 && !has_exclave) fail("refusing: %s has no .exclave/ directory; wrap makes one", ex);
    free(dot_exclave);
    free(can);
    free(tree);
}

/* ---------------------------------------------------------------- the tree hash (6.4) */
struct entry {
    char *p;
    size_t n;
};
struct entries {
    struct entry *e;
    size_t n, cap;
};

static int entry_order(const void *a, const void *b)
{
    const struct entry *x = a, *y = b;
    int c = memcmp(x->p, y->p, x->n < y->n ? x->n : y->n);
    return c ? c : (x->n > y->n) - (x->n < y->n);
}

static _Noreturn void unreadable(const char *path)
{
    if (errno == EACCES) fail("cannot read %s: the tree hash needs every file readable", path);
    fail_errno(path);
}

/* the BLAKE2b-256 of a file's contents, as lowercase hex */
static void hash_file(const char *path, struct buf *out)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) unreadable(path);
    struct blake2b s;
    b2_init(&s, 32);
    static char chunk[1 << 16];
    for (;;) {
        ssize_t k = read(fd, chunk, sizeof chunk);
        if (k < 0) unreadable(path);
        if (k == 0) break;
        b2_update(&s, chunk, (size_t)k);
    }
    close(fd);
    uint8_t d[32];
    char text[B2_TEXT];
    b2_final(&s, d);
    b2_text(d, text);
    buf_str(out, text + 3);
}

/* One entry of the listing: path, NUL, kind, NUL, what the kind records, NUL. A regular file stands for its original
 * in .real/ when it has one, so a wrapper is hashed with the program it runs and its own mode. */
static void add_entry(struct entries *all, const char *rel, const char *real, const struct stat *st)
{
    struct buf b = {0};
    buf_add(&b, rel, strlen(rel) + 1);
    if (S_ISLNK(st->st_mode)) {
        char target[4096];
        ssize_t k = readlink(real, target, sizeof target);
        if (k < 0) fail_errno(real);
        buf_add(&b, "l", 2);
        buf_add(&b, target, (size_t)k);
    } else if (S_ISDIR(st->st_mode)) {
        buf_add(&b, "d", 2);
    } else if (S_ISREG(st->st_mode)) {
        buf_add(&b, st->st_mode & 0111 ? "x" : "f", 2);
        const char *slash = strrchr(real, '/');
        struct buf original = {0};
        buf_add(&original, real, slash ? (size_t)(slash - real + 1) : 0);
        buf_str(&original, ".real/");
        buf_str(&original, slash ? slash + 1 : real);
        buf_add(&original, "", 1);
        struct stat ost;
        hash_file(stat(original.p, &ost) == 0 ? original.p : real, &b);
        free(original.p);
    } else {
        free(b.p); /* sockets, pipes and devices are not in the hash */
        return;
    }
    buf_add(&b, "", 1);
    if (all->n == all->cap) {
        all->cap = all->cap ? 2 * all->cap : 1024;
        all->e = xrealloc(all->e, all->cap * sizeof *all->e);
    }
    all->e[all->n++] = (struct entry){b.p, b.n};
}

static char *rel_join(const char *rel, const char *name)
{
    struct buf b = {0};
    if (*rel) {
        buf_str(&b, rel);
        buf_add(&b, "/", 1);
    }
    buf_str(&b, name);
    buf_add(&b, "", 1);
    return b.p;
}

/* Every entry under real, a directory; .real/ directories are not listed, but a .real/ file without a wrapper beside it
 * is, under its own path, so that no file goes unhashed. */
static void walk(struct entries *all, const char *real, const char *rel)
{
    DIR *d = opendir(real);
    if (!d) unreadable(real);
    struct buf subdirs = {0};
    int has_real = 0;
    for (;;) {
        errno = 0;
        const struct dirent *de = readdir(d);
        if (!de) break;
        const char *name = de->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        char *path = path_join(real, name), *r = rel_join(rel, name);
        struct stat st;
        if (lstat(path, &st)) fail_errno(path);
        if (!strcmp(name, ".real") && is_dir(path)) {
            has_real = 1;
        } else {
            add_entry(all, r, path, &st);
            if (S_ISDIR(st.st_mode)) buf_add(&subdirs, name, strlen(name) + 1);
        }
        free(path);
        free(r);
    }
    if (errno) unreadable(real);
    closedir(d);
    if (has_real) {
        char *dot_real = path_join(real, ".real");
        DIR *rd = opendir(dot_real);
        if (!rd) unreadable(dot_real);
        for (;;) {
            errno = 0;
            const struct dirent *de = readdir(rd);
            if (!de) break;
            const char *name = de->d_name;
            if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
            char *beside = path_join(real, name);
            struct stat st;
            if (lstat(beside, &st) && errno == ENOENT) {
                char *path = path_join(dot_real, name), *dr = rel_join(rel, ".real"), *r = rel_join(dr, name);
                if (lstat(path, &st)) fail_errno(path);
                add_entry(all, r, path, &st);
                free(path);
                free(dr);
                free(r);
            }
            free(beside);
        }
        if (errno) unreadable(dot_real);
        closedir(rd);
        free(dot_real);
    }
    for (size_t i = 0; i < subdirs.n; i += strlen(subdirs.p + i) + 1) {
        char *path = path_join(real, subdirs.p + i), *r = rel_join(rel, subdirs.p + i);
        walk(all, path, r);
        free(path);
        free(r);
    }
    free(subdirs.p);
}

void tree_hash(const char *root, char out[B2_TEXT])
{
    struct entries all = {0};
    walk(&all, root, "");
    if (all.n) qsort(all.e, all.n, sizeof *all.e, entry_order);
    struct blake2b s;
    b2_init(&s, 32);
    for (size_t i = 0; i < all.n; i++) {
        b2_update(&s, all.e[i].p, all.e[i].n);
        free(all.e[i].p);
    }
    free(all.e);
    uint8_t d[32];
    b2_final(&s, d);
    b2_text(d, out);
}
