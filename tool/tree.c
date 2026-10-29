/* tree.c — an exclave's tree on disk: the refusal of a directory that is none, and the tree hash (DESIGN.md 6.1,
 * 6.4). */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
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
/* a file's contents to hash, its hash text to be written at entry e's offset off */
struct job {
    char *path;
    size_t e, off;
    int err; /* the errno of a read that failed, 0 */
};
struct entries {
    struct entry *e;
    size_t n, cap;
    struct job *j;
    size_t nj, capj;
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

/* the BLAKE2b-256 of a file's contents as lowercase hex, 64 characters at out; 0, or the errno of a failed read */
static int hash_file(const char *path, char *out, char *chunk, size_t chunk_size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno;
    struct blake2b s;
    b2_init(&s, 32);
    for (;;) {
        ssize_t k = read(fd, chunk, chunk_size);
        if (k < 0) {
            int e = errno;
            close(fd);
            return e;
        }
        if (k == 0) break;
        b2_update(&s, chunk, (size_t)k);
    }
    close(fd);
    uint8_t d[32];
    char text[B2_TEXT];
    b2_final(&s, d);
    b2_text(d, text);
    memcpy(out, text + 3, 64);
    return 0;
}

/* the files' contents are hashed on several threads, each taking the next job, after the walk has listed them in
 * order; each writes only its own entry's text, so the listing, and the hash of it, are the walk's alone */
struct hashing {
    struct entries *all;
    atomic_size_t next;
};

static void *hash_jobs(void *arg)
{
    struct hashing *h = arg;
    char *chunk = xrealloc(NULL, 1 << 16);
    for (;;) {
        size_t i = atomic_fetch_add(&h->next, 1);
        if (i >= h->all->nj) break;
        struct job *j = &h->all->j[i];
        j->err = hash_file(j->path, h->all->e[j->e].p + j->off, chunk, 1 << 16);
    }
    free(chunk);
    return NULL;
}

static void hash_all(struct entries *all)
{
    struct hashing h = {all, 0};
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    size_t n = cpus < 1 ? 1 : cpus > 8 ? 8 : (size_t)cpus;
    if (n > all->nj) n = all->nj ? all->nj : 1;
    pthread_t t[8];
    size_t started = 0;
    for (; started + 1 < n; started++)
        if (pthread_create(&t[started], NULL, hash_jobs, &h)) break;
    hash_jobs(&h); /* this thread too, and alone where no other could start */
    for (size_t i = 0; i < started; i++) pthread_join(t[i], NULL);
    /* the first file the walk listed that could not be read, as a serial hash would name it */
    for (size_t i = 0; i < all->nj; i++)
        if (all->j[i].err) {
            errno = all->j[i].err;
            unreadable(all->j[i].path);
        }
    for (size_t i = 0; i < all->nj; i++) free(all->j[i].path);
    free(all->j);
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
        if (all->nj == all->capj) {
            all->capj = all->capj ? 2 * all->capj : 1024;
            all->j = xrealloc(all->j, all->capj * sizeof *all->j);
        }
        char *path = original.p;
        if (stat(original.p, &ost)) {
            free(original.p);
            struct buf r = {0};
            buf_str(&r, real);
            buf_add(&r, "", 1);
            path = r.p;
        }
        /* the hash's 64 characters, written by hash_all */
        all->j[all->nj++] = (struct job){path, all->n, b.n, 0};
        buf_add(&b, "................................................................", 64);
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

char *rel_join(const char *rel, const char *name)
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
    hash_all(&all);
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
/* ---------------------------------------------------------------- walks */
static int name_order(const void *a, const void *b)
{ return strcmp(((const struct entry_info *)a)->name, ((const struct entry_info *)b)->name); }

int list_dir(const char *path, struct entry_info **out, size_t *n)
{
    DIR *d = opendir(path);
    *out = NULL;
    *n = 0;
    if (!d) return -1;
    size_t cap = 0;
    for (;;) {
        errno = 0;
        const struct dirent *de = readdir(d);
        if (!de) break;
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (*n == cap) {
            cap = cap ? 2 * cap : 32;
            *out = xrealloc(*out, cap * sizeof **out);
        }
        struct entry_info *e = &(*out)[(*n)++];
        size_t k = strlen(de->d_name);
        e->name = xrealloc(NULL, k + 1);
        memcpy(e->name, de->d_name, k + 1);
        char *p = path_join(path, e->name);
        struct stat st;
        if (lstat(p, &e->st)) memset(&e->st, 0, sizeof e->st);
        e->is_dir = S_ISDIR(e->st.st_mode) || (S_ISLNK(e->st.st_mode) && !stat(p, &st) && S_ISDIR(st.st_mode));
        free(p);
    }
    int saved = errno;
    closedir(d);
    if (saved) {
        free_list(*out, *n);
        errno = saved;
        return -1;
    }
    if (*n) qsort(*out, *n, sizeof **out, name_order);
    return 0;
}

void free_list(struct entry_info *e, size_t n)
{
    for (size_t i = 0; i < n; i++) free(e[i].name);
    free(e);
}

static void walk_dirs_at(const char *dir, const char *rel, int bottom_up, walk_fn fn, void *ctx)
{
    struct entry_info *e;
    size_t n;
    if (list_dir(dir, &e, &n)) return; /* unreadable: skipped with what is beneath it */
    if (!bottom_up) fn(dir, rel, e, n, ctx);
    for (size_t i = 0; i < n; i++)
        if (e[i].is_dir && !S_ISLNK(e[i].st.st_mode)) {
            char *sub = path_join(dir, e[i].name), *r = rel_join(rel, e[i].name);
            walk_dirs_at(sub, r, bottom_up, fn, ctx);
            free(sub);
            free(r);
        }
    if (bottom_up) {
        /* the listing again: what the walk below moved has changed it */
        free_list(e, n);
        if (list_dir(dir, &e, &n)) return;
        fn(dir, rel, e, n, ctx);
    }
    free_list(e, n);
}

void walk_dirs(const char *root, int bottom_up, walk_fn fn, void *ctx) { walk_dirs_at(root, "", bottom_up, fn, ctx); }

int is_real_dir(const char *dir)
{
    const char *slash = strrchr(dir, '/');
    return !strcmp(slash ? slash + 1 : dir, ".real");
}

static void collect_strays(const char *dir, const char *rel, struct entry_info *e, size_t n, void *ctx)
{
    if (!is_real_dir(dir)) return;
    const char *slash = strrchr(dir, '/');
    char *parent = xrealloc(NULL, (size_t)(slash - dir) + 1);
    memcpy(parent, dir, (size_t)(slash - dir));
    parent[slash - dir] = 0;
    for (size_t i = 0; i < n; i++) {
        if (e[i].is_dir) continue;
        char *beside = path_join(parent, e[i].name);
        struct stat st;
        if (lstat(beside, &st)) {
            char *r = rel_join(rel, e[i].name);
            buf_add(ctx, "/", 1);
            buf_add(ctx, r, strlen(r) + 1);
            free(r);
        }
        free(beside);
    }
    free(parent);
}

void strays(const char *root, struct buf *out) { walk_dirs(root, 0, collect_strays, out); }

static void walk_files_at(const char *dir, const char *rel, file_fn fn, void *ctx)
{
    struct entry_info *e;
    size_t n;
    if (list_dir(dir, &e, &n)) return; /* unreadable: passed over with what is beneath it */
    for (size_t i = 0; i < n; i++) {
        if (e[i].is_dir && (!strcmp(e[i].name, ".real") || !S_ISLNK(e[i].st.st_mode))) continue;
        char *real = path_join(dir, e[i].name), *r = rel_join(rel, e[i].name), *v = path_join("/", r);
        fn(real, v, &e[i].st, ctx);
        free(real);
        free(r);
        free(v);
    }
    for (size_t i = 0; i < n; i++) {
        if (!e[i].is_dir || S_ISLNK(e[i].st.st_mode) || !strcmp(e[i].name, ".real")) continue;
        char *sub = path_join(dir, e[i].name), *r = rel_join(rel, e[i].name);
        walk_files_at(sub, r, fn, ctx);
        free(sub);
        free(r);
    }
    free_list(e, n);
}

void walk_files(const char *root, file_fn fn, void *ctx) { walk_files_at(root, "", fn, ctx); }
