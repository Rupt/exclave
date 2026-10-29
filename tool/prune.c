/* prune.c — the exclave pruned to what logged workloads touched (DESIGN.md 10.4). */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tool.h"

/* The virtual paths of the packages' licence texts, which prune keeps: under every usr/share/ of the tree, a data
 * directory's included, Debian's doc/PKG/copyright and every file under common-licenses/ and licenses/, where RPM's
 * %license files and Alpine's -doc packages put theirs. */
static void licence_files_at(const char *dir, const char *rel, struct strs *out)
{
    struct entry_info *e;
    size_t n;
    if (list_dir(dir, &e, &n)) return;
    for (size_t i = 0; i < n; i++)
        if (!e[i].is_dir) {
            char *r = rel_join(rel, e[i].name), *v = path_join("/", r);
            strs_add(out, v);
            free(r);
            free(v);
        }
    for (size_t i = 0; i < n; i++)
        if (e[i].is_dir && !S_ISLNK(e[i].st.st_mode)) {
            char *sub = path_join(dir, e[i].name), *r = rel_join(rel, e[i].name);
            licence_files_at(sub, r, out);
            free(sub);
            free(r);
        }
    free_list(e, n);
}

static void find_shares(const char *dir, const char *rel, struct strs *out)
{
    struct entry_info *e;
    size_t n;
    if (list_dir(dir, &e, &n)) return;
    int is_share = !strcmp(basename_of(dir), "share") && rel[0];
    if (is_share) {
        char *parent = dirname_of(dir);
        is_share = !strcmp(basename_of(parent), "usr");
        free(parent);
    }
    if (is_share) { /* below a usr/share/, only its licence texts */
        char *doc = path_join(dir, "doc");
        struct entry_info *pk;
        size_t k;
        if (!list_dir(doc, &pk, &k)) {
            for (size_t i = 0; i < k; i++) {
                if (pk[i].name[0] == '.') continue;
                char *c = path_join(doc, pk[i].name), *cr = path_join(c, "copyright");
                struct stat st;
                if (lstat(cr, &st) == 0) {
                    char v[8192];
                    snprintf(v, sizeof v, "/%s/doc/%s/copyright", rel, pk[i].name);
                    strs_add(out, v);
                }
                free(c);
                free(cr);
            }
            free_list(pk, k);
        }
        free(doc);
        static const char *const tops[] = {"common-licenses", "licenses"};
        for (int t = 0; t < 2; t++) {
            char *top = path_join(dir, tops[t]), *r = rel_join(rel, tops[t]);
            licence_files_at(top, r, out);
            free(top);
            free(r);
        }
    } else {
        for (size_t i = 0; i < n; i++)
            if (e[i].is_dir && !S_ISLNK(e[i].st.st_mode)) {
                char *sub = path_join(dir, e[i].name), *r = rel_join(rel, e[i].name);
                find_shares(sub, r, out);
                free(sub);
                free(r);
            }
    }
    free_list(e, n);
}

/* ---------------------------------------------------------------- the libraries kept ELF files need */
struct closure {
    const struct search *s;
    struct set seen;
    struct uniq *out;
};

static void visit(struct closure *c, const char *vpath, const struct elf *e, const struct strs *rpaths)
{
    struct buf key = {0};
    buf_str(&key, vpath);
    for (size_t i = 0; i < rpaths->n; i++) {
        buf_add(&key, "\n\x01", 2);
        buf_str(&key, rpaths->s[i]);
    }
    int fresh = set_add(&c->seen, key.p, key.n);
    free(key.p);
    if (!fresh) return;
    if (e->interp) uniq_add(c->out, e->interp);
    struct strs below = {0};
    if (!e->runpath && e->rpath) strs_add(&below, e->rpath);
    for (size_t i = 0; i < rpaths->n; i++) strs_add(&below, rpaths->s[i]);
    for (size_t i = 0; i < e->nneeded; i++) {
        char *found = find_library(c->s, e->needed[i], e, vpath, rpaths);
        if (!found) continue;
        uniq_add(c->out, found);
        char *pay = tree_payload(c->s->root, found), why[ELF_WHY];
        struct elf fe;
        if (elf_read(pay, &fe, why) == ELF_OK) {
            visit(c, found, &fe, &below);
            elf_free(&fe);
        }
        free(pay);
        free(found);
    }
    strs_free(&below);
}

/* Every library the given ELF files reach through DT_NEEDED, each found by the loader's search with RPATHs inherited
 * down the chain, and each loader the files name, since the launcher loads it and no logged call does (10.4). */
static void needed_closure(const char *root, const struct strs *elfs, struct uniq *out)
{
    struct cache cache;
    int has_cache = read_cache(root, &cache);
    const char *interp = NULL;
    struct elf first = {0};
    char why[ELF_WHY];
    for (size_t i = 0; i < elfs->n && !interp; i++) {
        char *pay = tree_payload(root, elfs->s[i]);
        if (elf_read(pay, &first, why) == ELF_OK) {
            if (first.interp) interp = first.interp;
            else elf_free(&first);
        }
        free(pay);
    }
    struct strs defaults = {0};
    free(loader_dirs(root, interp, &defaults));
    struct search s = {root, has_cache ? &cache : NULL, &defaults, interp, NULL, NULL};
    struct closure c = {&s, {0}, out};
    struct strs none = {0};
    for (size_t i = 0; i < elfs->n; i++) {
        char *pay = tree_payload(root, elfs->s[i]);
        struct elf e;
        if (elf_read(pay, &e, why) == ELF_OK) {
            visit(&c, elfs->s[i], &e, &none);
            elf_free(&e);
        }
        free(pay);
    }
    set_free(&c.seen);
    strs_free(&defaults);
    elf_free(&first);
    cache_free(&cache);
}

/* ---------------------------------------------------------------- prune */
static int bytes_order(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

struct keeping {
    const char *root;
    struct uniq *keep;
};

/* every symlink that reaches a kept file, or a directory, stays with its chain */
static void keep_link(const char *real, const char *v, const struct stat *st, void *ctx)
{
    (void)real;
    struct keeping *k = ctx;
    if (!S_ISLNK(st->st_mode) || uniq_has(k->keep, v)) return;
    struct strs chain = {0};
    char *final = tree_resolve(k->root, v, 1, &chain);
    int keep = 0;
    if (final) {
        char *fr = tree_real(k->root, final);
        struct stat fst;
        keep = uniq_has(k->keep, final) || (stat(fr, &fst) == 0 && S_ISDIR(fst.st_mode));
        free(fr);
    }
    if (keep) {
        for (size_t i = 0; i < chain.n; i++) uniq_add(k->keep, chain.s[i]);
        uniq_add(k->keep, v);
    }
    strs_free(&chain);
    free(final);
}

struct removal {
    const char *root;
    const struct uniq *keep;
    size_t kept, removed;
    unsigned long long freed;
};

static void remove_dir(const char *dir, const char *rel, struct entry_info *e, size_t n, void *ctx)
{
    struct removal *r = ctx;
    int in_real = is_real_dir(dir);
    char *parent_rel = in_real ? dirname_of(rel) : NULL;
    for (size_t i = 0; i < n; i++) {
        if (e[i].is_dir && !S_ISLNK(e[i].st.st_mode)) continue;
        char *real = path_join(dir, e[i].name), *wr = rel_join(in_real ? parent_rel : rel, e[i].name),
             *w = path_join("/", wr);
        if (uniq_has(r->keep, w)) {
            r->kept++;
        } else {
            /* originals and plain files; a wrapper is a link to the launcher */
            char *dot_real = path_join(dir, ".real"), *orig = path_join(dot_real, e[i].name);
            struct stat st;
            int is_wrap = !in_real && stat(orig, &st) == 0;
            if (S_ISREG(e[i].st.st_mode) && !is_wrap) r->freed += (unsigned long long)e[i].st.st_size;
            if (unlink(real)) fail_errno(real);
            r->removed++;
            free(dot_real);
            free(orig);
        }
        free(real);
        free(wr);
        free(w);
    }
    free(parent_rel);
}

/* Prune the tree to what the logged workloads touched: the files they touched, the entries of directories they opened,
 * the symlink chains that reach kept files, the libraries kept ELF files need, the identity files and the licence
 * texts. Directories are never removed, so ownership and ls do not change. Then the static check runs on what is
 * left. */
int cmd_prune(int argc, char **argv)
{
    if (argc < 2) usage("prune EXCLAVE LOG...");
    const char *ex = argv[0];
    require_exclave(ex, "prune");
    struct ownership own;
    ownership_of(ex, &own);
    char *root = path_join(ex, "tree");
    struct uniq keep = {0}, whole = {0};
    size_t programs = 0;
    for (int l = 1; l < argc; l++) {
        struct log_line *lines;
        size_t n = read_log(argv[l], &lines);
        for (size_t i = 0; i < n; i++) {
            const struct log_line *x = &lines[i];
            if (!strcmp(x->what, "launcher") || x->path[0] != '/' || x->result < 0 || host_owned(x->path, &own))
                continue;
            struct strs links = {0};
            char *final = tree_resolve(root, x->path, 1, &links);
            for (size_t k = 0; k < links.n; k++) uniq_add(&keep, links.s[k]);
            strs_free(&links);
            if (!final) continue;
            char *real = tree_real(root, final);
            struct stat st;
            if (stat(real, &st) == 0 && S_ISDIR(st.st_mode)) {
                if (!strcmp(x->what, "open")) uniq_add(&whole, final); /* a directory opened may be listed */
            } else {
                uniq_add(&keep, final);
                if (!strcmp(x->what, "exec") || !strcmp(x->what, "load")) programs++;
            }
            free(real);
            free(final);
        }
        free_log(lines, n);
    }
    if (!programs) fail("the logs name no program in this exclave; nothing to prune to");
    for (size_t i = 0; i < N_IDENTITY_FILES + 1; i++) {
        const char *f = i < N_IDENTITY_FILES ? IDENTITY_FILES[i] : "/etc/ld.so.cache";
        char *p = tree_real(root, f);
        struct stat st;
        if (lstat(p, &st) == 0) uniq_add(&keep, f);
        free(p);
    }
    struct strs licences = {0}; /* the packages' licence texts go with every copy */
    find_shares(root, "", &licences);
    for (size_t i = 0; i < licences.n; i++) {
        struct strs links = {0};
        char *final = tree_resolve(root, licences.s[i], 1, &links);
        for (size_t k = 0; k < links.n; k++) uniq_add(&keep, links.s[k]);
        if (final) uniq_add(&keep, final);
        strs_free(&links);
        free(final);
    }
    strs_free(&licences);
    for (size_t i = 0; i < whole.list.n; i++) { /* its own entries: a getdents shows names, nothing below them */
        char *d = tree_real(root, whole.list.s[i]);
        struct entry_info *e;
        size_t n;
        if (list_dir(d, &e, &n)) fail_errno(d);
        for (size_t j = 0; j < n; j++)
            if (!e[j].is_dir || S_ISLNK(e[j].st.st_mode)) {
                char *v = path_join(whole.list.s[i], e[j].name);
                uniq_add(&keep, v);
                free(v);
            }
        free_list(e, n);
        free(d);
    }
    /* the libraries every kept ELF needs, by the loader's own search (10.3) */
    struct strs sorted = {0}, elfs = {0};
    struct uniq closure = {0};
    for (size_t i = 0; i < keep.list.n; i++) strs_add(&sorted, keep.list.s[i]);
    if (sorted.n) qsort(sorted.s, sorted.n, sizeof *sorted.s, bytes_order);
    for (size_t i = 0; i < sorted.n; i++) {
        char *real = tree_real(root, sorted.s[i]);
        struct stat st;
        if (lstat(real, &st) == 0 && S_ISREG(st.st_mode) && !strstr(sorted.s[i], "/.real/")) {
            char *pay = tree_payload(root, sorted.s[i]), head[4];
            int fd = open(pay, O_RDONLY | O_CLOEXEC);
            if (fd < 0) fail_errno(pay);
            if (read(fd, head, 4) == 4 && !memcmp(head,
                                                  "\x7f"
                                                  "ELF",
                                                  4))
                strs_add(&elfs, sorted.s[i]);
            close(fd);
            free(pay);
        }
        free(real);
    }
    needed_closure(root, &elfs, &closure);
    for (size_t i = 0; i < closure.list.n; i++) { /* the chain of links, then the file they reach */
        struct strs links = {0};
        char *final = tree_resolve(root, closure.list.s[i], 1, &links);
        for (size_t k = 0; k < links.n; k++) uniq_add(&keep, links.s[k]);
        if (final) uniq_add(&keep, final);
        strs_free(&links);
        free(final);
    }
    /* the log names canonical paths, so every alias a program used is a symlink to keep */
    struct keeping k = {root, &keep};
    walk_files(root, keep_link, &k);
    struct removal r = {root, &keep, 0, 0, 0};
    walk_dirs(root, 0, remove_dir, &r);
    printf("pruned %s: kept %zu files, removed %zu, %llu bytes freed\n", ex, r.kept, r.removed, r.freed);
    if (has_tree_record(ex)) write_hashes(ex, NULL, 0, 1);
    int errors = static_report(ex);
    strs_free(&sorted);
    strs_free(&elfs);
    uniq_free(&closure);
    uniq_free(&keep);
    uniq_free(&whole);
    ownership_free(&own);
    free(root);
    return errors ? 1 : 0;
}
