/* paths.c — virtual paths in an exclave's tree, resolved as a chroot would, and the prefixes the visibility rule
 * compares them with (DESIGN.md 6.1, 8.1). */
#include <errno.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tool.h"

/* The host's volatile directories (8.1): always the host's at run time. */
static const char *const VOLATILE[] = {"/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run"};

int under(const char *v, const char *prefix)
{
    size_t n = strlen(prefix);
    while (n && prefix[n - 1] == '/') n--;
    return !strcmp(v, prefix) || (!strncmp(v, prefix, n) && v[n] == '/');
}

int under_any(const char *v, const struct strs *prefixes)
{
    for (size_t i = 0; prefixes && i < prefixes->n; i++)
        if (under(v, prefixes->s[i])) return 1;
    return 0;
}

int volatile_path(const char *v)
{
    for (size_t i = 0; i < sizeof VOLATILE / sizeof *VOLATILE; i++)
        if (under(v, VOLATILE[i])) return 1;
    return 0;
}

static long longest(const char *v, const struct strs *prefixes)
{
    long best = -1;
    for (size_t i = 0; i < prefixes->n; i++)
        if (under(v, prefixes->s[i]) && (long)strlen(prefixes->s[i]) > best) best = (long)strlen(prefixes->s[i]);
    return best;
}

/* Whether the launcher resolves v on the host (8.1): under a volatile prefix, or when the longest host record
 * covering it is at least as long as the longest own prefix covering it. A path covered by neither is the host's. */
int host_owned(const char *v, const struct ownership *o)
{ return volatile_path(v) || longest(v, &o->host) >= longest(v, &o->own); }

char *tree_real(const char *root, const char *vpath)
{
    while (*vpath == '/') vpath++;
    return path_join(root, vpath);
}

/* the file a path in the tree stands for: a wrapper's original in .real/ beside it when there is one */
char *payload_path(const char *real)
{
    const char *slash = strrchr(real, '/');
    struct buf p = {0};
    buf_add(&p, real, slash ? (size_t)(slash - real + 1) : 0);
    buf_str(&p, ".real/");
    buf_str(&p, slash ? slash + 1 : real);
    buf_add(&p, "", 1);
    struct stat st;
    if (stat(p.p, &st) == 0) return p.p;
    free(p.p);
    size_t n = strlen(real);
    char *copy = xrealloc(NULL, n + 1);
    memcpy(copy, real, n + 1);
    return copy;
}

char *tree_payload(const char *root, const char *vpath)
{
    char *real = tree_real(root, vpath), *p = payload_path(real);
    free(real);
    return p;
}

/* Every component of vpath resolved inside the tree, its symlinks too; with follow_last, the last one's. Returns the
 * canonical virtual path, or NULL when a component is missing or the links loop (the kernel's 40). links, when
 * given, gains every link met on the way. */
static char *dup_str(const char *s)
{
    size_t n = strlen(s);
    char *p = xrealloc(NULL, n + 1);
    memcpy(p, s, n + 1);
    return p;
}

char *tree_resolve(const char *root, const char *vpath, int follow_last, struct strs *links)
{
    struct buf cur = {0}; /* the canonical path so far, NUL-terminated past n */
    buf_add(&cur, "", 1);
    cur.n = 0;
    char *rest = dup_str(vpath), *result = NULL;
    size_t pos = 0;
    int hops = 0;
    for (;;) {
        while (rest[pos] == '/') pos++;
        if (!rest[pos]) {
            if (!cur.n) buf_add(&cur, "/", 1);
            buf_add(&cur, "", 1);
            result = cur.p;
            break;
        }
        const char *comp = rest + pos;
        size_t k = strcspn(comp, "/"), keep = cur.n;
        pos += k;
        if (k == 1 && comp[0] == '.') continue;
        if (k == 2 && comp[0] == '.' && comp[1] == '.') {
            const char *slash = memrchr(cur.p, '/', cur.n);
            cur.n = slash ? (size_t)(slash - cur.p) : 0;
            cur.p[cur.n] = 0;
            continue;
        }
        buf_add(&cur, "/", 1);
        buf_add(&cur, comp, k);
        buf_add(&cur, "", 1);
        cur.n--;
        char *real = tree_real(root, cur.p);
        struct stat st;
        int there = lstat(real, &st) == 0;
        while (rest[pos] == '/') pos++;
        if (!there) {
            free(real);
            break;
        }
        if (S_ISLNK(st.st_mode) && (rest[pos] || follow_last)) {
            char target[PATH_MAX];
            ssize_t t = readlink(real, target, sizeof target - 1);
            free(real);
            if (t < 0 || ++hops > 40) break; /* the kernel's limit, ELOOP */
            target[t] = 0;
            if (links) strs_add(links, cur.p);
            struct buf next = {0};
            buf_add(&next, target, (size_t)t);
            buf_add(&next, "/", 1);
            buf_str(&next, rest + pos);
            buf_add(&next, "", 1);
            free(rest);
            rest = next.p;
            pos = 0;
            cur.n = target[0] == '/' ? 0 : keep;
            cur.p[cur.n] = 0;
            continue;
        }
        free(real);
    }
    free(rest);
    if (!result) free(cur.p);
    return result;
}

/* ---------------------------------------------------------------- the manifest and ownership (6.2, 8.1) */
static struct records manifest_of(const char *ex)
{
    struct records rs = {0};
    char *p = path_join(ex, ".exclave/manifest");
    struct stat st;
    if (stat(p, &st) == 0) {
        size_t n;
        char *data = read_file(p, &n), err[GRAMMAR_ERR];
        if (grammar_parse(data, n, KIND_MANIFEST, &rs, err)) fail_grammar(err);
        free(data);
    }
    free(p);
    return rs;
}

static void values_of(const struct records *rs, const char *key, struct strs *out)
{
    for (size_t i = 0; i < rs->n; i++)
        if (!strcmp(rs->r[i].key, key)) strs_add(out, rs->r[i].f[0].v);
}

void data_prefixes(const char *ex, struct strs *out)
{
    struct records m = manifest_of(ex);
    values_of(&m, "data", out);
    records_free(&m);
}

/* the tree's top-level entries the exclave owns by 8.1 rule 1: all but the empty directories */
void owned_top(const char *ex, struct strs *out)
{
    char *root = path_join(ex, "tree");
    struct entry_info *e;
    size_t n;
    if (list_dir(root, &e, &n)) fail_errno(root);
    for (size_t i = 0; i < n; i++) {
        int empty = 0;
        if (!S_ISLNK(e[i].st.st_mode) && e[i].is_dir) {
            char *p = path_join(root, e[i].name);
            struct entry_info *sub;
            size_t k;
            empty = list_dir(p, &sub, &k) == 0 && k == 0; /* one that cannot be listed is not empty */
            free_list(sub, k);
            free(p);
        }
        if (!empty) {
            char name[4096];
            snprintf(name, sizeof name, "/%s", e[i].name);
            strs_add(out, name);
        }
    }
    free_list(e, n);
    free(root);
}

void ownership_of(const char *ex, struct ownership *o)
{
    *o = (struct ownership){0};
    struct records m = manifest_of(ex);
    values_of(&m, "own", &o->own);
    values_of(&m, "host", &o->host);
    records_free(&m);
    owned_top(ex, &o->own);
}

void ownership_free(struct ownership *o)
{
    strs_free(&o->own);
    strs_free(&o->host);
}

/* ---------------------------------------------------------------- path spelling, as Python's posixpath */
char *normpath(const char *p)
{
    if (!*p) return path_join(".", "");
    int slashes = p[0] == '/' ? (p[1] == '/' && p[2] != '/' ? 2 : 1) : 0;
    struct strs comps = {0};
    for (const char *c = p; *c;) {
        size_t k = strcspn(c, "/");
        char part[4096];
        snprintf(part, sizeof part, "%.*s", (int)k, c);
        c += k;
        while (*c == '/') c++;
        if (!*part || !strcmp(part, ".")) continue;
        if (strcmp(part, "..") != 0 || (!slashes && !comps.n) || (comps.n && !strcmp(comps.s[comps.n - 1], ".."))) {
            strs_add(&comps, part);
        } else if (comps.n) {
            free(comps.s[--comps.n]);
        }
    }
    struct buf out = {0};
    buf_add(&out, "//", (size_t)slashes);
    for (size_t i = 0; i < comps.n; i++) {
        if (i) buf_add(&out, "/", 1);
        buf_str(&out, comps.s[i]);
    }
    if (!out.n) buf_add(&out, ".", 1);
    buf_add(&out, "", 1);
    strs_free(&comps);
    return out.p;
}

char *dirname_of(const char *p)
{
    const char *slash = strrchr(p, '/');
    size_t n = slash ? (size_t)(slash - p + 1) : 0, k = n;
    while (k && p[k - 1] == '/') k--;
    if (k) n = k; /* trailing slashes go, unless the head is all slashes */
    struct buf out = {0};
    buf_add(&out, p, n);
    buf_add(&out, "", 1);
    return out.p;
}

const char *basename_of(const char *p)
{
    const char *slash = strrchr(p, '/');
    return slash ? slash + 1 : p;
}

/* path relative to base, both made absolute and normal as Python's relpath does */
char *relpath(const char *path, const char *base)
{
    char *a = normpath(path), *b = normpath(base);
    struct strs pa = {0}, pb = {0};
    for (int k = 0; k < 2; k++)
        for (char *c = k ? b : a; *c;) {
            size_t n = strcspn(c, "/");
            if (n) {
                char part[4096];
                snprintf(part, sizeof part, "%.*s", (int)n, c);
                strs_add(k ? &pb : &pa, part);
            }
            c += n;
            if (*c) c++;
        }
    size_t i = 0;
    while (i < pa.n && i < pb.n && !strcmp(pa.s[i], pb.s[i])) i++;
    struct buf out = {0};
    for (size_t j = i; j < pb.n; j++) buf_str(&out, out.n ? "/.." : "..");
    for (size_t j = i; j < pa.n; j++) {
        if (out.n) buf_add(&out, "/", 1);
        buf_str(&out, pa.s[j]);
    }
    if (!out.n) buf_add(&out, ".", 1);
    buf_add(&out, "", 1);
    strs_free(&pa);
    strs_free(&pb);
    free(a);
    free(b);
    return out.p;
}
