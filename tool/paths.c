/* paths.c — virtual paths in an exclave's tree, resolved as a chroot would, and the prefixes the visibility rule
 * compares them with (DESIGN.md 6.1, 8.1). */
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tool.h"

/* The host's volatile directories (8.1): always the host's at run time. */
static const char *const VOLATILE[] = {"/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run"};

void strs_add(struct strs *l, const char *s)
{
    size_t n = strlen(s);
    l->s = xrealloc(l->s, (l->n + 1) * sizeof *l->s);
    l->s[l->n] = xrealloc(NULL, n + 1);
    memcpy(l->s[l->n++], s, n + 1);
}

void strs_free(struct strs *l)
{
    for (size_t i = 0; i < l->n; i++) free(l->s[i]);
    free(l->s);
    *l = (struct strs){0};
}

int strs_has(const struct strs *l, const char *s)
{
    for (size_t i = 0; i < l->n; i++)
        if (!strcmp(l->s[i], s)) return 1;
    return 0;
}

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
