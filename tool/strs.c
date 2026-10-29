/* strs.c — collections of strings: a list in the order added, a set of byte strings, and a list of distinct strings
 * with a set as its index, so that a membership test costs the same for a hundred thousand paths as for ten. */
#include <stdlib.h>
#include <string.h>
#include "tool.h"

void strs_add(struct strs *l, const char *s)
{
    size_t n = strlen(s);
    if (l->n == l->cap) {
        l->cap = l->cap ? 2 * l->cap : 16;
        l->s = xrealloc(l->s, l->cap * sizeof *l->s);
    }
    l->s[l->n] = xrealloc(NULL, n + 1);
    memcpy(l->s[l->n++], s, n + 1);
}

void strs_free(struct strs *l)
{
    for (size_t i = 0; i < l->n; i++) free(l->s[i]);
    free(l->s);
    *l = (struct strs){0};
}

/* a linear search, for the short lists: prefixes, a library's RPATHs, the names of a chain */
int strs_has(const struct strs *l, const char *s)
{
    for (size_t i = 0; i < l->n; i++)
        if (!strcmp(l->s[i], s)) return 1;
    return 0;
}

static uint64_t fnv(const char *p, size_t n)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) h = (h ^ (unsigned char)p[i]) * 1099511628211ULL;
    return h;
}

/* adds the key and returns 1, or returns 0 when it was there; open addressing, at most half full */
int set_add(struct set *s, const char *p, size_t n)
{
    if (2 * (s->n + 1) > s->cap) {
        struct set bigger = {xrealloc(NULL, (s->cap ? 2 * s->cap : 64) * sizeof *s->k), 0, s->cap ? 2 * s->cap : 64};
        memset(bigger.k, 0, bigger.cap * sizeof *bigger.k);
        for (size_t i = 0; i < s->cap; i++)
            if (s->k[i].p) {
                size_t j = fnv(s->k[i].p, s->k[i].n) % bigger.cap;
                while (bigger.k[j].p) j = (j + 1) % bigger.cap;
                bigger.k[j] = s->k[i];
                bigger.n++;
            }
        free(s->k);
        *s = bigger;
    }
    size_t j = fnv(p, n) % s->cap;
    for (; s->k[j].p; j = (j + 1) % s->cap)
        if (s->k[j].n == n && !memcmp(s->k[j].p, p, n)) return 0;
    struct buf b = {0};
    buf_add(&b, p, n);
    buf_add(&b, "", 1);
    b.n = n;
    s->k[j] = b;
    s->n++;
    return 1;
}

int set_has(const struct set *s, const char *p, size_t n)
{
    if (!s->cap) return 0;
    for (size_t j = fnv(p, n) % s->cap; s->k[j].p; j = (j + 1) % s->cap)
        if (s->k[j].n == n && !memcmp(s->k[j].p, p, n)) return 1;
    return 0;
}

void set_free(struct set *s)
{
    for (size_t i = 0; i < s->cap; i++) free(s->k[i].p);
    free(s->k);
    *s = (struct set){0};
}

int uniq_add(struct uniq *u, const char *s)
{
    if (!set_add(&u->index, s, strlen(s))) return 0;
    strs_add(&u->list, s);
    return 1;
}

int uniq_has(const struct uniq *u, const char *s) { return set_has(&u->index, s, strlen(s)); }

void uniq_free(struct uniq *u)
{
    strs_free(&u->list);
    set_free(&u->index);
}
