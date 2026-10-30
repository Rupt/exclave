/* search.c — the loader's search for a library, as the tree's own loader makes it (DESIGN.md 10.3): the machine's
 * default directories, DT_RPATH and DT_RUNPATH with their tokens expanded, ld.so.cache, and the directories the loader
 * names for itself; and the glibc a tree carries, by its banner. The static check and prune ask it. */
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "tool.h"

/* ---------------------------------------------------------------- machines (7.1) */
const struct machine MACHINES[2] = {
    {62,
     "x86_64",
     "x86_64-linux-gnu",
     {"glibc-hwcaps/x86-64-v4", "glibc-hwcaps/x86-64-v3", "glibc-hwcaps/x86-64-v2"},
     3},
    {183, "aarch64", "aarch64-linux-gnu", {0}, 0},
};
#if defined(__x86_64__)
const struct machine *MACHINE = &MACHINES[0];
#elif defined(__aarch64__)
const struct machine *MACHINE = &MACHINES[1];
#endif

/* The exclave's machine is its launcher's (10.1): the checks read the tree as that machine's loader would, so an
 * exclave of another architecture is wrapped and checked here. A launcher for a machine the table lacks is refused. */
void machine_of_launcher(const char *ex)
{
    char *ld = path_join(ex, ".exclave/launcher"), why[ELF_WHY];
    struct elf e;
    if (elf_read(ld, &e, why) == ELF_OK) {
        const struct machine *m = NULL;
        for (size_t i = 0; i < sizeof MACHINES / sizeof *MACHINES; i++)
            if (MACHINES[i].e_machine == e.machine) m = &MACHINES[i];
        if (!m) fail("%s is a launcher for machine %d, which this command does not know", ld, e.machine);
        MACHINE = m;
        elf_free(&e);
    }
    free(ld);
}

/* glibc's default directories on Debian and Fedora, for a loader that carries no table of them */
void default_dirs(struct strs *out)
{
    char d[96];
    snprintf(d, sizeof d, "/lib/%s", MACHINE->triplet);
    strs_add(out, d);
    snprintf(d, sizeof d, "/usr/lib/%s", MACHINE->triplet);
    strs_add(out, d);
    strs_add(out, "/lib64");
    strs_add(out, "/usr/lib64");
    strs_add(out, "/lib");
    strs_add(out, "/usr/lib");
}

/* glibc's substitutions in an RPATH, a RUNPATH or a DT_NEEDED path (dl-load.c), each made over the whole string in
 * turn */
static char *expand(const char *s, const char *origin)
{
    char lib[96];
    snprintf(lib, sizeof lib, "lib/%s", MACHINE->triplet);
    const char *const subs[][2] = {{"$ORIGIN", origin}, {"${ORIGIN}", origin},         {"$LIB", lib},
                                   {"${LIB}", lib},     {"$PLATFORM", MACHINE->uname}, {"${PLATFORM}", MACHINE->uname}};
    struct buf cur = {0};
    buf_str(&cur, s);
    buf_add(&cur, "", 1);
    for (size_t i = 0; i < sizeof subs / sizeof *subs; i++) {
        struct buf next = {0};
        size_t k = strlen(subs[i][0]);
        for (const char *c = cur.p; *c;) {
            if (!strncmp(c, subs[i][0], k)) {
                buf_str(&next, subs[i][1]);
                c += k;
            } else {
                buf_add(&next, c++, 1);
            }
        }
        buf_add(&next, "", 1);
        free(cur.p);
        cur = next;
    }
    return cur.p;
}

/* ---------------------------------------------------------------- the loader's search */
int is_payload_file(const char *root, const char *v)
{
    char *p = tree_payload(root, v);
    struct stat st;
    int ok = stat(p, &st) == 0 && S_ISREG(st.st_mode);
    free(p);
    return ok;
}

/* the first of the tree's files the loader would take in directory d for name, its hwcaps subdirectories first */
static char *search_dir(const char *root, const char *d, const char *name)
{
    for (int i = 0; i <= MACHINE->nhwcaps; i++) {
        char *sub = i < MACHINE->nhwcaps ? path_join(d, MACHINE->hwcaps[i]) : NULL;
        char *cand = path_join(sub ? sub : d, name);
        free(sub);
        char *r = tree_resolve(root, cand, 1, NULL);
        free(cand);
        if (r && is_payload_file(root, r)) return r;
        free(r);
    }
    return NULL;
}

static void split_add(struct strs *out, const char *list, const char *origin)
{
    for (const char *c = list; *c;) {
        size_t k = strcspn(c, ":");
        if (k) {
            char part[4096];
            snprintf(part, sizeof part, "%.*s", (int)k, c);
            char *x = expand(part, origin);
            strs_add(out, x);
            free(x);
        }
        c += k;
        if (*c) c++;
    }
}

/* The virtual path the loader would load for a DT_NEEDED entry, or NULL. The loader satisfies its own soname without
 * a search; a name with a slash is loaded as a path; otherwise glibc's search: RPATH (with those inherited) unless
 * there is a RUNPATH, then RUNPATH, the cache and the default directories. */
char *find_library(const struct search *s, const char *name, const struct elf *e, const char *vpath,
                   const struct strs *rpaths)
{
    if (s->interp && !strcmp(name, basename_of(s->interp))) {
        char *r = tree_resolve(s->root, s->interp, 1, NULL);
        if (r) return r;
    }
    if (strchr(name, '/')) { /* glibc expands the tokens in a path first (dl-load.c); musl does not */
        char *n2 = NULL;
        if (s->interp && !strstr(basename_of(s->interp), "musl")) {
            char *origin = dirname_of(vpath), *x = expand(name, origin);
            n2 = normpath(x);
            free(origin);
            free(x);
        }
        const char *use = n2 ? n2 : name;
        char *r = use[0] == '/' ? tree_resolve(s->root, use, 1, NULL) : NULL;
        free(n2);
        return r;
    }
    char *origin = dirname_of(vpath);
    struct strs search = {0};
    if (!e->runpath) {
        if (e->rpath) split_add(&search, e->rpath, origin);
        for (size_t i = 0; i < rpaths->n; i++) split_add(&search, rpaths->s[i], origin);
    } else {
        split_add(&search, e->runpath, origin);
    }
    free(origin);
    char *found = NULL;
    for (size_t i = 0; i < search.n && !found; i++) {
        if (s->host_hits) {
            char *np = normpath(search.s[i]);
            if (host_owned(np, s->own)) strs_add(s->host_hits, search.s[i]);
            free(np);
        }
        found = search_dir(s->root, search.s[i], name);
    }
    strs_free(&search);
    for (size_t i = 0; !found && s->cache && i < s->cache->n; i++) {
        if (strcmp(s->cache->e[i].soname, name) != 0) continue;
        char *r = tree_resolve(s->root, s->cache->e[i].path, 1, NULL);
        if (r && is_payload_file(s->root, r)) found = r;
        else free(r);
    }
    for (size_t i = 0; !found && i < s->defaults->n; i++) {
        if (s->host_hits) {
            char *np = normpath(s->defaults->s[i]);
            if (host_owned(np, s->own)) strs_add(s->host_hits, s->defaults->s[i]);
            free(np);
        }
        found = search_dir(s->root, s->defaults->s[i], name);
    }
    return found;
}

/* ---------------------------------------------------------------- the loader's own directories */
/* The first run of two or more NUL-terminated strings spelt /.../ in data[0..n), each ending in a slash, appended to
 * out without the trailing slash; returns the number found. */
static size_t dirs_run(const char *data, size_t n, struct strs *out)
{
    size_t at = 0, run_from = 0;
    int run = 0;
    while (at < n) {
        size_t k = strnlen(data + at, n - at);
        if (k >= 2 && data[at] == '/' && data[at + k - 1] == '/') {
            if (!run) run_from = at;
            run++;
        } else if (run >= 2) {
            break;
        } else {
            run = 0;
        }
        at += k + 1;
    }
    if (run < 2) return 0;
    for (size_t i = run_from, left = (size_t)run; left; left--) {
        size_t k = strnlen(data + i, n - i);
        char *v = xrealloc(NULL, k + 1);
        memcpy(v, data + i, k);
        v[k] = 0;
        while (k > 1 && v[k - 1] == '/') v[--k] = 0;
        strs_add(out, v);
        free(v);
        i += strnlen(data + i, n - i) + 1;
    }
    return (size_t)run;
}

static uint64_t le(const unsigned char *p, int n) /* a little-endian field of n bytes */
{
    uint64_t v = 0;
    for (int i = n - 1; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

/* The table in an ELF file's read-only data: its allocated sections that are neither code nor writable, in file order,
 * so that a string is one a section holds and not the tail of the code before it; a file without section headers is
 * read whole. */
static size_t dirs_table(const char *data, size_t n, struct strs *out)
{
    if (n < 64 || memcmp(data, "\177ELF", 4) != 0 || (data[4] != 1 && data[4] != 2)) return dirs_run(data, n, out);
    const unsigned char *u = (const unsigned char *)data;
    int cls = (unsigned char)data[4];
    uint64_t shoff = cls == 1 ? le(u + 32, 4) : le(u + 40, 8);
    uint64_t shentsize = cls == 1 ? le(u + 46, 2) : le(u + 58, 2), shnum = cls == 1 ? le(u + 48, 2) : le(u + 60, 2);
    size_t found = 0, seen = 0;
    for (uint64_t i = 0; i < shnum && !found; i++) {
        uint64_t o = shoff + i * shentsize;
        if (o + (cls == 1 ? 40 : 64) > n) break;
        uint64_t kind = le(u + o + 4, 4);
        uint64_t flags = cls == 1 ? le(u + o + 8, 4) : le(u + o + 8, 8);
        uint64_t off = cls == 1 ? le(u + o + 16, 4) : le(u + o + 24, 8);
        uint64_t size = cls == 1 ? le(u + o + 20, 4) : le(u + o + 32, 8);
        /* SHT_PROGBITS, SHF_ALLOC, neither SHF_EXECINSTR nor SHF_WRITE */
        if (kind != 1 || !(flags & 2) || (flags & 5) || off > n || size > n - off) continue;
        seen++;
        found = dirs_run(data + off, (size_t)size, out);
    }
    return seen ? found : dirs_run(data, n, out);
}

/* The default search directories of the tree's loader, read from the loader file: glibc's build writes them into the
 * loader as a table of consecutive strings, each `/.../`, the same table `--list-diagnostics` prints as
 * path.system_dirs; musl's are fixed. Nothing of the tree runs, so a loader of another machine is read like this one's
 * (10.3). The loader read is the file PT_INTERP names in the tree, never a host file an absolute link names. Returns
 * the reason when the directories were assumed instead: Debian's and Fedora's defaults, for a loader without the
 * table. */
char *loader_dirs(const char *root, const char *interp, struct strs *out)
{
    if (!interp) {
        default_dirs(out);
        return NULL;
    }
    if (strstr(basename_of(interp), "musl")) {
        strs_add(out, "/lib");
        strs_add(out, "/usr/local/lib");
        strs_add(out, "/usr/lib");
        return NULL;
    }
    char *r = tree_resolve(root, interp, 1, NULL), *loader = tree_payload(root, r ? r : interp);
    free(r);
    size_t n = 0;
    struct stat st;
    char *data = stat(loader, &st) == 0 && S_ISREG(st.st_mode) ? read_file(loader, &n) : xrealloc(NULL, 1);
    free(loader);
    dirs_table(data, n, out);
    free(data);
    if (out->n) return NULL;
    default_dirs(out);
    struct buf why = {0};
    buf_str(&why, "the loader ");
    buf_str(&why, interp);
    buf_str(&why, " carries no table of search directories (not glibc's?): ");
    for (size_t i = 0; i < out->n; i++) {
        if (i) buf_add(&why, ":", 1);
        buf_str(&why, out->s[i]);
    }
    buf_str(&why, " assumed");
    buf_add(&why, "", 1);
    return why.p;
}

int glibc_version(const char *root, int *major, int *minor)
{
    struct strs dirs = {0};
    default_dirs(&dirs);
    int got = 0;
    for (size_t i = 0; i < dirs.n && !got; i++) {
        char *p = path_join(dirs.s[i], GLIBC_SONAME), *r = tree_resolve(root, p, 1, NULL);
        free(p);
        if (r && is_payload_file(root, r)) {
            char *pay = tree_payload(root, r);
            size_t n;
            char *data = read_file(pay, &n);
            static const char lead[] = "GNU C Library (";
            /* GNU C Library (...) [WORD ]release version M.N, the first such banner */
            const char *c = data;
            while (!got) {
                c = memmem(c, (size_t)(data + n - c), lead, sizeof lead - 1);
                if (!c) break;
                c += sizeof lead - 1;
                const char *q = c;
                while (q < data + n && *q != ')') q++;
                const char *t = q + 1;
                if (q >= data + n || t >= data + n || *t != ' ') continue;
                t++;
                static const char rv[] = "release version ";
                const char *w = t;
                while (w < data + n && (isalnum((unsigned char)*w) || *w == '_')) w++;
                if (w > t && w < data + n && *w == ' ' && (size_t)(data + n - (w + 1)) >= sizeof rv - 1 &&
                    !memcmp(w + 1, rv, sizeof rv - 1))
                    t = w + 1;
                if ((size_t)(data + n - t) < sizeof rv - 1 || memcmp(t, rv, sizeof rv - 1) != 0) continue;
                t += sizeof rv - 1;
                char *end;
                long a = strtol(t, &end, 10);
                if (end == t || *end != '.' || !isdigit((unsigned char)end[1]) || !isdigit((unsigned char)*t)) continue;
                long b = strtol(end + 1, NULL, 10);
                *major = (int)a;
                *minor = (int)b;
                got = 1;
            }
            free(data);
            free(pay);
        }
        free(r);
    }
    strs_free(&dirs);
    return got;
}
