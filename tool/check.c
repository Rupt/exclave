/* check.c — the static and dynamic checks of an exclave's ELF files, and the check command (DESIGN.md 10.3).
 *
 * The static check reads every ELF file under tree/ outside data directories, taking originals in place of wrappers.
 * All of them must name one interpreter, resolved through the tree's symlinks; every DT_NEEDED must resolve inside
 * the tree by the loader's own search; and every library reached must depend on that loader's libc and no other. A
 * library that would load from the host, or a mix of libcs, is an error that refuses the exclave. Static executables
 * are counted.
 *
 * The dynamic check reads the EXCLAVE_LOG files a workload wrote. Every library opened must lie on a path the
 * exclave owns, and NSS modules that this host's nsswitch.conf names but the exclave lacks are reported. */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "tool.h"

enum { ET_DYN = 3 };

/* ---------------------------------------------------------------- machines (7.1) */
struct machine {
    int e_machine;
    const char *uname, *triplet; /* uname -m, which glibc's loader substitutes for $PLATFORM; the multiarch triplet */
    const char *hwcaps[3];       /* the glibc-hwcaps subdirectories searched first, best first */
    int nhwcaps;
};
static const struct machine MACHINES[] = {
    {62,
     "x86_64",
     "x86_64-linux-gnu",
     {"glibc-hwcaps/x86-64-v4", "glibc-hwcaps/x86-64-v3", "glibc-hwcaps/x86-64-v2"},
     3},
    {183, "aarch64", "aarch64-linux-gnu", {0}, 0},
};
#if defined(__x86_64__)
static const struct machine *const NATIVE = &MACHINES[0];
#elif defined(__aarch64__)
static const struct machine *const NATIVE = &MACHINES[1];
#endif
#define GLIBC_SONAME "libc.so.6"

static const char *uname_machine(void)
{
    static struct utsname u;
    if (!u.machine[0] && uname(&u)) return NATIVE->uname;
    return u.machine;
}

/* glibc's default directories on Debian and Fedora, for a loader that cannot be asked */
static void default_dirs(struct strs *out)
{
    char d[96];
    snprintf(d, sizeof d, "/lib/%s", NATIVE->triplet);
    strs_add(out, d);
    snprintf(d, sizeof d, "/usr/lib/%s", NATIVE->triplet);
    strs_add(out, d);
    strs_add(out, "/lib64");
    strs_add(out, "/usr/lib64");
    strs_add(out, "/lib");
    strs_add(out, "/usr/lib");
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

/* glibc's substitutions in an RPATH, a RUNPATH or a DT_NEEDED path (dl-load.c), each made over the whole string in
 * turn */
static char *expand(const char *s, const char *origin)
{
    char lib[96];
    snprintf(lib, sizeof lib, "lib/%s", NATIVE->triplet);
    const char *const subs[][2] = {{"$ORIGIN", origin}, {"${ORIGIN}", origin},        {"$LIB", lib},
                                   {"${LIB}", lib},     {"$PLATFORM", NATIVE->uname}, {"${PLATFORM}", NATIVE->uname}};
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
static int is_payload_file(const char *root, const char *v)
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
    for (int i = 0; i <= NATIVE->nhwcaps; i++) {
        char *sub = i < NATIVE->nhwcaps ? path_join(d, NATIVE->hwcaps[i]) : NULL;
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

struct search {
    const char *root;
    const struct cache *cache;
    const struct strs *defaults;
    const char *interp;            /* the loader's virtual path, or NULL for a static program */
    const struct ownership *own;   /* with host_hits, to find searched directories that are the host's */
    struct strs *host_hits;
};

/* The virtual path the loader would load for a DT_NEEDED entry, or NULL. The loader satisfies its own soname without
 * a search; a name with a slash is loaded as a path; otherwise glibc's search: RPATH (with those inherited) unless
 * there is a RUNPATH, then RUNPATH, the cache and the default directories. */
static char *find_library(const struct search *s, const char *name, const struct elf *e, const char *vpath,
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
/* The default search directories of the tree's loader, and the reason when they were assumed: glibc 2.33 and later
 * prints them with --list-diagnostics; musl's are fixed; an older glibc is taken to search Debian's and Fedora's
 * defaults. The loader run is the file PT_INTERP names in the tree, never a host file an absolute link names. */
static char *loader_dirs(const char *root, const char *interp, struct strs *out)
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
    int pipefd[2];
    struct buf text = {0};
    if (pipe2(pipefd, O_CLOEXEC) == 0) {
        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_adddup2(&fa, pipefd[1], 1);
        posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
        static char diagnostics[] = "--list-diagnostics";
        char *argv[] = {loader, diagnostics, NULL};
        pid_t pid;
        if (posix_spawn(&pid, loader, &fa, NULL, argv, environ) == 0) {
            close(pipefd[1]);
            struct timespec start, now;
            clock_gettime(CLOCK_MONOTONIC, &start);
            for (;;) { /* 20 s at most, as for a loader that hangs */
                clock_gettime(CLOCK_MONOTONIC, &now);
                long left = 20000 - (now.tv_sec - start.tv_sec) * 1000 - (now.tv_nsec - start.tv_nsec) / 1000000;
                struct pollfd p = {pipefd[0], POLLIN, 0};
                if (left <= 0 || poll(&p, 1, (int)left) <= 0) {
                    kill(pid, SIGKILL);
                    text.n = 0;
                    break;
                }
                char chunk[4096];
                ssize_t k = read(pipefd[0], chunk, sizeof chunk);
                if (k <= 0) break;
                buf_add(&text, chunk, (size_t)k);
            }
            waitpid(pid, NULL, 0);
        } else {
            close(pipefd[1]);
        }
        posix_spawn_file_actions_destroy(&fa);
        close(pipefd[0]);
    }
    free(loader);
    buf_add(&text, "", 1);
    /* lines path.system_dirs[0xN]="DIR" */
    for (char *line = text.p; line && *line;) {
        char *end = strchr(line, '\n');
        if (end) *end = 0;
        static const char key[] = "path.system_dirs[0x";
        if (!strncmp(line, key, sizeof key - 1)) {
            char *c = line + sizeof key - 1;
            size_t hexes = strspn(c, "0123456789abcdef");
            if (hexes && !strncmp(c + hexes, "]=\"", 3)) {
                char *v = c + hexes + 3, *q = strchr(v, '"');
                if (q && q > v) {
                    *q = 0;
                    size_t k = strlen(v);
                    while (k && v[k - 1] == '/') v[--k] = 0;
                    strs_add(out, v);
                }
            }
        }
        line = end ? end + 1 : NULL;
    }
    free(text.p);
    if (out->n) return NULL;
    default_dirs(out);
    struct buf why = {0};
    buf_str(&why, "the loader ");
    buf_str(&why, interp);
    buf_str(&why, " lists no search directories (glibc before 2.33, or it cannot run here): ");
    for (size_t i = 0; i < out->n; i++) {
        if (i) buf_add(&why, ":", 1);
        buf_str(&why, out->s[i]);
    }
    buf_str(&why, " assumed");
    buf_add(&why, "", 1);
    return why.p;
}

/* ---------------------------------------------------------------- a set of byte strings */
struct set {
    struct buf *k;
    size_t n, cap;
};

static uint64_t fnv(const char *p, size_t n)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) h = (h ^ (unsigned char)p[i]) * 1099511628211ULL;
    return h;
}

/* adds the key and returns 1, or returns 0 when it was there */
static int set_add(struct set *s, const char *p, size_t n)
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

static int set_has(const struct set *s, const char *p, size_t n)
{
    if (!s->cap) return 0;
    for (size_t j = fnv(p, n) % s->cap; s->k[j].p; j = (j + 1) % s->cap)
        if (s->k[j].n == n && !memcmp(s->k[j].p, p, n)) return 1;
    return 0;
}

static void set_free(struct set *s)
{
    for (size_t i = 0; i < s->cap; i++) free(s->k[i].p);
    free(s->k);
    *s = (struct set){0};
}

/* an object and the RPATHs it inherited, as one key */
static struct buf object_key(const char *vpath, const struct strs *rpaths)
{
    struct buf k = {0};
    const char *parts[1] = {vpath};
    for (size_t i = 0; i <= rpaths->n; i++) {
        const char *s = i ? rpaths->s[i - 1] : parts[0];
        size_t n = strlen(s);
        buf_add(&k, &n, sizeof n);
        buf_add(&k, s, n);
    }
    return k;
}

/* ---------------------------------------------------------------- the static check */
static void addf(struct strs *l, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void addf(struct strs *l, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char *s = NULL;
    if (vasprintf(&s, fmt, ap) < 0) fail("out of memory");
    va_end(ap);
    strs_add(l, s);
    free(s);
}

struct object {
    char *vpath;
    struct elf e;
};
struct objects {
    struct object *o;
    size_t n;
};

static void objects_add(struct objects *l, const char *vpath, struct elf e)
{
    l->o = xrealloc(l->o, (l->n + 1) * sizeof *l->o);
    size_t k = strlen(vpath);
    l->o[l->n].vpath = xrealloc(NULL, k + 1);
    memcpy(l->o[l->n].vpath, vpath, k + 1);
    l->o[l->n++].e = e;
}

static void objects_free(struct objects *l)
{
    for (size_t i = 0; i < l->n; i++) {
        free(l->o[i].vpath);
        elf_free(&l->o[i].e);
    }
    free(l->o);
}

struct scan {
    const char *root;
    const struct strs *data;
    const struct ownership *own;
    struct report *rep;
    struct objects executables, libraries;
    struct strs interp_r, interp_text, interp_v; /* each loader resolved, as named, and by whom, first come */
};

static void scan_file(struct scan *s, const char *vpath, const struct stat *st, const char *real)
{
    struct report *rep = s->rep;
    if (S_ISLNK(st->st_mode)) {
        char *r = tree_resolve(s->root, vpath, 1, NULL);
        if (!r) {
            char target[4096];
            ssize_t t = readlink(real, target, sizeof target - 1);
            target[t < 0 ? 0 : t] = 0;
            addf(&rep->warnings, "dangling symlink %s -> %s", vpath, target);
        }
        free(r);
        return;
    }
    if (!S_ISREG(st->st_mode)) return;
    char *pay = tree_payload(s->root, vpath), head[4];
    int fd = open(pay, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno != EACCES && errno != EPERM) fail_errno(pay);
        addf(&rep->errors,
             "unreadable file %s: chmod u+r it; no copy of the exclave can carry it and the tree hash needs it (10.3)",
             vpath);
        free(pay);
        return;
    }
    ssize_t k = read(fd, head, 4);
    close(fd);
    if (k != 4 || memcmp(head,
                         "\x7f"
                         "ELF",
                         4) != 0) {
        free(pay);
        return;
    }
    struct elf e;
    char why[ELF_WHY];
    int rc = elf_read(pay, &e, why);
    if (rc == ELF_OS) fail_errno(pay);
    free(pay);
    if (rc == ELF_FOREIGN) {
        addf(&rep->warnings, "%s: %s", vpath, why); /* Fedora's gcc ships 32-bit crt objects beside the 64-bit ones */
        return;
    }
    if (rc == ELF_BAD) {
        addf(&rep->errors, "%s: %s", vpath, why);
        return;
    }
    if (e.machine != NATIVE->e_machine) {
        addf(&rep->warnings, "%s: not %s: a foreign object, not checked (13)", vpath, NATIVE->uname);
        elf_free(&e);
        return;
    }
    if (e.debug_only) { /* debug information, which nothing loads or runs */
        elf_free(&e);
        return;
    }
    if (!e.interp && e.type != ET_DYN) {
        strs_add(&rep->statics, vpath);
    } else if (e.interp) {
        char *r = tree_resolve(s->root, e.interp, 1, NULL);
        if (!r) addf(&rep->errors, "%s wants interpreter %s, which does not resolve in the tree", vpath, e.interp);
        else if (under_any(r, s->data))
            addf(&rep->errors,
                 "%s wants interpreter %s, which resolves into the data directory %s: never executed or loaded (6.2)",
                 vpath, e.interp, r);
        else if (host_owned(r, s->own))
            addf(&rep->errors,
                 "%s wants interpreter %s, which resolves to %s, a path the exclave does not own: the launcher refuses "
                 "a host loader (7.4.5)",
                 vpath, e.interp, r);
        else if (!strs_has(&s->interp_r, r)) {
            strs_add(&s->interp_r, r);
            strs_add(&s->interp_text, e.interp);
            strs_add(&s->interp_v, vpath);
        }
        free(r);
    }
    objects_add(e.interp || e.type != ET_DYN ? &s->executables : &s->libraries, vpath, e);
}

/* every entry under dir outside data directories, .real/ directories aside, each directory's entries in the order
 * of their bytes; a directory that cannot be read is passed over */
static void scan_dir(struct scan *s, const char *dir, const char *rel)
{
    if (under_any(*rel ? rel : "", s->data)) return;
    struct entry_info *e;
    size_t n;
    if (list_dir(dir, &e, &n)) return;
    for (size_t i = 0; i < n; i++) {
        /* a link the host would take for a directory is a link here, judged in the tree */
        if (e[i].is_dir && !S_ISLNK(e[i].st.st_mode)) continue;
        char *real = path_join(dir, e[i].name), v[8192];
        snprintf(v, sizeof v, "%s/%s", rel, e[i].name);
        scan_file(s, v, &e[i].st, real);
        free(real);
    }
    for (size_t i = 0; i < n; i++) {
        if (!e[i].is_dir || S_ISLNK(e[i].st.st_mode) || !strcmp(e[i].name, ".real")) continue;
        char *sub = path_join(dir, e[i].name), v[8192];
        snprintf(v, sizeof v, "%s/%s", rel, e[i].name);
        scan_dir(s, sub, v);
        free(sub);
    }
    free_list(e, n);
}

/* the major and minor version libc.so.6's banner names, found in the default directories, or 0 */
static int glibc_version(const char *root, int *major, int *minor)
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

struct walk_ctx {
    const char *root;
    const struct strs *data;
    const struct search *search;
    const char *libc_soname;
    struct report *rep;
    struct set seen, reached;
};

/* the DT_NEEDED entries of an object the walk has reached through chain, and theirs */
static void check_object(struct walk_ctx *w, const char *vpath, const struct elf *e, const struct strs *rpaths,
                         const struct strs *chain)
{
    struct buf key = object_key(vpath, rpaths);
    int fresh = set_add(&w->seen, key.p, key.n);
    free(key.p);
    if (!fresh) return;
    w->rep->seen++;
    if (chain->n) set_add(&w->reached, vpath, strlen(vpath));
    struct strs below = {0}, next = {0};
    if (!e->runpath && e->rpath) strs_add(&below, e->rpath);
    for (size_t i = 0; i < rpaths->n; i++) strs_add(&below, rpaths->s[i]);
    for (size_t i = 0; i < chain->n; i++) strs_add(&next, chain->s[i]);
    strs_add(&next, vpath);
    if (e->runpath) { /* RUNPATH ends the inheritance: what reaches it passes on as it came */
        strs_free(&below);
        for (size_t i = 0; i < rpaths->n; i++) strs_add(&below, rpaths->s[i]);
    }
    for (size_t i = 0; i < e->nneeded; i++) {
        const char *n = e->needed[i];
        struct strs hits = {0};
        struct search s = *w->search;
        s.host_hits = &hits;
        char *found = find_library(&s, n, e, vpath, rpaths);
        for (size_t h = 0; h < hits.n; h++)
            addf(&w->rep->errors,
                 "%s searches %s for %s, a directory the exclave does not own: the host's library would load", vpath,
                 hits.s[h], n);
        strs_free(&hits);
        if (!found) {
            struct buf path = {0};
            for (size_t c = 0; c < next.n; c++) {
                if (c) buf_str(&path, " > ");
                buf_str(&path, next.s[c]);
            }
            buf_add(&path, "", 1);
            addf(&w->rep->errors, "%s needs %s, which does not resolve in the tree (chain %s)", vpath, n, path.p);
            free(path.p);
            continue;
        }
        if (under_any(found, w->data)) {
            addf(&w->rep->errors, "%s needs %s, which resolves into the data directory %s: never loaded (6.2)", vpath,
                 n, found);
            free(found);
            continue;
        }
        if (!strncmp(n, "libc.", 5) && strcmp(n, w->libc_soname) != 0)
            addf(&w->rep->errors, "%s needs %s: a libc other than the loader's %s", vpath, n, w->libc_soname);
        char *pay = tree_payload(w->root, found), why[ELF_WHY];
        struct elf fe;
        int rc = elf_read(pay, &fe, why);
        free(pay);
        if (rc == ELF_OS) {
            addf(&w->rep->errors, "%s: %s", found, strerror(errno));
        } else if (rc != ELF_OK) {
            addf(&w->rep->errors, "%s: %s", found, why);
        } else {
            check_object(w, found, &fe, &below, &next);
            elf_free(&fe);
        }
        free(found);
    }
    strs_free(&below);
    strs_free(&next);
}

void static_check(const char *ex, const struct ownership *own, const struct strs *data, struct report *rep)
{
    *rep = (struct report){0};
    char *root = path_join(ex, "tree"), *ld = path_join(ex, ".exclave/launcher"), why[ELF_WHY];
    struct elf le;
    int e_machine = elf_read(ld, &le, why) == ELF_OK ? le.machine : 0;
    if (e_machine) elf_free(&le);
    free(ld);
    /* an exclave is checked on a machine of its own architecture, where its loader can be asked (10.1) */
    if (e_machine && e_machine != NATIVE->e_machine) {
        char theirs[32];
        int known = e_machine == MACHINES[0].e_machine ? 0 : e_machine == MACHINES[1].e_machine ? 1 : -1;
        if (known >= 0) snprintf(theirs, sizeof theirs, "%s", MACHINES[known].uname);
        else snprintf(theirs, sizeof theirs, "machine %d", e_machine);
        addf(&rep->errors,
             "the exclave's launcher is for %s and this machine is %s: wrap the exclave on a machine of its "
             "architecture (10.1)",
             theirs, uname_machine());
        free(root);
        return;
    }
    struct cache cache;
    int has_cache = read_cache(root, &cache);
    if (host_owned("/etc", own)) { /* the loader would read the host's cache and preload list */
        addf(&rep->errors, "/etc is the host's: the loader would read the host's /etc/ld.so.cache and "
                           "/etc/ld.so.preload; the tree must own /etc");
    } else if (!has_cache) {
        /* musl has no cache; glibc without one searches its defaults only */
        char musl[64];
        snprintf(musl, sizeof musl, "/lib/ld-musl-%s.so.1", NATIVE->uname);
        char *r = tree_resolve(root, musl, 1, NULL);
        if (!(r && is_payload_file(root, r)))
            addf(&rep->warnings, "no /etc/ld.so.cache: only the loader's default directories are searched at run time");
        free(r);
    } else {
        for (size_t i = 0; i < cache.n; i++) { /* no cache entry may name the launcher (10.3), by soname in order */
            int first = 1;
            for (size_t j = 0; j < i && first; j++) first = strcmp(cache.e[j].soname, cache.e[i].soname) != 0;
            if (!first) continue;
            for (size_t j = i; j < cache.n; j++) {
                if (strcmp(cache.e[j].soname, cache.e[i].soname) != 0) continue;
                char *r = tree_resolve(root, cache.e[j].path, 1, NULL);
                if (r && is_payload_file(root, r)) {
                    char *pay = tree_payload(root, r);
                    struct elf e;
                    if (elf_read(pay, &e, why) == ELF_OK) {
                        if (!e.soname && e.type == ET_DYN && !e.nneeded)
                            addf(&rep->errors,
                                 "ld.so.cache entry %s names %s, which is not a shared library (the launcher?)",
                                 cache.e[i].soname, cache.e[j].path);
                        elf_free(&e);
                    }
                    free(pay);
                }
                free(r);
            }
        }
    }
    struct scan s = {root, data, own, rep, {0}, {0}, {0}, {0}, {0}};
    scan_dir(&s, root, "");
    /* one loader, and so one libc, per exclave (7.3): read from the ELF files, not declared anywhere */
    if (s.interp_r.n > 1) {
        size_t *order = xrealloc(NULL, s.interp_r.n * sizeof *order);
        for (size_t i = 0; i < s.interp_r.n; i++) order[i] = i;
        for (size_t i = 1; i < s.interp_r.n; i++)
            for (size_t j = i; j > 0 && strcmp(s.interp_r.s[order[j - 1]], s.interp_r.s[order[j]]) > 0; j--) {
                size_t t = order[j];
                order[j] = order[j - 1];
                order[j - 1] = t;
            }
        struct buf mixed = {0};
        for (size_t i = 0; i < s.interp_r.n; i++) {
            if (i) buf_str(&mixed, ", ");
            buf_str(&mixed, s.interp_text.s[order[i]]);
            buf_str(&mixed, " (");
            buf_str(&mixed, s.interp_v.s[order[i]]);
            buf_str(&mixed, ")");
        }
        buf_add(&mixed, "", 1);
        addf(&rep->errors, "the tree mixes loaders %s (one world inside an exclave, 7.3)", mixed.p);
        free(mixed.p);
        free(order);
    }
    const char *interp = s.interp_text.n ? s.interp_text.s[0] : NULL;
    int musl = interp && strstr(basename_of(interp), "musl");
    char musl_soname[64];
    snprintf(musl_soname, sizeof musl_soname, "libc.musl-%s.so.1", NATIVE->uname);
    struct strs defaults = {0};
    char *assumed = loader_dirs(root, interp, &defaults);
    if (assumed) strs_add(&rep->warnings, assumed);
    free(assumed);
    /* 6.2: the locale inside an exclave is C.UTF-8, built into glibc 2.35 and later and into musl; an older glibc
     * needs the C.utf8 directory or every program runs in the plain C locale, and bash and perl say so */
    int major, minor;
    if (interp && !musl && glibc_version(root, &major, &minor) && (major < 2 || (major == 2 && minor < 35))) {
        int has = 0;
        const char *const locales[] = {"/usr/lib/locale/C.utf8", "/usr/lib/locale/C.UTF-8"};
        for (size_t i = 0; i < 2 && !has; i++) {
            char *r = tree_resolve(root, locales[i], 1, NULL);
            if (r) {
                char *real = tree_real(root, r);
                struct stat st;
                has = stat(real, &st) == 0 && S_ISDIR(st.st_mode);
                free(real);
            }
            free(r);
        }
        if (!has)
            addf(&rep->warnings,
                 "glibc %d.%d predates the built-in C.UTF-8 locale and the tree has no /usr/lib/locale/C.utf8: "
                 "programs will run in the plain C locale",
                 major, minor);
    }
    struct search search = {root, has_cache ? &cache : NULL, &defaults, interp, own, NULL};
    struct walk_ctx w = {root, data, &search, musl ? musl_soname : GLIBC_SONAME, rep, {0}, {0}};
    struct strs none = {0};
    for (size_t i = 0; i < s.executables.n; i++) /* executables first, so that RPATH inheritance is seen */
        check_object(&w, s.executables.o[i].vpath, &s.executables.o[i].e, &none, &none);
    for (size_t i = 0; i < s.libraries.n; i++) /* a library nothing reaches is a dlopen candidate: checked alone */
        if (!set_has(&w.reached, s.libraries.o[i].vpath, strlen(s.libraries.o[i].vpath)))
            check_object(&w, s.libraries.o[i].vpath, &s.libraries.o[i].e, &none, &none);
    set_free(&w.seen);
    set_free(&w.reached);
    strs_free(&defaults);
    cache_free(&cache);
    objects_free(&s.executables);
    objects_free(&s.libraries);
    strs_free(&s.interp_r);
    strs_free(&s.interp_text);
    strs_free(&s.interp_v);
    free(root);
}

/* ---------------------------------------------------------------- the dynamic check */
/* the path's \n and \\ escapes undone in one pass from left to right (6.2) */
static void unescape(char *p)
{
    char *o = p;
    for (char *c = p; *c; c++) {
        if (c[0] == '\\' && (c[1] == 'n' || c[1] == '\\')) {
            *o++ = c[1] == 'n' ? '\n' : '\\';
            c++;
        } else {
            *o++ = *c;
        }
    }
    *o = 0;
}

/* whether a path ends in .so and any version numbers after it */
static int library_name(const char *p)
{
    size_t n = strlen(p);
    for (;;) {
        if (n >= 3 && !memcmp(p + n - 3, ".so", 3)) return 1;
        size_t k = n;
        while (k && isdigit((unsigned char)p[k - 1])) k--;
        if (k == n || !k || p[k - 1] != '.') return 0;
        n = k - 1;
    }
}

static int bytes_order(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

void dynamic_check(const char *ex, char **logs, int nlogs, const struct ownership *own, struct report *rep)
{
    *rep = (struct report){0};
    struct strs libs = {0}, cwds = {0};
    for (int l = 0; l < nlogs; l++) {
        size_t n;
        char *data = read_file(logs[l], &n);
        for (char *line = data; line < data + n;) {
            char *end = memchr(line, '\n', (size_t)(data + n - line));
            if (end) *end = 0;
            char *next = end ? end + 1 : data + n;
            /* CALL RESULT PATH, the result an integer (6.2) */
            char *sp1 = strchr(line, ' '), *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
            if (sp2) {
                *sp1 = *sp2 = 0;
                const char *num = sp1 + 1 + (sp1[1] == '-');
                int ok = *num && strspn(num, "0123456789") == strlen(num);
                if (ok) {
                    rep->lines++;
                    char *what = line, *path = sp2 + 1;
                    long r = strtol(sp1 + 1, NULL, 10);
                    unescape(path);
                    static const char given[] = "cwd given to the host ";
                    /* 8.1 rule 4 as the launcher applied it; the plain cwd line is a diagnostic and gives nothing */
                    if (!strcmp(what, "launcher") && !strncmp(path, given, sizeof given - 1)) {
                        if (strcmp(path + sizeof given - 1, "/") != 0) strs_add(&cwds, path + sizeof given - 1);
                    } else if (!strcmp(what, "launcher") && !strncmp(path, "cwd ", 4) &&
                               strncmp(path, "cwd given", 9) != 0 && volatile_path(path + 4)) {
                        /* a working directory under a volatile prefix is the host's already (8.1 rule 3), so the
                         * launcher logs no given line for it; it is the workload's own all the same */
                        strs_add(&cwds, path + 4);
                    }
                    if (!strcmp(what, "open") && r >= 0 && library_name(path) && !strs_has(&libs, path))
                        strs_add(&libs, path);
                }
            }
            line = next;
        }
        free(data);
    }
    if (libs.n) qsort(libs.s, libs.n, sizeof *libs.s, bytes_order);
    for (size_t i = 0; i < libs.n; i++) {
        int mine = 0; /* the workload's own build directory: the host's by 8.1 rule 4, whatever prefix it lies under */
        for (size_t c = 0; c < cwds.n && !mine; c++) {
            size_t k = strlen(cwds.s[c]);
            while (k && cwds.s[c][k - 1] == '/') k--;
            mine = !strncmp(libs.s[i], cwds.s[c], k) && libs.s[i][k] == '/';
        }
        if (mine)
            addf(&rep->warnings, "library opened under the workload's working directory, its own output presumably: %s",
                 libs.s[i]);
        else if (host_owned(libs.s[i], own)) addf(&rep->errors, "library opened on the host: %s", libs.s[i]);
    }
    char *root = path_join(ex, "tree");
    struct strs dirs = {0}, mods = {0};
    default_dirs(&dirs);
    struct stat st;
    if (stat("/etc/nsswitch.conf", &st) == 0) {
        size_t n;
        char *data = read_file("/etc/nsswitch.conf", &n);
        for (char *line = strtok(data, "\r\n"); line; line = strtok(NULL, "\r\n")) {
            char *hash = strchr(line, '#');
            if (hash) *hash = 0;
            char *colon = strchr(line, ':');
            if (!colon) continue;
            /* a module name, mdns4_minimal included; not [NOTFOUND=return] */
            for (char *w = colon + 1; *w;) {
                w += strspn(w, " \t\v\f");
                size_t k = strcspn(w, " \t\v\f");
                if (!k) break;
                char word[256];
                snprintf(word, sizeof word, "%.*s", (int)k, w);
                int ok = k < sizeof word;
                for (size_t j = 0; j < k && ok; j++) ok = isalnum((unsigned char)word[j]) || word[j] == '_';
                if (ok && strcmp(word, "files") != 0 && strcmp(word, "dns") != 0 && !strs_has(&mods, word))
                    strs_add(&mods, word);
                w += k;
            }
        }
        free(data);
    }
    if (mods.n) qsort(mods.s, mods.n, sizeof *mods.s, bytes_order);
    for (size_t m = 0; m < mods.n; m++) {
        int has = 0;
        for (size_t d = 0; d < dirs.n && !has; d++) {
            char so[300], *p, *r;
            snprintf(so, sizeof so, "libnss_%s.so.2", mods.s[m]);
            p = path_join(dirs.s[d], so);
            r = tree_resolve(root, p, 1, NULL);
            has = r != NULL;
            free(p);
            free(r);
        }
        if (!has)
            addf(&rep->warnings, "this host's nsswitch.conf names %s; the exclave has no libnss_%s.so.2", mods.s[m],
                 mods.s[m]);
    }
    strs_free(&dirs);
    strs_free(&mods);
    strs_free(&libs);
    strs_free(&cwds);
    free(root);
}

void report_free(struct report *rep)
{
    strs_free(&rep->errors);
    strs_free(&rep->warnings);
    strs_free(&rep->statics);
}

/* ---------------------------------------------------------------- the wrappers (6.1) */
struct launcher_id {
    char *path;
    dev_t dev;
    ino_t ino;
    off_t size;
};

static struct launcher_id launcher_of(const char *ex)
{
    struct launcher_id l = {path_join(ex, ".exclave/launcher"), 0, 0, 0};
    struct stat st;
    if (stat(l.path, &st)) fail_errno(l.path);
    l.dev = st.st_dev;
    l.ino = st.st_ino;
    l.size = st.st_size;
    return l;
}

static int same_contents(const char *a, const char *b)
{
    size_t na, nb;
    char *x = read_file(a, &na), *y = read_file(b, &nb);
    int same = na == nb && !memcmp(x, y, na);
    free(x);
    free(y);
    return same;
}

/* a wrapper of this launcher: a hard link to it, or, where a copy split the links, a file with its contents that has
 * an original in .real/ */
static int is_wrapper(const char *real, const struct stat *st, const struct launcher_id *l)
{
    if (!S_ISREG(st->st_mode)) return 0;
    if (st->st_dev == l->dev && st->st_ino == l->ino) return 1;
    if (st->st_size != l->size) return 0;
    char *orig = payload_path(real);
    int has_orig = strcmp(orig, real) != 0;
    free(orig);
    return has_orig && same_contents(real, l->path);
}

struct problems {
    const struct strs *data;
    const struct launcher_id *l;
    struct strs *out;
    const char *ex;
    char *places[2];
    int nplaces;
    int unwrapped; /* the executables not wrapped too, as check reports them */
};

static void wrapper_entry(const char *real, const char *v, const struct stat *st, void *ctx)
{
    struct problems *p = ctx;
    if (!S_ISREG(st->st_mode) || under_any(v, p->data)) return;
    int w = is_wrapper(real, st, p->l);
    char *orig = payload_path(real);
    int has_orig = strcmp(orig, real) != 0;
    free(orig);
    if (!w && has_orig) addf(p->out, "stale wrapper (not this exclave's launcher): %s; run exclave relink", v);
    else if (st->st_mode & 0111 && !w && access(real, X_OK))
        addf(p->out,
             "executable file its user cannot execute: %s (mode %o); a wrapper would run as the launcher's mode", v,
             st->st_mode & 07777);
    if (w && !has_orig) addf(p->out, "wrapper without original: %s", v);
}

/* The problems with the tree's wrappers and originals as it stands: a stale wrapper (one of another launcher), a
 * wrapper without an original, an executable its user cannot run, and an original without a wrapper, a stray under
 * the reserved name. Executables not yet wrapped are not problems here. */
void wrapper_problems(const char *ex, const struct strs *data, struct strs *out)
{
    struct launcher_id l = launcher_of(ex);
    char *root = path_join(ex, "tree");
    struct problems p = {data, &l, out, ex, {0}, 0, 0};
    walk_files(root, wrapper_entry, &p);
    struct buf s = {0};
    strays(root, &s);
    for (size_t i = 0; i < s.n; i += strlen(s.p + i) + 1)
        addf(out, "original without wrapper: %s (.real is reserved for originals, 6.1)", s.p + i);
    free(s.p);
    free(root);
    free(l.path);
}

/* path relative to base, both made absolute and normal as Python's relpath does */
static char *relpath(const char *path, const char *base)
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

static void located_entry(const char *real, const char *v, const struct stat *st, void *ctx)
{
    struct problems *p = ctx;
    if (!S_ISLNK(st->st_mode)) return;
    char text[PATH_MAX];
    ssize_t t = readlink(real, text, sizeof text - 1);
    if (t < 0) fail_errno(real);
    text[t] = 0;
    for (int i = 0; i < p->nplaces; i++) {
        if (!under(text, p->places[i])) continue;
        char *tree = path_join(p->places[i], "tree"), *inside = relpath(text, tree);
        if (strncmp(inside, "..", 2) != 0 && strcmp(inside, ".") != 0)
            addf(p->out, "link naming the exclave's own location: %s -> %s; ln -sfn /%s %s", v, text, inside, real);
        else addf(p->out, "link naming the exclave's own location: %s -> %s", v, text);
        free(tree);
        free(inside);
        break;
    }
}

/* The tree's symlinks whose text names the exclave's own location (6.1). Packages never make one; one added by hand
 * would break when the exclave is moved or copied, so wrap and check refuse it, naming the fix. */
void located_links(const char *ex, struct strs *out)
{
    char cwd[PATH_MAX], *abs, *real = realpath(ex, NULL);
    if (!getcwd(cwd, sizeof cwd)) fail_errno(".");
    char *joined = ex[0] == '/' ? path_join(ex, "") : path_join(cwd, ex);
    abs = normpath(joined);
    free(joined);
    struct problems p = {NULL, NULL, out, ex, {abs, real}, real && strcmp(real, abs) != 0 ? 2 : 1, 0};
    char *root = path_join(ex, "tree");
    walk_files(root, located_entry, &p);
    free(root);
    free(abs);
    free(real);
}

static void unwrapped_entry(const char *real, const char *v, const struct stat *st, void *ctx)
{
    struct problems *p = ctx;
    if (!S_ISREG(st->st_mode) || !(st->st_mode & 0111) || under_any(v, p->data) || is_wrapper(real, st, p->l)) return;
    char *orig = payload_path(real);
    if (!strcmp(orig, real)) addf(p->out, "executable not wrapped: %s", v);
    free(orig);
}

static void any_wrapper(const char *real, const char *v, const struct stat *st, void *ctx)
{
    (void)v;
    struct problems *p = ctx;
    if (is_wrapper(real, st, p->l)) p->unwrapped = 1;
}

void print_report(const struct report *rep)
{
    for (size_t i = 0; i < rep->warnings.n; i++) printf("warning: %s\n", rep->warnings.s[i]);
    for (size_t i = 0; i < rep->errors.n; i++) printf("error: %s\n", rep->errors.s[i]);
}

int static_report(const char *ex)
{
    struct ownership own;
    struct strs data = {0};
    struct report rep;
    data_prefixes(ex, &data);
    ownership_of(ex, &own);
    static_check(ex, &own, &data, &rep);
    print_report(&rep);
    printf("static check: %zu ELF files, %zu static executables, %zu warnings, %zu errors\n", rep.seen, rep.statics.n,
           rep.warnings.n, rep.errors.n);
    int errors = (int)rep.errors.n;
    report_free(&rep);
    ownership_free(&own);
    strs_free(&data);
    return errors;
}

/* Check a wrapped exclave: every executable outside data directories wrapped by this exclave's launcher, no stray
 * original, the tree as its recorded hash says; then the static check, and with EXCLAVE_LOG files the dynamic
 * check. */
int cmd_check(int argc, char **argv)
{
    if (argc < 1) usage("check EXCLAVE [LOG...]");
    const char *ex = argv[0];
    require_exclave(ex, "check");
    struct strs data = {0}, problems = {0};
    data_prefixes(ex, &data);
    struct launcher_id l = launcher_of(ex);
    char *root = path_join(ex, "tree"), *hashes = path_join(ex, ".exclave/hashes");
    wrapper_problems(ex, &data, &problems);
    located_links(ex, &problems);
    struct problems p = {&data, &l, &problems, ex, {0}, 0, 0};
    walk_files(root, unwrapped_entry, &p);
    struct stat st;
    if (stat(hashes, &st) == 0) {
        size_t n;
        char *text = read_file(hashes, &n), err[GRAMMAR_ERR];
        struct records rs;
        if (grammar_parse(text, n, KIND_HASHES, &rs, err)) fail_grammar(err);
        free(text);
        const char *recorded = NULL;
        for (size_t i = 0; i < rs.n; i++)
            if (!strcmp(rs.r[i].key, "tree")) recorded = rs.r[i].f[0].v;
        if (recorded) {
            char actual[B2_TEXT];
            tree_hash(root, actual);
            if (strcmp(recorded, actual) != 0)
                addf(&problems, "the tree differs from the hashes file: recorded %s, now %s", recorded, actual);
        } else {
            strs_add(&problems, "an unwrapped exclave: the hashes file has no tree hash; run exclave wrap");
        }
        records_free(&rs);
    } else {
        walk_files(root, any_wrapper, &p); /* the third state: wrapped, never finished */
        if (p.unwrapped) strs_add(&problems, "wrappers but no hashes file: wrap never finished; run exclave wrap");
    }
    for (size_t i = 0; i < problems.n; i++) printf("%s\n", problems.s[i]);
    printf("%zu wrapper problems\n", problems.n);
    int errors = static_report(ex), rc = problems.n || errors ? 1 : 0;
    if (argc > 1) {
        struct ownership own;
        struct report d;
        ownership_of(ex, &own);
        dynamic_check(ex, argv + 1, argc - 1, &own, &d);
        print_report(&d);
        printf("dynamic check: %zu log lines, %zu errors\n", d.lines, d.errors.n);
        if (d.errors.n) rc = 1;
        report_free(&d);
        ownership_free(&own);
    }
    strs_free(&data);
    strs_free(&problems);
    free(root);
    free(hashes);
    free(l.path);
    return rc;
}
