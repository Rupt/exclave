/* search.c — the loader's search for a library, as the tree's own loader makes it (DESIGN.md 10.3): the machine's
 * default directories, DT_RPATH and DT_RUNPATH with their tokens expanded, ld.so.cache, and the directories the loader
 * names for itself; and the glibc a tree carries, by its banner. The static check and prune ask it. */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
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
const struct machine *const NATIVE = &MACHINES[0];
#elif defined(__aarch64__)
const struct machine *const NATIVE = &MACHINES[1];
#endif

const char *uname_machine(void)
{
    static struct utsname u;
    if (!u.machine[0] && uname(&u)) return NATIVE->uname;
    return u.machine;
}

/* glibc's default directories on Debian and Fedora, for a loader that cannot be asked */
void default_dirs(struct strs *out)
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
/* The default search directories of the tree's loader, and the reason when they were assumed: glibc 2.33 and later
 * prints them with --list-diagnostics; musl's are fixed; an older glibc is taken to search Debian's and Fedora's
 * defaults. The loader run is the file PT_INTERP names in the tree, never a host file an absolute link names. */
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
