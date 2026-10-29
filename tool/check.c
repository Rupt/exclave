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
struct walk_ctx {
    const char *root;
    const struct strs *data;
    const struct search *search;
    const char *libc_soname;
    struct report *rep;
    struct set seen, reached;
    const struct objects *libraries; /* every library in the tree, for a soname no search finds */
};

/* a library of the tree whose DT_SONAME is name, outside the data directories, or NULL; a name with a slash is a path,
 * which the loader opens and never matches by soname */
static const char *by_soname(const struct walk_ctx *w, const char *name)
{
    if (strchr(name, '/')) return NULL;
    for (size_t i = 0; i < w->libraries->n; i++) {
        const struct object *o = &w->libraries->o[i];
        if (o->e.soname && !strcmp(o->e.soname, name) && !under_any(o->vpath, w->data)) return o->vpath;
    }
    return NULL;
}

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
            /* no search finds it, so no host library can stand in for it either: an error when the tree lacks it,
             * a package missing; a warning when the tree has it elsewhere, which loads only when a program has
             * opened it first by its path, as the JVM opens its libjvm.so (10.3) */
            const char *elsewhere = by_soname(w, n);
            if (elsewhere)
                addf(&w->rep->warnings,
                     "%s needs %s, which no search finds; the tree has it at %s, loaded only once a program has "
                     "opened it by its path (chain %s)",
                     vpath, n, elsewhere, path.p);
            else addf(&w->rep->errors, "%s needs %s, which does not resolve in the tree (chain %s)", vpath, n, path.p);
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
    int major = 0, minor = 0;
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
    struct walk_ctx w = {root, data, &search, musl ? musl_soname : GLIBC_SONAME, rep, {0}, {0}, &s.libraries};
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

size_t read_log(const char *path, struct log_line **out)
{
    size_t n, count = 0, cap = 0;
    char *data = read_file(path, &n);
    *out = NULL;
    for (char *line = data; line < data + n;) {
        char *end = memchr(line, '\n', (size_t)(data + n - line));
        if (end) *end = 0;
        char *next = end ? end + 1 : data + n;
        /* CALL RESULT PATH, the result an integer (6.2) */
        char *sp1 = strchr(line, ' '), *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
        if (sp2) {
            *sp1 = *sp2 = 0;
            const char *num = sp1 + 1 + (sp1[1] == '-');
            if (*num && strspn(num, "0123456789") == strlen(num)) {
                unescape(sp2 + 1);
                if (count == cap) {
                    cap = cap ? 2 * cap : 256;
                    *out = xrealloc(*out, cap * sizeof **out);
                }
                struct log_line *x = &(*out)[count++];
                x->what = xrealloc(NULL, strlen(line) + 1);
                strcpy(x->what, line); /* NOLINT(clang-analyzer-security.insecureAPI.strcpy) -- sized above */
                x->path = xrealloc(NULL, strlen(sp2 + 1) + 1);
                strcpy(x->path, sp2 + 1); /* NOLINT(clang-analyzer-security.insecureAPI.strcpy) -- sized above */
                x->result = strtol(sp1 + 1, NULL, 10);
            }
        }
        line = next;
    }
    free(data);
    return count;
}

void free_log(struct log_line *l, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        free(l[i].what);
        free(l[i].path);
    }
    free(l);
}

void dynamic_check(const char *ex, char **logs, int nlogs, const struct ownership *own, struct report *rep)
{
    *rep = (struct report){0};
    struct strs libs = {0}, cwds = {0};
    for (int l = 0; l < nlogs; l++) {
        struct log_line *lines;
        size_t n = read_log(logs[l], &lines);
        rep->lines += n;
        for (size_t i = 0; i < n; i++) {
            const char *what = lines[i].what, *path = lines[i].path;
            static const char given[] = "cwd given to the host ";
            /* 8.1 rule 4 as the launcher applied it; the plain cwd line is a diagnostic and gives nothing */
            if (!strcmp(what, "launcher") && !strncmp(path, given, sizeof given - 1)) {
                if (strcmp(path + sizeof given - 1, "/") != 0) strs_add(&cwds, path + sizeof given - 1);
            } else if (!strcmp(what, "launcher") && !strncmp(path, "cwd ", 4) && strncmp(path, "cwd given", 9) != 0 &&
                       volatile_path(path + 4)) {
                /* a working directory under a volatile prefix is the host's already (8.1 rule 3), so the launcher
                 * logs no given line for it; it is the workload's own all the same */
                strs_add(&cwds, path + 4);
            }
            if (!strcmp(what, "open") && lines[i].result >= 0 && library_name(path) && !strs_has(&libs, path))
                strs_add(&libs, path);
        }
        free_log(lines, n);
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
