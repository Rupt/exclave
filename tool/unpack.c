/* unpack.c — `exclave unpack OUT APK...`: the unwrapped exclave OUT from Alpine package files (DESIGN.md 10.1).
 *
 * The step scripts/unpack takes in Python, for .apk files so far, and to the same result, which test/unpack_oracle.py
 * compares: each package's payload extracted into OUT/tree, what its install scripts would have made synthesised, what
 * it ships in the volatile directories removed, and each package file recorded in OUT/.exclave/hashes. The dependency
 * report is not here yet, nor the synthesis an Alpine set rarely needs (the ca-certificates bundles and an ELF
 * ldconfig); a set that would need one is refused, so that the tree is never other than scripts/unpack makes. On any
 * failure OUT is removed. Paths are Python's spellings throughout: os.path.join, dirname, realpath and makedirs as
 * Python has them, so that a tree's symlinks lead both to the same place. */
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tool.h"

/* ---------------------------------------------------------------- a map from strings, for the sets the steps keep */
struct map_entry {
    char *k;
    void *v;
};
struct map {
    struct map_entry *e;
    size_t cap, n;
};

static size_t str_hash(const char *s)
{
    size_t h = 1469598103934665603U;
    while (*s) h = (h ^ (unsigned char)*s++) * 1099511628211U;
    return h;
}

static struct map_entry *slot(const struct map *m, const char *k)
{
    for (size_t i = str_hash(k) & (m->cap - 1);; i = (i + 1) & (m->cap - 1))
        if (!m->e[i].k || !strcmp(m->e[i].k, k)) return &m->e[i];
}

static struct map_entry *map_find(const struct map *m, const char *k)
{
    if (!m->cap) return NULL;
    struct map_entry *e = slot(m, k);
    return e->k ? e : NULL;
}

static char *str_copy(const char *s)
{
    size_t n = strlen(s) + 1;
    return memcpy(xrealloc(NULL, n), s, n);
}

static void map_put(struct map *m, const char *k, void *v)
{
    if (2 * (m->n + 1) > m->cap) {
        struct map old = *m;
        m->cap = m->cap ? 2 * m->cap : 64;
        m->e = xrealloc(NULL, m->cap * sizeof *m->e);
        memset(m->e, 0, m->cap * sizeof *m->e);
        m->n = 0;
        for (size_t i = 0; i < old.cap; i++)
            if (old.e[i].k) {
                *slot(m, old.e[i].k) = old.e[i];
                m->n++;
            }
        free(old.e);
    }
    struct map_entry *e = slot(m, k);
    if (!e->k) {
        e->k = str_copy(k);
        m->n++;
    }
    e->v = v;
}

static void map_free(struct map *m, int free_values)
{
    for (size_t i = 0; i < m->cap; i++) {
        free(m->e[i].k);
        if (free_values) free(m->e[i].v);
    }
    free(m->e);
    *m = (struct map){0};
}

/* ---------------------------------------------------------------- Python's paths */
static int lexists(const char *p)
{
    struct stat st;
    return !lstat(p, &st);
}
static int exists(const char *p)
{
    struct stat st;
    return !stat(p, &st);
}
static int islink(const char *p)
{
    struct stat st;
    return !lstat(p, &st) && S_ISLNK(st.st_mode);
}
static int isdir(const char *p)
{
    struct stat st;
    return !stat(p, &st) && S_ISDIR(st.st_mode);
}
static int isfile(const char *p)
{
    struct stat st;
    return !stat(p, &st) && S_ISREG(st.st_mode);
}

/* os.path.dirname */
static char *py_dirname(const char *p)
{
    const char *slash = strrchr(p, '/');
    size_t k = slash ? (size_t)(slash - p) + 1 : 0, all = 0;
    while (all < k && p[all] == '/') all++;
    if (k && all != k)
        while (k && p[k - 1] == '/') k--;
    char *d = xrealloc(NULL, k + 1);
    memcpy(d, p, k);
    d[k] = 0;
    return d;
}

/* os.path.join(root, vpath without its leading slashes): _v of the Python */
static char *vpath(const char *root, const char *v)
{
    while (*v == '/') v++;
    return path_join(root, v);
}

struct part {
    char *s;
    int mark; /* a symlink's target has been resolved: the link's own path is the entry below */
};
struct parts {
    struct part *p;
    size_t n, cap;
};

static void push(struct parts *r, char *s, int mark) /* NOLINT(readability-non-const-parameter): the stack owns s */
{
    if (r->n == r->cap) {
        r->cap = r->cap ? 2 * r->cap : 32;
        r->p = xrealloc(r->p, r->cap * sizeof *r->p);
    }
    r->p[r->n++] = (struct part){s, mark};
}

/* s's components, split at every slash, pushed last first; how many */
static size_t push_split(struct parts *r, const char *s, size_t n)
{
    size_t count = 1, start = n;
    for (size_t i = n; i-- > 0;)
        if (s[i] == '/') count++;
    for (size_t i = n + 1; i-- > 0;)
        if (i == 0 || s[i - 1] == '/') {
            char *c = xrealloc(NULL, start - i + 1);
            memcpy(c, s + i, start - i);
            c[start - i] = 0;
            push(r, c, 0);
            start = i ? i - 1 : 0;
        }
    return count;
}

static void set_path(struct buf *path, const char *s)
{
    path->n = 0;
    buf_str(path, s);
    buf_add(path, "", 1);
    path->n--;
}

/* os.path.realpath, not strict: each symlink resolved where it can be, a component that cannot be read or does not
 * exist taken as it is, and a loop left where it closes */
static char *py_realpath(const char *filename)
{
    struct parts rest = {0};
    size_t len = strlen(filename);
    while (len && filename[len - 1] == '/') len--;
    size_t count = push_split(&rest, filename, len);
    struct buf path = {0};
    if (filename[0] == '/') set_path(&path, "/");
    else {
        char *cwd = getcwd(NULL, 0);
        if (!cwd) fail("the working directory: %s", strerror(errno));
        set_path(&path, cwd);
        free(cwd);
    }
    struct map seen = {0};
    while (count) {
        struct part p = rest.p[--rest.n];
        if (p.mark) {
            struct part link = rest.p[--rest.n];
            map_put(&seen, link.s, str_copy(path.p));
            free(link.s);
            continue;
        }
        count--;
        char *name = p.s;
        if (!*name || !strcmp(name, ".")) {
            free(name);
            continue;
        }
        if (!strcmp(name, "..")) {
            char *last = strrchr(path.p, '/');
            path.n = (size_t)(last - path.p);
            if (!path.n) path.n = 1;
            path.p[path.n] = 0;
            free(name);
            continue;
        }
        struct buf next = {0};
        buf_str(&next, path.p);
        if (strcmp(path.p, "/") != 0) buf_add(&next, "/", 1);
        buf_str(&next, name);
        buf_add(&next, "", 1);
        free(name);
        struct stat st;
        char target[4097];
        ssize_t k = -1;
        const struct map_entry *e = NULL;
        if (!lstat(next.p, &st) && S_ISLNK(st.st_mode)) {
            e = map_find(&seen, next.p);
            if (!e) k = readlink(next.p, target, sizeof target - 1);
        }
        if (k < 0) set_path(&path, e && e->v ? e->v : next.p); /* a link seen and not resolved yet closes a loop */
        else {
            target[k] = 0;
            if (target[0] == '/') set_path(&path, "/");
            map_put(&seen, next.p, NULL);
            push(&rest, str_copy(next.p), 0);
            push(&rest, NULL, 1);
            count += push_split(&rest, target, (size_t)k);
        }
        free(next.p);
    }
    for (size_t i = 0; i < rest.n; i++) free(rest.p[i].s);
    free(rest.p);
    map_free(&seen, 1);
    return path.p;
}

/* os.makedirs(name, exist_ok=True) */
static void py_makedirs(const char *name)
{
    char *head = py_dirname(name);
    const char *slash = strrchr(name, '/');
    const char *tail = slash ? slash + 1 : name;
    if (!*tail) {
        char *h2 = py_dirname(head);
        slash = strrchr(head, '/');
        tail = name + (slash ? (size_t)(slash - head) + 1 : 0);
        free(head);
        head = h2;
    }
    if (*head && *tail && !exists(head)) py_makedirs(head);
    free(head);
    if (mkdir(name, 0777) && !isdir(name)) fail_errno(name);
}

/* ---------------------------------------------------------------- the packages */
static const char *const VOLATILE[] = {"/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run"};

struct pkg {
    const char *path;
    char *name, *version, *arch, *replaces;
};

struct apk {
    struct buf data;
    struct tar t;
};

static void apk_open(const char *path, struct apk *a)
{
    size_t n;
    char *raw = read_file(path, &n), why[INFLATE_WHY + TAR_WHY];
    a->data = (struct buf){0};
    if (gunzip((const uint8_t *)raw, n, &a->data, why) || tar_read((const uint8_t *)a->data.p, a->data.n, &a->t, why))
        fail("%s: not an apk: %s", path, why);
    free(raw);
}

static void apk_close(struct apk *a)
{
    tar_free(&a->t);
    free(a->data.p);
}

/* a member's name without its leading ./ and slashes: a control file's starts with a dot */
static const char *norm(const char *name)
{
    while (name[0] == '.' && name[1] == '/') name += 2;
    while (*name == '/') name++;
    return name;
}

static int is_control(const struct tar_member *m) { return norm(m->name)[0] == '.'; }

static int py_space(char c) { return c == ' ' || (c >= '\t' && c <= '\r') || (c >= 0x1c && c <= 0x1f); }

static char *stripped(const char *s, size_t n)
{
    while (n && py_space(*s)) s++, n--;
    while (n && py_space(s[n - 1])) n--;
    char *c = xrealloc(NULL, n + 1);
    memcpy(c, s, n);
    c[n] = 0;
    return c;
}

/* .PKGINFO's pkgname, pkgver, arch and replaces, as the Python's control() gives them */
static void control(const char *path, const struct apk *a, struct pkg *p)
{
    struct buf replaces = {0};
    char *name = NULL, *version = NULL, *arch = NULL;
    for (size_t i = 0; i < a->t.n; i++) {
        const struct tar_member *m = &a->t.m[i];
        if (!is_control(m) || !tar_regular(m->type) || strcmp(norm(m->name), ".PKGINFO") != 0) continue;
        const char *d = a->data.p + m->data, *end = d + m->size;
        for (const char *line = d; line <= end;) {
            const char *lf = memchr(line, '\n', (size_t)(end - line));
            size_t k = lf ? (size_t)(lf - line) : (size_t)(end - line);
            const char *eq = k && line[0] != '#' ? memmem(line, k, " = ", 3) : NULL;
            if (eq) {
                char *key = stripped(line, (size_t)(eq - line)), *v = stripped(eq + 3, k - (size_t)(eq - line) - 3);
                char **first = !strcmp(key, "pkgname")  ? &name
                               : !strcmp(key, "pkgver") ? &version
                               : !strcmp(key, "arch")   ? &arch
                                                        : NULL;
                if (first && !*first) *first = v;
                else if (!strcmp(key, "replaces")) {
                    if (replaces.n) buf_add(&replaces, " ", 1);
                    buf_str(&replaces, v);
                    free(v);
                } else free(v);
                free(key);
            }
            line += k + 1;
        }
    }
    if (!name || !version) fail("%s: no pkgname or pkgver in .PKGINFO", path);
    if (!arch || !strcmp(arch, "noarch")) {
        free(arch);
        arch = str_copy("all");
    }
    buf_add(&replaces, "", 1);
    *p = (struct pkg){path, name, version, arch, replaces.p};
}

/* the names a Replaces field gives, as apk's parse_deps reads its items: a ! item is a conflict, dropped */
static void replaced(const struct pkg *p, struct strs *out)
{
    for (const char *s = p->replaces; *s;) {
        while (*s && py_space(*s)) s++;
        if (!*s) break;
        const char *end = s;
        while (*end && !py_space(*end)) end++;
        const char *name = s + (*s == '!'), *op = name;
        while (op < end && !strchr("<>=~", *op)) op++;
        if (op == name || *name == '!' || (op < end && op + 1 == end))
            fail("%s: cannot parse dependency '%.*s'", p->path, (int)(end - s), s);
        if (*s != '!') {
            char *n = xrealloc(NULL, (size_t)(op - name) + 1);
            memcpy(n, name, (size_t)(op - name));
            n[op - name] = 0;
            strs_add(out, n);
            free(n);
        }
        s = end;
    }
}

/* _safe_rel: a member's path relative to the tree, refusing .. and the reserved .real */
static char *safe_rel(const char *name)
{
    struct buf b = {0};
    int dotdot = 0, real = 0;
    for (const char *s = name;;) {
        const char *slash = strchr(s, '/');
        size_t k = slash ? (size_t)(slash - s) : strlen(s);
        if (k && !(k == 1 && s[0] == '.')) {
            if (k == 2 && !memcmp(s, "..", 2)) dotdot = 1;
            if (k == 5 && !memcmp(s, ".real", 5)) real = 1;
            if (b.n) buf_add(&b, "/", 1);
            buf_add(&b, s, k);
        }
        if (!slash) break;
        s = slash + 1;
    }
    if (dotdot) fail("path escapes the tree: %s", name);
    if (real) fail("the reserved name .real is shipped at %s", name);
    buf_add(&b, "", 1);
    return b.p;
}

/* _inside: refuse dst unless its parent, every symlink resolved, lies in the tree */
static void inside(const char *root_real, const char *dst)
{
    char *dir = py_dirname(dst), *parent = py_realpath(dir);
    size_t k = strlen(root_real);
    if (strcmp(parent, root_real) != 0 && !(!strncmp(parent, root_real, k) && parent[k] == '/'))
        fail("%s escapes the tree through a symlink (resolves under %s)", dst, parent);
    free(dir);
    free(parent);
}

/* the /lib and /usr/lib spellings of a path are one file */
static char *owner_key(const char *rel)
{
    static const char *const aliased[] = {"bin", "sbin", "lib", "lib32", "lib64", "libx32"};
    size_t k = strcspn(rel, "/");
    for (size_t i = 0; i < sizeof aliased / sizeof *aliased; i++)
        if (strlen(aliased[i]) == k && !strncmp(rel, aliased[i], k)) {
            struct buf b = {0};
            buf_str(&b, "usr/");
            buf_str(&b, rel);
            buf_add(&b, "", 1);
            return b.p;
        }
    return str_copy(rel);
}

static int by_key(const void *a, const void *b)
{ return strcmp(((const struct map_entry *)a)->k, ((const struct map_entry *)b)->k); }

static void write_all(const char *path, int fd, const void *data, size_t n)
{
    for (const char *p = data; n;) {
        ssize_t k = write(fd, p, n);
        if (k < 0) fail_errno(path);
        p += k;
        n -= (size_t)k;
    }
}

/* os.utime(path, (t, t)) */
static void set_mtime(const char *path, const struct tar_member *m)
{
    struct timespec ts = {(time_t)m->mtime, 0};
    if (m->mtime_float) { /* as CPython rounds a float: towards minus infinity */
        double whole, frac = modf(m->mtime_f, &whole);
        double ns = floor(frac * 1e9);
        if (ns >= 1e9) ns -= 1e9, whole += 1.0;
        else if (ns < 0) ns += 1e9, whole -= 1.0;
        ts = (struct timespec){(time_t)whole, (long)ns};
    }
    struct timespec both[2] = {ts, ts};
    if (utimensat(AT_FDCWD, path, both, 0)) fail_errno(path);
}

struct pending {
    char *src, *dst;
};

/* ---------------------------------------------------------------- extraction (10.1 step 2) */
static void extract(const char *root, struct pkg *pkgs, int npkgs, const struct map *links, const struct map *parents)
{
    char *usr = path_join(root, "usr");
    py_makedirs(usr);
    free(usr);
    char *root_real = py_realpath(root);
    /* a relative symlink one package ships where others ship files, made before anything is extracted */
    struct map_entry *rels = xrealloc(NULL, (links->n + 1) * sizeof *rels);
    size_t nrels = 0;
    for (size_t i = 0; i < links->cap; i++)
        if (links->e[i].k) rels[nrels++] = links->e[i];
    qsort(rels, nrels, sizeof *rels, by_key);
    static const char *const merged[] = {"usr/bin", "usr/sbin", "usr/lib", "usr/lib32", "usr/lib64", "usr/libx32"};
    for (size_t i = 0; i < nrels; i++) {
        const char *rel = rels[i].k, *target = rels[i].v;
        int is_merged = 0;
        for (size_t j = 0; j < sizeof merged / sizeof *merged; j++) is_merged |= !strcmp(rel, merged[j]);
        int dotdot = 0;
        for (const char *s = target; s; s = strchr(s, '/') ? strchr(s, '/') + 1 : NULL)
            dotdot |= !strncmp(s, "..", 2) && (s[2] == '/' || !s[2]);
        if ((!map_find(parents, rel) && !is_merged) || target[0] == '/' || dotdot) continue;
        char *dst = path_join(root, rel);
        if (!lexists(dst)) {
            char *dir = py_dirname(dst);
            py_makedirs(dir);
            free(dir);
            if (symlink(target, dst)) fail_errno(dst);
        }
        free(dst);
    }
    free(rels);
    struct map owner = {0}; /* each path's package, by its index plus one */
    struct strs *repl = xrealloc(NULL, (size_t)npkgs * sizeof *repl);
    struct pending *pend = NULL;
    size_t npend = 0;
    for (int pi = 0; pi < npkgs; pi++) {
        const struct pkg *p = &pkgs[pi];
        repl[pi] = (struct strs){0};
        replaced(p, &repl[pi]);
        struct apk a;
        apk_open(p->path, &a);
        for (size_t i = 0; i < a.t.n; i++) {
            const struct tar_member *m = &a.t.m[i];
            if (is_control(m)) continue;
            char *rel = safe_rel(m->name);
            if (!*rel) {
                free(rel);
                continue;
            }
            char *dst = path_join(root, rel), *key = owner_key(rel);
            inside(root_real, dst);
            if (m->type == '5') {
                if (!(islink(dst) && isdir(dst))) {
                    py_makedirs(dst);
                    if (chmod(dst, (mode_t)((m->mode & 0777) | 0700))) fail_errno(dst);
                }
                free(rel), free(dst), free(key);
                continue;
            }
            if (lexists(dst) && (islink(dst) || !isdir(dst))) {
                const struct map_entry *e = map_find(&owner, key);
                int prev = e ? (int)(intptr_t)e->v - 1 : -1;
                char target[4097];
                ssize_t k = m->type == '2' && islink(dst) ? readlink(dst, target, sizeof target - 1) : -1;
                if (k >= 0) target[k] = 0;
                if (k >= 0 && !strcmp(target, m->linkname)) { /* the same symlink from two packages: normal */
                    free(rel), free(dst), free(key);
                    continue;
                }
                if (islink(dst) && isdir(dst) && m->type != '2')
                    fail("%s ships /%s over a directory symlink", p->name, rel);
                if (prev >= 0 && strs_has(&repl[pi], pkgs[prev].name)) {
                    if (unlink(dst)) fail_errno(dst); /* this package replaces the previous owner's file */
                } else if (prev >= 0 && strs_has(&repl[prev], p->name)) {
                    free(rel), free(dst), free(key); /* the previous owner replaces ours: keep theirs */
                    continue;
                } else if (prev >= 0)
                    fail("%s and %s both ship /%s and neither declares Replaces", pkgs[prev].name, p->name, rel);
                else if (unlink(dst)) fail_errno(dst);
            }
            char *dir = py_dirname(dst);
            py_makedirs(dir);
            free(dir);
            if (m->type == '2') {
                if (symlink(m->linkname, dst)) fail_errno(dst);
            } else if (m->type == '1') {
                char *src_rel = safe_rel(m->linkname);
                pend = xrealloc(pend, (npend + 1) * sizeof *pend);
                pend[npend++] = (struct pending){path_join(root, src_rel), str_copy(dst)};
                free(src_rel);
            } else if (tar_regular(m->type)) {
                int fd = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
                if (fd < 0) fail_errno(dst);
                write_all(dst, fd, a.data.p + m->data, (size_t)m->size);
                if (close(fd)) fail_errno(dst);
                /* setuid and setgid mean nothing under no_new_privs; a tree stays readable by its owner */
                if (chmod(dst, (mode_t)((m->mode & 0777) | 0400))) fail_errno(dst);
                set_mtime(dst, m);
            } else {
                printf("skipping special file /%s from %s\n", rel, p->name);
                free(rel), free(dst), free(key);
                continue;
            }
            map_put(&owner, key, (void *)(intptr_t)(pi + 1));
            free(rel), free(dst), free(key);
        }
        apk_close(&a);
    }
    for (size_t i = 0; i < npend; i++) {
        inside(root_real, pend[i].dst);
        inside(root_real, pend[i].src); /* a link to a file outside the tree would ship that file */
        if (lexists(pend[i].dst) && unlink(pend[i].dst)) fail_errno(pend[i].dst);
        /* the member the archive names, never what a shipped symlink there points at */
        if (linkat(AT_FDCWD, pend[i].src, AT_FDCWD, pend[i].dst, 0)) fail_errno(pend[i].dst);
        free(pend[i].src);
        free(pend[i].dst);
    }
    free(pend);
    for (int i = 0; i < npkgs; i++) strs_free(&repl[i]);
    free(repl);
    map_free(&owner, 0);
    free(root_real);
}

/* ---------------------------------------------------------------- synthesis (10.1 step 3) */
/* _link: a symlink at a virtual path, unless something stands there */
static void make_link(const char *root, const char *link, const char *target)
{
    char *p = vpath(root, link);
    if (!lexists(p)) {
        char *dir = py_dirname(p);
        py_makedirs(dir);
        free(dir);
        if (symlink(target, p)) fail_errno(p);
        printf("synthesised %s -> %s\n", link, target);
    }
    free(p);
}

/* os.path.relpath("/bin/busybox", start), start an absolute path without . or .. */
static char *busybox_from(const char *start)
{
    static const char *const target[] = {"bin", "busybox"};
    struct strs parts = {0};
    for (const char *s = start; *s;) {
        while (*s == '/') s++;
        size_t k = strcspn(s, "/");
        if (!k) break;
        char *c = xrealloc(NULL, k + 1);
        memcpy(c, s, k);
        c[k] = 0;
        strs_add(&parts, c);
        free(c);
        s += k;
    }
    size_t common = 0;
    while (common < parts.n && common < 2 && !strcmp(parts.s[common], target[common])) common++;
    struct buf b = {0};
    for (size_t i = common; i < parts.n; i++) buf_str(&b, b.n ? "/.." : "..");
    for (size_t i = common; i < 2; i++) {
        if (b.n) buf_add(&b, "/", 1);
        buf_str(&b, target[i]);
    }
    if (!b.n) buf_str(&b, ".");
    buf_add(&b, "", 1);
    strs_free(&parts);
    return b.p;
}

/* busybox (Alpine): the applet links its post-install makes from the paths it ships in /etc/busybox-paths.d, one per
 * line, each a relative link to /bin/busybox */
static void busybox_links(const char *root)
{
    char *bbd = vpath(root, "/etc/busybox-paths.d"), *bb = vpath(root, "/bin/busybox");
    int present = isdir(bbd) && isfile(bb);
    free(bb);
    if (!present) {
        free(bbd);
        return;
    }
    char *root_real = py_realpath(root);
    struct entry_info *e;
    size_t ne, made = 0;
    if (list_dir(bbd, &e, &ne)) fail_errno(bbd);
    for (size_t i = 0; i < ne; i++) {
        char *f = path_join(bbd, e[i].name);
        size_t n;
        char *text = read_file(f, &n);
        /* lines as Python's text mode splits them, at \n, \r and \r\n */
        for (const char *line = text, *end = text + n; line < end;) {
            size_t k = 0;
            while (line + k < end && line[k] != '\r' && line[k] != '\n') k++;
            if (memchr(line, 0, k)) fail("%s: a NUL in a path", f);
            const char *next = line + k;
            if (next < end) next += next[0] == '\r' && next + 1 < end && next[1] == '\n' ? 2 : 1;
            char *s = stripped(line, k), *rel = safe_rel(s);
            line = next;
            free(s);
            if (!*rel) {
                free(rel);
                continue;
            }
            char *dst = path_join(root, rel);
            if (!lexists(dst)) {
                inside(root_real, dst);
                char *dir = py_dirname(dst);
                py_makedirs(dir);
                free(dir);
                struct buf v = {0};
                buf_add(&v, "/", 1);
                buf_str(&v, rel);
                buf_add(&v, "", 1);
                char *vdir = py_dirname(v.p), *target = busybox_from(vdir);
                if (symlink(target, dst)) fail_errno(dst);
                made++;
                free(vdir), free(target), free(v.p);
            }
            free(dst);
            free(rel);
        }
        free(text);
        free(f);
    }
    free_list(e, ne);
    printf("synthesised %zu busybox applet links from /etc/busybox-paths.d\n", made);
    free(root_real);
    free(bbd);
}

static int has_name(const struct pkg *pkgs, int n, const char *name, int prefix)
{
    for (int i = 0; i < n; i++)
        if (prefix ? !strncmp(pkgs[i].name, name, strlen(name)) : !strcmp(pkgs[i].name, name)) return 1;
    return 0;
}

/* whether Python's glob of DIR and a star then SUFFIX finds anything: an entry of the directory that does not start
 * with a dot and ends in suffix */
static int globbed(const char *root, const char *dir, const char *suffix)
{
    char *d = vpath(root, dir);
    struct entry_info *e;
    size_t n, k = strlen(suffix);
    int found = 0;
    if (!list_dir(d, &e, &n)) {
        for (size_t i = 0; i < n; i++) {
            size_t len = strlen(e[i].name);
            found |= e[i].name[0] != '.' && len >= k && !strcmp(e[i].name + len - k, suffix);
        }
        free_list(e, n);
    }
    free(d);
    return found;
}

static _Noreturn void not_yet(const char *what)
{ fail("this set needs %s, which exclave unpack does not synthesise yet; scripts/unpack does", what); }

static void synthesise(const char *root, const struct pkg *pkgs, int n)
{
    busybox_links(root);
    /* dash: /bin/sh is made by its postinst, not shipped */
    char *dash = vpath(root, "/usr/bin/dash");
    if (has_name(pkgs, n, "dash", 0) && lexists(dash)) make_link(root, "/usr/bin/sh", "dash");
    free(dash);
    char *conf = vpath(root, "/etc/ca-certificates.conf");
    int debian_ca = has_name(pkgs, n, "ca-certificates", 0) && exists(conf);
    free(conf);
    if (debian_ca) not_yet("the CA bundle update-ca-certificates makes");
    char *extracted = vpath(root, "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem");
    int p11 = (globbed(root, "/usr/share/pki/ca-trust-source", ".p11-kit") ||
               globbed(root, "/etc/pki/ca-trust/source/anchors", "")) &&
              !lexists(extracted);
    free(extracted);
    if (p11) not_yet("the CA bundle update-ca-trust extracts");
    /* libssl: OpenSSL's compiled-in trust paths, which point at the host's bundle at the identity path (8.4) */
    if (has_name(pkgs, n, "libssl", 1)) {
        make_link(root, "/usr/lib/ssl/certs", "/etc/ssl/certs");
        make_link(root, "/usr/lib/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt");
    }
    /* base-passwd: /etc/passwd and /etc/group come from update-passwd, not the package */
    static const char *const passwd[][2] = {{"passwd", "passwd.master"}, {"group", "group.master"}};
    for (int i = 0; i < 2; i++) {
        struct buf s = {0}, d = {0};
        buf_str(&s, "/usr/share/base-passwd/");
        buf_str(&s, passwd[i][1]);
        buf_add(&s, "", 1);
        buf_str(&d, "/etc/");
        buf_str(&d, passwd[i][0]);
        buf_add(&d, "", 1);
        char *src = vpath(root, s.p), *dst = vpath(root, d.p);
        if (has_name(pkgs, n, "base-passwd", 0) && exists(src) && !lexists(dst)) {
            size_t k;
            char *data = read_file(src, &k);
            int fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
            if (fd < 0) fail_errno(dst);
            write_all(dst, fd, data, k);
            if (close(fd)) fail_errno(dst);
            free(data);
            printf("synthesised /etc/%s from base-passwd\n", passwd[i][0]);
        }
        free(src), free(dst), free(s.p), free(d.p);
    }
    /* ldconfig: the exclave's own, static; Alpine's is a shell script, which musl's loader has no cache for */
    static const char *const ldconfig[] = {"/usr/sbin/ldconfig.real", "/sbin/ldconfig.real", "/usr/sbin/ldconfig",
                                           "/sbin/ldconfig", "/usr/bin/ldconfig"};
    for (size_t i = 0; i < sizeof ldconfig / sizeof *ldconfig; i++) {
        char *p = vpath(root, ldconfig[i]);
        int elf = 0;
        if (isfile(p)) {
            int fd = open(p, O_RDONLY | O_CLOEXEC);
            char magic[4];
            if (fd < 0) fail_errno(p);
            elf = read(fd, magic, 4) == 4 && !memcmp(magic, "\177ELF", 4);
            close(fd);
        }
        free(p);
        if (elf) not_yet("an ld.so.cache from the tree's ldconfig");
    }
    if (has_name(pkgs, n, "libc-bin", 0)) printf("libc-bin present but no static ldconfig found; no ld.so.cache\n");
}

/* ---------------------------------------------------------------- the volatile directories (10.1 step 4) */
static int remove_one(const char *path, const struct stat *st, int flag, struct FTW *ftw)
{
    (void)st, (void)ftw;
    return (flag == FTW_DP ? rmdir(path) : unlink(path)) ? -1 : 0;
}

/* shutil.rmtree: 0, or -1 with errno at the first entry that cannot be removed */
static int remove_tree(const char *path) { return nftw(path, remove_one, 64, FTW_DEPTH | FTW_PHYS); }

static void strip_volatile(const char *root)
{
    for (size_t i = 0; i < sizeof VOLATILE / sizeof *VOLATILE; i++) {
        char *p = vpath(root, VOLATILE[i]);
        struct stat st;
        if (!lstat(p, &st) && !S_ISLNK(st.st_mode)) {
            if (!S_ISDIR(st.st_mode)) {
                errno = ENOTDIR;
                fail_errno(p);
            }
            if (remove_tree(p)) fail_errno(p);
        }
        free(p);
    }
}

/* ---------------------------------------------------------------- the inputs (10.1 step 5, 6.4) */
static int printable(const char *s)
{
    for (; *s; s++)
        if (*s < ' ' || *s > '~') return 0;
    return 1;
}

static int by_row(const void *a, const void *b)
{
    char *const *x = a, *const *y = b;
    for (int i = 0; i < 4; i++) {
        int c = strcmp(x[i], y[i]);
        if (c) return c;
    }
    return 0;
}

static void write_records(const char *out, const struct pkg *pkgs, int n)
{
    char **cells = xrealloc(NULL, (size_t)n * 4 * sizeof *cells);
    for (int i = 0; i < n; i++) {
        size_t k;
        char *data = read_file(pkgs[i].path, &k), text[B2_TEXT];
        struct blake2b s;
        uint8_t d[32];
        b2_init(&s, 32);
        b2_update(&s, data, k);
        b2_final(&s, d);
        b2_text(d, text);
        free(data);
        char **row = cells + (size_t)4 * (size_t)i;
        row[0] = str_copy(pkgs[i].name), row[1] = str_copy(pkgs[i].version), row[2] = str_copy(pkgs[i].arch),
        row[3] = str_copy(text);
        for (int j = 0; j < 4; j++)
            if (!printable(row[j])) fail("%s: control field '%s' is not printable ASCII", pkgs[i].path, row[j]);
    }
    qsort(cells, (size_t)n, 4 * sizeof *cells, by_row);
    struct buf b = {0};
    buf_str(&b, "hashes 1\n\n");
    for (int i = 0; i < n; i++) {
        buf_str(&b, "pkg");
        for (int j = 0; j < 4; j++) {
            buf_str(&b, " \"");
            for (const char *c = cells[4 * i + j]; *c; c++) {
                if (*c == '\\' || *c == '"') buf_add(&b, "\\", 1);
                buf_add(&b, c, 1);
            }
            buf_add(&b, "\"", 1);
            free(cells[4 * i + j]);
        }
        buf_add(&b, "\n", 1);
    }
    free(cells);
    char *dir = path_join(out, ".exclave"), *path = path_join(dir, "hashes");
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) fail_errno(path);
    write_all(path, fd, b.p, b.n);
    if (close(fd)) fail_errno(path);
    free(b.p), free(dir), free(path);
}

/* ---------------------------------------------------------------- the command */
static char *made; /* OUT, once it is made and until it is finished: removed when the command fails */

static void remove_made(void)
{
    if (!made) return;
    (void)remove_tree(made);
}

/* the links and the parents of files that a package ships, as the extraction's first pass collects them */
static void first_pass(const struct apk *a, struct map *links, struct map *parents)
{
    for (size_t i = 0; i < a->t.n; i++) {
        const struct tar_member *m = &a->t.m[i];
        if (is_control(m)) continue;
        char *rel = safe_rel(m->name);
        if (*rel && m->type == '2') {
            const struct map_entry *e = map_find(links, rel);
            if (e) free(e->v);
            map_put(links, rel, str_copy(m->linkname));
        } else if (*rel && m->type != '5')
            for (char *s = strchr(rel, '/'); s; s = strchr(s + 1, '/')) {
                *s = 0;
                map_put(parents, rel, (void *)1);
                *s = '/';
            }
        free(rel);
    }
}

int cmd_unpack(int argc, char **argv)
{
    if (argc < 2) usage("unpack OUT APK...");
    const char *out = argv[0];
    if (exists(out)) fail("refusing: %s exists", out);
    int apk = 0, rpm = 0, deb = 0, n = argc - 1;
    for (int i = 1; i < argc; i++) {
        size_t k = strlen(argv[i]);
        int a = k >= 4 && !strcmp(argv[i] + k - 4, ".apk"), r = k >= 4 && !strcmp(argv[i] + k - 4, ".rpm");
        apk |= a, rpm |= r, deb |= !a && !r;
    }
    if (apk + rpm + deb > 1) fail("the package files mix formats: one format per exclave");
    if (!apk) fail("exclave unpack reads .apk files so far; scripts/unpack reads .deb and .rpm files");
    struct pkg *pkgs = xrealloc(NULL, (size_t)n * sizeof *pkgs);
    struct map links = {0}, parents = {0};
    for (int i = 0; i < n; i++) {
        struct apk a;
        apk_open(argv[i + 1], &a);
        control(argv[i + 1], &a, &pkgs[i]);
        if (!*pkgs[i].name || !*pkgs[i].version) fail("%s: no Package or Version in its control file", argv[i + 1]);
        for (int j = 0; j < i; j++)
            if (!strcmp(pkgs[j].name, pkgs[i].name))
                fail("%s and %s both carry package %s: one version of a package per exclave", pkgs[j].path,
                     pkgs[i].path, pkgs[i].name);
        first_pass(&a, &links, &parents);
        apk_close(&a);
    }
    for (int i = 0; i < n; i++)
        for (int j = 0; j < i; j++)
            if (strcmp(pkgs[i].arch, "all") != 0 && *pkgs[i].arch && strcmp(pkgs[j].arch, "all") != 0 &&
                *pkgs[j].arch && strcmp(pkgs[i].arch, pkgs[j].arch) != 0)
                fail("the packages mix architectures %s and %s", pkgs[j].arch, pkgs[i].arch);
    char *dot = path_join(out, ".exclave");
    py_makedirs(dot);
    free(dot);
    made = str_copy(out);
    atexit(remove_made);
    char *root = path_join(out, "tree");
    extract(root, pkgs, n, &links, &parents);
    synthesise(root, pkgs, n);
    strip_volatile(root);
    write_records(out, pkgs, n);
    printf("unpacked %d packages into %s; exclave wrap %s makes it an exclave\n", n, out, out);
    free(made);
    made = NULL;
    free(root);
    map_free(&links, 1);
    map_free(&parents, 0);
    for (int i = 0; i < n; i++) free(pkgs[i].name), free(pkgs[i].version), free(pkgs[i].arch), free(pkgs[i].replaces);
    free(pkgs);
    return 0;
}
