/* vis.c — the visibility rule (DESIGN.md section 8) and wrapper redirect (7.4.4).
 *
 * Decides, for a virtual path, whether it is the host's or the exclave's, and
 * turns it into a real path. The table is built once at startup from the
 * tree, the manifest, the working directory and the host identity files.
 */
#include "common.h"

static const char *volatile_dirs[] = {"/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run", 0};
/* 8.1.5: the host's by default; an own record naming one exactly removes it. /etc/localtime is the host's zone, a
 * TZif file any libc reads through the host's link into its zoneinfo, and TZ is dropped at the border (6.2). */
static const char *identity_files[] = {"/etc/passwd",
                                       "/etc/group",
                                       "/etc/nsswitch.conf",
                                       "/etc/host.conf",
                                       "/etc/resolv.conf",
                                       "/etc/hosts",
                                       "/etc/localtime",
                                       "/etc/ssl/certs/ca-certificates.crt",
                                       "/etc/pki/tls/certs/ca-bundle.crt",
                                       0};
_Static_assert(sizeof identity_files / sizeof identity_files[0] == N_IDENTITY + 1,
               "N_IDENTITY counts the identity files");
/* 8.1.5: directories the host's by default, as the identity files are: SSSD's state, whose socket and memory cache
 * its lookup module reads (13 item 17); an own record naming one exactly removes it */
static const char *host_dirs[] = {"/var/lib/sss", 0};
_Static_assert(sizeof host_dirs / sizeof host_dirs[0] == N_HOST_DIRS + 1, "N_HOST_DIRS counts the host directories");

struct dirent64 {
    unsigned long d_ino;
    long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

/* does name, an entry of the tree's top level open as dfd, hold anything but . and ..? Read until an entry or the end,
 * since only a read that returns nothing proves a directory empty. A directory that cannot be listed is not a
 * placeholder: it counts as the exclave's, and a failure that is not the directory's own, no descriptor left or an
 * I/O error, is fatal rather than a silent answer of "the host's"; real names it in the message. The buffer holds .
 * and .. and one name of the longest kind, all an answer needs */
static int dir_nonempty(int dfd, const char *name, const char *real)
{
    static char buf[512];
    long fd = sys_openat(dfd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd == -EACCES || fd == -EPERM) return 1;
    if (fd < 0) die("cannot read a top-level directory of tree/", real, fd);
    for (;;) {
        long n = sys_getdents64((int)fd, buf, sizeof buf);
        if (n < 0) die("cannot read a top-level directory of tree/", real, n);
        if (n == 0) {
            sys_close((int)fd);
            return 0;
        }
        for (long o = 0; o < n;) {
            struct dirent64 *d = (struct dirent64 *)(buf + o);
            if (!(d->d_name[0] == '.' && (d->d_name[1] == 0 || (d->d_name[1] == '.' && d->d_name[2] == 0)))) {
                sys_close((int)fd);
                return 1;
            }
            o += d->d_reclen;
        }
    }
}

/* 8.1.3: a top-level name that is a volatile directory, /tmp say, is the host's whatever the tree ships there, so
 * whether it is a placeholder decides nothing */
static int volatile_top(const char *name)
{
    for (int i = 0; volatile_dirs[i]; i++)
        if (xstrcmp(volatile_dirs[i] + 1, name) == 0) return 1;
    return 0;
}

/* 8.1.1: the exclave owns every top-level entry of its tree that is not an empty directory. Read from the tree at
 * startup, so an edited tree needs no index to be refreshed; the manifest's own records are added by the parser before
 * this runs. One directory read per top-level directory, opened by its name in tree/, and none for a volatile
 * directory, which takes no slot either (8.1.3). */
static void own_from_tree(void)
{
    static char buf[16384];
    static char real[PATH_MAX];
    long fd = sys_open(C.root, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0) die("cannot read tree/", C.root, fd);
    /* the manifest's own records come first; the tree has 256 slots of its own */
    int first = C.nown;
    for (;;) {
        long n = sys_getdents64((int)fd, buf, sizeof buf);
        if (n < 0) die("cannot read tree/", C.root, n);
        if (n == 0) break;
        for (long o = 0; o < n;) {
            struct dirent64 *d = (struct dirent64 *)(buf + o);
            o += d->d_reclen;
            if (d->d_name[0] == '.' && (d->d_name[1] == 0 || (d->d_name[1] == '.' && d->d_name[2] == 0))) continue;
            if (volatile_top(d->d_name)) continue;
            scpy(real, C.root, PATH_MAX);
            scat(real, "/", PATH_MAX);
            scat(real, d->d_name, PATH_MAX);
            int type = d->d_type;
            if (type == DT_UNKNOWN) {
                struct kstat st;
                if (sys_fstatat((int)fd, d->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) continue;
                type = (st.st_mode & S_IFMT) == S_IFDIR ? DT_DIR : (st.st_mode & S_IFMT) == S_IFLNK ? DT_LNK : DT_REG;
            }
            /* a placeholder: ls / shows it, the host owns it */
            if (type == DT_DIR && !dir_nonempty((int)fd, d->d_name, real)) continue;
            if (C.nown - first >= MAX_TOP_LEVEL) die("more than 256 top-level entries in tree/", C.root, 0);
            size_t l = xstrlen(d->d_name);
            char *v = arena_alloc(l + 2);
            v[0] = '/';
            xmemcpy(v + 1, d->d_name, l + 1);
            C.own[C.nown++] = v;
        }
    }
    sys_close((int)fd);
}

/* 8.1.5: the identity files and the default host directories join the host table unless an own record names one;
 * the table has room for them after the manifest's records by construction */
static void host_default(const char *v, int is_dir)
{
    for (int j = 0; j < C.nown; j++)
        if (xstrcmp(C.own[j], v) == 0) return;
    if (C.nhost >= (int)(sizeof C.host / sizeof C.host[0])) die("host table full", v, 0);
    C.host[C.nhost].v = v;
    C.host[C.nhost].r = v;
    C.host[C.nhost].is_file = 0;
    C.host[C.nhost].is_default_dir = is_dir;
    C.nhost++;
}
static void identity_defaults(void)
{
    for (int i = 0; i < N_IDENTITY; i++) host_default(identity_files[i], 0);
    for (int i = 0; i < N_HOST_DIRS; i++) host_default(host_dirs[i], 1);
}

/* 6.2: a data directory is never executed and never a loader */
int vis_in_data(const char *v)
{
    for (int i = 0; i < C.ndata; i++)
        if (starts_dir(v, C.data[i])) return 1;
    return 0;
}

static int base_is_host(const char *v, const char **real);
static void rule_build(void);

static void claim_cwd(void)
{
    char real[PATH_MAX];
    C.cwdclaim[0] = 0;
    C.cwdclaim_len = 0;
    long n = sys_getcwd(real, PATH_MAX);
    if (n <= 0) return;
    /* the workload's directory, for the dynamic check (10.3) */
    if (C.boundary) log_msg("cwd", real);
    /* inside the tree: virtual path, nothing given (8.1.4) */
    if (starts_dir(real, C.root)) return;
    /* the root itself is the tree's (8.3): nothing to give */
    if (real[0] == '/' && real[1] == 0) return;
    /* a real host path: give it to the host as a subtree if the base rule would otherwise hand it to the exclave; the
     * subtrees given do not count, or a cwd above the exclave's directory would never be given */
    const char *r;
    if (base_is_host(real, &r)) return;
    scpy(C.cwdclaim, real, PATH_MAX);
    C.cwdclaim_len = (long)xstrlen(real);
    log_msg("cwd given to the host", real);
}

void vis_init(void)
{
    identity_defaults();
    own_from_tree();
    /* identity files and host records: resolve each on the host; drop the ones the host lacks */
    int n = 0, nextra = 0;
    const char *extra[N_HOST_DIRS] = {0};
    for (int i = 0; i < C.nhost; i++) {
        struct kstat st;
        if (sys_lstat(C.host[i].v, &st) < 0) {
            log_msg("host path absent, using the exclave's", C.host[i].v);
            continue;
        }
        if ((st.st_mode & S_IFMT) == S_IFDIR) {
            C.host[n] = C.host[i];
            C.host[n].is_file = 0;
            n++;
            continue;
        }
        /* a default directory that is a host link to a directory: the name stays a directory record, and the directory
         * the host resolves it to, as the kernel names it, is the host's as well, so that the walk, which follows the
         * link's text in virtual space (7.4.4), reaches it */
        if (C.host[i].is_default_dir && (st.st_mode & S_IFMT) == S_IFLNK) {
            static char dir[PATH_MAX];
            long fd = sys_open(C.host[i].v, O_PATH | O_CLOEXEC | O_DIRECTORY, 0);
            long len = fd >= 0 ? fd_real_path((int)fd, dir) : -1;
            if (fd >= 0) sys_close((int)fd);
            if (len > 0 && dir[0] == '/') {
                C.host[n] = C.host[i];
                C.host[n].is_file = 0;
                n++;
                /* one at most for each default directory, by construction */
                if (nextra >= N_HOST_DIRS) die("host table full", dir, 0);
                extra[nextra++] = arena_str(dir, (size_t)len);
                continue;
            }
        }
        /* a file, or a link the host resolves: the host's name is its real path, so that a call follows the host's
         * link as the host has it at that moment, in the host's space (8.4) */
        if ((st.st_mode & S_IFMT) == S_IFLNK && sys_stat(C.host[i].v, &st) < 0) {
            log_msg("host path unresolvable, using the exclave's", C.host[i].v);
            continue;
        }
        C.host[n].v = C.host[n].r = C.host[i].v;
        C.host[n].is_file = 1;
        C.host[n].is_default_dir = 0;
        n++;
    }
    for (int i = 0; i < nextra; i++) {
        C.host[n].v = C.host[n].r = extra[i];
        C.host[n].is_file = 0;
        C.host[n].is_default_dir = 1;
        n++;
    }
    C.nhost = n;
    rule_build();
    claim_cwd();
}

/* The rule compiled (DESIGN.md 16.2, 16.6 item 3). Every string the rule matches a path against, an owned path,
 * a host record, an identity file, a volatile directory, and every proper ancestor of an identity file, is an
 * entry of one table built at startup, with what it is. starts_dir(v, p) holds exactly when p is v cut at a '/'
 * or at its end, so the prefixes of v the rule can match are found by one pass over v, hashing as it goes and
 * looking each cut up: a path's answer costs one pass over its length. The table is written once before
 * anything traps and only read afterwards. */
enum { R_OWN = 1, R_HOSTDIR = 2, R_HOSTFILE = 4, R_VOLATILE = 8, R_LEADS = 16 };
#define RULE_SLOTS 2048
/* host: the index of a file's record */
static struct rule {
    const char *s;
    unsigned len, flags;
    int host;
} rules[RULE_SLOTS];
static int nrules;                                             /* entries placed, at most half the slots in use */
/* the slots in use, less one: the first of the table, enough for twice the entries rule_build can place, so that the
 * pages a start touches are the ones its entries need (16.6 item 9) */
static unsigned rule_mask = RULE_SLOTS - 1;
/* a rule string "/", which starts_dir lets match every absolute path */
static int root_flags;
/* the exclave's directory's length, for the subtree there that vis_is_host gives the host */
static unsigned dir_len;

static unsigned long rule_hash(unsigned long h, char c) { return (h ^ (unsigned char)c) * 1099511628211UL; }
#define RULE_BASIS 1469598103934665603UL
static struct rule *rule_find(const char *v, unsigned len, unsigned long h)
{
    for (unsigned i = (unsigned)h & rule_mask, n = 0; n <= rule_mask; i = (i + 1) & rule_mask, n++) {
        if (!rules[i].s) return 0;
        if (rules[i].len == len && xmemcmp(rules[i].s, v, len) == 0) return &rules[i];
    }
    return 0;
}
static void rule_add(const char *v, unsigned len, unsigned flags, int host)
{
    if (len == 1 && v[0] == '/') {
        root_flags |= (int)flags;
        return;
    }
    unsigned long h = RULE_BASIS;
    for (unsigned i = 0; i < len; i++) h = rule_hash(h, v[i]);
    struct rule *r = rule_find(v, len, h);
    if (!r) {
        unsigned i = (unsigned)h & rule_mask;
        while (rules[i].s) i = (i + 1) & rule_mask;
        /* slack left, so that a probe always meets an empty slot */
        if (++nrules > (int)(rule_mask + 1) / 2) die("visibility table full", v, 0);
        r = &rules[i];
        r->s = v;
        r->len = len;
        r->host = -1;
    }
    /* a file named twice: the first record, as the scans found it */
    if ((flags & R_HOSTFILE) && !(r->flags & R_HOSTFILE)) r->host = host;
    r->flags |= flags;
}
static void rule_build(void)
{
    dir_len = (unsigned)xstrlen(C.dir);
    unsigned most = (unsigned)C.nown + (unsigned)(sizeof volatile_dirs / sizeof volatile_dirs[0]);
    for (int i = 0; i < C.nhost; i++)
        for (const char *p = C.host[i].v; *p; p++) most += *p == '/';
    while (rule_mask + 1 > 64 && rule_mask / 2 + 1 >= 2 * most) rule_mask /= 2;
    for (int i = 0; i < C.nown; i++) rule_add(C.own[i], (unsigned)xstrlen(C.own[i]), R_OWN, -1);
    for (int i = 0; volatile_dirs[i]; i++)
        rule_add(volatile_dirs[i], (unsigned)xstrlen(volatile_dirs[i]), R_VOLATILE, -1);
    for (int i = 0; i < C.nhost; i++) {
        const char *v = C.host[i].v;
        unsigned len = (unsigned)xstrlen(v);
        if (!C.host[i].is_file) {
            rule_add(v, len, R_HOSTDIR, -1);
            /* a default directory's way is made of directories, as an identity file's is (8.1.5) */
            if (C.host[i].is_default_dir) {
                for (unsigned k = 1; k < len; k++)
                    if (v[k] == '/') rule_add(v, k, R_LEADS, -1);
                if (v[0] == '/') root_flags |= R_LEADS;
            }
            continue;
        }
        rule_add(v, len, R_HOSTFILE, i);
        /* the directories on the way to it */
        for (unsigned k = 1; k < len; k++)
            if (v[k] == '/') rule_add(v, k, R_LEADS, -1);
        /* and the root, which starts_dir lets lead to every absolute path */
        if (v[0] == '/') root_flags |= R_LEADS;
    }
}

/* what the rule's strings say of v: the identity file it is, the longest host record and owned path that are prefixes
 * of it, whether a volatile directory is */
struct facts {
    struct rule *exact;
    long best_host, best_own;
    int vol;
    unsigned len;
};
static void rule_facts(const char *v, struct facts *f)
{
    f->exact = 0;
    f->best_host = f->best_own = -1;
    f->vol = 0;
    if (v[0] == '/') {                                         /* starts_dir(v, "/") */
        if (root_flags & R_OWN) f->best_own = 1;
        if (root_flags & R_HOSTDIR) f->best_host = 1;
        if (root_flags & R_VOLATILE) f->vol = 1;
    }
    unsigned long h = RULE_BASIS;
    for (unsigned i = 0;; i++) {
        char c = v[i];
        /* a trailing slash names the directory without it, to which the same rules apply */
        int end = c == 0 || (i > 0 && c == '/' && v[i + 1] == 0);
        if (i > 0 && (c == '/' || c == 0)) {
            struct rule *r = rule_find(v, i, h);
            if (r) {
                if (r->flags & R_OWN) f->best_own = i;
                if (r->flags & R_HOSTDIR) f->best_host = i;
                if (r->flags & R_VOLATILE) f->vol = 1;
                if (end) f->exact = r;
            }
        }
        if (end) {
            f->len = i;
            break;
        }
        h = rule_hash(h, c);
    }
}
/* starts_dir(v, p) || starts_dir(p, v), v of length vl and p of length pl, neither "/" (vis_is_host answers it) */
static int on_the_way(const char *v, unsigned vl, const char *p, unsigned pl)
{
    if (pl == 1 && p[0] == '/') return starts_dir(v, p) || starts_dir(p, v);
    if (vl >= pl) return xmemcmp(v, p, pl) == 0 && (v[pl] == '/' || v[pl] == 0);
    return xmemcmp(p, v, vl) == 0 && p[vl] == '/';
}
static struct rule *rule_exact(const char *v)
{
    unsigned long h = RULE_BASIS;
    unsigned len = 0;
    for (; v[len]; len++) h = rule_hash(h, v[len]);
    return len ? rule_find(v, len, h) : 0;
}

/* 8.1 without the two subtrees given to the host: identity file > volatile > host records > own > default host;
 * longest prefix wins. The root directory itself is the tree's, so ls / lists the tree and its placeholders (8.3). */
static int base_is_host_facts(const char *v, const struct facts *f, const char **real)
{
    if (v[0] == '/' && v[1] == 0) return 0;
    if (f->exact && (f->exact->flags & R_HOSTFILE)) {
        *real = C.host[f->exact->host].r;
        return 1;
    }
    if (f->vol) {
        *real = v;
        return 1;
    }
    /* includes the default: nothing owns it */
    if (f->best_host >= f->best_own) {
        *real = v;
        return 1;
    }
    return 0;
}
static int base_is_host(const char *v, const char **real)
{
    struct facts f;
    rule_facts(v, &f);
    return base_is_host_facts(v, &f, real);
}

/* the full rule: the root, the identity files, the two subtrees given to the host (8.1.4, 8.1.6), then the base rule */
static int is_host_facts(const char *v, const struct facts *fp, const char **real)
{
    struct facts f = *fp;
    /* the root itself is the tree's (8.3), before the subtrees that pass through it */
    if (v[0] == '/' && v[1] == 0) return 0;
    if (f.exact && (f.exact->flags & R_HOSTFILE)) {
        *real = C.host[f.exact->host].r;
        return 1;
    }
    /* 8.1.4: a working directory given to the host is the host's as a subtree, and so is every directory on the way to
     * it, or realpath and pwd -P could not walk the path the process was started in */
    if (C.cwdclaim_len && on_the_way(v, f.len, C.cwdclaim, (unsigned)C.cwdclaim_len)) {
        *real = v;
        return 1;
    }
    /* 8.1.6: the exclave's own directory is the host's as a subtree, and so are the directories on the way to it: a
     * program that locates its files relative to its real executable path, as gcc does, must reach them wherever the
     * exclave lives, including under a prefix its own tree owns */
    if (on_the_way(v, f.len, C.dir, dir_len)) {
        *real = v;
        return 1;
    }
    return base_is_host_facts(v, &f, real);
}
int vis_is_host(const char *v, const char **real)
{
    struct facts f;
    rule_facts(v, &f);
    return is_host_facts(v, &f, real);
}
int is_exclave_path(const char *v)
{
    const char *r;
    return !vis_is_host(v, &r);
}
static int leads_facts(const char *v, const struct facts *f)
{
    /* starts_dir(file, "") and (file, "/") */
    if (!v[0] || (v[0] == '/' && !v[1])) return (root_flags & R_LEADS) != 0;
    return f->exact && (f->exact->flags & R_LEADS);
}
/* the one-step host check's question (DESIGN.md 16.6 item 4): is every '/'-boundary prefix of p at least from long
 * plain host, the host's by the full rule, not an identity file, not on the way to one and not the tree's root by its
 * name, so that a walk through them would do nothing but lstat each and find a directory? One pass, as rule_facts. */
int vis_plain_host_chain(const char *p, unsigned from)
{
    struct facts f;
    f.exact = 0;
    f.best_host = f.best_own = -1;
    f.vol = 0;
    f.len = 0;
    if (p[0] != '/' || from < 2) return 0;
    if (root_flags & R_OWN) f.best_own = 1;
    if (root_flags & R_HOSTDIR) f.best_host = 1;
    if (root_flags & R_VOLATILE) f.vol = 1;
    unsigned long h = RULE_BASIS;
    for (unsigned i = 0;; i++) {
        char c = p[i];
        if (i > 0 && (c == '/' || c == 0)) {
            struct rule *r = rule_find(p, i, h);
            if (r) {
                if (r->flags & R_OWN) f.best_own = i;
                if (r->flags & R_HOSTDIR) f.best_host = i;
                if (r->flags & R_VOLATILE) f.vol = 1;
            }
            if (i >= from) {                                   /* the candidate p[0..i), i >= 2: never the root */
                if (r && (r->flags & (R_HOSTFILE | R_LEADS))) return 0;
                if (C.rootlen == (long)i && xmemcmp(p, C.root, i) == 0) return 0;
                struct facts g = f;
                g.exact = r;
                g.len = i;
                const char *real;
                if (!is_host_facts(p, &g, &real)) return 0;
            }
        }
        if (c == 0) return 1;
        h = rule_hash(h, c);
    }
}
/* the walk's three questions of a candidate in one pass (7.4.4): whether it is an identity file, whether it is a
 * directory on the way to one, and whose it is; 1 if the host's, *real its real path */
int vis_walk_facts(const char *v, int *identity, int *leads, const char **real)
{
    struct facts f;
    rule_facts(v, &f);
    *identity = f.exact && (f.exact->flags & R_HOSTFILE);
    *leads = leads_facts(v, &f);
    return is_host_facts(v, &f, real);
}

int is_wrapper_st(const char *real, const struct kstat *st, char *tmp)
{
    if ((st->st_mode & S_IFMT) != S_IFREG) return 0;
    if ((st->st_dev != C.launcher_dev || st->st_ino != C.launcher_ino) && st->st_size != C.launcher_size) return 0;
    /* the launcher's inode or a copy: a wrapper only where its original exists;
     * .exclave/launcher itself is not one */
    struct kstat pst;
    return payload_of(real, tmp) && sys_lstat(tmp, &pst) == 0;
}
int is_wrapper_real(const char *real, char *tmp)
{
    struct kstat st;
    return sys_lstat(real, &st) == 0 && is_wrapper_st(real, &st, tmp);
}
int payload_of(const char *wrapper, char *payload)
{
    const char *b = xstrrchr(wrapper, '/');
    if (!b) return 0;
    size_t dl = (size_t)(b - wrapper);
    if (dl + 7 + xstrlen(b) >= PATH_MAX) return 0;
    xmemcpy(payload, wrapper, dl);
    payload[dl] = 0;
    scat(payload, "/.real", PATH_MAX);
    scat(payload, b, PATH_MAX);
    return 1;
}

char *to_real_exec(const char *v, char *out)
{
    const char *r;
    if (vis_is_host(v, &r)) {
        scpy(out, r, PATH_MAX);
        /* a trailing slash asks the kernel for a directory, whatever host path the rules map to */
        size_t vl = xstrlen(v), ol = xstrlen(out);
        if (vl > 1 && v[vl - 1] == '/' && ol > 0 && out[ol - 1] != '/') scat(out, "/", PATH_MAX);
        return out;
    }
    scpy(out, C.root, PATH_MAX);
    if (!(v[0] == '/' && v[1] == 0)) scat(out, v, PATH_MAX);
    return out;
}
char *to_real(const char *v, char *out, char *tmp)
{
    to_real_exec(v, out);
    if (!C.rootlen || !starts_dir(out, C.root)) return out;
    int k = cache_classify(v, out, tmp);                       /* the wrapper check, remembered (7.4.4) */
    if ((k == CK_WRAPPER || (!k && is_wrapper_real(out, tmp))) && payload_of(out, tmp)) scpy(out, tmp, PATH_MAX);
    return out;
}
void from_real(char *r)
{
    if (!C.rootlen || xstrncmp(r, C.root, (size_t)C.rootlen) != 0) return;
    if (r[C.rootlen] == 0) {
        r[0] = '/';
        r[1] = 0;
        return;
    }
    if (r[C.rootlen] != '/') return;
    memmove(r, r + C.rootlen, xstrlen(r + C.rootlen) + 1);
    /* an original seen through /proc reports the wrapper's name: drop a final "/.real" directory */
    char *b = xstrrchr(r, '/');
    if (b && b - r >= 6 && xmemcmp(b - 6, "/.real", 6) == 0) memmove(b - 6, b, xstrlen(b) + 1);
}
int vis_is_identity_file(const char *v)
{
    struct rule *r = rule_exact(v);
    return r && (r->flags & R_HOSTFILE);
}
int vis_readlink_identity(const char *v, char *out)
{
    struct rule *r = rule_exact(v);
    if (!r || !(r->flags & R_HOSTFILE)) return 0;
    /* the host's link as it is now: the kernel's EINVAL for a file, ENOENT for a name the host has removed */
    long n = sys_readlink(C.host[r->host].v, out, PATH_MAX - 1);
    if (n < 0) return (int)n;
    out[n] = 0;
    return 1;
}
