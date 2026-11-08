/* vis.c — the visibility rule (DESIGN.md section 8) and wrapper redirect (7.4.4).
 *
 * Decides, for a virtual path, whether it is the host's or the exclave's, and
 * turns it into a real path. The table is built once at startup from the
 * tree, the manifest, the working directory and the host identity files.
 */
#include "common.h"

static const char *volatile_dirs[] = {"/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run", 0};
/* 8.1.5: the host's by default; an own record naming one exactly removes it. /etc/localtime is the host's zone, a
 * TZif file any libc reads through the host's link into its zoneinfo, and TZ is dropped at the border (6.2). The trust
 * bundles and Java's keystores come in pairs, Debian's path and Red Hat's. */
static const char *identity_files[] = {"/etc/passwd",
                                       "/etc/group",
                                       "/etc/nsswitch.conf",
                                       "/etc/host.conf",
                                       "/etc/resolv.conf",
                                       "/etc/hosts",
                                       "/etc/localtime",
                                       "/etc/ssl/certs/ca-certificates.crt",
                                       "/etc/pki/tls/certs/ca-bundle.crt",
                                       "/etc/ssl/certs/java/cacerts",
                                       "/etc/pki/java/cacerts",
                                       0};
_Static_assert(sizeof identity_files / sizeof identity_files[0] == N_IDENTITY + 1,
               "N_IDENTITY counts the identity files");
/* 8.1.5, 8.4: the identity directories, the host's by default with the links at and below them followed on the host:
 * the two trust directories, where a host keeps its authorities one to a name, and SSSD's state, whose socket and
 * memory cache its lookup module reads (13 item 17); an own record naming one exactly removes it */
static const char *identity_dirs[] = {"/etc/ssl/certs", "/etc/pki/tls/certs", "/var/lib/sss", 0};
_Static_assert(sizeof identity_dirs / sizeof identity_dirs[0] == N_IDENTITY_DIRS + 1,
               "N_IDENTITY_DIRS counts the identity directories");
/* identity files the host lacks, the exclave's copies (8.1.5): where one lies in an identity directory the host has,
 * the rule names it the exclave's (rule_build) */
static const char *absent[N_IDENTITY];
static int nabsent;
/* the real path of each such copy, and of each path an own record makes the exclave's inside an identity directory, its
 * directory as the tree resolves it, where the tool places a copy */
static const char *absent_real[N_IDENTITY + MAX_OWN_RECORDS];
static const char *mapped_v[N_IDENTITY + MAX_OWN_RECORDS]; /* the virtual path each stands for, for from_real */
static int nmapped;

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

/* 8.1.5: the identity files and directories join the host table unless an own record names one; the table has room
 * for them after the manifest's records by construction */
static void host_default(const char *v, int is_dir)
{
    for (int j = 0; j < C.nown; j++)
        if (xstrcmp(C.own[j], v) == 0) return;
    if (C.nhost >= (int)(sizeof C.host / sizeof C.host[0])) die("host table full", v, 0);
    C.host[C.nhost].v = v;
    C.host[C.nhost].r = v;
    C.host[C.nhost].is_file = 0;
    C.host[C.nhost].is_identity_dir = is_dir;
    C.host[C.nhost].is_link = 0;
    C.nhost++;
}
static void identity_defaults(void)
{
    for (int i = 0; i < N_IDENTITY; i++) host_default(identity_files[i], 0);
    for (int i = 0; i < N_IDENTITY_DIRS; i++) host_default(identity_dirs[i], 1);
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
    int nrec = C.nhost; /* the manifest's host records come first */
    identity_defaults();
    own_from_tree();
    /* identity files and directories and host records: resolve each on the host; drop the ones the host lacks */
    int n = 0, nextra = 0;
    const char *extra[N_IDENTITY_DIRS] = {0};
    nabsent = 0;
    for (int i = 0; i < C.nhost; i++) {
        struct kstat st;
        const char *v = C.host[i].v;
        int idir = C.host[i].is_identity_dir, ifile = !idir && i >= nrec;
        if (sys_lstat(v, &st) < 0) {
            log_msg("host path absent, using the exclave's", v);
            if (ifile) absent[nabsent++] = v;
            continue;
        }
        if ((st.st_mode & S_IFMT) == S_IFDIR) {
            C.host[n] = C.host[i];
            C.host[n].is_file = 0;
            n++;
            continue;
        }
        /* an identity directory that is a host link: the name stays an identity directory, passed by name and
         * followed by the kernel at each call, and the directory the host resolves it to, as the kernel names it, is
         * one too at its own name, where a working directory or a descriptor there is named (8.4). One that leads to
         * no directory, or that the kernel names outside this root, is the exclave's. */
        if (idir) {
            static char dir[PATH_MAX];
            long fd = (st.st_mode & S_IFMT) == S_IFLNK ? sys_open(v, O_PATH | O_CLOEXEC | O_DIRECTORY, 0) : -ENOTDIR;
            long len = fd >= 0 ? fd_real_path((int)fd, dir) : -1;
            if (fd >= 0) sys_close((int)fd);
            if (len <= 0 || dir[0] != '/') {
                log_msg("host path unresolvable, using the exclave's", v);
                continue;
            }
            C.host[n] = C.host[i];
            C.host[n].is_file = 0;
            C.host[n].is_link = 1;
            n++;
            /* one at most for each identity directory, by construction */
            if (nextra >= N_IDENTITY_DIRS) die("host table full", dir, 0);
            extra[nextra++] = arena_str(dir, (size_t)len);
            continue;
        }
        /* a file, or a link the host resolves: the host's name is its real path, so that a call follows the host's
         * link as the host has it at that moment, in the host's space (8.4) */
        if ((st.st_mode & S_IFMT) == S_IFLNK && sys_stat(v, &st) < 0) {
            log_msg("host path unresolvable, using the exclave's", v);
            if (ifile) absent[nabsent++] = v;
            continue;
        }
        C.host[n].v = C.host[n].r = v;
        C.host[n].is_file = 1;
        C.host[n].is_identity_dir = 0;
        C.host[n].is_link = 0;
        n++;
    }
    for (int i = 0; i < nextra; i++) {
        /* an own record naming the directory reached removes it, as it removes any default (8.1.5) */
        int owned = 0;
        for (int j = 0; j < C.nown && !owned; j++) owned = xstrcmp(C.own[j], extra[i]) == 0;
        if (owned) continue;
        C.host[n].v = C.host[n].r = extra[i];
        C.host[n].is_file = 0;
        C.host[n].is_identity_dir = 1;
        C.host[n].is_link = 0;
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
/* R_IDDIR: an identity directory the host has (8.4), and R_IDLINK where its host name is a link; R_EXREAL: an exclave
 * path in an identity directory the host has, at absent_real[host], and its subtree (rule_build) */
enum {
    R_OWN = 1,
    R_HOSTDIR = 2,
    R_HOSTFILE = 4,
    R_VOLATILE = 8,
    R_LEADS = 16,
    R_IDDIR = 32,
    R_IDLINK = 64,
    R_EXREAL = 128
};
#define RULE_SLOTS 2048
/* host: the index of a file's record */
static struct rule {
    const char *s;
    unsigned len, flags;
    int host;   /* R_HOSTFILE: the index of the file's record */
    int mapped; /* R_EXREAL: the index of its real path in absent_real */
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
static struct rule *rule_add(const char *v, unsigned len, unsigned flags, int host)
{
    if (len == 1 && v[0] == '/') {
        root_flags |= (int)flags;
        return 0;
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
        r->mapped = -1;
    }
    /* a file named twice: the first record, as the scans found it */
    if ((flags & R_HOSTFILE) && !(r->flags & R_HOSTFILE)) r->host = host;
    r->flags |= flags;
    return r;
}
static const char *tree_real_of(const char *v);
/* an exclave path in an identity directory the host has, at its directory as the tree resolves it (8.4) */
static void rule_map(const char *v)
{
    if (nmapped >= (int)(sizeof absent_real / sizeof absent_real[0])) die("mapping table full", v, 0);
    struct rule *r = rule_add(v, (unsigned)xstrlen(v), R_EXREAL, -1);
    if (!r || r->mapped >= 0) return;
    absent_real[nmapped] = tree_real_of(v);
    mapped_v[nmapped] = v;
    r->mapped = nmapped++;
}
/* the real path in the tree of v, an exclave path in an identity directory the host has: its directory resolved
 * through the tree's links as a chroot would resolve it, a missing component taken as a directory, then its name,
 * which is where the tool places an identity file's copy (tool/layout.go, treeRealDir), so that a Fedora tree's link
 * /etc/ssl/certs -> /etc/pki/tls/certs is followed in the tree and not by the kernel on the host. A component that is
 * a file, a loop, a link that cannot be read or a path too long has no place, as the tool places nothing there: the
 * path then fails, as one under the launcher, a file, does (ENOTDIR). Startup only. */
static const char *tree_real_of(const char *v)
{
    static char cur[PATH_MAX], rest[2 * PATH_MAX], next[2 * PATH_MAX], text[PATH_MAX], real[PATH_MAX];
    const char *base = xstrrchr(v, '/');
    size_t dl = (size_t)(base - v);
    xmemcpy(rest, v, dl);
    rest[dl] = 0;
    cur[0] = 0;
    int hops = 0, placed = 1;
    for (char *rp = rest;;) {
        while (*rp == '/') rp++;
        if (!*rp) break;
        char *e = rp;
        while (*e && *e != '/') e++;
        size_t cl = (size_t)(e - rp), curl = xstrlen(cur);
        if (cl == 1 && rp[0] == '.') {
            rp = e;
            continue;
        }
        if (cl == 2 && rp[0] == '.' && rp[1] == '.') {
            char *s = xstrrchr(cur, '/');
            if (s) *s = 0;
            rp = e;
            continue;
        }
        if (curl + 1 + cl + 1 >= PATH_MAX) {
            placed = 0;
            break;
        }
        cur[curl] = '/';
        xmemcpy(cur + curl + 1, rp, cl);
        cur[curl + 1 + cl] = 0;
        rp = e;
        scpy(real, C.root, PATH_MAX);
        scat(real, cur, PATH_MAX);
        struct kstat st;
        if (sys_lstat(real, &st) < 0 || (st.st_mode & S_IFMT) == S_IFDIR) continue;
        if ((st.st_mode & S_IFMT) != S_IFLNK) {
            placed = 0;
            break;
        }
        long n = sys_readlink(real, text, PATH_MAX - 1);
        if (n <= 0 || ++hops > 40 || (size_t)n + 1 + xstrlen(rp) + 1 >= sizeof next) {
            placed = 0;
            break;
        }
        text[n] = 0;
        cur[curl] = 0;
        if (text[0] == '/') cur[0] = 0;
        scpy(next, text, sizeof next);
        scat(next, "/", sizeof next);
        scat(next, rp, sizeof next);
        scpy(rest, next, sizeof rest);
        rp = rest;
    }
    scpy(real, C.root, PATH_MAX);
    scat(real, cur, PATH_MAX);
    if (placed && xstrlen(real) + xstrlen(base) < PATH_MAX) {
        scat(real, base, PATH_MAX);
        return arena_str(real, xstrlen(real));
    }
    scpy(real, C.launcher, PATH_MAX);
    scat(real, "/unplaced", PATH_MAX);
    return arena_str(real, xstrlen(real));
}

static void rule_build(void)
{
    dir_len = (unsigned)xstrlen(C.dir);
    unsigned most = (unsigned)C.nown + (unsigned)nabsent + (unsigned)(sizeof volatile_dirs / sizeof volatile_dirs[0]);
    for (int i = 0; i < C.nhost; i++)
        for (const char *p = C.host[i].v; *p; p++) most += *p == '/';
    /* the directories on the way to an absent identity file, which the walk takes as directories */
    for (int i = 0; i < nabsent; i++)
        for (const char *p = absent[i]; *p; p++) most += *p == '/';
    while (rule_mask + 1 > 64 && rule_mask / 2 + 1 >= 2 * most) rule_mask /= 2;
    for (int i = 0; i < C.nown; i++) rule_add(C.own[i], (unsigned)xstrlen(C.own[i]), R_OWN, -1);
    for (int i = 0; volatile_dirs[i]; i++)
        rule_add(volatile_dirs[i], (unsigned)xstrlen(volatile_dirs[i]), R_VOLATILE, -1);
    for (int i = 0; i < C.nhost; i++) {
        const char *v = C.host[i].v;
        unsigned len = (unsigned)xstrlen(v);
        if (!C.host[i].is_file) {
            rule_add(v, len, R_HOSTDIR, -1);
            /* an identity directory's way is made of directories, as an identity file's is (8.1.5) */
            if (C.host[i].is_identity_dir) {
                rule_add(v, len, R_IDDIR | (C.host[i].is_link ? R_IDLINK : 0), -1);
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
    /* 8.1.5: an identity file the host lacks, in an identity directory the host has, is the exclave's copy; the walk
     * asks the rule of every name below the directory before the host's entry (8.4), and the directories between are
     * directories to it, as the way to any identity file is, so that it reaches the copy where the host lacks them */
    for (int i = 0; i < nabsent; i++)
        for (int j = 0; j < C.nhost; j++) {
            const char *d = C.host[j].v;
            if (!C.host[j].is_identity_dir || !starts_dir(absent[i], d) || !xstrcmp(absent[i], d)) continue;
            unsigned len = (unsigned)xstrlen(absent[i]);
            rule_add(absent[i], len, R_OWN, -1);
            rule_map(absent[i]);
            for (unsigned k = (unsigned)xstrlen(d) + 1; k < len; k++)
                if (absent[i][k] == '/') rule_add(absent[i], k, R_LEADS, -1);
            break;
        }
    /* an own record inside an identity directory the host has: the walk reached it through the host's directory, so
     * the tree's links on the way to it are followed in the tree, as for an identity file's copy */
    for (int i = 0; i < C.nown; i++)
        for (int j = 0; j < C.nhost; j++) {
            const char *d = C.host[j].v;
            if (!C.host[j].is_identity_dir || !starts_dir(C.own[i], d) || !xstrcmp(C.own[i], d)) continue;
            rule_map(C.own[i]);
            break;
        }
}

/* what the rule's strings say of v: the identity file it is, the longest host record and owned path that are prefixes
 * of it, whether a volatile directory is */
struct facts {
    struct rule *exact;
    long best_host, best_own;
    long iddir; /* the longest identity directory that is a prefix, or -1 */
    int vol;
    unsigned len;
};
static void rule_facts(const char *v, struct facts *f)
{
    f->exact = 0;
    f->best_host = f->best_own = f->iddir = -1;
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
                if (r->flags & R_IDDIR) f->iddir = i;
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
    f.best_host = f.best_own = f.iddir = -1;
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
                if (r && (r->flags & (R_HOSTFILE | R_LEADS | R_IDDIR))) return 0;
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
/* the walk's questions of a candidate in one pass (7.4.4): whether it is an identity file, whether it is a directory on
 * the way to one, whether it is an identity directory or the host's below one, and whose it is; 1 if the host's, *real
 * its real path. *idd is 1 at an identity directory the host has as a directory, 2 at one whose host name is a link, 3
 * below either where the rule gives the name to the host, and 0 otherwise (8.4) */
int vis_walk_facts(const char *v, int *identity, int *leads, int *idd, const char **real)
{
    struct facts f;
    rule_facts(v, &f);
    *identity = f.exact && (f.exact->flags & R_HOSTFILE);
    *leads = leads_facts(v, &f);
    int host = is_host_facts(v, &f, real);
    *idd = 0;
    if (host && f.exact && (f.exact->flags & R_IDDIR)) *idd = (f.exact->flags & R_IDLINK) ? 2 : 1;
    else if (host && f.iddir > 0 && f.iddir < (long)f.len && f.iddir >= f.best_own) *idd = 3;
    return host;
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
    return vis_exclave_real(v, out);
}
/* an exclave path's real path: under the tree's root, or an identity file's copy where the tree places it (8.1.5) */
char *vis_exclave_real(const char *v, char *out)
{
    if (nmapped) {
        /* the longest mapped prefix, at v's '/' boundaries, as rule_facts finds prefixes */
        struct rule *best = 0;
        unsigned at = 0;
        unsigned long h = RULE_BASIS;
        for (unsigned i = 0;; i++) {
            char c = v[i];
            if (i > 0 && (c == '/' || c == 0)) {
                struct rule *r = rule_find(v, i, h);
                if (r && (r->flags & R_EXREAL)) {
                    best = r;
                    at = i;
                }
            }
            if (!c) break;
            h = rule_hash(h, c);
        }
        if (best) {
            scpy(out, absent_real[best->mapped], PATH_MAX);
            scat(out, v + at, PATH_MAX);
            return out;
        }
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
    /* a mapped path, by the tree's name for it, is the virtual path it stands for (8.4) */
    int best = -1;
    size_t bl = 0;
    for (int k = 0; k < nmapped; k++) {
        size_t l = xstrlen(absent_real[k]);
        if (l > bl && starts_dir(r, absent_real[k])) {
            best = k;
            bl = l;
        }
    }
    if (best >= 0) {
        size_t vl = xstrlen(mapped_v[best]), rl = xstrlen(r + bl);
        if (vl + rl + 1 <= PATH_MAX) {
            memmove(r + vl, r + bl, rl + 1);
            xmemcpy(r, mapped_v[best], vl);
            return;
        }
    }
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
int vis_identity_dir_kind(const char *v)
{
    struct rule *r = rule_exact(v);
    if (!r || !(r->flags & R_IDDIR)) return 0;
    return (r->flags & R_IDLINK) ? 2 : 1;
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
