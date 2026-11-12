/* canon.c — canonicalisation in virtual space (DESIGN.md 7.4.4).
 *
 * Resolves a path the way the kernel would inside a bind-mounted root:
 * component by component, following symlinks whose targets are virtual
 * paths whoever created them, with the visibility rule deciding where each
 * candidate lives. Descriptor-addressed paths never reach the walk.
 */
#include "common.h"

static int in_tree(const char *r)
{ return C.rootlen && xstrncmp(r, C.root, (size_t)C.rootlen) == 0 && (r[C.rootlen] == '/' || r[C.rootlen] == 0); }
/* Whether text, the real path a descriptor's or a procfs magic link's target is given by, leads to obj, the object
 * behind the link. The kernel marks an unlinked file's path " (deleted)", but a file can be named so too: only a name
 * that leads to the object itself is its path. */
__attribute__((noinline)) static int names_object(const char *text, const struct kstat *obj)
{
    struct kstat st;
    return sys_lstat(text, &st) == 0 && st.st_dev == obj->st_dev && st.st_ino == obj->st_ino;
}
/* Whether a magic link below /proc/<pid>/, at real path link with target text of length n, leads to an object with no
 * path: a pipe, a socket or an anonymous inode, whose text is not a path at all, or an unlinked file. Both functions
 * stay out of line, so that their stat buffers are not part of canon's frame (test/stackcheck.py). */
__attribute__((noinline)) static int pathless(const char *link, const char *text, long n)
{
    if (text[0] != '/') return 1;
    if (n <= 10 || xstrcmp(text + n - 10, " (deleted)") != 0) return 0;
    struct kstat obj;
    return sys_stat(link, &obj) < 0 || !names_object(text, &obj);
}
/* the virtual path of a descriptor or of the working directory; *tree, when asked, says whether the kernel's real path
 * lay in the tree. -ENOENT: the descriptor's file has no path, and the caller passes the syscall through */
/* The real path the kernel gives descriptor fd, its /proc/self/fd link's text, into out[PATH_MAX]: its length, or
 * -errno (ENOENT for no such descriptor). */
long fd_real_path(int fd, char *out)
{
    char link[32] = "/proc/self/fd/", n[24];
    ltoa_(fd, n);
    scat(link, n, sizeof link);
    long r = sys_readlink(link, out, PATH_MAX - 1);
    if (r >= 0) out[r] = 0;
    return r;
}

static int fd_virtual_in(int fd, char *out, int *tree)
{
    /* no such link: no such descriptor */
    long r = fd_real_path(fd, out);
    if (r < 0) return r == -ENOENT ? -EBADF : (int)r;
    if (r > 10 && xstrcmp(out + r - 10, " (deleted)") == 0) {
        struct kstat obj;
        if (SC2(NR_fstat, fd, &obj) < 0 || !names_object(out, &obj)) return -ENOENT;
    }
    if (tree) *tree = in_tree(out);
    return from_real(out);
}
static int cwd_virtual_in(char *out, int *tree)
{
    long r = sys_getcwd(out, PATH_MAX);
    if (r < 0) return (int)r;
    if (tree) *tree = in_tree(out);
    return from_real(out);
}
int fd_virtual(int fd, char *out) { return fd_virtual_in(fd, out, 0); }
int cwd_virtual(char *out) { return cwd_virtual_in(out, 0); }

/* the process whose exe link p is, in any spelling: self, thread-self, <pid>, <pid>/task/<tid>, as mypid for the
 * first two; 0 for a path that is no exe link. The walk has already resolved the self link into a pid, so the
 * numeric forms are the ones that occur there */
static long exe_link_pid(const char *p, pid_t mypid)
{
    if (xstrncmp(p, "/proc/", 6) != 0) return 0;
    p += 6;
    if (xstrcmp(p, "self/exe") == 0 || xstrcmp(p, "thread-self/exe") == 0) return mypid;
    long pid = 0;
    while (*p >= '0' && *p <= '9') pid = pid * 10 + (*p++ - '0');
    if (!pid) return 0;
    if (xstrcmp(p, "/exe") == 0) return pid;
    if (xstrncmp(p, "/task/", 6) != 0) return 0;
    p += 6;
    while (*p >= '0' && *p <= '9') p++;
    return xstrcmp(p, "/exe") == 0 ? pid : 0;
}
int is_self_exe(const char *p, pid_t mypid) { return exe_link_pid(p, mypid) == mypid; }

/* EXCLAVE_EXEC of another process, from the kernel's copy of its environment (13 item 46), which /proc/<pid>/environ
 * reads for a process of this user: 1 with the program's virtual path in out (PATH_MAX), 0 for a process without
 * it or one this process may not read. The file is read through out itself, a variable at a time; one longer than
 * the buffer, which EXCLAVE_EXEC never is, is skipped. */
static int exec_of_pid(long pid, char *out)
{
    scpy(out, "/proc/", PATH_MAX);
    ltoa_(pid, out + 6);
    scat(out, "/environ", PATH_MAX);
    long fd = sys_open(out, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return 0;
    size_t have = 0;
    int found = 0, skipping = 0;
    for (;;) {
        long n = sys_read((int)fd, out + have, PATH_MAX - 1 - have);
        if (n <= 0) break;
        have += (size_t)n;
        size_t start = 0;
        for (size_t i = 0; i < have && !found; i++) {
            if (out[i]) continue;
            if (skipping) skipping = 0;
            else if (i - start > 13 && xmemcmp(out + start, "EXCLAVE_EXEC=", 13) == 0 && out[start + 13] == '/') {
                for (size_t k = 0; k <= i - start - 13; k++) out[k] = out[start + 13 + k];
                found = 1;
            }
            start = i + 1;
        }
        if (found) break;
        if (start == 0 && have == PATH_MAX - 1) {
            skipping = 1; /* a variable longer than the buffer: dropped up to its end */
            have = 0;
            continue;
        }
        for (size_t k = start; k < have; k++) out[k - start] = out[k];
        have -= start;
    }
    sys_close((int)fd);
    return found;
}

/* Whether this process traces another, pid: the TracerPid line of /proc/<pid>/status names the tracing thread, the
 * caller, its process or one of its threads; not for a file this process may not read */
static int traced_by(long pid, const struct scratch *S)
{
    char buf[256];
    scpy(buf, "/proc/", sizeof buf);
    ltoa_(pid, buf + 6);
    scat(buf, "/status", sizeof buf);
    long t = tracer_of(buf);
    if (!t) return 0;
    if (t == S->tid || t == S->pid) return 1;
    scpy(buf, "/proc/self/task/", sizeof buf);
    ltoa_(t, buf + 16);
    return sys_faccessat(AT_FDCWD, buf, 0) == 0; /* F_OK */
}

/* The TracerPid of the status file at path, /proc/<pid>/status: 0 for none or a file this process may not read. The
 * kernel writes the line eighth, after a name of at most 64 bytes escaped and six short lines, so the file's first 256
 * bytes hold it. */
long tracer_of(const char *path)
{
    char buf[256];
    long fd = sys_open(path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return 0;
    long have = 0, n;
    while (have < (long)sizeof buf && (n = sys_read((int)fd, buf + have, sizeof buf - (size_t)have)) > 0) have += n;
    sys_close((int)fd);
    return status_tracer(buf, have);
}

/* Another process's exe link whose text names the launcher: that process runs a program on the loader path, the one
 * its EXCLAVE_EXEC names (7.4.5), which the kernel would name natively (7.6, 13 item 10). 1 with text replaced by
 * the program's virtual path; 0 leaves text as it is. -1 for the link of a process the caller traces, whose text is
 * the kernel's own, a wrapper's answered as the launcher it is: a debugger learns what it debugs from the link, the
 * launcher and the script it carries (7.6). */
int other_exe(const struct scratch *S, const char *v, char *text)
{
    long pid = exe_link_pid(v, S->pid);
    if (!pid || pid == S->pid) return 0;
    if (traced_by(pid, S)) {
        /* a wrapper is the launcher under the program's name: the launcher's own path, since an open of the wrapper's
         * reaches its original (7.4.4) */
        if (starts_dir(text, C.root)) scpy(text, C.launcher, PATH_MAX);
        return -1;
    }
    return xstrcmp(text, C.launcher) == 0 && exec_of_pid(pid, text);
}

/* ---------- the one-step host check (DESIGN.md 16.6 item 4) ----------
 * A walk through host directories lstats each, to follow a host symlink in virtual space (a link into /usr reaches the
 * exclave's) and to see the tree's root by another name. Where the remaining directories are all plain host by the
 * rule, one openat2 with RESOLVE_NO_SYMLINKS answers the first question for all of them: it succeeds only if each is a
 * directory reached without a link. The second needs no question where the tree's filesystem is mounted once and its
 * device is the tree's own: within one mount a directory has one path, and the rule has already refused the tree's own
 * name. Anything else, a link, a missing directory, a refusal, a second mount, a kernel without openat2, is the walk's.
 * The last component is always the walk's, so that the walk finds its kind, its link and its error. */
/* the tree's filesystem mounted once with its device: 0 not yet known, 1 yes, -1 no or unknowable */
static int tree_once;
static int no_openat2;                                       /* the kernel predates openat2 (5.6) */

/* the decoded mount point at f (mountinfo escapes a space, a tab, a newline and a backslash as \ooo) as a '/'-boundary
 * prefix of the tree's real path: its length, or -1 */
static long mount_prefix(const char *f, const char *fe)
{
    long k = 0;
    while (f < fe) {
        char c = *f++;
        if (c == '\\' && fe - f >= 3) {
            c = (char)(((f[0] - '0') << 6) | ((f[1] - '0') << 3) | (f[2] - '0'));
            f += 3;
        }
        if (C.root[k] != c) return -1;
        k++;
    }
    if (k == 1 && C.root[0] == '/') return 1;                 /* the root mount */
    return C.root[k] == '/' || C.root[k] == 0 ? k : -1;
}
/* one pass over /proc/self/mountinfo in buf (PATH_MAX): pass 0 finds the mount holding the tree, the
 * longest mount point that is a prefix of its path, the last of equals since a later mount covers an
 * earlier; pass 1 counts the mounts of that device. 1 when answered; 0 when no descriptor was free, to be
 * asked again; -1 when it cannot be answered here: no /proc, an unreadable file, a line longer than the
 * buffer, no mount holding the tree, as in a chroot */
static long mounts(char *buf, int pass, unsigned long *dev, long *count)
{
    long fd = sys_open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC, 0);
    if (fd == -EMFILE || fd == -ENFILE) return 0;
    if (fd < 0) return -1;
    long have = 0, best = -1, ok = 1;
    for (;;) {
        long n = sys_read((int)fd, buf + have, PATH_MAX - 1 - (size_t)have);
        if (n < 0) {
            ok = 0;
            break;
        }
        have += n;
        buf[have] = 0;
        char *l = buf, *nl;
        while ((nl = xstrchr(l, '\n'))) {
            /* id parent major:minor root mountpoint ... */
            char *f[5];
            int nf = 0;
            char *q = l;
            while (nf < 5 && q < nl) {
                while (q < nl && *q == ' ') q++;
                f[nf++] = q;
                while (q < nl && *q != ' ') q++;
            }
            if (nf == 5) {
                unsigned long ma = 0, mi = 0;
                char *d = f[2];
                while (*d >= '0' && *d <= '9') ma = ma * 10 + (unsigned long)(*d++ - '0');
                if (*d == ':') d++;
                while (*d >= '0' && *d <= '9') mi = mi * 10 + (unsigned long)(*d++ - '0');
                unsigned long md = ma << 32 | mi;
                if (pass == 0) {
                    char *e = f[4];
                    while (e < nl && *e != ' ') e++;
                    long k = mount_prefix(f[4], e);
                    if (k >= best && k > 0) {
                        best = k;
                        *dev = md;
                    }
                } else if (md == *dev) (*count)++;
            }
            l = nl + 1;
        }
        have -= l - buf;
        memmove(buf, l, (size_t)have + 1);
        if (n == 0) break;
        /* a line longer than the buffer */
        if (have >= PATH_MAX - 1) {
            ok = 0;
            break;
        }
    }
    sys_close((int)fd);
    return ok && (pass == 1 || best > 0) ? 1 : -1;
}
static int tree_mounted_once(char *buf)
{
    unsigned long dev = 0;
    long count = 0;
    /* no descriptor: asked again at the next walk; else decided */
    long r = mounts(buf, 0, &dev, &count);
    if (r <= 0) return (int)r;
    r = mounts(buf, 1, &dev, &count);
    if (r <= 0) return (int)r;
    unsigned long sd = C.root_dev;                            /* the stat encoding: glibc's major and minor */
    unsigned long ma = ((sd >> 8) & 0xfff) | ((sd >> 32) & ~0xfffUL), mi = (sd & 0xff) | ((sd >> 12) & ~0xffUL);
    /* a btrfs subvolume's device is not its mount's: the walk's */
    return count == 1 && dev == (ma << 32 | mi) ? 1 : -1;
}
/* at the plain host directory cur, not the last component, with the rest of the path at *rpp: try to stand in for the
 * walk through every directory before the final component. 1 if it did, cur then the last of them and *rpp the final;
 * 0 if the chain does not qualify; -1 if the openat2 was made and could not vouch for it, which the walk remembers
 * until it restarts at a link, so that a failing chain is not tried again at every component */
static int host_chain(struct scratch *S, char *cur, char **rpp)
{
    if (no_openat2 || tree_once < 0) return 0;
    /* magic links, the process's own exe: the walk's */
    if (xstrncmp(cur, "/proc", 5) == 0 && (cur[5] == '/' || !cur[5])) return 0;
    char *p = S->real, *q = *rpp;
    size_t n = xstrlen(cur);
    int dirs = 1;
    xmemcpy(p, cur, n);
    for (;;) {
        while (*q == '/') q++;
        char *e = q;
        while (*e && *e != '/') e++;
        char *after = e;
        while (*after == '/') after++;
        if (!*after) break;                                    /* q is the final component */
        size_t cl = (size_t)(e - q);
        if (cl > NAME_MAX || n + 1 + cl + 1 >= PATH_MAX) return 0;   /* the walk's ENAMETOOLONG */
        /* "." and "..": the walk's, by the rule */
        if (q[0] == '.' && (cl == 1 || (cl == 2 && q[1] == '.'))) return 0;
        p[n++] = '/';
        xmemcpy(p + n, q, cl);
        n += cl;
        dirs++;
        q = after;
    }
    p[n] = 0;
    if (dirs < 3) return 0;                                   /* an openat2 and a close for fewer lstats than that */
    if (!vis_plain_host_chain(p, (unsigned)xstrlen(cur))) return 0;
    if (!tree_once) tree_once = tree_mounted_once(S->tmp);
    if (tree_once <= 0) return 0;
    unsigned long how[3] = {O_PATH | O_DIRECTORY | O_CLOEXEC, 0, RESOLVE_NO_SYMLINKS};
    long fd = SC4(NR_openat2, AT_FDCWD, p, how, sizeof how);
    /* a kernel before 5.6 */
    if (fd == -ENOSYS || fd == -E2BIG || fd == -EINVAL) {
        no_openat2 = 1;
        return 0;
    }
    if (fd < 0) return -1;
    /* the kernel's name for what it reached must be the path itself: on a case-insensitive filesystem x.exclave/TREE is
     * the tree's root under another spelling on the same mount, and the tree's root, pinned by the program's own
     * mappings, keeps its own name; any other difference, an alias nobody foresaw, is the walk's too */
    long k = fd_real_path((int)fd, S->tmp);
    sys_close((int)fd);
    if (k != (long)n || xmemcmp(S->tmp, p, n) != 0) return -1;
    scpy(cur, p, PATH_MAX);
    *rpp = q;
    return 1;
}

/* a relative walk's starting directory, as the kernel names it (DESIGN.md 16.6 item 5): the kernel starts a relative
 * lookup at the directory itself and never walks its ancestors again, and getcwd and /proc/self/fd/N name it without a
 * link, so the walk may start there resolved. Not where the name could mislead: a tree directory known by a host name,
 * a host name the rule does not plainly give the host, procfs, or a host directory on a filesystem that could hold the
 * tree's root under another name (the one-step check's condition) */
static int start_resolved(struct scratch *S, const char *v, int owned, int tree)
{
    if (xstrncmp(v, "/proc", 5) == 0 && (v[5] == '/' || !v[5])) return 0;
    if (owned || tree) return owned && tree;
    if (!vis_plain_host_chain(v, 2)) return 0;
    if (!tree_once) tree_once = tree_mounted_once(S->tmp);
    return tree_once > 0;
}

/* path relative to dfd spelt through the descriptor's magic link, /proc/self/fd/N/path or /proc/self/cwd/path: a host
 * path the kernel resolves itself from the directory, whatever its name is by then (7.4.3) */
int through_magic(struct scratch *S, const char *path, int dfd, char *out)
{
    char *n = S->comp;
    if (dfd != AT_FDCWD) ltoa_(dfd, n);
    scpy(out, dfd == AT_FDCWD ? "/proc/self/cwd" : "/proc/self/fd/", PATH_MAX);
    if (dfd != AT_FDCWD) scat(out, n, PATH_MAX);
    if (xstrlen(out) + 1 + xstrlen(path) >= PATH_MAX) return -ENAMETOOLONG;
    scat(out, "/", PATH_MAX);
    scat(out, path, PATH_MAX);
    return 0;
}

/* a walk's state from one component to the next (canon) */
struct walk {
    char *rp;           /* the rest of the path, in S->rest */
    const char *base;   /* a scoped walk's root, S->v2; "" otherwise */
    unsigned rf;        /* openat2's resolve flags (7.4.3) */
    int magic_err;      /* the answer at a magic link the flags refuse (nd_jump_link), or 0 */
    int dom;            /* RESOLVE_NO_XDEV: the domain the walk is in, the exclave's (1) or the host's (0) */
    int hops;           /* links followed, at most 40 */
    int chain_failed;   /* a one-step host check that could not vouch: not tried again until a link */
    /* the length of the starting directory a relative walk walks again from the root, whose own components cross
     * no mount for RESOLVE_NO_XDEV, since the kernel starts in that directory */
    size_t start_len;
};

/* where the walk starts: S->cur the directory, S->rest the path from there, 0; 1 when out holds the answer already, a
 * path spelt through a magic link; or -errno */
static int walk_start(struct scratch *S, struct walk *w, const char *path, int dfd, char *out)
{
    char *rest = S->rest, *cur = S->cur;
    if (path[0] == '/') {
        if (w->rf & RESOLVE_BENEATH) return -EXDEV; /* nd_jump_root: an absolute path leaves the scope */
        S->touched_exclave = 1;                      /* the root is the tree's */
        scpy(rest, path, sizeof S->rest);
        scpy(cur, w->base, PATH_MAX);
        /* whose a name is can fail, here and below: the read of a top-level directory of the tree that the name
         * reaches first (8.1.1), whose error is then the walk's */
        if (w->base[0] && (w->dom = vis_owned(w->base)) < 0) return w->dom;
        /* a path spelt through the tree's real root, as a program that finds its files from its argv[0] spells them:
         * the walk would lstat every directory above the tree and then see the tree's root by name, and the
         * launcher resolved that name from /proc/self/exe, so the path starts at the root (DESIGN.md 16.6 item 7) */
        if (!w->rf && C.rootlen && xstrncmp(path, C.root, (size_t)C.rootlen) == 0 &&
            (path[C.rootlen] == '/' || !path[C.rootlen])) {
            /* the walk's own answer for the directories above the tree, which the kernel searches: EACCES where one is
             * not searchable, ENOENT where the exclave was moved while it runs; one question for six lstats */
            long e = sys_faccessat(AT_FDCWD, C.dir, X_OK);
            if (e < 0) return (int)e;
            scpy(rest, path + C.rootlen, sizeof S->rest);
        }
        return 0;
    }
    int tree = 0, r = (dfd == AT_FDCWD) ? cwd_virtual_in(rest, &tree) : fd_virtual_in(dfd, rest, &tree);
    /* a directory deleted under the program, which the kernel still walks from and the handler cannot name: the path
     * is spelt through the magic link, a host path the kernel resolves itself; a walk from there into the exclave
     * stays the host's (7.4.3) */
    if (r == -ENOENT) {
        r = through_magic(S, path, dfd, out);
        return r < 0 ? r : 1;
    }
    if (r < 0) return r;
    int owned = rest[1] ? vis_owned(rest) : 1;
    if (owned < 0) return owned;
    if (w->rf & RESOLVE_NO_XDEV) w->dom = owned;
    if (owned) S->touched_exclave = 1; /* the directory the walk starts from */
    if (!w->rf && rest[1] && start_resolved(S, rest, owned, tree)) {
        /* the walk starts in the directory, resolved */
        scpy(cur, rest, PATH_MAX);
        scpy(rest, path, sizeof S->rest);
    } else {
        /* a directory and a path, each under PATH_MAX, fit rest together */
        w->start_len = xstrlen(rest);
        scat(rest, "/", sizeof S->rest);
        scat(rest, path, sizeof S->rest);
        cur[0] = 0;
    }
    return 0;
}

/* a walk that openat2's flags scope or that refuses links or mounts follows the links at and below an identity
 * directory itself, as the kernel would on a bind mount of the host's directory: BENEATH whatever its scope, since
 * nd_jump_root and follow_dotdot refuse at the root too, and IN_ROOT at a scope below the root (8.4) */
static int scoped_walk(const struct walk *w)
{
    return (w->rf & (RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV | RESOLVE_BENEATH)) ||
           ((w->rf & RESOLVE_IN_ROOT) && w->base[0]);
}

/* a ".." component: S->cur its parent, 0; or EXDEV where the resolve flags refuse the step */
static int walk_dotdot(struct scratch *S, struct walk *w)
{
    char *cur = S->cur;
    /* at an identity directory whose host name is a link, which the walk passed by name: the kernel climbs from the
     * directory the link reaches, so the walk does, by the kernel's name for it (8.4). The link's own answers as the
     * kernel walks through it, ENOENT, ENOTDIR, ELOOP and EACCES, are the walk's; an error of the open's or the
     * read-back's own is no lookup's, and the walk climbs from the directory the kernel named at startup */
    if (!scoped_walk(w) && vis_identity_dir_kind(cur) == 2) {
        long fd = sys_open(cur, O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
        if (fd == -ENOENT || fd == -ENOTDIR || fd == -ELOOP || fd == -EACCES) return (int)fd;
        long n = fd >= 0 ? fd_real_path((int)fd, S->tmp) : -1;
        if (fd >= 0) sys_close((int)fd);
        if (n <= 0 || S->tmp[0] != '/') {
            const char *at = vis_identity_link_reached(cur);
            if (!at) return -ENOENT; /* recorded for every such directory, by construction */
            scpy(S->tmp, at, PATH_MAX);
        }
        if (++w->hops > 40) return -ELOOP;
        /* the tree's directory, reached by its real name, is its virtual path */
        if (from_real(S->tmp) < 0) return -ENAMETOOLONG;
        scpy(cur, S->tmp[1] ? S->tmp : "", PATH_MAX);
        S->touched_exclave = 1;
    }
    /* at the scope's root: stays there in root, leaves it beneath */
    if (w->base[0] ? xstrcmp(cur, w->base) == 0 : cur[0] == 0) {
        if (w->rf & RESOLVE_BENEATH) return -EXDEV;
        if (w->rf & RESOLVE_IN_ROOT) return 0;
    }
    char *s = xstrrchr(cur, '/');
    if (s) *s = 0;
    else cur[0] = 0;
    w->start_len = 0; /* past the starting directory, which the kernel names without a .. */
    /* the tree's root or an exclave directory, reached from below, from an identity directory say (8.4): the walk is
     * the handler's, not the kernel's own */
    int d = cur[0] ? vis_owned(cur) : 1;
    if (d < 0) return d;
    if (d) S->touched_exclave = 1;
    if (w->rf & RESOLVE_NO_XDEV) { /* follow_dotdot: leaving a mount upward is a crossing */
        if (d != w->dom) return -EXDEV;
        w->dom = d;
    }
    return 0;
}

/* text and a slash put before the rest of the path, which the walk goes on with: 0, or ENAMETOOLONG */
static int walk_splice(struct scratch *S, struct walk *w, const char *text)
{
    char *rest = S->rest;
    size_t tl = xstrlen(text), rl = xstrlen(w->rp);
    if (tl + 1 + rl + 1 >= sizeof S->rest) return -ENAMETOOLONG;
    memmove(rest + tl + 1, w->rp, rl + 1);
    xmemcpy(rest, text, tl);
    rest[tl] = '/';
    w->rp = rest;
    return 0;
}

/* the walk goes on from S->cur as it stands: the one-step host check stood in for the directories before the final
 * component, or the component was the tree's root by another name, and the walk is at / */
enum { CK_ONWARD = CK_WRAPPER + 1 };

/* a host component, its real path in S->real, by its lstat: its kind; its error in *err for CK_NONE; the link's text in
 * S->tmp for CK_LINK; CK_ONWARD, at /, for the tree's root reached by another name; or -errno */
static int host_component(struct scratch *S, struct walk *w, int last, int *err)
{
    char *cur = S->cur, *real = S->real, *tmp = S->tmp;
    struct kstat st;
    long r = sys_lstat(real, &st);
    if (r < 0) {
        *err = (int)r;
        return CK_NONE;
    }
    if ((st.st_mode & S_IFMT) == S_IFDIR) {
        /* any spelling of the tree's root directory, through a bind mount or another link, is / */
        if (C.root_ino && st.st_dev == C.root_dev && st.st_ino == C.root_ino) {
            cur[0] = 0;
            S->touched_exclave = 1;
            return CK_ONWARD;
        }
        return CK_DIR;
    }
    if ((st.st_mode & S_IFMT) != S_IFLNK) return CK_FILE;
    /* a link the walk must follow and cannot read: its own error, EACCES for another process's magic link (get_link);
     * the last component is followed here too */
    long n = sys_readlink(real, tmp, PATH_MAX - 1);
    if (n < 0) return (int)n;
    tmp[n] = 0;
    /* a link below /proc/<pid>/ is a magic link; one at /proc/ is not */
    int magic = xstrncmp(cur, "/proc/", 6) == 0 && xstrchr(cur + 6, '/');
    if (magic && w->magic_err) return w->magic_err;
    if (magic && pathless(real, tmp, n)) {
        /* reachable only through the link itself: the walk ends here, and the re-issue follows it */
        if (!last) return -ENOTDIR;
        S->follow_end = 1;
        return CK_FILE;
    }
    /* procfs links report real paths */
    if (xstrncmp(cur, "/proc/", 6) == 0 && from_real(tmp) < 0) return -ENAMETOOLONG;
    return CK_LINK;
}

/* a name at or below an identity directory, its host name in S->real, in a walk the kernel's links may be handed to
 * (8.4): its kind by its lstat, its error in *err for CK_NONE. A link that is the last component is the kernel's to
 * follow on the host, at the call; one with components after it is opened on the host, and the walk goes on from the
 * directory it reaches, by the kernel's name for it, where the rule gives that name to the host or it is the tree's,
 * and otherwise passes the link by name, the kernel following it at each call. CK_ONWARD where the walk goes on from
 * S->cur as it stands, or -errno */
static int identity_component(struct scratch *S, struct walk *w, int last, int *err)
{
    char *cur = S->cur, *real = S->real, *tmp = S->tmp;
    struct kstat st;
    long r = sys_lstat(real, &st);
    if (r < 0) {
        *err = (int)r;
        return CK_NONE;
    }
    if ((st.st_mode & S_IFMT) == S_IFDIR) return CK_DIR;
    if ((st.st_mode & S_IFMT) != S_IFLNK) return CK_FILE;
    if (last) {
        S->follow_end = 2;
        return CK_FILE;
    }
    long fd = sys_open(real, O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
    /* the link's own answer as the kernel walks through it; an error of the open's own, EMFILE say, is no lookup's,
     * so the link is passed by its name and the re-issue answers */
    if (fd == -ENOENT || fd == -ENOTDIR || fd == -ELOOP || fd == -EACCES) return (int)fd;
    if (fd < 0) return CK_DIR;
    long n = fd_real_path((int)fd, tmp);
    sys_close((int)fd);
    if (++w->hops > 40) return -ELOOP;
    const char *hreal;
    if (n > 0 && tmp[0] == '/' && (starts_dir(tmp, C.root) || vis_is_host(tmp, &hreal))) {
        /* the tree's directory, reached by its real name, is its virtual path */
        if (from_real(tmp) < 0) return -ENAMETOOLONG;
        scpy(cur, tmp[1] ? tmp : "", PATH_MAX);
        w->chain_failed = 0;
        return CK_ONWARD;
    }
    return CK_DIR;
}

/* the component at the end of S->cur, by the rule and then by the cache or an lstat: its kind as host_component
 * answers, CK_ONWARD where the walk goes on from S->cur as it stands, or -errno */
static int walk_classify(struct scratch *S, struct walk *w, int last, int *err)
{
    char *cur = S->cur, *real = S->real, *tmp = S->tmp;
    int idf, leads, idd, chain = 0;
    const char *hreal;
    /* the rule asked once for the candidate (DESIGN.md 16.6 item 3) */
    int host = vis_walk_facts(cur, &idf, &leads, &idd, &hreal);
    if (host < 0) return host;
    leads = leads && !last;
    if (idf || leads || idd || !host) S->touched_exclave = 1; /* anything but a plain host component */
    /* 8.4: followed on the host, by its host name, at each call; its host symlinks are not ours to follow */
    if (idf) {
        /* it is a symlink where the walk sees it */
        if ((w->rf & RESOLVE_NO_SYMLINKS) && vis_readlink_identity(cur, tmp) == 1) return -ELOOP;
        /* followed as the last component: the re-issue on the host name follows the host's link */
        if (last) S->follow_end = 2;
        return CK_FILE;
    }
    /* 8.4: an identity directory and the names below it; in a scoped walk (scoped_walk) a host link at the
     * directory's name is read and followed like any, not passed as a directory */
    int scoped = scoped_walk(w);
    if (leads && !(idd == 2 && scoped)) return CK_DIR; /* on the way to an identity file or directory */
    if (idd && !scoped) {
        /* otherwise the directory is passed by name, the kernel following a host link there at each call; a ".."
         * after it climbs from where the link leads (walk_dotdot) */
        if (idd != 3 && !last) return CK_DIR;
        scpy(real, hreal, PATH_MAX);
        return identity_component(S, w, last, err);
    }
    if (!host) {
        /* 7.4.4: the exclave's components are remembered for the process's life, and the real path is made only for a
         * component not yet remembered */
        int kind = cache_get(cur, tmp);
        if (kind) return kind;
        /* to_real_exec's answer for an exclave path; cur is never "/" here */
        vis_exclave_real(cur, real);
        kind = cache_classify(cur, real, tmp);
        /* a name mapped outside the tree that has no place answers its lstat's own error, ENOTDIR, as a chroot would
         * answer one under a file (vis.c tree_real_of) */
        if ((!kind || kind == CK_NONE) && !starts_dir(real, C.root)) {
            struct kstat st;
            long e = sys_lstat(real, &st);
            if (e < 0) *err = (int)e;
        }
        return kind ? kind : CK_NONE;
    }
    /* the one-step host check, standing in for the directories before the final component */
    if (!last && !w->rf && !w->chain_failed && (chain = host_chain(S, cur, &w->rp)) > 0) return CK_ONWARD;
    if (chain < 0) w->chain_failed = 1; /* the walk's, from here to the next link */
    scpy(real, hreal, PATH_MAX); /* to_real_exec's answer for a host path */
    return host_component(S, w, last, err);
}

int canon(struct scratch *S, const char *path, int dfd, int follow_last, char *out)
{
    char *cur = S->cur, *tmp = S->tmp;
    size_t pl = xstrlen(path);
    int trailing = pl > 1 && path[pl - 1] == '/';
    /* openat2's resolve flags (7.4.3): a scoped walk (RESOLVE_IN_ROOT, RESOLVE_BENEATH) cannot leave S->v2, the
     * descriptor's directory; a magic link is ELOOP under NO_MAGICLINKS and NO_SYMLINKS and then EXDEV under the
     * scoped flags (nd_jump_link); NO_XDEV refuses to cross between the exclave's domain and the host's, which is where
     * the kernel under a bind mount changes mounts */
    struct walk w = {.rf = S->resolve, .base = "", .dom = 1};
    if (w.rf & (RESOLVE_IN_ROOT | RESOLVE_BENEATH)) w.base = S->v2;
    if (w.base[0] == '/' && w.base[1] == 0) w.base = "";
    w.magic_err = (w.rf & (RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS)) ? -ELOOP
                  : (w.rf & (RESOLVE_BENEATH | RESOLVE_IN_ROOT))         ? -EXDEV
                                                                         : 0;
    /* a walk that stays in the host's domain is the kernel's own to make (7.4.3) */
    S->touched_exclave = 0;
    S->follow_end = 0;
    int r = walk_start(S, &w, path, dfd, out);
    if (r) return r < 0 ? r : 0;
    w.rp = S->rest;
    for (;;) {
        while (*w.rp == '/') w.rp++;
        if (!*w.rp) break;
        char *e = w.rp;
        while (*e && *e != '/') e++;
        size_t cl = (size_t)(e - w.rp);
        if (cl > NAME_MAX) return -ENAMETOOLONG;
        char *comp = S->comp;
        xmemcpy(comp, w.rp, cl);
        comp[cl] = 0;
        w.rp = e;
        if (comp[0] == '.' && comp[1] == 0) continue;
        if (comp[0] == '.' && comp[1] == '.' && comp[2] == 0) {
            if ((r = walk_dotdot(S, &w)) < 0) return r;
            continue;
        }
        size_t curl = xstrlen(cur);
        if (curl + 1 + cl + 1 >= PATH_MAX) return -ENAMETOOLONG;
        cur[curl] = '/';
        xmemcpy(cur + curl + 1, comp, cl + 1);
        /* the tree's real root directory is an alias of /: a path spelt through <exclave>/tree/ is the same path in
         * virtual space, with the same ownership and the same read-only rule */
        if (C.rootlen && xstrcmp(cur, C.root) == 0) {
            cur[0] = 0;
            w.start_len = 0; /* the walk is at / now, past the starting directory */
            S->touched_exclave = 1;
            while (*w.rp == '/') w.rp++;
            continue;
        }
        while (*w.rp == '/') w.rp++;
        int last = (*w.rp == 0);
        /* an exclave path is re-issued under the tree's root prefix: one that would not fit PATH_MAX there is refused
         * here, ENAMETOOLONG, and never cut to a shorter name (13 item 13) */
        if (C.rootlen + (long)(curl + 1 + cl) + (last ? trailing : 0) >= PATH_MAX && (r = vis_owned(cur)) != 0)
            return r < 0 ? r : -ENAMETOOLONG;
        /* the mount changes where the domain does; an identity symlink that is not followed is the tree's own entry,
         * and its host target is not reached; a last name with a trailing slash that a create refuses before any
         * lookup (open_last_lookups, EISDIR) is never stepped into, so its mount is not met */
        if (w.rf & RESOLVE_NO_XDEV) {
            int d = vis_owned(cur);
            if (d < 0) return d;
            /* the starting directory's own way, walked again: the kernel starts in it and crosses nothing there */
            if (w.start_len && xstrlen(cur) > w.start_len) w.start_len = 0;
            if (!w.start_len && d != w.dom && !(last && trailing && (follow_last & WALK_PARENT)) &&
                !(last && !(follow_last & WALK_FOLLOW) && !trailing &&
                  ((vis_is_identity_file(cur) && vis_readlink_identity(cur, tmp) == 1) ||
                   vis_identity_dir_kind(cur) == 2)))
                return -EXDEV;
            w.dom = d;
        }
        /* the last component is the caller's where the kernel leaves it to the call (WALK_FOLLOW, WALK_PARENT): a
         * trailing slash means "a directory", which a lookup follows (lookup_last) and a call on the parent never
         * looks up (filename_parentat) */
        if (last && (trailing ? (follow_last & WALK_PARENT) != 0 : !(follow_last & WALK_FOLLOW))) {
            /* a top-level name left to the call is still a name the walk reached: its directory is read, or the
             * walk fails, before the handler asks whose the path is (8.1.1) */
            if (!curl && (r = vis_owned(cur)) < 0) return r;
            break;
        }
        /* the process's own exe names the program, not the launcher (7.6), on the loader path and for a script whose
         * exe is its interpreter */
        if ((C.loader_mode || xstrcmp(C.exe, C.program) != 0) && is_self_exe(cur, S->pid)) {
            if (w.magic_err) return w.magic_err; /* a magic link, refused by the resolve flags */
            if (++w.hops > 40) return -ELOOP;
            S->touched_exclave = 1;
            if ((r = walk_splice(S, &w, C.exe)) < 0) return r;
            cur[0] = 0;
            w.start_len = 0;
            continue;
        }
        /* classify the component: a directory, a symlink (text in tmp), absent, or something else */
        int err = -ENOENT, kind = walk_classify(S, &w, last, &err);
        if (kind < 0) return kind;
        if (kind == CK_ONWARD) {
            w.start_len = 0; /* the walk went on from where the step left it, past the starting directory */
            continue;
        }
        if (kind != CK_LINK) {
            /* an intermediate component must be a directory: the kernel says so before it looks further, and
             * a textual ".." must not hide that (oracle 17.2); the final component is the kernel's business.
             * A directory the exclave lacks on the way to a host identity file is the host's (8.4). */
            if (!last) {
                if (kind == CK_NONE) return err;
                if (kind != CK_DIR) return -ENOTDIR;
            }
            continue;
        }
        if (w.rf & RESOLVE_NO_SYMLINKS) return -ELOOP;
        if (++w.hops > 40) return -ELOOP;
        /* another process's exe that is the launcher names the program that process runs (7.6) */
        if (other_exe(S, cur, tmp) > 0) S->touched_exclave = 1;
        /* the kernel walks the final link's text as the rest of the path (link_path_walk), so a slash ending it is
         * the path's trailing slash: a directory is meant, and O_CREAT answers EISDIR (open_last_lookups) */
        if (last && tmp[0] && tmp[xstrlen(tmp) - 1] == '/') trailing = 1;
        w.chain_failed = 0; /* the walk restarts at the link's text */
        w.start_len = 0;
        if ((r = walk_splice(S, &w, tmp)) < 0) return r;
        if (tmp[0] == '/') {
            if (w.rf & RESOLVE_BENEATH) return -EXDEV; /* an absolute link target leaves the scope */
            scpy(cur, w.base, PATH_MAX); /* the scope's root is / for a scoped walk in root */
            S->touched_exclave = 1; /* the walk restarts at the tree's root */
        } else {
            char *s = xstrrchr(cur, '/');
            if (s) *s = 0;
            else cur[0] = 0;
        }
    }
    if (!cur[0]) {
        cur[0] = '/';
        cur[1] = 0;
    }
    scpy(out, cur, PATH_MAX);
    if (trailing && !(out[0] == '/' && out[1] == 0)) scat(out, "/", PATH_MAX);
    return 0;
}
