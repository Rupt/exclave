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
    from_real(out);
    return 0;
}
static int cwd_virtual_in(char *out, int *tree)
{
    long r = sys_getcwd(out, PATH_MAX);
    if (r < 0) return (int)r;
    if (tree) *tree = in_tree(out);
    from_real(out);
    return 0;
}
int fd_virtual(int fd, char *out) { return fd_virtual_in(fd, out, 0); }
int cwd_virtual(char *out) { return cwd_virtual_in(out, 0); }

/* /proc/self/exe in any spelling: self, thread-self, <pid>, <pid>/task/<tid>; the walk has already resolved
 * the self link into a pid, so the numeric forms are the ones that occur */
int is_self_exe(const char *p, pid_t mypid)
{
    if (xstrncmp(p, "/proc/", 6) != 0) return 0;
    p += 6;
    if (xstrcmp(p, "self/exe") == 0 || xstrcmp(p, "thread-self/exe") == 0) return 1;
    long pid = 0;
    while (*p >= '0' && *p <= '9') pid = pid * 10 + (*p++ - '0');
    if (!pid || pid != mypid) return 0;
    if (xstrcmp(p, "/exe") == 0) return 1;
    if (xstrncmp(p, "/task/", 6) != 0) return 0;
    p += 6;
    while (*p >= '0' && *p <= '9') p++;
    return xstrcmp(p, "/exe") == 0;
}

/* ---------- the one-step host check (DESIGN.md 16.6 item 4) ----------
 * A walk through host directories lstats each, to follow a host symlink in virtual space (a link into /usr reaches the
 * exclave's) and to see the tree's root by another name. Where the remaining directories are all plain host by the
 * rule, one openat2 with RESOLVE_NO_SYMLINKS answers the first question for all of them: it succeeds only if each is a
 * directory reached without a link. The second needs no question where the tree's filesystem is mounted once and its
 * device is the tree's own: within one mount a directory has one path, and the rule has already refused the tree's own
 * name. Anything else, a link, a missing directory, a refusal, a second mount, a kernel without openat2, is the walk's.
 * The last component is always the walk's, so that its kind, its link and its error are found as before. */
/* the tree's filesystem mounted once with its device: 0 not yet known, 1, -1 */
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
/* one pass over /proc/self/mountinfo in buf (PATH_MAX): pass 0 finds the mount holding the tree, the longest mount point
 * that is a prefix of its path, the last of equals since a later mount covers an earlier; pass 1 counts the mounts of
 * that device. 1 when answered; 0 when no descriptor was free, to be asked again; -1 when it cannot be answered here: no
 * /proc, an unreadable file, a line longer than the buffer, no mount holding the tree, as in a chroot */
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
        if (have >= PATH_MAX - 1) {
            ok = 0;
            break;
        }          /* a line longer than the buffer */
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
    if (fd == -ENOSYS || fd == -E2BIG || fd == -EINVAL) {
        no_openat2 = 1;
        return 0;
    }   /* before 5.6 */
    if (fd < 0) return -1;
    /* the kernel's name for what it reached must be the path itself: on a case-insensitive filesystem x.exclave/TREE is the
     * tree's root under another spelling on the same mount, and the tree's root, pinned by the program's own mappings,
     * keeps its own name; any other difference, an alias nobody foresaw, is the walk's too */
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

int canon(struct scratch *S, const char *path, int dfd, int follow_last, char *out)
{
    char *rest = S->rest, *cur = S->cur, *real = S->real, *tmp = S->tmp;
    /* a one-step host check that could not vouch: not tried again until a link */
    int hops = 0, chain_failed = 0;
    size_t pl = xstrlen(path);
    int trailing = pl > 1 && path[pl - 1] == '/';
    /* openat2's resolve flags (7.4.3): a scoped walk (RESOLVE_IN_ROOT, RESOLVE_BENEATH) cannot leave S->v2, the
     * descriptor's directory; NO_SYMLINKS and the scoped flags refuse magic links; NO_XDEV refuses to cross between
     * the exclave's domain and the host's, which is where the kernel under a bind mount changes mounts */
    unsigned rf = S->resolve;
    const char *base = (rf & (RESOLVE_IN_ROOT | RESOLVE_BENEATH)) ? S->v2 : "";
    if (base[0] == '/' && base[1] == 0) base = "";
    unsigned nomagic = rf & (RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH | RESOLVE_IN_ROOT);
    int dom = 1;
    /* a walk that stays in the host's domain is the kernel's own to make (7.4.3) */
    S->touched_exclave = 0;
    S->magic_end = 0;
    if (path[0] == '/') {
        if (rf & RESOLVE_BENEATH) return -EXDEV;               /* nd_jump_root: an absolute path leaves the scope */
        S->touched_exclave = 1;                                 /* the root is the tree's */
        scpy(rest, path, sizeof S->rest);
        scpy(cur, base, PATH_MAX);
        if (base[0]) dom = is_exclave_path(base);
        /* a path spelt through the tree's real root, as a program that finds its files from its argv[0] spells them:
         * the walk would lstat every directory above the tree and then see the tree's root by name, and the
         * launcher resolved that name from /proc/self/exe, so the path starts at the root (DESIGN.md 16.6 item 7) */
        if (!rf && C.rootlen && xstrncmp(path, C.root, (size_t)C.rootlen) == 0 &&
            (path[C.rootlen] == '/' || !path[C.rootlen])) {
            /* the walk's own answer for the directories above the tree, which the kernel searches: EACCES where one is
             * not searchable, ENOENT where the exclave was moved while it runs; one question for six lstats */
            long e = sys_faccessat(AT_FDCWD, C.dir, X_OK);
            if (e < 0) return (int)e;
            scpy(rest, path + C.rootlen, sizeof S->rest);
        }
    } else {
        int tree = 0, r = (dfd == AT_FDCWD) ? cwd_virtual_in(rest, &tree) : fd_virtual_in(dfd, rest, &tree);
        /* a directory deleted under the program, which the kernel still walks from and
         * the handler cannot name: the path is spelt through the magic link, a host
         * path the kernel resolves itself; a walk from there into the exclave stays
         * the host's (7.4.3) */
        if (r == -ENOENT) {
            char *n = S->b2;
            if (dfd != AT_FDCWD) ltoa_(dfd, n);
            scpy(out, dfd == AT_FDCWD ? "/proc/self/cwd" : "/proc/self/fd/", PATH_MAX);
            if (dfd != AT_FDCWD) scat(out, n, PATH_MAX);
            if (xstrlen(out) + 1 + pl >= PATH_MAX) return -ENAMETOOLONG;
            scat(out, "/", PATH_MAX);
            scat(out, path, PATH_MAX);
            return 0;
        }
        if (r < 0) return r;
        if (rf & RESOLVE_NO_XDEV) dom = rest[1] ? is_exclave_path(rest) : 1;
        int owned = !rest[1] || is_exclave_path(rest);
        if (owned) S->touched_exclave = 1;                         /* the directory the walk starts from */
        if (!rf && rest[1] && start_resolved(S, rest, owned, tree)) {
            /* the walk starts in the directory, resolved */
            scpy(cur, rest, PATH_MAX);
            scpy(rest, path, sizeof S->rest);
        } else {
            /* a directory and a path, each under PATH_MAX, fit rest together */
            scat(rest, "/", sizeof S->rest);
            scat(rest, path, sizeof S->rest);
            cur[0] = 0;
        }
    }
    char *rp = rest;
    for (;;) {
        while (*rp == '/') rp++;
        if (!*rp) break;
        char *e = rp;
        while (*e && *e != '/') e++;
        size_t cl = (size_t)(e - rp);
        if (cl > NAME_MAX) return -ENAMETOOLONG;
        char *comp = S->b2;
        xmemcpy(comp, rp, cl);
        comp[cl] = 0;
        rp = e;
        if (comp[0] == '.' && comp[1] == 0) continue;
        if (comp[0] == '.' && comp[1] == '.' && comp[2] == 0) {
            /* at the scope's root: stays there in root, leaves it beneath */
            if (base[0] ? xstrcmp(cur, base) == 0 : cur[0] == 0) {
                if (rf & RESOLVE_BENEATH) return -EXDEV;
                if (rf & RESOLVE_IN_ROOT) continue;
            }
            char *s = xstrrchr(cur, '/');
            if (s) *s = 0;
            else cur[0] = 0;
            /* the tree's root, reached from below: the walk is the handler's, not the kernel's own */
            if (!cur[0]) S->touched_exclave = 1;
            if (rf & RESOLVE_NO_XDEV) { /* follow_dotdot: leaving a mount upward is a crossing */
                int d = cur[0] ? is_exclave_path(cur) : 1;
                if (d != dom) return -EXDEV;
                dom = d;
            }
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
            S->touched_exclave = 1;
            while (*rp == '/') rp++;
            continue;
        }
        while (*rp == '/') rp++;
        int last = (*rp == 0);
        /* an exclave path is re-issued under the tree's root prefix: one that would not fit PATH_MAX there is refused here,
         * ENAMETOOLONG, and never cut to a shorter name (13) */
        if (C.rootlen + (long)(curl + 1 + cl) + (last ? trailing : 0) >= PATH_MAX && is_exclave_path(cur))
            return -ENAMETOOLONG;
        /* the mount changes where the domain does; an identity symlink that is
         * not followed is the tree's own entry, and its host target is not reached */
        if (rf & RESOLVE_NO_XDEV) {
            int d = is_exclave_path(cur);
            if (d != dom && !(last && !follow_last && !trailing && vis_is_identity_file(cur) &&
                              vis_readlink_identity(cur, tmp) == 1))
                return -EXDEV;
            dom = d;
        }
        /* a trailing slash means "a directory": the kernel follows */
        if (last && !follow_last && !trailing) break;
        /* the process's own exe on the loader path names the program, not the launcher (7.6) */
        /* loader path, or a script whose exe is its interpreter */
        if ((C.loader_mode || xstrcmp(C.exe, C.program) != 0) && is_self_exe(cur, S->pid)) {
            if (nomagic) return -ELOOP; /* a magic link, refused by the resolve flags */
            if (++hops > 40) return -ELOOP;
            S->touched_exclave = 1;
            size_t el = xstrlen(C.exe), rl = xstrlen(rp);
            if (el + 1 + rl + 1 >= sizeof S->rest) return -ENAMETOOLONG;
            memmove(rest + el + 1, rp, rl + 1);
            xmemcpy(rest, C.exe, el);
            rest[el] = '/';
            rp = rest;
            cur[0] = 0;
            continue;
        }
        /* classify the component: a directory, a symlink (text in tmp), absent, or something else */
        int kind, err = -ENOENT, idf, leads, chain = 0;
        const char *hreal;
        /* the rule asked once for the candidate (DESIGN.md 16.6 item 3) */
        int host = vis_walk_facts(cur, &idf, &leads, &hreal);
        leads = leads && !last;
        if (idf || leads || !host) S->touched_exclave = 1; /* anything but a plain host component */
        /* 8.4: resolved on the host at startup; its host symlinks are not ours to follow */
        if (idf) {
            /* it is a symlink where the walk sees it */
            if ((rf & RESOLVE_NO_SYMLINKS) && vis_readlink_identity(cur, tmp) == 1) return -ELOOP;
            kind = CK_FILE;
        } else if (leads) kind = CK_DIR; /* on the way to an identity file: a directory (8.4) */
        /* 7.4.4: the exclave's components are remembered for the process's life */
        else if (!host) {
            /* the real path only for a component not yet remembered */
            kind = cache_get(cur, tmp);
            if (!kind) {
                /* to_real_exec's answer for an exclave path; cur is never "/" here */
                scpy(real, C.root, PATH_MAX);
                scat(real, cur, PATH_MAX);
                kind = cache_classify(cur, real, tmp);
                if (!kind) kind = CK_NONE;
            }
        } else if (!last && !rf && !chain_failed && (chain = host_chain(S, cur, &rp)) > 0) {
            /* cur is the last directory before the final component */
            continue;
        } else {
            if (chain < 0) chain_failed = 1; /* the walk's, from here to the next link */
            scpy(real, hreal, PATH_MAX); /* to_real_exec's answer for a host path */
            struct kstat st;
            long r = sys_lstat(real, &st);
            if (r < 0) {
                kind = CK_NONE;
                err = (int)r;
            } else if ((st.st_mode & S_IFMT) == S_IFDIR) kind = CK_DIR;
            else if ((st.st_mode & S_IFMT) != S_IFLNK) kind = CK_FILE;
            else {
                /* a link the walk must follow and cannot read: its own error, EACCES for another process's magic link
                 * (get_link); the last component is followed here too */
                long n = sys_readlink(real, tmp, PATH_MAX - 1);
                if (n < 0) return (int)n;
                tmp[n] = 0;
                kind = CK_LINK;
                /* a link below /proc/<pid>/ is a magic link; one at /proc/ is not */
                int magic = xstrncmp(cur, "/proc/", 6) == 0 && xstrchr(cur + 6, '/');
                if (magic && nomagic) return -ELOOP;
                if (magic && pathless(real, tmp, n)) {
                    /* reachable only through the link itself: the walk ends here, and the re-issue follows it */
                    if (!last) return -ENOTDIR;
                    kind = CK_FILE;
                    S->magic_end = 1;
                } else if (xstrncmp(cur, "/proc/", 6) == 0) from_real(tmp); /* procfs links report real paths */
            }
            /* any spelling of the tree's root directory, through a bind mount or another link, is / */
            if (kind == CK_DIR && C.root_ino && st.st_dev == C.root_dev && st.st_ino == C.root_ino) {
                cur[0] = 0;
                S->touched_exclave = 1;
                continue;
            }
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
        if (rf & RESOLVE_NO_SYMLINKS) return -ELOOP;
        if (++hops > 40) return -ELOOP;
        chain_failed = 0; /* the walk restarts at the link's text */
        size_t tl = xstrlen(tmp), rl = xstrlen(rp);
        if (tl + 1 + rl + 1 >= sizeof S->rest) return -ENAMETOOLONG;
        memmove(rest + tl + 1, rp, rl + 1);
        xmemcpy(rest, tmp, tl);
        rest[tl] = '/';
        rp = rest;
        if (tmp[0] == '/') {
            if (rf & RESOLVE_BENEATH) return -EXDEV; /* an absolute link target leaves the scope */
            scpy(cur, base, PATH_MAX); /* the scope's root is / for a scoped walk in root */
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
