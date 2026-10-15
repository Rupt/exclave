/* canon.c — canonicalisation in virtual space (PROPOSAL.md 7.4.4).
 *
 * Resolves a path the way the kernel would inside a bind-mounted root:
 * component by component, following symlinks whose targets are virtual
 * paths whoever created them, with the visibility rule deciding where each
 * candidate lives. Descriptor-addressed paths never reach the walk.
 */
#include "common.h"

static int in_tree(const char *r) { return C.rootlen && xstrncmp(r, C.root, (size_t)C.rootlen) == 0 && (r[C.rootlen] == '/' || r[C.rootlen] == 0); }
/* the virtual path of a descriptor or of the working directory; *tree, when asked, says whether the kernel's real path
 * lay in the tree */
static int fd_virtual_in(int fd, char *out, int *tree)
{
    char l[64] = "/proc/self/fd/"; char n[24]; ltoa_(fd, n); scat(l, n, sizeof l);
    long r = sys_readlink(l, out, PATH_MAX - 1); if (r < 0) return r == -ENOENT ? -EBADF : (int)r;   /* no such link: no such descriptor */
    out[r] = 0;
    if (r > 10 && xstrcmp(out + r - 10, " (deleted)") == 0) return -ENOENT;   /* let the caller pass it through */
    if (tree) *tree = in_tree(out);
    from_real(out); return 0;
}
static int cwd_virtual_in(char *out, int *tree)
{
    long r = sys_getcwd(out, PATH_MAX); if (r < 0) return (int)r;
    if (tree) *tree = in_tree(out);
    from_real(out); return 0;
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
    long pid = 0; while (*p >= '0' && *p <= '9') pid = pid * 10 + (*p++ - '0');
    if (!pid || pid != mypid) return 0;
    if (xstrcmp(p, "/exe") == 0) return 1;
    if (xstrncmp(p, "/task/", 6) != 0) return 0;
    p += 6; while (*p >= '0' && *p <= '9') p++;
    return xstrcmp(p, "/exe") == 0;
}

/* ---------- the one-step host check (PERFORMANCE.md 4 item 4) ----------
 * A walk through host directories lstats each, to follow a host symlink in virtual space (a link into /usr reaches the
 * can's) and to see the tree's root by another name (F3-13). Where the remaining directories are all plain host by the
 * rule, one openat2 with RESOLVE_NO_SYMLINKS answers the first question for all of them: it succeeds only if each is a
 * directory reached without a link. The second needs no question where the tree's filesystem is mounted once and its
 * device is the tree's own: within one mount a directory has one path, and the rule has already refused the tree's own
 * name. Anything else, a link, a missing directory, a refusal, a second mount, a kernel without openat2, is the walk's.
 * The last component is always the walk's, so that its kind, its link and its error are found as before. */
static int tree_once;                                        /* the tree's filesystem mounted once with its device: 0 not yet known, 1, -1 */
static int no_openat2;                                       /* the kernel predates openat2 (5.6) */

/* the decoded mount point at f (mountinfo escapes a space, a tab, a newline and a backslash as \ooo) as a '/'-boundary
 * prefix of the tree's real path: its length, or -1 */
static long mount_prefix(const char *f, const char *fe)
{
    long k = 0;
    while (f < fe) {
        char c = *f++;
        if (c == '\\' && fe - f >= 3) { c = (char)(((f[0] - '0') << 6) | ((f[1] - '0') << 3) | (f[2] - '0')); f += 3; }
        if (C.root[k] != c) return -1;
        k++;
    }
    if (k == 1 && C.root[0] == '/') return 1;                 /* the root mount */
    return C.root[k] == '/' || C.root[k] == 0 ? k : -1;
}
/* one pass over /proc/self/mountinfo in buf (PATH_MAX): pass 0 finds the mount holding the tree, the longest mount point
 * that is a prefix of its path, the last of equals since a later mount covers an earlier; pass 1 counts the mounts of
 * that device. 0 when the file cannot be read or a line does not fit */
static long mounts(char *buf, int pass, unsigned long *dev, long *count)
{
    long fd = sys_open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC, 0); if (fd < 0) return 0;
    long have = 0, best = -1, ok = 1;
    for (;;) {
        long n = sys_read((int)fd, buf + have, PATH_MAX - 1 - (size_t)have);
        if (n < 0) { ok = 0; break; }
        have += n; buf[have] = 0;
        char *l = buf, *nl;
        while ((nl = xstrchr(l, '\n'))) {
            /* id parent major:minor root mountpoint ... */
            char *f[5]; int nf = 0; char *q = l;
            while (nf < 5 && q < nl) { while (q < nl && *q == ' ') q++; f[nf++] = q; while (q < nl && *q != ' ') q++; }
            if (nf == 5) {
                unsigned long ma = 0, mi = 0; char *d = f[2];
                while (*d >= '0' && *d <= '9') ma = ma * 10 + (unsigned long)(*d++ - '0');
                if (*d == ':') d++;
                while (*d >= '0' && *d <= '9') mi = mi * 10 + (unsigned long)(*d++ - '0');
                unsigned long md = ma << 32 | mi;
                if (pass == 0) { char *e = f[4]; while (e < nl && *e != ' ') e++; long k = mount_prefix(f[4], e); if (k >= best && k > 0) { best = k; *dev = md; } }
                else if (md == *dev) (*count)++;
            }
            l = nl + 1;
        }
        have -= l - buf; memmove(buf, l, (size_t)have + 1);
        if (n == 0) break;
        if (have >= PATH_MAX - 1) { ok = 0; break; }          /* a line longer than the buffer */
    }
    sys_close((int)fd);
    return ok && (pass == 1 || best > 0);
}
static int tree_mounted_once(char *buf)
{
    unsigned long dev = 0; long count = 0;
    if (!mounts(buf, 0, &dev, &count)) return 0;              /* unread: asked again at the next walk */
    if (!mounts(buf, 1, &dev, &count)) return 0;
    unsigned long sd = C.root_dev;                            /* the stat encoding: glibc's major and minor */
    unsigned long ma = ((sd >> 8) & 0xfff) | ((sd >> 32) & ~0xfffUL), mi = (sd & 0xff) | ((sd >> 12) & ~0xffUL);
    return count == 1 && dev == (ma << 32 | mi) ? 1 : -1;     /* a btrfs subvolume's device is not its mount's: the walk's */
}
/* at the plain host directory cur, not the last component, with the rest of the path at *rpp: try to stand in for the
 * walk through every directory before the final component. 1 if it did, cur then the last of them and *rpp the final */
static int host_chain(struct scratch *S, char *cur, char **rpp)
{
    if (no_openat2 || tree_once < 0) return 0;
    if (xstrncmp(cur, "/proc", 5) == 0 && (cur[5] == '/' || !cur[5])) return 0;   /* magic links, the process's own exe: the walk's */
    char *p = S->real, *q = *rpp; size_t n = xstrlen(cur);
    int dirs = 1;
    xmemcpy(p, cur, n);
    for (;;) {
        while (*q == '/') q++;
        char *e = q; while (*e && *e != '/') e++;
        char *after = e; while (*after == '/') after++;
        if (!*after) break;                                    /* q is the final component */
        size_t cl = (size_t)(e - q);
        if (cl > NAME_MAX || n + 1 + cl + 1 >= PATH_MAX) return 0;   /* the walk's ENAMETOOLONG */
        if (q[0] == '.' && (cl == 1 || (cl == 2 && q[1] == '.'))) return 0;   /* "." and "..": the walk's, by the rule */
        p[n++] = '/'; xmemcpy(p + n, q, cl); n += cl; dirs++;
        q = after;
    }
    p[n] = 0;
    if (dirs < 3) return 0;                                   /* an openat2 and a close for fewer lstats than that */
    if (!vis_plain_host_chain(p, (unsigned)xstrlen(cur))) return 0;
    if (!tree_once) tree_once = tree_mounted_once(S->tmp);
    if (tree_once <= 0) return 0;
    unsigned long how[3] = { O_PATH | O_DIRECTORY | O_CLOEXEC, 0, RESOLVE_NO_SYMLINKS };
    long fd = SC4(NR_openat2, AT_FDCWD, p, how, sizeof how);
    if (fd == -ENOSYS || fd == -E2BIG || fd == -EINVAL) { no_openat2 = 1; return 0; }   /* before 5.6 */
    if (fd < 0) return 0;
    sys_close((int)fd);
    scpy(cur, p, PATH_MAX); *rpp = q;
    return 1;
}

/* a relative walk's starting directory, as the kernel names it (PERFORMANCE.md 4 item 5): the kernel starts a relative
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
    int hops = 0;
    size_t pl = xstrlen(path);
    int trailing = pl > 1 && path[pl - 1] == '/';
    /* openat2's resolve flags (7.4.3): a scoped walk (RESOLVE_IN_ROOT, RESOLVE_BENEATH) cannot leave S->v2, the
     * descriptor's directory; NO_SYMLINKS and the scoped flags refuse magic links; NO_XDEV refuses to cross between
     * the can's domain and the host's, which is where the kernel under a bind mount changes mounts */
    unsigned rf = S->resolve;
    const char *base = (rf & (RESOLVE_IN_ROOT | RESOLVE_BENEATH)) ? S->v2 : "";
    if (base[0] == '/' && base[1] == 0) base = "";
    int nomagic = rf & (RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH | RESOLVE_IN_ROOT);
    int dom = 1;
    S->touched_can = 0;                                     /* a walk that stays in the host's domain is the kernel's own to make (7.4.3) */
    if (path[0] == '/') {
        if (rf & RESOLVE_BENEATH) return -EXDEV;               /* nd_jump_root: an absolute path leaves the scope */
        S->touched_can = 1;                                 /* the root is the tree's */
        scpy(rest, path, sizeof S->rest); scpy(cur, base, PATH_MAX);
        if (base[0]) dom = is_can_owned(base);
    } else {
        int tree = 0, r = (dfd == AT_FDCWD) ? cwd_virtual_in(rest, &tree) : fd_virtual_in(dfd, rest, &tree);
        if (r == -ENOENT) {                                    /* a directory deleted under the program, which the kernel still walks from and
                                                                * the handler cannot name: the path is spelt through the magic link, a host
                                                                * path the kernel resolves itself; a walk from there into the can stays
                                                                * the host's (7.4.3) */
            char *n = S->b2; if (dfd != AT_FDCWD) ltoa_(dfd, n);
            scpy(out, dfd == AT_FDCWD ? "/proc/self/cwd" : "/proc/self/fd/", PATH_MAX); if (dfd != AT_FDCWD) scat(out, n, PATH_MAX);
            if (xstrlen(out) + 1 + pl >= PATH_MAX) return -ENAMETOOLONG;
            scat(out, "/", PATH_MAX); scat(out, path, PATH_MAX);
            return 0;
        }
        if (r < 0) return r;
        if (rf & RESOLVE_NO_XDEV) dom = rest[1] ? is_can_owned(rest) : 1;
        int owned = !rest[1] || is_can_owned(rest);
        if (owned) S->touched_can = 1;                         /* the directory the walk starts from */
        if (!rf && rest[1] && start_resolved(S, rest, owned, tree)) {
            scpy(cur, rest, PATH_MAX); scpy(rest, path, sizeof S->rest);   /* the walk starts in the directory, resolved */
        } else {
            scat(rest, "/", sizeof S->rest); scat(rest, path, sizeof S->rest);   /* a directory and a path, each under PATH_MAX, fit rest together */
            cur[0] = 0;
        }
    }
    char *rp = rest;
    for (;;) {
        while (*rp == '/') rp++;
        if (!*rp) break;
        char *e = rp; while (*e && *e != '/') e++;
        size_t cl = (size_t)(e - rp);
        if (cl > NAME_MAX) return -ENAMETOOLONG;
        char *comp = S->b2; xmemcpy(comp, rp, cl); comp[cl] = 0; rp = e;
        if (comp[0] == '.' && comp[1] == 0) continue;
        if (comp[0] == '.' && comp[1] == '.' && comp[2] == 0) {
            if (base[0] ? xstrcmp(cur, base) == 0 : cur[0] == 0) {   /* at the scope's root: stays there in root, leaves it beneath */
                if (rf & RESOLVE_BENEATH) return -EXDEV;
                if (rf & RESOLVE_IN_ROOT) continue;
            }
            char *s = xstrrchr(cur, '/'); if (s) *s = 0; else cur[0] = 0;
            if (!cur[0]) S->touched_can = 1;                   /* the tree's root, reached from below: the walk is the handler's, not the kernel's own */
            if (rf & RESOLVE_NO_XDEV) {                        /* follow_dotdot: leaving a mount upward is a crossing */
                int d = cur[0] ? is_can_owned(cur) : 1;
                if (d != dom) return -EXDEV;
                dom = d;
            }
            continue;
        }
        size_t curl = xstrlen(cur); if (curl + 1 + cl + 1 >= PATH_MAX) return -ENAMETOOLONG;
        cur[curl] = '/'; xmemcpy(cur + curl + 1, comp, cl + 1);
        /* the tree's real root directory is an alias of /: a path spelt through <can>/root/ is the same path in
         * virtual space, with the same ownership and the same read-only rule (review F3-1) */
        if (C.rootlen && xstrcmp(cur, C.root) == 0) { cur[0] = 0; S->touched_can = 1; while (*rp == '/') rp++; continue; }
        while (*rp == '/') rp++;
        int last = (*rp == 0);
        /* a can-owned path is re-issued under the tree's root prefix: one that would not fit PATH_MAX there is refused here,
         * ENAMETOOLONG, and never cut to a shorter name (13) */
        if (C.rootlen + (long)(curl + 1 + cl) + (last ? trailing : 0) >= PATH_MAX && is_can_owned(cur)) return -ENAMETOOLONG;
        if (rf & RESOLVE_NO_XDEV) {                            /* the mount changes where the domain does; an identity symlink that is
                                                                * not followed is the tree's own entry, and its host target is not reached */
            int d = is_can_owned(cur);
            if (d != dom && !(last && !follow_last && !trailing && vis_is_identity_file(cur) && vis_readlink_identity(cur, tmp) == 1)) return -EXDEV;
            dom = d;
        }
        if (last && !follow_last && !trailing) break;          /* a trailing slash means "a directory": the kernel follows */
        /* the process's own exe on the loader path names the program, not the opener (7.6) */
        if ((C.loader_mode || xstrcmp(C.exe, C.program) != 0) && is_self_exe(cur, S->pid)) {   /* loader path, or a script whose exe is its interpreter */
            if (nomagic) return -ELOOP;                        /* a magic link, refused by the resolve flags */
            if (++hops > 40) return -ELOOP;
            S->touched_can = 1;
            size_t el = xstrlen(C.exe), rl = xstrlen(rp);
            if (el + 1 + rl + 1 >= sizeof S->rest) return -ENAMETOOLONG;
            memmove(rest + el + 1, rp, rl + 1); xmemcpy(rest, C.exe, el); rest[el] = '/'; rp = rest; cur[0] = 0; continue;
        }
        /* classify the component: a directory, a symlink (text in tmp), absent, or something else */
        int kind, err = -ENOENT, idf, leads; const char *hreal;
        int host = vis_walk_facts(cur, &idf, &leads, &hreal); /* the rule asked once for the candidate (PERFORMANCE.md 4 item 3) */
        leads = leads && !last;
        if (idf || leads || !host) S->touched_can = 1;         /* anything but a plain host component */
        if (idf) {                                             /* 8.4: resolved on the host at startup; its host symlinks are not ours to follow */
            if ((rf & RESOLVE_NO_SYMLINKS) && vis_readlink_identity(cur, tmp) == 1) return -ELOOP;   /* it is a symlink where the walk sees it */
            kind = CK_FILE;
        }
        else if (leads) kind = CK_DIR;                         /* on the way to an identity file: a directory (8.4) */
        else if (!host) {                                      /* 7.4.4: can-owned components are remembered for the process's life */
            kind = cache_get(cur, tmp);                        /* the real path only for a component not yet remembered */
            if (!kind) {
                scpy(real, C.root, PATH_MAX); scat(real, cur, PATH_MAX);   /* to_real_exec's answer for a can path; cur is never "/" here */
                kind = cache_classify(cur, real, tmp);
                if (!kind) kind = CK_NONE;
            }
        } else if (!last && !rf && host_chain(S, cur, &rp)) {
            continue;                                          /* cur is the last directory before the final component */
        } else {
            scpy(real, hreal, PATH_MAX);                       /* to_real_exec's answer for a host path */
            struct kstat st; long r = sys_lstat(real, &st);
            if (r < 0) { kind = CK_NONE; err = (int)r; }
            else if ((st.st_mode & S_IFMT) == S_IFDIR) kind = CK_DIR;
            else if ((st.st_mode & S_IFMT) != S_IFLNK) kind = CK_FILE;
            else {
                long n = sys_readlink(real, tmp, PATH_MAX - 1);
                if (n < 0) return (int)n;                      /* a link the walk must follow and cannot read: its own error, EACCES for another
                                                                * process's magic link (get_link); the last component is followed here too */
                else {
                    tmp[n] = 0; kind = CK_LINK;
                    if (xstrncmp(cur, "/proc/", 6) == 0) {
                        if (nomagic && xstrchr(cur + 6, '/')) return -ELOOP;   /* a link below /proc/<pid>/ is a magic link; one at /proc/ is not */
                        /* a procfs magic link to something that has no path (a pipe, a socket, an unlinked
                         * file) is reachable only through the link itself: the walk ends here (review F3-11) */
                        if ((tmp[0] != '/' && xstrchr(tmp, ':') && xstrchr(tmp, '[')) || (n > 10 && xstrcmp(tmp + n - 10, " (deleted)") == 0)) {   /* pipe:[n], socket:[n], anon_inode:[x], a deleted file */
                            if (!last) return -ENOTDIR;
                            kind = CK_FILE;
                        } else from_real(tmp);                 /* procfs links report real paths */
                    }
                }
            }
            /* any spelling of the tree's root directory, through a bind mount or another link, is / (F3-13) */
            if (kind == CK_DIR && C.root_ino && st.st_dev == C.root_dev && st.st_ino == C.root_ino) { cur[0] = 0; S->touched_can = 1; continue; }
        }
        if (kind != CK_LINK) {
            /* an intermediate component must be a directory: the kernel says so before it looks further, and
             * a textual ".." must not hide that (oracle 17.2); the final component is the kernel's business.
             * A directory the can lacks on the way to a host identity file is the host's (8.4). */
            if (!last) { if (kind == CK_NONE) return err; if (kind != CK_DIR) return -ENOTDIR; }
            continue;
        }
        if (rf & RESOLVE_NO_SYMLINKS) return -ELOOP;
        if (++hops > 40) return -ELOOP;
        size_t tl = xstrlen(tmp), rl = xstrlen(rp);
        if (tl + 1 + rl + 1 >= sizeof S->rest) return -ENAMETOOLONG;
        memmove(rest + tl + 1, rp, rl + 1); xmemcpy(rest, tmp, tl); rest[tl] = '/'; rp = rest;
        if (tmp[0] == '/') {
            if (rf & RESOLVE_BENEATH) return -EXDEV;           /* an absolute link target leaves the scope */
            scpy(cur, base, PATH_MAX);                         /* the scope's root is / for a scoped walk in root */
            S->touched_can = 1;                                /* the walk restarts at the tree's root */
        } else { char *s = xstrrchr(cur, '/'); if (s) *s = 0; else cur[0] = 0; }
    }
    if (!cur[0]) { cur[0] = '/'; cur[1] = 0; }
    scpy(out, cur, PATH_MAX);
    if (trailing && !(out[0] == '/' && out[1] == 0)) scat(out, "/", PATH_MAX);
    return 0;
}
