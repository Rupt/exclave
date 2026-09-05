/* canon.c — canonicalisation in virtual space (PROPOSAL.md 7.4.4).
 *
 * Resolves a path the way the kernel would inside a bind-mounted root:
 * component by component, following symlinks whose targets are virtual
 * paths whoever created them, with the visibility rule deciding where each
 * candidate lives. Descriptor-addressed paths never reach the walk.
 */
#include "common.h"

int fd_virtual(int fd, char *out)
{
    char l[64] = "/proc/self/fd/"; char n[24]; ltoa_(fd, n); scat(l, n, sizeof l);
    long r = sys_readlink(l, out, PATH_MAX - 1); if (r < 0) return (int)r;
    out[r] = 0;
    if (r > 10 && xstrcmp(out + r - 10, " (deleted)") == 0) return -ENOENT;   /* let the caller pass it through */
    from_real(out); return 0;
}
int cwd_virtual(char *out)
{
    long r = sys_getcwd(out, PATH_MAX); if (r < 0) return (int)r;
    from_real(out); return 0;
}

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

int canon(struct scratch *S, const char *path, int dfd, int follow_last, char *out)
{
    char *rest = S->rest, *cur = S->cur, *real = S->real, *tmp = S->tmp;
    int hops = 0;
    size_t pl = xstrlen(path);
    int trailing = pl > 1 && path[pl - 1] == '/';
    if (path[0] == '/') scpy(rest, path, PATH_MAX);
    else {
        int r = (dfd == AT_FDCWD) ? cwd_virtual(rest) : fd_virtual(dfd, rest);
        if (r < 0) return r;
        scat(rest, "/", PATH_MAX); scat(rest, path, PATH_MAX);
    }
    cur[0] = 0; char *rp = rest;
    for (;;) {
        while (*rp == '/') rp++;
        if (!*rp) break;
        char *e = rp; while (*e && *e != '/') e++;
        size_t cl = (size_t)(e - rp);
        if (cl > NAME_MAX) return -ENAMETOOLONG;
        char *comp = S->b2; xmemcpy(comp, rp, cl); comp[cl] = 0; rp = e;
        if (comp[0] == '.' && comp[1] == 0) continue;
        if (comp[0] == '.' && comp[1] == '.' && comp[2] == 0) { char *s = xstrrchr(cur, '/'); if (s) *s = 0; else cur[0] = 0; continue; }
        size_t curl = xstrlen(cur); if (curl + 1 + cl + 1 >= PATH_MAX) return -ENAMETOOLONG;
        cur[curl] = '/'; xmemcpy(cur + curl + 1, comp, cl + 1);
        while (*rp == '/') rp++;
        int last = (*rp == 0);
        if (last && !follow_last && !trailing) break;          /* a trailing slash means "a directory": the kernel follows */
        /* the process's own exe on the loader path names the program, not the opener (7.6) */
        if (C.loader_mode && is_self_exe(cur, S->pid)) {
            if (++hops > 40) return -ELOOP;
            scpy(tmp, C.program, PATH_MAX); scat(tmp, "/", PATH_MAX); scat(tmp, rp, PATH_MAX);
            scpy(rest, tmp, PATH_MAX); rp = rest; cur[0] = 0; continue;
        }
        /* classify the component: a directory, a symlink (text in tmp), absent, or something else */
        int kind, err = -ENOENT;
        if (!last && vis_leads_to_host_file(cur)) kind = CK_DIR;   /* on the way to an identity file: a directory (8.4) */
        else if (is_can_owned(cur)) {                          /* 7.4.4: can-owned components are remembered for the process's life */
            to_real_exec(cur, real);
            kind = cache_classify(cur, real, tmp);
            if (!kind) kind = CK_NONE;
        } else {
            to_real_exec(cur, real);
            struct kstat st; long r = sys_lstat(real, &st);
            if (r < 0) { kind = CK_NONE; err = (int)r; }
            else if ((st.st_mode & S_IFMT) == S_IFDIR) kind = CK_DIR;
            else if ((st.st_mode & S_IFMT) != S_IFLNK) kind = CK_FILE;
            else {
                long n = sys_readlink(real, tmp, PATH_MAX - 1);
                if (n < 0) kind = CK_FILE;
                else { tmp[n] = 0; kind = CK_LINK; if (xstrncmp(cur, "/proc/", 6) == 0) from_real(tmp); }   /* procfs links report real paths */
            }
        }
        if (kind != CK_LINK) {
            /* an intermediate component must be a directory: the kernel says so before it looks further, and
             * a textual ".." must not hide that (oracle 17.2); the final component is the kernel's business */
            if (!last) { if (kind == CK_NONE) return err; if (kind != CK_DIR) return -ENOTDIR; }
            continue;
        }
        if (++hops > 40) return -ELOOP;
        size_t tl = xstrlen(tmp), rl = xstrlen(rp);
        if (tl + 1 + rl + 1 >= PATH_MAX) return -ENAMETOOLONG;
        memmove(rest + tl + 1, rp, rl + 1); xmemcpy(rest, tmp, tl); rest[tl] = '/'; rp = rest;
        if (tmp[0] == '/') cur[0] = 0; else { char *s = xstrrchr(cur, '/'); if (s) *s = 0; else cur[0] = 0; }
    }
    if (!cur[0]) { cur[0] = '/'; cur[1] = 0; }
    scpy(out, cur, PATH_MAX);
    if (trailing && !(out[0] == '/' && out[1] == 0)) scat(out, "/", PATH_MAX);
    return 0;
}
