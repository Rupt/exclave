/* vis.c — the visibility rule (PROPOSAL.md section 8) and wrapper redirect (7.4.4).
 *
 * Decides, for a virtual path, whether it is the host's or the can's, and
 * turns it into a real path. The table is built once at startup from the
 * index, the working directory and the host identity files.
 */
#include "common.h"

static const char *volatile_dirs[] = { "/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run", 0 };

/* identity files: link text recorded at startup for readlink fidelity (8.4) */
static const char *id_link[64];

/* resolve a host path's symlink chain on the host; returns the final path in out, first link text in link */
static int host_resolve(const char *p, char *out, char *link)
{
    char cur[PATH_MAX], t[PATH_MAX]; scpy(cur, p, PATH_MAX); link[0] = 0;
    for (int hops = 0; hops < 40; hops++) {
        struct kstat st;
        if (sys_lstat(cur, &st) < 0) return 0;
        if ((st.st_mode & S_IFMT) != S_IFLNK) { scpy(out, cur, PATH_MAX); return 1; }
        long n = sys_readlink(cur, t, PATH_MAX - 1); if (n < 0) return 0; t[n] = 0;
        if (!link[0]) scpy(link, t, PATH_MAX);
        if (t[0] == '/') scpy(cur, t, PATH_MAX);
        else { char *s = xstrrchr(cur, '/'); if (s) s[1] = 0; else cur[0] = 0; scat(cur, t, PATH_MAX); }
    }
    return 0;
}

static void claim_cwd(void)
{
    char real[PATH_MAX];
    C.cwdclaim[0] = 0; C.cwdclaim_len = 0;
    long n = sys_getcwd(real, PATH_MAX); if (n <= 0) return;
    if (starts_dir(real, C.root)) return;                       /* inside the tree: virtual path, no claim (8.1.4) */
    /* a real host path: claim it as a subtree if the rule would otherwise hand it to the can */
    const char *r; if (vis_is_host(real, &r)) return;
    scpy(C.cwdclaim, real, PATH_MAX); C.cwdclaim_len = (long)xstrlen(real);
    log_msg("cwd claimed for the host", real);
}

void vis_init(char **envp)
{
    /* identity files and host records: resolve each on the host; drop the ones the host lacks */
    int n = 0;
    for (int i = 0; i < C.nhost; i++) {
        struct kstat st;
        if (sys_lstat(C.host[i].v, &st) < 0) { log_msg("host path absent, using the can's", C.host[i].v); continue; }
        if ((st.st_mode & S_IFMT) == S_IFDIR) { C.host[n] = C.host[i]; C.host[n].is_file = 0; id_link[n] = 0; n++; continue; }
        static char out[PATH_MAX], link[PATH_MAX];
        if (!host_resolve(C.host[i].v, out, link)) { log_msg("host path unresolvable, using the can's", C.host[i].v); continue; }
        C.host[n].v = C.host[i].v; C.host[n].r = arena_str(out, xstrlen(out)); C.host[n].is_file = 1;
        id_link[n] = link[0] ? arena_str(link, xstrlen(link)) : 0; n++;
    }
    C.nhost = n;
    /* TZ names a zone the can may lack (8.4) */
    for (char **e = envp; *e; e++) {
        if (!xstarts(*e, "TZ=")) continue;
        const char *z = *e + 3; if (*z == ':') z++;
        if (!*z || *z == '/' || xstrchr(z, '.')) break;                 /* absolute or POSIX-format TZ: not a zone file */
        static char v[PATH_MAX], real[PATH_MAX];
        scpy(v, "/usr/share/zoneinfo/", PATH_MAX); scat(v, z, PATH_MAX);
        scpy(real, C.root, PATH_MAX); scat(real, v, PATH_MAX);
        struct kstat st;
        if (sys_stat(real, &st) == 0) break;                            /* the can has it */
        static char out[PATH_MAX], link[PATH_MAX];
        if (host_resolve(v, out, link) && C.nhost < (int)(sizeof C.host / sizeof C.host[0])) {
            C.host[C.nhost].v = arena_str(v, xstrlen(v)); C.host[C.nhost].r = arena_str(out, xstrlen(out)); C.host[C.nhost].is_file = 1;
            id_link[C.nhost] = link[0] ? arena_str(link, xstrlen(link)) : 0; C.nhost++;
        }
        break;
    }
    claim_cwd();
}

/* 8.1: identity file > volatile > cwd claim > host records > own > default host; longest prefix wins among prefixes */
int vis_is_host(const char *v, const char **real)
{
    for (int i = 0; i < C.nhost; i++)
        if (C.host[i].is_file && xstrcmp(v, C.host[i].v) == 0) { *real = C.host[i].r; return 1; }
    for (int i = 0; volatile_dirs[i]; i++)
        if (starts_dir(v, volatile_dirs[i])) { *real = v; return 1; }
    long best_host = -1, best_own = -1;
    /* 8.1.4: a claimed working directory is the host's as a subtree, and so is every directory on the way to
     * it, or realpath and pwd -P could not walk the path the process was started in */
    if (C.cwdclaim_len && (starts_dir(v, C.cwdclaim) || starts_dir(C.cwdclaim, v))) { *real = v; return 1; }
    for (int i = 0; i < C.nhost; i++)
        if (!C.host[i].is_file && starts_dir(v, C.host[i].v)) { long l = (long)xstrlen(C.host[i].v); if (l > best_host) best_host = l; }
    for (int i = 0; i < C.nown; i++)
        if (starts_dir(v, C.own[i])) { long l = (long)xstrlen(C.own[i]); if (l > best_own) best_own = l; }
    if (best_host >= best_own) { *real = v; return 1; }      /* includes the default: nothing owns it */
    return 0;
}
int is_can_owned(const char *v) { const char *r; return !vis_is_host(v, &r); }

/* 8.4: the directories on the way to a host file (an identity file, a TZ zone) exist on the host whether or
 * not the can ships them; a path walk treats them as directories so that the file itself can be reached */
int vis_leads_to_host_file(const char *v)
{
    for (int i = 0; i < C.nhost; i++)
        if (C.host[i].is_file && starts_dir(C.host[i].v, v) && xstrcmp(C.host[i].v, v) != 0) return 1;
    return 0;
}

int is_wrapper_real(const char *real, char *tmp)
{
    struct kstat st;
    if (sys_lstat(real, &st) < 0 || (st.st_mode & S_IFMT) != S_IFREG) return 0;
    if (st.st_dev == C.opener_dev && st.st_ino == C.opener_ino) return 1;
    if (st.st_size != C.opener_size) return 0;
    return payload_of(real, tmp) && sys_lstat(tmp, &st) == 0;   /* a copy of the opener: real only if its payload exists */
}
int payload_of(const char *real, char *out)
{
    const char *b = xstrrchr(real, '/'); if (!b) return 0;
    size_t dl = (size_t)(b - real); if (dl + 7 + xstrlen(b) >= PATH_MAX) return 0;
    xmemcpy(out, real, dl); out[dl] = 0; scat(out, "/.real", PATH_MAX); scat(out, b, PATH_MAX);
    return 1;
}

char *to_real_exec(const char *v, char *out)
{
    const char *r;
    if (vis_is_host(v, &r)) return scpy(out, r, PATH_MAX);
    scpy(out, C.root, PATH_MAX);
    if (!(v[0] == '/' && v[1] == 0)) scat(out, v, PATH_MAX);
    return out;
}
char *to_real(const char *v, char *out, char *tmp)
{
    to_real_exec(v, out);
    if (!C.rootlen || !starts_dir(out, C.root)) return out;
    int k = cache_classify(v, out, tmp);                       /* the wrapper check, remembered (7.4.4) */
    if (k == CK_WRAPPER || (!k && is_wrapper_real(out, tmp))) { if (payload_of(out, tmp)) scpy(out, tmp, PATH_MAX); }
    return out;
}
void from_real(char *r)
{
    if (!C.rootlen || xstrncmp(r, C.root, (size_t)C.rootlen) != 0) return;
    if (r[C.rootlen] == 0) { r[0] = '/'; r[1] = 0; return; }
    if (r[C.rootlen] != '/') return;
    memmove(r, r + C.rootlen, xstrlen(r + C.rootlen) + 1);
    /* a payload seen through /proc reports the wrapper's name: drop a final "/.real" directory */
    char *b = xstrrchr(r, '/');
    if (b && b - r >= 6 && xmemcmp(b - 6, "/.real", 6) == 0) memmove(b - 6, b, xstrlen(b) + 1);
}
int vis_readlink_identity(const char *v, char *out)
{
    for (int i = 0; i < C.nhost; i++)
        if (C.host[i].is_file && xstrcmp(v, C.host[i].v) == 0) { if (!id_link[i]) return -EINVAL; scpy(out, id_link[i], PATH_MAX); return 1; }
    return 0;
}
