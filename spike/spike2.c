/* spike2.c — second spike: the opener as the can's ELF interpreter.
 *
 * Built as an ET_DYN object with no PT_INTERP (like ld.so itself), so it can be
 * (1) run directly as the entry program, (2) used as the PT_INTERP of every
 * patched ELF in the can via the path /proc/self/fd/999, and (3) loaded by
 * itself in "--child" loader mode for targets without a usable PT_INTERP
 * (static binaries, host programs).
 *
 * Modes, decided at startup:
 *   AT_BASE != 0            interpreter mode: the kernel mapped the program and us;
 *                           install handler, map the real ld.so, fix AT_BASE, jump.
 *   argv[1] == "--child"    loader mode (as in spike 1).
 *   otherwise               entry mode: spike2 [-d] [-r ROOT] [-p A:B] [-t TRACE]
 *                           [-i INTERP] -- /virtual/prog args...
 *
 * Configuration lives in spike.cfg next to the binary (stand-in for the manifest).
 * x86_64 only.
 */
#include "sys.h"

#define PATH_MAX 4096
#define INTERP_FD 999
#define INTERP_STR "/proc/self/fd/999"
#define SIGSYS 31
#define SA_SIGINFO   4
#define SA_ONSTACK   0x08000000
#define SA_RESTORER  0x04000000
#define SA_NODEFER   0x40000000
#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2
#define NR_seccomp 317
#define NR_exit_group_ 231
#define PR_SET_NAME 15
#define PR_SET_SECCOMP 22
#define SECCOMP_MODE_FILTER 2
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_RET_ALLOW 0x7fff0000u
#define SECCOMP_RET_TRAP  0x00030000u
#define SECCOMP_RET_KILL_PROCESS 0x80000000u
#define AUDIT_ARCH_X86_64 0xC000003Eu
#define X32_SYSCALL_BIT 0x40000000u
#define AT_SYMLINK_FOLLOW 0x400
#define O_EXCL_ 0200
#define O_APPEND_ 02000
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 2
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED_NOREPLACE 0x100000
#define ELOOP 40
#define EBADF 9
#define ENOEXEC 8
#define E2BIG 7
#define ENOMEM 12
#define F_GETFD 1
#define F_SETFD 2
#define CLONE_CLEAR_SIGHAND 0x100000000UL

enum {
    NR_open = 2, NR_stat = 4, NR_lstat = 6, NR_access = 21, NR_dup2 = 33, NR_fcntl = 72,
    NR_truncate = 76, NR_rename = 82, NR_mkdir = 83, NR_rmdir = 84, NR_creat = 85, NR_link = 86,
    NR_unlink = 87, NR_symlink = 88, NR_readlink = 89, NR_chmod = 90, NR_chown = 92, NR_lchown = 94,
    NR_utime = 132, NR_mknod = 133, NR_uselib = 134, NR_chroot = 161, NR_acct = 163,
    NR_setxattr = 188, NR_lsetxattr = 189, NR_getxattr = 191, NR_lgetxattr = 192,
    NR_listxattr = 194, NR_llistxattr = 195, NR_removexattr = 197, NR_lremovexattr = 198,
    NR_utimes = 235, NR_inotify_add_watch = 254, NR_mknodat = 259, NR_fchownat = 260,
    NR_futimesat = 261, NR_renameat = 264, NR_linkat = 265, NR_fchmodat = 268,
    NR_utimensat = 280, NR_name_to_handle_at = 303, NR_renameat2 = 316,
    NR_execveat = 322, NR_statx = 332, NR_clone3 = 435, NR_close_range = 436,
    NR_openat2 = 437, NR_faccessat2 = 439, NR_fchmodat2 = 452,
};

/* ---------- ELF ---------- */
typedef struct { unsigned char e_ident[16]; uint16_t e_type, e_machine; uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff; uint32_t e_flags; uint16_t e_ehsize, e_phentsize, e_phnum,
    e_shentsize, e_shnum, e_shstrndx; } Ehdr;
typedef struct { uint32_t p_type, p_flags; uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align; } Phdr;
#define PT_LOAD 1
#define PT_INTERP 3
#define PT_NOTE 4
#define PT_PHDR 6
#define ET_EXEC 2
#define ET_DYN 3
#define PF_X 1
#define PF_W 2
#define PF_R 4
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_BASE 7
#define AT_ENTRY 9

/* ---------- freestanding glue ---------- */
void *memcpy(void *d, const void *s, size_t n) { return xmemcpy(d, s, n); }
void *memset(void *d, int c, size_t n) { return xmemset(d, c, n); }
void *memmove(void *d, const void *s, size_t n) {
    char *dd = d; const char *ss = s;
    if (dd < ss) { while (n--) *dd++ = *ss++; } else { dd += n; ss += n; while (n--) *--dd = *--ss; }
    return d;
}
int memcmp(const void *a, const void *b, size_t n) { return xmemcmp(a, b, n); }
size_t strlen(const char *s) { return xstrlen(s); }

__asm__(
    ".text\n.globl _start\n_start:\n"
    "  xor %rbp, %rbp\n  mov %rsp, %rdi\n  and $-16, %rsp\n  call cmain\n  hlt\n"
    ".globl sig_restorer\nsig_restorer:\n  mov $15, %rax\n  syscall\n"
    /* identification note: other openers are recognised by it */
    ".section .note.cont,\"a\",@note\n.balign 4\n.long 5\n.long 4\n.long 1\n.asciz \"cont\"\n.balign 4\n.long 1\n.previous\n");
void sig_restorer(void);
extern const unsigned long _DYNAMIC[] __attribute__((visibility("hidden")));
extern char __ehdr_start[] __attribute__((visibility("hidden")));

/* self-relocation for ET_DYN: only R_X86_64_RELATIVE is expected */
static void reloc_self(void)
{
    unsigned long base = (unsigned long)__ehdr_start, rela = 0, relasz = 0;
    for (const unsigned long *d = _DYNAMIC; d[0]; d += 2) { if (d[0] == 7) rela = d[1]; else if (d[0] == 8) relasz = d[1]; }
    if (!rela) return;
    typedef struct { unsigned long off, info; long addend; } Rela;
    const Rela *r = (const Rela *)(base + rela);
    for (unsigned long i = 0; i < relasz / sizeof(Rela); i++)
        if ((r[i].info & 0xffffffffu) == 8) *(unsigned long *)(base + r[i].off) = base + (unsigned long)r[i].addend;
}

/* ---------- state ---------- */
static char g_self[PATH_MAX];       /* real path of this binary */
static char g_root[PATH_MAX]; static long g_rootlen;
static char g_pass[PATH_MAX]; static const char *g_passv[64]; static int g_passn;
static char g_trace[PATH_MAX]; static int g_tracefd = -1;
static char g_interp[PATH_MAX];     /* the can's real ld.so, virtual path */
static char g_vexe[PATH_MAX];       /* loader mode only: virtual path of the program */
static int g_debug; static volatile int g_probe; static long g_traps;

#define dbg(...) do { if (g_debug) { outs(2, "[spike2 "); outn(2, sys_getpid()); outs(2, "] "); dbg_(__VA_ARGS__, (const char *)0); } } while (0)
static void dbg_(const char *s, ...)
{ __builtin_va_list ap; __builtin_va_start(ap, s); while (s) { outs(2, s); s = __builtin_va_arg(ap, const char *); } __builtin_va_end(ap); outs(2, "\n"); }
static __attribute__((noreturn)) void die(const char *a, const char *b, long err)
{ outs(2, "spike2: "); outs(2, a); if (b) { outs(2, " "); outs(2, b); } if (err) { outs(2, ": "); outs(2, strerr(err)); } outs(2, "\n"); sys_exit(127); }

static char *scpy(char *d, const char *s, size_t n) { size_t l = xstrlen(s); if (l >= n) l = n - 1; xmemcpy(d, s, l); d[l] = 0; return d; }
static char *scat(char *d, const char *s, size_t n) { size_t l = xstrlen(d); scpy(d + l, s, n - l); return d; }
static const char *basename_(const char *p) { const char *b = xstrrchr(p, '/'); return b ? b + 1 : p; }
static void ltoa_(long v, char *b) { int i = 0; char t[24]; if (v == 0) t[i++] = '0'; while (v) { t[i++] = '0' + v % 10; v /= 10; } while (i) *b++ = t[--i]; *b = 0; }

/* ---------- scratch pool ---------- */
struct scratch { char b1[PATH_MAX], b2[PATH_MAX], rest[PATH_MAX], cur[PATH_MAX], real[PATH_MAX], tmp[PATH_MAX], v[PATH_MAX]; };
#define NSLOT 32
static struct scratch g_slot[NSLOT]; static volatile int g_busy[NSLOT];
static struct scratch *grab(void) { for (int i = 0; i < NSLOT; i++) if (!g_busy[i] && !__sync_lock_test_and_set(&g_busy[i], 1)) return &g_slot[i]; return 0; }
static void release(struct scratch *s) { if (s) __sync_lock_release(&g_busy[s - g_slot]); }

/* ---------- path translation ---------- */
static int is_pass(const char *v)
{
    for (int i = 0; i < g_passn; i++) { size_t l = xstrlen(g_passv[i]); if (xstrncmp(v, g_passv[i], l) == 0 && (v[l] == '/' || v[l] == 0)) return 1; }
    return 0;
}
static char *to_real(const char *v, char *out)
{
    if (!g_rootlen || is_pass(v)) return scpy(out, v, PATH_MAX);
    scpy(out, g_root, PATH_MAX); if (!(v[0] == '/' && v[1] == 0)) scat(out, v, PATH_MAX); return out;
}
static void from_real(char *r)
{
    if (!g_rootlen) return;
    if (xstrncmp(r, g_root, g_rootlen) == 0) {
        if (r[g_rootlen] == 0) { r[0] = '/'; r[1] = 0; }
        else if (r[g_rootlen] == '/') memmove(r, r + g_rootlen, xstrlen(r + g_rootlen) + 1);
    }
}
static int is_proc_self(const char *v, const char **rest)
{
    if (xstrncmp(v, "/proc/", 6) != 0) return 0;
    const char *p = v + 6;
    if (xstrncmp(p, "self", 4) == 0 && (p[4] == '/' || p[4] == 0)) { *rest = p + 4; return 1; }
    char pid[24]; ltoa_(sys_getpid(), pid); size_t l = xstrlen(pid);
    if (xstrncmp(p, pid, l) == 0 && (p[l] == '/' || p[l] == 0)) { *rest = p + l; return 1; }
    return 0;
}
static int fd_virtual(int fd, char *out)
{
    char l[64] = "/proc/self/fd/"; char n[24]; ltoa_(fd, n); scat(l, n, 64);
    long r = sys_readlink(l, out, PATH_MAX - 1); if (r < 0) return (int)r;
    out[r] = 0; from_real(out); return 0;
}
static int cwd_virtual(char *out) { long r = sys_getcwd(out, PATH_MAX); if (r < 0) return (int)r; from_real(out); return 0; }

/* Canonicalise in virtual space. A symlink found at a host-owned location moves
 * the rest of the resolution into the host domain (review B.1). */
static int canon_s(struct scratch *S, const char *path, int dfd, int follow_last, char *out)
{
    char *rest = S->rest, *cur = S->cur, *real = S->real, *tmp = S->tmp;
    int hops = 0, hostdom = 0;
    if (path[0] == '/') scpy(rest, path, PATH_MAX);
    else { int r = (dfd == AT_FDCWD) ? cwd_virtual(rest) : fd_virtual(dfd, rest); if (r < 0) return r; scat(rest, "/", PATH_MAX); scat(rest, path, PATH_MAX); }
    cur[0] = 0; char *rp = rest;
    for (;;) {
        while (*rp == '/') rp++;
        if (!*rp) break;
        char *e = rp; while (*e && *e != '/') e++;
        size_t cl = (size_t)(e - rp); char comp[256]; if (cl >= sizeof comp) return -ENAMETOOLONG;
        xmemcpy(comp, rp, cl); comp[cl] = 0; rp = e;
        if (comp[0] == '.' && comp[1] == 0) continue;
        if (comp[0] == '.' && comp[1] == '.' && comp[2] == 0) { char *s = xstrrchr(cur, '/'); if (s) *s = 0; else cur[0] = 0; continue; }
        size_t curl = xstrlen(cur); if (curl + 1 + cl + 1 >= PATH_MAX) return -ENAMETOOLONG;
        cur[curl] = '/'; xmemcpy(cur + curl + 1, comp, cl + 1);
        while (*rp == '/') rp++;
        int last = (*rp == 0);
        if (last && !follow_last) break;
        const char *pr;
        if (g_vexe[0] && is_proc_self(cur, &pr) && xstrcmp(pr, "/exe") == 0) {   /* loader mode only */
            if (++hops > 40) return -ELOOP;
            scpy(tmp, g_vexe, PATH_MAX); scat(tmp, "/", PATH_MAX); scat(tmp, rp, PATH_MAX);
            scpy(rest, tmp, PATH_MAX); rp = rest; cur[0] = 0; continue;
        }
        int host_here = hostdom || is_pass(cur);
        if (hostdom) scpy(real, cur, PATH_MAX); else to_real(cur, real);
        struct kstat st;
        if (sys_lstat(real, &st) < 0) continue;
        if ((st.st_mode & S_IFMT) != S_IFLNK) continue;
        if (++hops > 40) return -ELOOP;
        long n = sys_readlink(real, tmp, PATH_MAX - 1); if (n < 0) continue;
        tmp[n] = 0;
        if (xstrncmp(cur, "/proc/", 6) == 0) from_real(tmp);
        else if (host_here) hostdom = 1;                          /* host symlink: host target */
        size_t tl = xstrlen(tmp), rl = xstrlen(rp);
        if (tl + 1 + rl + 1 >= PATH_MAX) return -ENAMETOOLONG;
        memmove(rest + tl + 1, rp, rl + 1); xmemcpy(rest, tmp, tl); rest[tl] = '/'; rp = rest;
        if (tmp[0] == '/') cur[0] = 0; else { char *s = xstrrchr(cur, '/'); if (s) *s = 0; else cur[0] = 0; }
    }
    if (!cur[0]) { cur[0] = '/'; cur[1] = 0; }
    scpy(out, cur, PATH_MAX);
    return hostdom ? 1 : 0;      /* 1: out is a host path, do not prefix */
}
static int canon(const char *path, int dfd, int follow_last, char *out)
{ struct scratch *S = grab(); if (!S) return -ENOMEM; int r = canon_s(S, path, dfd, follow_last, out); release(S); return r; }

static void trace(const char *v)
{ if (g_tracefd < 0) return; char b[PATH_MAX + 1]; size_t l = xstrlen(v); if (l > PATH_MAX - 1) l = PATH_MAX - 1; xmemcpy(b, v, l); b[l] = '\n'; sys_write(g_tracefd, b, l + 1); }

/* translate a path argument; returns the pointer to pass to the kernel */
static const char *xlate(const char *p, int dfd, int follow_last, char *out, int *err)
{
    *err = 0;
    if (!p || !p[0]) return p;
    struct scratch *S = grab(); if (!S) { *err = -ENOMEM; return p; }
    int r = canon_s(S, p, dfd, follow_last, S->v);
    if (r < 0) { release(S); *err = r; return p; }
    trace(S->v);
    if (r == 1) scpy(out, S->v, PATH_MAX); else to_real(S->v, out);
    release(S);
    return out;
}
/* resolve to (virtual path, real path); returns 1 if host domain */
static int resolve2(const char *p, int dfd, char *v, char *real)
{ int r = canon(p, dfd, 1, v); if (r < 0) return r; if (r == 1) scpy(real, v, PATH_MAX); else to_real(v, real); return r; }

/* ---------- ELF probing ---------- */
static Phdr g_ph[128];
/* returns 1 = has PT_INTERP (copied to interp), 0 = none, <0 = error; *is_opener set from .note.cont */
static int elf_probe(const char *real, char *interp, int *is_opener)
{
    *is_opener = 0;
    long fd = sys_open(real, O_RDONLY | O_CLOEXEC, 0); if (fd < 0) return (int)fd;
    Ehdr eh; Phdr ph[64]; int ret = -ENOEXEC;
    if (sys_pread(fd, &eh, sizeof eh, 0) == sizeof eh && eh.e_ident[0] == 0x7f && eh.e_ident[1] == 'E' && eh.e_phnum <= 64 && eh.e_phentsize == sizeof(Phdr)
        && sys_pread(fd, ph, (size_t)eh.e_phnum * sizeof(Phdr), (long)eh.e_phoff) == (long)(eh.e_phnum * sizeof(Phdr))) {
        ret = 0;
        for (int i = 0; i < eh.e_phnum; i++) {
            if (ph[i].p_type == PT_INTERP && ph[i].p_filesz < PATH_MAX) {
                if (sys_pread(fd, interp, ph[i].p_filesz, (long)ph[i].p_offset) == (long)ph[i].p_filesz) { interp[ph[i].p_filesz] = 0; ret = 1; }
            } else if (ph[i].p_type == PT_NOTE && ph[i].p_filesz <= 512) {
                unsigned char nb[512]; long n = sys_pread(fd, nb, ph[i].p_filesz, (long)ph[i].p_offset); long o = 0;
                while (n >= 12 && o + 12 <= n) {
                    uint32_t nsz = *(uint32_t *)(nb + o), dsz = *(uint32_t *)(nb + o + 4);
                    if (nsz == 5 && o + 12 + 5 <= n && xmemcmp(nb + o + 12, "cont", 5) == 0) *is_opener = 1;
                    o += 12 + ((nsz + 3) & ~3u) + ((dsz + 3) & ~3u);
                }
            }
        }
    }
    sys_close((int)fd);
    return ret;
}

/* ---------- fd 999 ---------- */
static void ensure_fd(void)
{
    struct kstat st;
    if (SC2(NR_fstat, INTERP_FD, &st) < 0) {
        long fd = sys_open(g_self, O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) { sys_dup3((int)fd, INTERP_FD, 0); sys_close((int)fd); }
    }
    SC3(NR_fcntl, INTERP_FD, F_SETFD, 0);   /* never close-on-exec */
}

/* ---------- exec ---------- */
static long do_exec(const char *path, int dfd, char *const *argv, char *const *envp, unsigned long framemask)
{
    struct scratch *S = grab(); if (!S) return -ENOMEM;
    char *v = S->b1, *real = S->b2, *xargv[64]; int xargc = 0;
    int host = resolve2(path, dfd, v, real); if (host < 0) { release(S); return host; }
    char shebang[2][256]; int depth = 0; char interp[PATH_MAX]; int has_interp = 0, is_opener = 0;
    for (;;) {
        long fd = sys_open(real, O_RDONLY | O_CLOEXEC, 0); if (fd < 0) { release(S); return fd; }
        char hdr[256]; long n = sys_read(fd, hdr, sizeof hdr - 1); sys_close(fd);
        if (n < 2) { release(S); return -ENOEXEC; }
        hdr[n] = 0;
        if (hdr[0] == 0x7f && hdr[1] == 'E') break;
        if (hdr[0] == '#' && hdr[1] == '!') {
            if (depth >= 2) { release(S); return -ELOOP; }
            char *l = hdr + 2, *e = xstrchr(l, '\n'); if (e) *e = 0;
            while (*l == ' ' || *l == '\t') l++;
            char *i = l; while (*i && *i != ' ' && *i != '\t') i++;
            char *arg = 0; if (*i) { *i++ = 0; while (*i == ' ' || *i == '\t') i++; if (*i) arg = i; }
            if (!*l) { release(S); return -ENOEXEC; }
            scpy(shebang[depth], l, 256); xargv[xargc++] = shebang[depth];
            if (arg) { char *a = shebang[depth] + xstrlen(shebang[depth]) + 1; scpy(a, arg, 256 - (a - shebang[depth])); xargv[xargc++] = a; }
            xargv[xargc++] = (char *)path;
            for (int k = 1; argv && argv[k] && xargc < 60; k++) xargv[xargc++] = argv[k];
            xargv[xargc] = 0; argv = xargv; depth++;
            host = resolve2(l, AT_FDCWD, v, real); if (host < 0) { release(S); return host; }
            continue;
        }
        release(S); return -ENOEXEC;
    }
    trace(v);
    host = host || !g_rootlen || is_pass(v);
    has_interp = elf_probe(real, interp, &is_opener);
    char rcopy[PATH_MAX]; scpy(rcopy, real, PATH_MAX);
    int kernel_exec = (has_interp == 1 && xstrcmp(interp, INTERP_STR) == 0) || (has_interp == 0 && is_opener);
    if (kernel_exec) {
        /* the kernel loads it; we are its interpreter via fd 999 */
        release(S);
        ensure_fd();
        SC4(NR_rt_sigprocmask, SIG_SETMASK, &framemask, 0, 8);
        dbg("kernel-exec ", rcopy);
        return sys_execve(rcopy, argv, envp);
    }
    /* loader mode for everything else: self --child root pass trace interp vpath argv... */
    int argc = 0; while (argv && argv[argc]) argc++;
    if (argc > 4000) { release(S); return -E2BIG; }
    char *cargv[argc + 9]; int c = 0;
    cargv[c++] = g_self; cargv[c++] = "--child";
    cargv[c++] = host ? "-" : g_root; cargv[c++] = g_pass[0] ? g_pass : "-"; cargv[c++] = g_trace[0] ? g_trace : "-";
    cargv[c++] = g_interp[0] ? g_interp : "-";
    char vcopy[PATH_MAX]; scpy(vcopy, v, PATH_MAX); cargv[c++] = vcopy;
    for (int k = 0; k < argc; k++) cargv[c++] = argv[k];
    cargv[c] = 0;
    release(S);
    SC4(NR_rt_sigprocmask, SIG_SETMASK, &framemask, 0, 8);
    dbg("loader-exec ", vcopy, host ? " (host)" : "");
    return sys_execve(g_self, cargv, envp);
}

/* ---------- clone3 with a prepared child frame ---------- */
static long clone3_child_frame(long args, long size, long child_sp)
{
    long ret;
    register long r10 __asm__("r10") = 0; register long r8 __asm__("r8") = 0; register long r9 __asm__("r9") = (long)MAGIC; register long csp __asm__("r12") = child_sp;
    __asm__ volatile ("syscall\n test %%rax, %%rax\n jnz 1f\n mov %%r12, %%rsp\n mov $15, %%eax\n syscall\n hlt\n1:\n"
                      : "=a"(ret) : "a"(NR_clone3), "D"(args), "S"(size), "d"(0), "r"(r10), "r"(r8), "r"(r9), "r"(csp) : "rcx", "r11", "memory");
    return ret;
}

/* ---------- the SIGSYS handler ---------- */
enum { R8 = 0, R9 = 1, R10 = 2, RDI = 8, RSI = 9, RDX = 12, RAX = 13, RSP = 15 };
static long sc(long nr, long a, long b, long c, long d, long e) { return __sc6(nr, a, b, c, d, e, MAGIC); }

static void on_sigsys(int sig, void *si, void *uc)
{
    (void)sig;
    int nr = *(int *)((char *)si + 24);
    unsigned long *r = (unsigned long *)((char *)uc + 40);
    unsigned long *ucmask = (unsigned long *)((char *)uc + 296);
    long a0 = r[RDI], a1 = r[RSI], a2 = r[RDX], a3 = r[R10], a4 = r[R8];
    g_traps++;
    if (g_probe == -1) { g_probe = 1; r[RAX] = (unsigned long)-ENOSYS; return; }
    struct scratch *H = grab(); if (!H) { r[RAX] = (unsigned long)-ENOMEM; return; }
    char *b1 = H->b1, *b2 = H->b2; int e1 = 0, e2 = 0; const char *p1, *p2; long ret;
#define P(arg, dfd, follow) (p1 = xlate((const char *)(arg), (dfd), (follow), b1, &e1))
#define P2(arg, dfd, follow) (p2 = xlate((const char *)(arg), (dfd), (follow), b2, &e2))
#define CHK if (e1) { ret = e1; break; } if (e2) { ret = e2; break; }
    switch (nr) {
    case NR_stat: case NR_access: case NR_truncate: case NR_chdir: case NR_chmod: case NR_chown:
    case NR_utime: case NR_utimes: case NR_statfs: case NR_setxattr: case NR_getxattr:
    case NR_listxattr: case NR_removexattr: case NR_uselib: case NR_acct: case NR_creat:
        P(a0, AT_FDCWD, 1); CHK; ret = sc(nr, (long)p1, a1, a2, a3, a4); break;
    case NR_lstat: case NR_rmdir: case NR_unlink: case NR_lchown: case NR_mkdir: case NR_mknod:
    case NR_lsetxattr: case NR_lgetxattr: case NR_llistxattr: case NR_lremovexattr:
        P(a0, AT_FDCWD, 0); CHK; ret = sc(nr, (long)p1, a1, a2, a3, a4); break;
    case NR_open: P(a0, AT_FDCWD, !(a1 & (O_NOFOLLOW | O_EXCL_))); CHK; ret = sc(nr, (long)p1, a1, a2, a3, a4); break;
    case NR_readlink: P(a0, AT_FDCWD, 0); CHK; ret = sc(nr, (long)p1, a1, a2, a3, a4); goto fix_readlink;
    case NR_rename: case NR_link: P(a0, AT_FDCWD, 0); P2(a1, AT_FDCWD, 0); CHK; ret = sc(nr, (long)p1, (long)p2, a2, a3, a4); break;
    case NR_symlink: P2(a1, AT_FDCWD, 0); CHK; ret = sc(nr, a0, (long)p2, a2, a3, a4); break;
    case NR_openat: P(a1, (int)a0, !(a2 & (O_NOFOLLOW | O_EXCL_))); CHK; ret = sc(nr, a0, (long)p1, a2, a3, a4); break;
    case NR_openat2: { unsigned long fl = a2 ? *(unsigned long *)a2 : 0; P(a1, (int)a0, !(fl & (O_NOFOLLOW | O_EXCL_))); CHK; ret = sc(nr, a0, (long)p1, a2, a3, a4); break; }
    case NR_mkdirat: case NR_mknodat: case NR_unlinkat: P(a1, (int)a0, 0); CHK; ret = sc(nr, a0, (long)p1, a2, a3, a4); break;
    case NR_futimesat: case NR_fchmodat: case NR_faccessat: case NR_inotify_add_watch: P(a1, (int)a0, 1); CHK; ret = sc(nr, a0, (long)p1, a2, a3, a4); break;
    case NR_newfstatat: case NR_utimensat: case NR_faccessat2: case NR_fchmodat2: P(a1, (int)a0, !(a3 & AT_SYMLINK_NOFOLLOW)); CHK; ret = sc(nr, a0, (long)p1, a2, a3, a4); break;
    case NR_statx: P(a1, (int)a0, !(a2 & AT_SYMLINK_NOFOLLOW)); CHK; ret = sc(nr, a0, (long)p1, a2, a3, a4); break;
    case NR_fchownat: case NR_name_to_handle_at: P(a1, (int)a0, !(a4 & AT_SYMLINK_NOFOLLOW)); CHK; ret = sc(nr, a0, (long)p1, a2, a3, a4); break;
    case NR_readlinkat:
        P(a1, (int)a0, 0); CHK; ret = sc(nr, a0, (long)p1, a2, a3, a4); a1 = a2; a2 = a3;
    fix_readlink:
        if (ret > 0) {
            const char *pr; char *vv = H->rest; scpy(vv, p1, PATH_MAX); from_real(vv);
            if (g_vexe[0] && is_proc_self(vv, &pr) && xstrcmp(pr, "/exe") == 0) {           /* loader mode only */
                size_t l = xstrlen(g_vexe); if (l > (size_t)a2) l = (size_t)a2; xmemcpy((char *)a1, g_vexe, l); ret = (long)l;
            } else if (xstrncmp(vv, "/proc/", 6) == 0 && ret < (long)a2) {
                char *t = H->tmp; xmemcpy(t, (char *)a1, (size_t)ret); t[ret] = 0; from_real(t);
                size_t l = xstrlen(t); if (l > (size_t)a2) l = (size_t)a2; xmemcpy((char *)a1, t, l); ret = (long)l;
            }
        }
        break;
    case NR_renameat: case NR_renameat2: P(a1, (int)a0, 0); P2(a3, (int)a2, 0); CHK; ret = sc(nr, a0, (long)p1, a2, (long)p2, a4); break;
    case NR_linkat: P(a1, (int)a0, !!(a4 & AT_SYMLINK_FOLLOW)); P2(a3, (int)a2, 0); CHK; ret = sc(nr, a0, (long)p1, a2, (long)p2, a4); break;
    case NR_symlinkat: P2(a2, (int)a1, 0); CHK; ret = sc(nr, a0, a1, (long)p2, a3, a4); break;
    case NR_execve:
        release(H); H = 0;
        ret = do_exec((const char *)a0, AT_FDCWD, (char *const *)a1, (char *const *)a2, *ucmask); break;
    case NR_execveat: {
        const char *pp = (const char *)a1;
        if ((a4 & AT_EMPTY_PATH) && (!pp || !pp[0])) { if (fd_virtual((int)a0, b1) < 0) { ret = -EBADF; break; } pp = b1; a0 = AT_FDCWD; }
        char pcopy[PATH_MAX]; scpy(pcopy, pp, PATH_MAX); release(H); H = 0;
        ret = do_exec(pcopy, (int)a0, (char *const *)a2, (char *const *)a3, *ucmask); break; }
    case NR_getcwd:
        ret = sc(nr, a0, a1, 0, 0, 0);
        if (ret > 0) { from_real((char *)a0); ret = (long)xstrlen((char *)a0) + 1; }
        break;
    case NR_rt_sigaction:
        if (a0 == SIGSYS && a1) { ret = a2 ? sc(nr, a0, 0, a2, a3, a4) : 0; break; }
        ret = sc(nr, a0, a1, a2, a3, a4); break;
    case NR_rt_sigprocmask: {
        unsigned long old = *ucmask;
        if (a3 != 8) { ret = -EINVAL; break; }
        if (a2) *(unsigned long *)a2 = old;
        if (a1) {
            unsigned long s = *(unsigned long *)a1, nw;
            if (a0 == SIG_BLOCK) nw = old | s; else if (a0 == SIG_UNBLOCK) nw = old & ~s; else if (a0 == SIG_SETMASK) nw = s; else { ret = -EINVAL; break; }
            nw &= ~((1UL << (SIGSYS - 1)) | (1UL << (9 - 1)) | (1UL << (19 - 1)));
            *ucmask = nw;
        }
        ret = 0; break; }
    case NR_clone3: {
        struct clone_args { unsigned long flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls; } *ca = (void *)a0;
        if (!ca || a1 < 64) { ret = sc(nr, a0, a1, a2, a3, a4); break; }
        ca->flags &= ~CLONE_CLEAR_SIGHAND;
        if (!ca->stack) { ret = sc(nr, a0, a1, a2, a3, a4); break; }
        unsigned long top = ca->stack + ca->stack_size;
        char *frame = (char *)uc - 8, *dst = (char *)(((top - 512 - 64) & ~15UL) - 8);
        xmemcpy(dst, frame, 512);
        unsigned long *cr = (unsigned long *)(dst + 8 + 40); cr[RAX] = 0; cr[RSP] = top;
        ret = clone3_child_frame(a0, a1, (long)(dst + 8)); break; }
    /* --- fd 999 protection --- */
    case NR_close: ret = (a0 == INTERP_FD) ? 0 : sc(nr, a0, 0, 0, 0, 0); break;
    case NR_dup2: case NR_dup3: ret = (a1 == INTERP_FD) ? -EBADF : sc(nr, a0, a1, a2, 0, 0); break;
    case NR_fcntl: ret = (a0 == INTERP_FD && a1 == F_SETFD) ? 0 : sc(nr, a0, a1, a2, 0, 0); break;
    case NR_close_range:
        if (a0 <= INTERP_FD && a1 >= INTERP_FD) {
            long r1 = a0 < INTERP_FD ? sc(nr, a0, INTERP_FD - 1, a2, 0, 0) : 0;
            long r2 = a1 > INTERP_FD ? sc(nr, INTERP_FD + 1, a1, a2, 0, 0) : 0;
            ret = r1 < 0 ? r1 : r2;
        } else ret = sc(nr, a0, a1, a2, 0, 0);
        break;
    case NR_mount: case NR_umount2: case NR_pivot_root: case NR_chroot: ret = -EPERM; break;
    case NR_exit_group_:
        if (g_debug) { outs(2, "[spike2] traps in pid "); outn(2, sys_getpid()); outs(2, ": "); outn(2, g_traps); outs(2, "\n"); }
        ret = sc(nr, a0, a1, a2, a3, a4); break;
    default: ret = sc(nr, a0, a1, a2, a3, a4); break;
    }
    r[RAX] = (unsigned long)ret;
    release(H);
}

/* ---------- seccomp filter ---------- */
struct sock_filter { uint16_t code; uint8_t jt, jf; uint32_t k; };
struct sock_fprog { unsigned short len; struct sock_filter *filter; };
#define LD_ABS 0x20
#define JEQ_K  0x15
#define JGT_K  0x25
#define JGE_K  0x35
#define JSET_K 0x45
#define RET_K  0x06
static const int trapped[] = {
    NR_open, NR_stat, NR_lstat, NR_access, NR_execve, NR_truncate, NR_getcwd, NR_chdir, NR_rename, NR_mkdir, NR_rmdir,
    NR_creat, NR_link, NR_unlink, NR_symlink, NR_readlink, NR_chmod, NR_chown, NR_lchown, NR_utime, NR_mknod, NR_uselib,
    NR_statfs, NR_chroot, NR_acct, NR_mount, NR_umount2, NR_pivot_root, NR_setxattr, NR_lsetxattr, NR_getxattr, NR_lgetxattr,
    NR_listxattr, NR_llistxattr, NR_removexattr, NR_lremovexattr, NR_utimes, NR_inotify_add_watch, NR_openat, NR_mkdirat,
    NR_mknodat, NR_fchownat, NR_futimesat, NR_newfstatat, NR_unlinkat, NR_renameat, NR_linkat, NR_symlinkat, NR_readlinkat,
    NR_fchmodat, NR_faccessat, NR_utimensat, NR_name_to_handle_at, NR_renameat2, NR_execveat, NR_statx, NR_openat2,
    NR_faccessat2, NR_fchmodat2, NR_rt_sigaction, NR_rt_sigprocmask, NR_exit_group_, NR_clone3,
};
#define NTRAP ((int)(sizeof trapped / sizeof trapped[0]))

/* tiny assembler: jumps carry absolute targets, fixed up at the end */
static struct sock_filter F[NTRAP + 64]; static int FT[NTRAP + 64], FF[NTRAP + 64]; static int FN;
static int emit(uint16_t code, uint32_t k, int jt, int jf) { F[FN] = (struct sock_filter){ code, 0, 0, k }; FT[FN] = jt; FF[FN] = jf; return FN++; }
enum { L_ALLOW = -1, L_TRAP = -2, L_KILL = -3 };

static void install_filter(void)
{
    FN = 0;
    emit(LD_ABS, 4, 0, 0);                                   /* arch */
    int j = emit(JEQ_K, AUDIT_ARCH_X86_64, 0, L_KILL); FT[j] = j + 1;
    emit(LD_ABS, 56, 0, 0);                                  /* args[5] lo */
    int jlo = emit(JEQ_K, (uint32_t)(MAGIC & 0xffffffffu), 0, 0);
    emit(LD_ABS, 60, 0, 0);                                  /* args[5] hi */
    int jhi = emit(JEQ_K, (uint32_t)(MAGIC >> 32), L_ALLOW, 0);
    int nrl = emit(LD_ABS, 0, 0, 0);                         /* nr */
    FT[jlo] = jlo + 1; FF[jlo] = nrl; FF[jhi] = nrl;
    j = emit(JSET_K, X32_SYSCALL_BIT, L_KILL, 0); FF[j] = j + 1;
    /* fd-protected syscalls: trap only when the fd argument is INTERP_FD */
    struct { int nr, argoff; } fdp[] = { { NR_close, 16 }, { NR_dup2, 24 }, { NR_dup3, 24 }, { NR_fcntl, 16 } };
    for (int i = 0; i < 4; i++) {
        int a = emit(JEQ_K, (uint32_t)fdp[i].nr, 0, 0); FT[a] = a + 1; FF[a] = a + 3;
        emit(LD_ABS, (uint32_t)fdp[i].argoff, 0, 0);
        emit(JEQ_K, INTERP_FD, L_TRAP, L_ALLOW);
        emit(LD_ABS, 0, 0, 0);                               /* reload nr for the chain */
        FF[a] = FN;                                          /* not this nr: skip to next test */
    }
    { int a = emit(JEQ_K, NR_close_range, 0, 0); FT[a] = a + 1;
      emit(LD_ABS, 16, 0, 0); emit(JGT_K, INTERP_FD, L_ALLOW, 0); FF[FN - 1] = FN;
      emit(LD_ABS, 24, 0, 0); emit(JGE_K, INTERP_FD, L_TRAP, L_ALLOW);
      emit(LD_ABS, 0, 0, 0); FF[a] = FN; }
    for (int i = 0; i < NTRAP; i++) { int a = emit(JEQ_K, (uint32_t)trapped[i], L_TRAP, 0); FF[a] = a + 1; }
    int allow = emit(RET_K, SECCOMP_RET_ALLOW, 0, 0);
    int trap = emit(RET_K, SECCOMP_RET_TRAP, 0, 0);
    int kill = emit(RET_K, SECCOMP_RET_KILL_PROCESS, 0, 0);
    for (int i = 0; i < FN; i++) {
        if ((F[i].code & 0x07) != 0x05) continue;             /* not a jump */
        int t = FT[i] == L_ALLOW ? allow : FT[i] == L_TRAP ? trap : FT[i] == L_KILL ? kill : FT[i];
        int f = FF[i] == L_ALLOW ? allow : FF[i] == L_TRAP ? trap : FF[i] == L_KILL ? kill : FF[i];
        if (t == 0) t = i + 1; if (f == 0) f = i + 1;
        F[i].jt = (uint8_t)(t - i - 1); F[i].jf = (uint8_t)(f - i - 1);
    }
    struct sock_fprog prog = { (unsigned short)FN, F };
    if (sys_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) die("no_new_privs", 0, -1);
    long r = SC3(NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
    if (r < 0) r = sys_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (unsigned long)&prog, 0, 0);
    if (r < 0) die("seccomp", 0, r);
}

static void install_handler(void)
{
    /* all signals masked during the handler except SIGSYS (review B.9); SA_NODEFER so
     * SIGSYS itself is not added; exec paths restore the program's mask explicitly */
    struct { void *h; unsigned long flags; void *restorer; unsigned long mask; } sa =
        { (void *)on_sigsys, SA_SIGINFO | SA_ONSTACK | SA_RESTORER | SA_NODEFER, (void *)sig_restorer, ~(1UL << (SIGSYS - 1)) };
    if (SC4(NR_rt_sigaction, SIGSYS, &sa, 0, 8) < 0) die("sigaction", 0, -1);
}
static void arm(void)
{
    install_handler();
    g_probe = -1; __sc6(NR_getcwd, 0, 0, 0, 0, 0, 0);
    if (g_probe == 1) dbg("inherited filter"); else { g_probe = 0; install_filter(); dbg("installed filter"); }
    g_probe = 0;
    if (g_trace[0]) { long t = sys_open(g_trace, O_WRONLY | O_CREAT | O_APPEND_ | O_CLOEXEC, 0644); if (t >= 0) g_tracefd = (int)t; }
}

/* ---------- ELF mapping ---------- */
static unsigned long map_elf(int fd, const Ehdr *eh, const Phdr *ph, unsigned long *entry, unsigned long *phdr_va, int *has_interp, char *interp)
{
    unsigned long lo = ~0UL, hi = 0; *has_interp = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_INTERP) { if (ph[i].p_filesz >= PATH_MAX) die("interp too long", 0, 0); if (sys_pread(fd, interp, ph[i].p_filesz, (long)ph[i].p_offset) != (long)ph[i].p_filesz) die("read interp", 0, 0); interp[ph[i].p_filesz] = 0; *has_interp = 1; }
        if (ph[i].p_type != PT_LOAD) continue;
        unsigned long s = ph[i].p_vaddr & ~0xfffUL, e = (ph[i].p_vaddr + ph[i].p_memsz + 0xfff) & ~0xfffUL;
        if (s < lo) lo = s;
        if (e > hi) hi = e;
    }
    if (lo == ~0UL) die("no PT_LOAD", 0, 0);
    unsigned long bias = 0;
    if (eh->e_type == ET_DYN) { long base = sys_mmap(0, hi - lo, 0, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); if (base < 0 && base > -4096) die("reserve", 0, base); bias = (unsigned long)base - lo; }
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        int prot = (ph[i].p_flags & PF_R ? PROT_READ : 0) | (ph[i].p_flags & PF_W ? PROT_WRITE : 0) | (ph[i].p_flags & PF_X ? PROT_EXEC : 0);
        unsigned long va = bias + ph[i].p_vaddr, off = ph[i].p_vaddr & 0xfff, mstart = va - off, flen = ph[i].p_filesz + off, mlen = ph[i].p_memsz + off;
        int fixed = (eh->e_type == ET_DYN) ? MAP_FIXED : MAP_FIXED_NOREPLACE;
        if (flen) { long m = sys_mmap((void *)mstart, flen, prot, MAP_PRIVATE | fixed, fd, (long)(ph[i].p_offset - off)); if (m < 0 && m > -4096) die("map segment", 0, m); }
        if (mlen > flen) {
            unsigned long fend = mstart + flen, zend = (fend + 0xfff) & ~0xfffUL;
            if ((ph[i].p_flags & PF_W) && flen) xmemset((void *)fend, 0, zend - fend);
            if (mstart + mlen > zend) { long m = sys_mmap((void *)zend, mstart + mlen - zend, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0); if (m < 0 && m > -4096) die("map bss", 0, m); }
        }
    }
    *entry = bias + eh->e_entry; *phdr_va = 0;
    for (int i = 0; i < eh->e_phnum; i++) if (ph[i].p_type == PT_PHDR) *phdr_va = bias + ph[i].p_vaddr;
    if (!*phdr_va) for (int i = 0; i < eh->e_phnum; i++) if (ph[i].p_type == PT_LOAD && ph[i].p_offset <= eh->e_phoff && eh->e_phoff < ph[i].p_offset + ph[i].p_filesz) { *phdr_va = bias + ph[i].p_vaddr + (eh->e_phoff - ph[i].p_offset); break; }
    return bias;
}
static int open_elf(const char *real, Ehdr *eh, Phdr *ph, int maxph)
{
    long fd = sys_open(real, O_RDONLY | O_CLOEXEC, 0); if (fd < 0) die("open", real, fd);
    if (sys_pread(fd, eh, sizeof *eh, 0) != sizeof *eh || eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E') die("not an ELF", real, 0);
    if (eh->e_ident[4] != 2 || eh->e_machine != 62) die("not x86_64 ELF", real, 0);
    if (eh->e_phnum > maxph || eh->e_phentsize != sizeof(Phdr)) die("bad phdrs", real, 0);
    if (sys_pread(fd, ph, (size_t)eh->e_phnum * sizeof(Phdr), (long)eh->e_phoff) != (long)(eh->e_phnum * sizeof(Phdr))) die("read phdrs", real, 0);
    return (int)fd;
}
/* map the can's real ld.so; returns its base and entry */
static unsigned long map_interp(const char *interp_v, unsigned long *ientry)
{
    char cv[PATH_MAX], ir[PATH_MAX]; int host = resolve2(interp_v, AT_FDCWD, cv, ir); if (host < 0) die("interp", interp_v, host);
    Ehdr ih; static Phdr iph[64]; unsigned long iphdr; int ii; char dummy[PATH_MAX];
    int ifd = open_elf(ir, &ih, iph, 64);
    unsigned long base = map_elf(ifd, &ih, iph, ientry, &iphdr, &ii, dummy) + 0;   /* bias == base for lo == 0 */
    sys_close(ifd); dbg("interp ", ir);
    return base;
}

/* loader mode: full userland exec (static binaries, host programs) */
static __attribute__((noreturn)) void ul_exec(const char *vpath, long argc, char **argv, char **envp, unsigned long *auxv)
{
    char real[PATH_MAX], interp_v[PATH_MAX], cv[PATH_MAX];
    Ehdr eh; unsigned long entry, phdr_va, base = 0, jump; int has_interp;
    { int r = resolve2(vpath, AT_FDCWD, cv, real); if (r < 0) die("resolve", vpath, r); }
    scpy(g_vexe, cv, PATH_MAX);
    int fd = open_elf(real, &eh, g_ph, 128);
    map_elf(fd, &eh, g_ph, &entry, &phdr_va, &has_interp, interp_v); sys_close(fd);
    jump = entry;
    if (has_interp) { unsigned long ie; base = map_interp(interp_v, &ie); jump = ie; }
    long auxc = 0; while (auxv[auxc * 2] != AT_NULL) auxc++;
    long envc = 0; while (envp[envc]) envc++;
    unsigned long words = 1 + argc + 1 + envc + 1 + (auxc + 1) * 2 + 2;
    unsigned long *sp = (unsigned long *)(((unsigned long)__builtin_alloca(words * 8 + 1024) + 15) & ~15UL), *w = sp;
    *w++ = (unsigned long)argc; for (long i = 0; i < argc; i++) *w++ = (unsigned long)argv[i]; *w++ = 0;
    for (long i = 0; i < envc; i++) *w++ = (unsigned long)envp[i]; *w++ = 0;
    int seen = 0;
    for (long i = 0; i < auxc; i++) {
        unsigned long k = auxv[i * 2], v = auxv[i * 2 + 1];
        switch (k) { case AT_PHDR: v = phdr_va; break; case AT_PHENT: v = sizeof(Phdr); break; case AT_PHNUM: v = eh.e_phnum; break;
                     case AT_BASE: v = base; break; case AT_ENTRY: v = entry; break; case AT_EXECFN: v = (unsigned long)vpath; seen = 1; break; }
        *w++ = k; *w++ = v;
    }
    if (!seen) { *w++ = AT_EXECFN; *w++ = (unsigned long)vpath; }
    *w++ = AT_NULL; *w++ = 0;
    char nm[16]; scpy(nm, basename_(vpath), 16); sys_prctl(PR_SET_NAME, (unsigned long)nm, 0, 0, 0);
    dbg("loader jump ", vpath);
    __asm__ volatile ("mov %0, %%rsp\n xor %%rdx, %%rdx\n xor %%rbp, %%rbp\n jmp *%1\n" : : "r"(sp), "r"(jump) : "memory");
    __builtin_unreachable();
}

/* ---------- configuration ---------- */
static void set_root(const char *r)
{
    if (!r || xstrcmp(r, "-") == 0 || !r[0]) { g_root[0] = 0; g_rootlen = 0; return; }
    g_rootlen = 0; g_passn = 0;
    if (canon(r, AT_FDCWD, 1, g_root) < 0) die("bad root", r, 0);
    g_rootlen = (long)xstrlen(g_root); while (g_rootlen > 1 && g_root[g_rootlen - 1] == '/') g_root[--g_rootlen] = 0;
}
static void set_pass(const char *p)
{
    g_passn = 0; g_pass[0] = 0;
    if (!p || xstrcmp(p, "-") == 0) return;
    scpy(g_pass, p, PATH_MAX); static char split[PATH_MAX]; scpy(split, p, PATH_MAX);
    char *s = split; while (s && *s && g_passn < 64) { char *c = xstrchr(s, ':'); if (c) *c = 0; if (*s) g_passv[g_passn++] = s; s = c ? c + 1 : 0; }
}
static void cfg_path(char *out) { scpy(out, g_self, PATH_MAX); char *s = xstrrchr(out, '/'); if (s) *s = 0; scat(out, "/spike.cfg", PATH_MAX); }
static void cfg_write(void)
{
    char p[PATH_MAX]; cfg_path(p);
    long fd = sys_open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644); if (fd < 0) die("write cfg", p, fd);
    char b[PATH_MAX * 4 + 64]; b[0] = 0;
    scat(b, "root=", sizeof b); scat(b, g_root, sizeof b); scat(b, "\npass=", sizeof b); scat(b, g_pass, sizeof b);
    scat(b, "\ntrace=", sizeof b); scat(b, g_trace, sizeof b); scat(b, "\ninterp=", sizeof b); scat(b, g_interp, sizeof b);
    scat(b, "\ndebug=", sizeof b); scat(b, g_debug ? "1" : "0", sizeof b); scat(b, "\n", sizeof b);
    sys_write((int)fd, b, xstrlen(b)); sys_close((int)fd);
}
static void cfg_read(void)
{
    char p[PATH_MAX]; cfg_path(p);
    long fd = sys_open(p, O_RDONLY | O_CLOEXEC, 0); if (fd < 0) die("read cfg", p, fd);
    static char b[PATH_MAX * 4 + 64]; long n = sys_read((int)fd, b, sizeof b - 1); sys_close((int)fd); if (n < 0) n = 0; b[n] = 0;
    char root[PATH_MAX] = "", pass[PATH_MAX] = "";
    for (char *l = b; l && *l; ) {
        char *e = xstrchr(l, '\n'); if (e) *e = 0;
        if (xstarts(l, "root=")) scpy(root, l + 5, PATH_MAX); else if (xstarts(l, "pass=")) scpy(pass, l + 5, PATH_MAX);
        else if (xstarts(l, "trace=")) scpy(g_trace, l + 6, PATH_MAX); else if (xstarts(l, "interp=")) scpy(g_interp, l + 7, PATH_MAX);
        else if (xstarts(l, "debug=")) g_debug = l[6] == '1';
        l = e ? e + 1 : 0;
    }
    set_root(root); set_pass(pass);
}

/* ---------- main ---------- */
__attribute__((noreturn, used)) void cmain(long *stack)
{
    reloc_self();
    long argc = stack[0]; char **argv = (char **)(stack + 1); char **envp = argv + argc + 1;
    char **e = envp; while (*e) e++; unsigned long *auxv = (unsigned long *)(e + 1);
    unsigned long at_base = 0;
    for (unsigned long *a = auxv; a[0] != AT_NULL; a += 2) if (a[0] == AT_BASE) at_base = a[1];

    if (at_base) {
        /* ---- interpreter mode: the kernel mapped the program and us ---- */
        long n = sys_readlink(INTERP_STR, g_self, PATH_MAX - 1); if (n < 0) die("fd 999 not open; run through the opener", 0, n); g_self[n] = 0;
        cfg_read();
        for (char **v = envp; *v; v++) if (xstrcmp(*v, "SPIKE_DEBUG=1") == 0) g_debug = 1;
        arm();
        ensure_fd();
        unsigned long ientry, ibase = map_interp(g_interp[0] ? g_interp : "/lib64/ld-linux-x86-64.so.2", &ientry);
        for (unsigned long *a = auxv; a[0] != AT_NULL; a += 2) if (a[0] == AT_BASE) a[1] = ibase;
        dbg("interp jump");
        __asm__ volatile ("mov %0, %%rsp\n xor %%rdx, %%rdx\n xor %%rbp, %%rbp\n jmp *%1\n" : : "r"(stack), "r"(ientry) : "memory");
        __builtin_unreachable();
    }

    long n = sys_readlink("/proc/self/exe", g_self, PATH_MAX - 1); if (n < 0) die("readlink self", 0, n); g_self[n] = 0;
    if (argc >= 7 && xstrcmp(argv[1], "--child") == 0) {
        /* ---- loader mode ---- */
        set_root(argv[2]); set_pass(argv[3]);
        if (xstrcmp(argv[4], "-") != 0) scpy(g_trace, argv[4], PATH_MAX);
        if (xstrcmp(argv[5], "-") != 0) scpy(g_interp, argv[5], PATH_MAX);
        for (char **v = envp; *v; v++) if (xstrcmp(*v, "SPIKE_DEBUG=1") == 0) g_debug = 1;
        arm();
        ul_exec(argv[6], argc - 7, argv + 7, envp, auxv);
    }
    /* ---- entry mode ---- */
    int i = 1; const char *root = "-", *pass = "-"; scpy(g_interp, "/lib64/ld-linux-x86-64.so.2", PATH_MAX);
    for (; i < argc; i++) {
        if (xstrcmp(argv[i], "-d") == 0) g_debug = 1;
        else if (xstrcmp(argv[i], "-r") == 0 && i + 1 < argc) root = argv[++i];
        else if (xstrcmp(argv[i], "-p") == 0 && i + 1 < argc) pass = argv[++i];
        else if (xstrcmp(argv[i], "-t") == 0 && i + 1 < argc) scpy(g_trace, argv[++i], PATH_MAX);
        else if (xstrcmp(argv[i], "-i") == 0 && i + 1 < argc) scpy(g_interp, argv[++i], PATH_MAX);
        else if (xstrcmp(argv[i], "--") == 0) { i++; break; }
        else break;
    }
    if (i >= argc) die("usage: spike2 [-d] [-r ROOT] [-p A:B] [-t TRACE] [-i INTERP] -- /prog args...", 0, 0);
    set_root(root); set_pass(pass);
    cfg_write();
    { long fd = sys_open(g_self, O_RDONLY | O_CLOEXEC, 0); if (fd < 0) die("open self", g_self, fd); sys_dup3((int)fd, INTERP_FD, 0); sys_close((int)fd); }
    /* hand the program to the kernel; we become its interpreter via fd 999 */
    unsigned long mask0 = 0;
    arm();
    long r = do_exec(argv[i], AT_FDCWD, argv + i, envp, mask0);
    die("exec", argv[i], r);
}
