/* str.c — string, number and arena helpers. No syscalls. */
#include "common.h"

void *memcpy(void *d, const void *s, size_t n) { return xmemcpy(d, s, n); }
void *memset(void *d, int c, size_t n) { return xmemset(d, c, n); }
void *memmove(void *d, const void *s, size_t n)
{
    char *dd = d;
    const char *ss = s;
    if (dd < ss) {
        while (n--) *dd++ = *ss++;
    } else {
        dd += n;
        ss += n;
        while (n--) *--dd = *--ss;
    }
    return d;
}
int memcmp(const void *a, const void *b, size_t n) { return xmemcmp(a, b, n); }
size_t strlen(const char *s) { return xstrlen(s); }

char *scpy(char *d, const char *s, size_t n)
{
    size_t l = xstrlen(s);
    if (l >= n) l = n - 1;
    xmemcpy(d, s, l);
    d[l] = 0;
    return d;
}
char *scat(char *d, const char *s, size_t n)
{
    size_t l = xstrlen(d);
    scpy(d + l, s, n - l);
    return d;
}
const char *base_name(const char *p)
{
    const char *b = xstrrchr(p, '/');
    return b ? b + 1 : p;
}

void ltoa_(long v, char *b)
{
    char t[24];
    int i = 0;
    unsigned long u = v < 0 ? (unsigned long)(-v) : (unsigned long)v;
    if (u == 0) t[i++] = '0';
    while (u) {
        t[i++] = (char)('0' + u % 10);
        u /= 10;
    }
    if (v < 0) *b++ = '-';
    while (i) *b++ = t[--i];
    *b = 0;
}
int starts_dir(const char *s, const char *pfx)
{
    if (pfx[0] == '/' && pfx[1] == 0) return s[0] == '/';
    size_t l = xstrlen(pfx);
    return xstrncmp(s, pfx, l) == 0 && (s[l] == '/' || s[l] == 0);
}

/* arena: the manifest's strings, the ownership and host tables, the environment and the entry's buffers, for the process's life */
static char arena[512 * 1024];
static size_t arena_used;
void *arena_alloc(size_t n)
{
    n = (n + 15) & ~(size_t)15;
    if (arena_used + n > sizeof arena) die("arena full", 0, ENOMEM);
    void *p = arena + arena_used;
    arena_used += n;
    return p;
}
char *arena_str(const char *s, size_t n)
{
    char *p = arena_alloc(n + 1);
    xmemcpy(p, s, n);
    p[n] = 0;
    return p;
}

static int blank(char c) { return c == ' ' || c == '\t'; }

/* Build the kernel's argv for a "#!" script, interp [arg] script args..., as fs/binfmt_script.c's load_script does
 * from the first n bytes of the file (n at most BINPRM_BUF_SIZE). line holds them and one byte more, is modified in
 * place and must outlive nargv. With no newline in the buffer, the line is its first BINPRM_BUF_SIZE - 1 bytes, and
 * an interpreter path that no blank or NUL ends within them is refused rather than cut short; the argument may be
 * cut. Returns the new argc, -1 for ENOEXEC (not a #! line, no interpreter, or one the buffer cuts), or -2 if nargv
 * (cap entries) is too small. */
long shebang_argv(char *line, long n, char *script, char **argv, long argc, char **nargv, long cap)
{
    if (n < 2 || line[0] != '#' || line[1] != '!') return -1;
    for (long i = n; i <= BINPRM_BUF_SIZE; i++) line[i] = 0;   /* the kernel's buffer is padded with NULs */
    char *end = 0;
    for (long i = 0; i < BINPRM_BUF_SIZE && !end; i++)
        if (line[i] == '\n') end = line + i;
    if (!end) {
        char *buf_end = line + BINPRM_BUF_SIZE - 1, *p = line + 2;
        while (p < buf_end && blank(*p)) p++;
        if (p == buf_end) return -1;
        while (p < buf_end && *p && !blank(*p)) p++;
        if (p == buf_end) return -1;                         /* the interpreter's path runs past the buffer */
        end = buf_end;
    }
    while (blank(end[-1])) end--;
    char *name = line + 2;
    while (name < end && blank(*name)) name++;
    if (name == end) return -1;
    char *sep = name, *arg = 0;
    while (sep < end && *sep && !blank(*sep)) sep++;
    if (sep < end && *sep) {
        arg = sep;
        while (arg < end && blank(*arg)) arg++;
        if (arg == end) arg = 0;
    }
    *end = 0;
    if (sep < end) *sep = 0;
    if (argc + 3 > cap) return -2;
    long k = 0;
    nargv[k++] = name;
    if (arg) nargv[k++] = arg;
    nargv[k++] = script;
    for (long i = 1; i < argc; i++) nargv[k++] = argv[i];
    nargv[k] = 0;
    return k;
}

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
