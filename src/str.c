/* str.c — string, number and arena helpers. No syscalls. */
#include "common.h"

void *memcpy(void *d, const void *s, size_t n) { return xmemcpy(d, s, n); }
void *memset(void *d, int c, size_t n) { return xmemset(d, c, n); }
void *memmove(void *d, const void *s, size_t n)
{
    char *dd = d; const char *ss = s;
    if (dd < ss) { while (n--) *dd++ = *ss++; } else { dd += n; ss += n; while (n--) *--dd = *--ss; }
    return d;
}
int memcmp(const void *a, const void *b, size_t n) { return xmemcmp(a, b, n); }
size_t strlen(const char *s) { return xstrlen(s); }

char *scpy(char *d, const char *s, size_t n)
{
    size_t l = xstrlen(s); if (l >= n) l = n - 1;
    xmemcpy(d, s, l); d[l] = 0; return d;
}
char *scat(char *d, const char *s, size_t n) { size_t l = xstrlen(d); scpy(d + l, s, n - l); return d; }
const char *base_name(const char *p) { const char *b = xstrrchr(p, '/'); return b ? b + 1 : p; }

void ltoa_(long v, char *b)
{
    char t[24]; int i = 0; unsigned long u = v < 0 ? (unsigned long)(-v) : (unsigned long)v;
    if (u == 0) t[i++] = '0';
    while (u) { t[i++] = (char)('0' + u % 10); u /= 10; }
    if (v < 0) *b++ = '-';
    while (i) *b++ = t[--i];
    *b = 0;
}
void xtoa_(unsigned long v, char *b)
{
    char t[20]; int i = 0; const char *h = "0123456789abcdef";
    if (v == 0) t[i++] = '0';
    while (v) { t[i++] = h[v & 15]; v >>= 4; }
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
    void *p = arena + arena_used; arena_used += n; return p;
}
char *arena_str(const char *s, size_t n)
{
    char *p = arena_alloc(n + 1); xmemcpy(p, s, n); p[n] = 0; return p;
}

/* Parse a "#!" line (NUL-terminated, first 255 bytes of the file) and build the
 * kernel's argv for it: interp [arg] script args... Returns the new argc, -1 if
 * the line is not a shebang, -2 if nargv (cap entries) is too small. The line
 * buffer is modified in place and must outlive nargv. */
long shebang_argv(char *line, char *script, char **argv, long argc, char **nargv, long cap)
{
    if (line[0] != '#' || line[1] != '!') return -1;
    char *e = xstrchr(line, '\n'); if (e) *e = 0;      /* no newline within the buffer: the kernel uses what it has (5.1+) */
    char *p = line + 2; while (*p == ' ' || *p == '\t') p++;
    if (!*p) return -1;
    char *interp = p; while (*p && *p != ' ' && *p != '\t') p++;
    char *arg = 0;
    if (*p) {
        *p++ = 0; while (*p == ' ' || *p == '\t') p++;
        if (*p) { arg = p; char *q = p + xstrlen(p); while (q > p && (q[-1] == ' ' || q[-1] == '\t')) *--q = 0; }
    }
    if (argc + 3 > cap) return -2;
    long k = 0; nargv[k++] = interp; if (arg) nargv[k++] = arg;
    nargv[k++] = script;
    for (long i = 1; i < argc; i++) nargv[k++] = argv[i];
    nargv[k] = 0;
    return k;
}
