/* str.c — string, number and arena helpers. No syscalls but the reserve's mapping. */
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

/* The reserve: one span mapped without access at the first need, the cache's strings, its full table and the arena's
 * rest, each opened for writing as it fills (13 item 60), since the kernel charges writable memory to RLIMIT_DATA
 * from the exec on and an image that carried the most a manifest could ask would be killed by its exec under a limit
 * a program runs within. It is made at startup, which is one thread, or under the cache's lock, and never freed. Each
 * part's offset and the step a part is opened by are multiples of every page size the kernel uses. */
#define ARENA_FIRST 32768
/* the reserve's base beside the arena's counts and its first block (below), so that a start touches one page of the
 * image for all of them (16.4) */
static struct {
    char *reserve; /* 0 until mapped */
    size_t opened; /* the bytes from the reserve's start that the start's mapping opened with it */
    size_t first_used, rest_used, rest_open;
    char first[ARENA_FIRST] __attribute__((aligned(16)));
} arena;
#ifdef HOST_TEST
/* the unit tests and the fuzzer have no syscall page; test/cache_test.c sets reserve_test_fail to make every opening
 * fail as an mprotect under RLIMIT_DATA does */
int reserve_test_fail;
static char reserve_bytes[RESERVE_SIZE] __attribute__((aligned(RESERVE_STEP)));
char *reserve_base(long *err)
{
    (void)err;
    return reserve_bytes;
}
long reserve_open(char *at, size_t n)
{
    (void)at, (void)n;
    return reserve_test_fail ? -ENOMEM : 0;
}
#else
char *reserve_base(long *err)
{
    if (!arena.reserve) {
        long m = sys_mmap(0, RESERVE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (m < 0 && m > -4096) {
            *err = -m;
            return 0;
        }
        arena.reserve = (char *)m;
    }
    return arena.reserve;
}
long reserve_open(char *at, size_t n)
{
    if (at >= arena.reserve && at + n <= arena.reserve + arena.opened) return 0;
    long r = sys_mprotect(at, n, PROT_READ | PROT_WRITE);
    return r < 0 ? r : 0;
}
/* The start's mapping (16.6 item 12): the cache's lock page, the first scratch chunk and the reserve as one span,
 * mapped without access by one call and opened by a second from the lock page through the cache's first strings,
 * which begin the reserve, where each had a mapping of its own and the strings an opening besides: two calls where
 * there were four. chunk is the chunk's size. Returns the lock page, which the chunk follows at the next page, or 0
 * where the span or its opening cannot be had, under a limit on the address space or on data: each of the three then
 * maps its own when it comes to need it, as it does in a process that has used them up. */
_Static_assert(RESERVE_STRINGS_AT == 0, "the cache's strings begin the reserve");
char *start_map(size_t chunk)
{
    size_t page = C.pagesz, head = page + ((chunk + page - 1) & ~(page - 1));
    long m = sys_mmap(0, head + RESERVE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (m < 0 && m > -4096) return 0;
    if (sys_mprotect((void *)m, head + RESERVE_STEP, PROT_READ | PROT_WRITE) < 0) {
        SC2(NR_munmap, m, head + RESERVE_SIZE);
        return 0;
    }
    arena.reserve = (char *)m + head;
    arena.opened = RESERVE_STEP;
    return (char *)m;
}
#endif

/* arena: the manifest's strings, the ownership and host tables, the entry's buffers; never freed. It holds the most
 * the limits allow (common.h), so that "arena full" is a broken invariant and never an input's doing: every field of
 * the records a manifest keeps, the exclave and cpu records with them, and of the record that fails (6.2); a name for
 * each top-level entry of the tree, the real path of each top-level directory whose reading waits (MAX_UNREAD_TOP)
 * and the real path of each identity directory that is a host link and of each
 * identity file's copy and own'd path the rule maps (vis.c); the border's four fixed variables, the positional entry's
 * three buffers, the #! line, script and interpreter of each of the six levels of an interpreter chain, and the
 * exclave's own paths (launcher.c, struct exclave). Each block is rounded up to 16 bytes. An array as long as the
 * environment or the arguments is mapped instead, since nothing bounds it here. The first ARENA_FIRST bytes are the
 * image's, which an ordinary start does not outgrow, so that it opens nothing; a block that does not fit there comes
 * from the reserve's arena, which holds the whole of ARENA_SIZE by itself, so that the one bound, on both parts
 * together, is the whole arena's. Only startup allocates. */
void *arena_alloc(size_t n)
{
    n = (n + 15) & ~(size_t)15;
    if (arena.first_used + arena.rest_used + n > ARENA_SIZE) die("arena full", 0, ENOMEM);
    if (arena.first_used + n <= ARENA_FIRST) {
        arena.first_used += n;
        return arena.first + arena.first_used - n;
    }
    long err = 0;
    char *base = reserve_base(&err);
    if (!base) die("cannot reserve the arena", 0, err);
    base += RESERVE_ARENA_AT;
    if (arena.rest_used + n > arena.rest_open) {
        size_t want = (arena.rest_used + n + RESERVE_STEP - 1) & ~(size_t)(RESERVE_STEP - 1);
        long r = reserve_open(base + arena.rest_open, want - arena.rest_open);
        if (r) die("cannot map the arena", 0, -r);
        arena.rest_open = want;
    }
    arena.rest_used += n;
    return base + arena.rest_used - n;
}
char *arena_str(const char *s, size_t n)
{
    char *p = arena_alloc(n + 1);
    xmemcpy(p, s, n);
    p[n] = 0;
    return p;
}
#ifdef HOST_TEST
/* test/launcher_fuzz.c parses one manifest after another in a process */
void arena_reset(void);
void arena_reset(void) { arena.first_used = arena.rest_used = 0; }
#endif

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
