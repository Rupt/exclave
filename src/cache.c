/* cache.c — the canonicalisation cache (DESIGN.md 7.4.4).
 *
 * Exclave paths are never modified by anything inside an exclave, so what a
 * component is (a directory, a symlink and its text, absent, a plain file,
 * a wrapper) is stable for the life of the process and is remembered here.
 * Host-owned paths are never cached. The table is per process, copied by
 * fork, shared by threads; entries are written once and published with a
 * release barrier, readers never lock, and an insert that cannot take the
 * lock is simply skipped, so a nested signal handler cannot deadlock on it.
 * The lock lives on a page of its own, wiped at fork: a child forked while
 * another thread held the lock starts with it free, where an inherited copy
 * would hold it for the child's life.
 */
#include "common.h"

#define SLOTS 16384
#define STRINGS (1024UL * 1024)

struct slot {
    volatile unsigned long hash;
    unsigned int off;
    unsigned char kind;
};
static struct slot table[SLOTS];
static char strings[STRINGS];
static volatile unsigned int used;
static unsigned int filled;
static volatile int lock_inherited; /* the lock before cache_init, or on a kernel without MADV_WIPEONFORK */
static volatile int *lock = &lock_inherited;
static volatile int full;

/* The lock on a page that reads as zero in a fork child (MADV_WIPEONFORK, 4.14+), since the holder's release never
 * reaches a copy; a vfork child shares the page, and the parent's release does reach it. On a kernel without the
 * advice the lock is inherited as a copy, held until the child execs: inserts are skipped there, never wrong. */
void cache_init(void)
{
    long m = sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m < 0 && m > -4096) return;
    sys_madvise((void *)m, 4096, MADV_WIPEONFORK);
    lock = (volatile int *)m;
}

static unsigned long hash_str(const char *s)
{
    unsigned long h = 1469598103934665603UL;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 1099511628211UL;
    }
    return h ? h : 1;
}

#ifdef HOST_TEST
/* test/cache_test.c: the lock as another thread holds it mid-insert */
void cache_test_hold(void);
void cache_test_release(void);
void cache_test_hold(void) { *lock = 1; }
void cache_test_release(void) { __sync_lock_release(lock); }
#endif

int cache_get(const char *v, char *link_out)
{
    unsigned long h = hash_str(v);
    for (unsigned i = h & (SLOTS - 1), n = 0; n < SLOTS; i = (i + 1) & (SLOTS - 1), n++) {
        unsigned long sh = table[i].hash;
        if (!sh) return 0;
        if (sh != h) continue;
        __sync_synchronize();
        const char *s = strings + table[i].off;
        if (xstrcmp(s, v) != 0) continue;
        int kind = table[i].kind;
        if (kind == CK_LINK && link_out) scpy(link_out, s + xstrlen(s) + 1, PATH_MAX);
        return kind;
    }
    return 0;
}

void cache_put(const char *v, int kind, const char *link)
{
    /* held: someone else is inserting, or we are nested */
    if (full || __sync_lock_test_and_set(lock, 1)) return;
    size_t vl = xstrlen(v) + 1, ll = (kind == CK_LINK && link) ? xstrlen(link) + 1 : 0;
    unsigned long h = hash_str(v);
    unsigned i = h & (SLOTS - 1), n = 0;
    for (; n < SLOTS; i = (i + 1) & (SLOTS - 1), n++) {
        if (!table[i].hash) break;
        if (table[i].hash == h && xstrcmp(strings + table[i].off, v) == 0) {
            __sync_lock_release(lock);
            return;
        }
    }
    /* stop with slack left: a probe must always meet an empty slot, or a miss would scan the whole table */
    if (table[i].hash || ++filled > SLOTS - SLOTS / 8 || used + vl + ll > STRINGS) {
        full = 1;
        __sync_lock_release(lock);
        return;
    }
    unsigned off = used;
    xmemcpy(strings + off, v, vl);
    if (ll) xmemcpy(strings + off + vl, link, ll);
    used += (unsigned)(vl + ll);
    table[i].off = off;
    table[i].kind = (unsigned char)kind;
    /* strings and kind before the hash that publishes them */
    __sync_synchronize();
    table[i].hash = h;
    __sync_lock_release(lock);
}

/* classify an exclave path (a virtual path) by one lstat, one more for a wrapper's original, and remember it;
 * real is its real path, tmp is PATH_MAX. No path buffer lives on the stack here: the handler runs on whatever
 * alternate stack the program set up. */
int cache_classify(const char *v, const char *real, char *tmp)
{
    int k = cache_get(v, tmp);
    if (k) return k;
    struct kstat st;
    if (sys_lstat(real, &st) < 0) k = CK_NONE;
    else if ((st.st_mode & S_IFMT) == S_IFDIR) k = CK_DIR;
    else if ((st.st_mode & S_IFMT) == S_IFLNK) {
        long n = sys_readlink(real, tmp, PATH_MAX - 1);
        if (n < 0) return 0;                                          /* raced or unreadable: not cached */
        tmp[n] = 0;
        k = CK_LINK;
    } else if (is_wrapper_st(real, &st, tmp)) k = CK_WRAPPER; /* by the lstat just made */
    else k = CK_FILE;
    cache_put(v, k, k == CK_LINK ? tmp : 0);
    return k;
}
