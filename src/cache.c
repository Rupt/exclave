/* cache.c — the canonicalisation cache (DESIGN.md 7.4.4).
 *
 * Exclave paths are never modified by anything inside an exclave, so what a
 * component is (a directory, a symlink and its text, absent, a plain file,
 * a wrapper) is stable for the life of the process and is remembered here.
 * Host-owned paths are never cached. The table is per process, copied by
 * fork, shared by threads; entries are written once and published with a
 * release barrier, readers never lock, and an insert that cannot take the
 * lock is simply skipped, so a nested signal handler cannot deadlock on it.
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
static volatile int lock;
static volatile int full;

static unsigned long hash_str(const char *s)
{
    unsigned long h = 1469598103934665603UL;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 1099511628211UL;
    }
    return h ? h : 1;
}

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
    if (full || __sync_lock_test_and_set(&lock, 1)) return;
    size_t vl = xstrlen(v) + 1, ll = (kind == CK_LINK && link) ? xstrlen(link) + 1 : 0;
    unsigned long h = hash_str(v);
    unsigned i = h & (SLOTS - 1), n = 0;
    for (; n < SLOTS; i = (i + 1) & (SLOTS - 1), n++) {
        if (!table[i].hash) break;
        if (table[i].hash == h && xstrcmp(strings + table[i].off, v) == 0) {
            __sync_lock_release(&lock);
            return;
        }
    }
    /* stop with slack left: a probe must always meet an empty slot, or a miss would scan the whole table */
    if (table[i].hash || ++filled > SLOTS - SLOTS / 8 || used + vl + ll > STRINGS) {
        full = 1;
        __sync_lock_release(&lock);
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
    __sync_lock_release(&lock);
}

/* classify an exclave path (a virtual path) by one lstat, two more for a regular file's wrapper check, and remember it;
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
    } else if ((st.st_mode & S_IFMT) == S_IFREG && is_wrapper_real(real, tmp)) k = CK_WRAPPER;
    else k = CK_FILE;
    cache_put(v, k, k == CK_LINK ? tmp : 0);
    return k;
}
