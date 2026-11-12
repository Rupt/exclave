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

#define SLOTS CACHE_SLOTS
#define FIRST_SLOTS 256
#define STRINGS CACHE_STRINGS

struct slot {
    volatile unsigned long hash;
    unsigned int off;
    unsigned char kind;
};
_Static_assert(sizeof(struct slot) == 16, "the reserve's table part holds CACHE_SLOTS slots of 16 bytes");
_Static_assert(RESERVE_ARENA_AT - RESERVE_TABLE_AT == CACHE_SLOTS * sizeof(struct slot),
               "the table's part is the table");
/* A process starts with the first table, 4 KB, one page for a short-lived program's few dozen entries,
 * where the full table's 256 KB would fault in a page for nearly every entry. The insert that would fill the first
 * past its share copies its entries into the full table and then publishes that (16.6 item 9). A reader uses the
 * table it loaded: the live one, or one replaced while it looked, which is never written again, so a lookup racing
 * the copy at worst misses and asks the kernel. The strings and the full table are parts of the reserve (str.c),
 * the strings opened for writing as they fill and the full table when the first fills, since the kernel charges
 * writable memory to RLIMIT_DATA (13 item 60); an opening that fails stops the inserts, which is never wrong. */
struct table {
    struct slot *slot;
    unsigned mask;
};
static struct slot first_slots[FIRST_SLOTS];
static const struct table first_table = {first_slots, FIRST_SLOTS - 1};
static struct table full_table = {0, SLOTS - 1};
static const struct table *volatile live = &first_table;
static char *volatile strings; /* set once, before the first entry it holds is published */
static unsigned int strings_open;
static volatile unsigned int used;
static unsigned int filled; /* the entries of the live table */
static volatile int lock_inherited; /* the lock before cache_init, or on a kernel without MADV_WIPEONFORK */
static volatile int *lock = &lock_inherited;
/* on the lock's page: the pid of the process whose memory this is, 0 in a fork child until it execs, and 0 throughout
 * on a kernel without the advice */
static volatile int no_owner;
static volatile int *owner = &no_owner;
static volatile int full;

/* The lock on a page that reads as zero in a fork child (MADV_WIPEONFORK, 4.14+), since the holder's release never
 * reaches a copy; a vfork child shares the page, and the parent's release does reach it. On a kernel without the
 * advice the lock is inherited as a copy, held until the child execs: inserts are skipped there, never wrong. The
 * same page holds the pid the launcher started as, which tells a vfork child (7.5.4). page: the page, where the start
 * mapped it with the first chunk and the reserve (str.c's start_map), or 0. */
void cache_init(pid_t pid, void *page)
{
    long m = (long)page;
    if (!m) m = sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m < 0 && m > -4096) return;
    long w = sys_madvise((void *)m, 4096, MADV_WIPEONFORK);
    lock = (volatile int *)m;
    if (w == 0) {
        owner = (volatile int *)m + 16;
        *owner = (int)pid;
    }
}

/* Whether the caller, pid, child of ppid, is a vfork child: one that shares its parent's memory. The kernel answers
 * by kcmp, comparing the two address spaces, where it can (CONFIG_KCMP; Docker's default profile refuses it without
 * CAP_SYS_PTRACE). Elsewhere the page answers: a vfork child reads its parent's pid there, a fork child zero, and so
 * does a vfork child of a fork child that has not exec'd since, which is taken for a fork child (13 item 54); a thread
 * reads its own process's. A process made by clone with CLONE_VM and without CLONE_VFORK reads as a vfork child. */
int vfork_child(pid_t pid, pid_t ppid)
{
    long k = SC5(NR_kcmp, pid, ppid, KCMP_VM, 0, 0);
    if (k >= 0) return k == 0;
    int o = *owner;
    return o != 0 && o != pid;
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
void cache_test_hold(void) { *lock = 1; }
void cache_test_release(void) { __sync_lock_release(lock); }
#endif

int cache_get(const char *v, char *link_out)
{
    unsigned long h = hash_str(v);
    const struct table *t = live;
    for (unsigned i = (unsigned)h & t->mask, n = 0; n <= t->mask; i = (i + 1) & t->mask, n++) {
        unsigned long sh = t->slot[i].hash;
        if (!sh) return 0;
        if (sh != h) continue;
        __sync_synchronize();
        const char *s = strings + t->slot[i].off;
        if (xstrcmp(s, v) != 0) continue;
        int kind = t->slot[i].kind;
        if (kind == CK_LINK && link_out) scpy(link_out, s + xstrlen(s) + 1, PATH_MAX);
        return kind;
    }
    return 0;
}

/* the slot of t for hash h: the empty one a probe for it ends at, or the one holding v; under the lock */
static unsigned slot_for(const struct table *t, unsigned long h, const char *v)
{
    unsigned i = (unsigned)h & t->mask;
    for (unsigned n = 0; n <= t->mask && t->slot[i].hash; i = (i + 1) & t->mask, n++)
        if (v && t->slot[i].hash == h && xstrcmp(strings + t->slot[i].off, v) == 0) break;
    return i;
}

/* under the lock: the first table's entries copied into the full one, opened now, which then becomes the live table;
 * 0 where the opening fails */
static int grow(void)
{
    long err = 0;
    char *r = reserve_base(&err);
    if (!r || reserve_open(r + RESERVE_TABLE_AT, SLOTS * sizeof(struct slot))) return 0;
    struct slot *full_slots = full_table.slot = (struct slot *)(r + RESERVE_TABLE_AT);
    for (unsigned j = 0; j < FIRST_SLOTS; j++) {
        if (!first_slots[j].hash) continue;
        unsigned i = slot_for(&full_table, first_slots[j].hash, 0);
        full_slots[i].off = first_slots[j].off;
        full_slots[i].kind = first_slots[j].kind;
        full_slots[i].hash = first_slots[j].hash;
    }
    /* every entry before the table that holds them */
    __sync_synchronize();
    live = &full_table;
    return 1;
}

/* under the lock: the strings opened for writing up to n bytes; 0 where the opening fails */
static int strings_reach(size_t n)
{
    long err = 0;
    char *r = reserve_base(&err);
    if (!r) return 0;
    size_t want = (n + RESERVE_STEP - 1) & ~(size_t)(RESERVE_STEP - 1);
    if (reserve_open(r + RESERVE_STRINGS_AT + strings_open, want - strings_open)) return 0;
    strings = r + RESERVE_STRINGS_AT;
    strings_open = (unsigned)want;
    return 1;
}

void cache_put(const char *v, int kind, const char *link)
{
    /* held: someone else is inserting, or we are nested */
    if (full || __sync_lock_test_and_set(lock, 1)) return;
    size_t vl = xstrlen(v) + 1, ll = (kind == CK_LINK && link) ? xstrlen(link) + 1 : 0;
    unsigned long h = hash_str(v);
    const struct table *t = live;
    unsigned i = slot_for(t, h, v);
    if (t->slot[i].hash) { /* there already */
        __sync_lock_release(lock);
        return;
    }
    /* stop with slack left: a probe must always meet an empty slot, or a miss would scan the whole table */
    int grown = 1;
    if (filled + 1 > t->mask + 1 - (t->mask + 1) / 8 && t == &first_table) {
        grown = grow();
        t = live;
        i = slot_for(t, h, v);
    }
    if (!grown || ++filled > t->mask + 1 - (t->mask + 1) / 8 || used + vl + ll > STRINGS ||
        (used + vl + ll > strings_open && !strings_reach(used + vl + ll))) {
        full = 1;
        __sync_lock_release(lock);
        return;
    }
    unsigned off = used;
    xmemcpy(strings + off, v, vl);
    if (ll) xmemcpy(strings + off + vl, link, ll);
    used += (unsigned)(vl + ll);
    t->slot[i].off = off;
    t->slot[i].kind = (unsigned char)kind;
    /* strings and kind before the hash that publishes them */
    __sync_synchronize();
    t->slot[i].hash = h;
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
