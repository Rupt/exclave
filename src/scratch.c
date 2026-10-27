/* scratch.c — handler scratch memory (DESIGN.md 7.5.4).
 *
 * The handler may use only 3 KB of the program's stack (7.5.4), so its path buffers live in chunks obtained with
 * mmap on demand. A chunk records its owner (pid, tid); it is released explicitly when the handler returns. When
 * nothing is free, chunks whose owner no longer exists are reclaimed by liveness, never by another thread's stack
 * position; a thread's own chunks left by a longjmp are released by frame (nest_enter). Nothing here takes a lock: a
 * handler that interrupts a handler, or a fork while another thread is in one, must never find a lock held by a
 * frame that cannot release it.
 *
 * Every claim and every release advances a chunk's sequence, and a sweep releases a chunk only by moving the
 * sequence it read: a sweep that saw a dead owner, and was overtaken by another sweep's release and a new claim
 * before it acted, finds the sequence moved and leaves the new holder alone (13 item 44). Without the rule two sweeps
 * could hand one chunk to two handlers, which posix_spawn's vfork children, leaving chunks with dead owners, make
 * likely.
 */
#include "common.h"

#ifdef SCRATCH_TEST
/* test/scratch_test.c: what other threads do between a sweep's judgement and its release */
void scratch_test_between(void *chunk);
#define BETWEEN(k) scratch_test_between(k)
#else
#define BETWEEN(k) ((void)0)
#endif

struct chunk {
    struct scratch s;
    pid_t pid, tid;
    unsigned long frame;
    volatile int busy;
    volatile int ready;
    volatile unsigned long seq;
};
/* ready: the owner fields are those of the holder of busy; seq: advanced by every claim and release */

/* Whether c's owner fields are set, read with acquire ordering: a reader that sees ready sees the fields the claim
 * stored before it, on aarch64 too, where loads may otherwise pass one another. */
static int owner_set(struct chunk *c) { return __atomic_load_n(&c->ready, __ATOMIC_ACQUIRE); }

#define MAX_CHUNKS 4096
/* a slot is reserved by advancing nchunks and filled once its chunk is mapped and claimed */
static struct chunk *volatile chunks[MAX_CHUNKS];
static volatile int nchunks;

static int slots(void)
{
    int n = nchunks;
    return n > MAX_CHUNKS ? MAX_CHUNKS : n;
}

static int owner_alive(struct chunk *c, pid_t mypid)
{
    if (c->pid == mypid) return sys_tgkill(mypid, c->tid, 0) != -ESRCH;
    return sys_kill(c->pid, 0) != -ESRCH;
}

static struct chunk *try_claim(pid_t pid, pid_t tid, unsigned long frame)
{
    int n = slots();
    for (int i = 0; i < n; i++) {
        struct chunk *c = chunks[i];
        if (c && !c->busy && !__sync_lock_test_and_set(&c->busy, 1)) {
            /* before the fields: a sweep that read the old sequence cannot release this claim */
            __sync_fetch_and_add(&c->seq, 1);
            c->pid = pid;
            c->tid = tid;
            c->frame = frame;
            __sync_synchronize();
            c->ready = 1;
            return c;
        }
    }
    return 0;
}

struct scratch *scratch_get(pid_t pid, pid_t tid, unsigned long frame)
{
    struct chunk *c = try_claim(pid, tid, frame);
    if (c) {
        c->s.pid = pid;
        c->s.tid = tid;
        return &c->s;
    }
    /* sweep: reclaim chunks whose owner is gone (a thread that exited, a longjmp'd frame in a dead process, a vfork
     * child that has exited; one that still runs keeps its chunk, 13 item 26) */
    int n = slots();
    for (int i = 0; i < n; i++) {
        struct chunk *k = chunks[i];
        if (!k) continue;
        /* the sequence first: the owner read after it is that claim's or a later one's */
        unsigned long q = k->seq;
        __sync_synchronize();
        if (!k->busy || !owner_set(k) || owner_alive(k, pid)) continue;
        BETWEEN(k);
        if (__sync_bool_compare_and_swap(&k->seq, q, q + 1)) {
            k->ready = 0;
            __sync_synchronize();
            __sync_lock_release(&k->busy);
        }
    }
    c = try_claim(pid, tid, frame);
    if (c) {
        c->s.pid = pid;
        c->s.tid = tid;
        return &c->s;
    }
    /* grow: reserve a slot, map the chunk already claimed, publish it; a mapping that fails leaves the slot empty */
    int i = __sync_fetch_and_add(&nchunks, 1);
    /* the pool's ceiling (13 item 26) */
    if (i >= MAX_CHUNKS) return 0;
    size_t sz = (sizeof(struct chunk) + 0xfff) & ~(size_t)0xfff;
    long m = sys_mmap(0, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m < 0 && m > -4096) return 0;
    c = (struct chunk *)m;
    c->busy = 1;
    c->pid = pid;
    c->tid = tid;
    c->frame = frame;
    c->s.pid = pid;
    c->s.tid = tid;
    c->ready = 1;
    /* the chunk's fields before the pointer that publishes them */
    __sync_synchronize();
    chunks[i] = c;
    return &c->s;
}

/* the add is a full barrier */
static void release(struct chunk *c)
{
    c->ready = 0;
    __sync_fetch_and_add(&c->seq, 1);
    __sync_lock_release(&c->busy);
}

void scratch_put(struct scratch *s)
{
    if (s) release((struct chunk *)s);
}

/* Nesting depth of this thread: the chunks it still holds, plus one. A chunk whose frame is at or below the current
 * frame cannot belong to a live ancestor on this stack: it was left by a longjmp out of a handler and is released
 * here, so a leak never counts as depth. Frames on another stack are above or below only by accident; the rare
 * handler that switches stacks between traps is accepted (13 item 27). */
int nest_enter(pid_t pid, pid_t tid, unsigned long frame)
{
    int n = slots(), d = 1;
    for (int i = 0; i < n; i++) {
        struct chunk *c = chunks[i];
        /* ready: a chunk mid-claim by another thread has stale fields */
        if (!c || !c->busy || !owner_set(c) || c->pid != pid || c->tid != tid) continue;
        if (c->frame <= frame) release(c);
        else d++;
    }
    return d;
}
