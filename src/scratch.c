/* scratch.c — handler scratch memory (PROPOSAL.md 7.5.4).
 *
 * The handler may use only about 2 KB of the program's stack, so its path
 * buffers live in chunks obtained with mmap on demand. A chunk records its
 * owner (pid, tid); it is released explicitly when the handler returns and
 * before any execve. When nothing is free, chunks whose owner no longer
 * exists are reclaimed by liveness, never by stack position.
 */
#include "common.h"

struct chunk { struct scratch s; pid_t pid, tid; unsigned long frame; volatile int busy; volatile int ready; };   /* ready: the owner fields are those of the holder of busy */

#define MAX_CHUNKS 4096
static struct chunk *chunks[MAX_CHUNKS];
static volatile int nchunks;
static volatile int growlock;

static void lock(volatile int *l) { while (__sync_lock_test_and_set(l, 1)) { for (volatile int i = 0; i < 64; i++) ; } }
static void unlock(volatile int *l) { __sync_lock_release(l); }

static int owner_alive(struct chunk *c, pid_t mypid)
{
    if (c->pid == mypid) return sys_tgkill(mypid, c->tid, 0) != -ESRCH;
    return sys_kill(c->pid, 0) != -ESRCH;
}

static struct chunk *try_claim(pid_t pid, pid_t tid, unsigned long frame)
{
    int n = nchunks;
    for (int i = 0; i < n; i++) {
        struct chunk *c = chunks[i];
        if (!c->busy && !__sync_lock_test_and_set(&c->busy, 1)) { c->pid = pid; c->tid = tid; c->frame = frame; __sync_synchronize(); c->ready = 1; return c; }
    }
    return 0;
}

struct scratch *scratch_get(pid_t pid, pid_t tid, unsigned long frame)
{
    struct chunk *c = try_claim(pid, tid, frame);
    if (c) { c->s.pid = pid; c->s.tid = tid; return &c->s; }
    /* sweep: reclaim chunks whose owner is gone (a thread that exited, a longjmp'd frame in a dead process) */
    int n = nchunks;
    for (int i = 0; i < n; i++) {
        struct chunk *k = chunks[i];
        if (k->busy && k->ready && !owner_alive(k, pid)) { k->ready = 0; __sync_lock_release(&k->busy); }
    }
    c = try_claim(pid, tid, frame);
    if (c) { c->s.pid = pid; c->s.tid = tid; return &c->s; }
    /* grow */
    lock(&growlock);
    if (nchunks >= MAX_CHUNKS) { unlock(&growlock); return 0; }
    size_t sz = (sizeof(struct chunk) + 0xfff) & ~(size_t)0xfff;
    long m = sys_mmap(0, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m < 0 && m > -4096) { unlock(&growlock); return 0; }
    c = (struct chunk *)m; c->busy = 1; c->pid = pid; c->tid = tid; c->frame = frame; c->s.pid = pid; c->s.tid = tid; c->ready = 1;
    chunks[nchunks] = c;
    __sync_synchronize();
    nchunks++;
    unlock(&growlock);
    return &c->s;
}

void scratch_put(struct scratch *s)
{
    if (!s) return;
    struct chunk *c = (struct chunk *)s;
    c->ready = 0; __sync_synchronize();
    __sync_lock_release(&c->busy);
}

/* before execve: nothing this thread holds may survive into a parent's memory (vfork) */
void scratch_release_all_mine(void)
{
    pid_t pid = (pid_t)sys_getpid(), tid = (pid_t)sys_gettid();
    int n = nchunks;
    for (int i = 0; i < n; i++) { struct chunk *c = chunks[i]; if (c->busy && c->ready && c->pid == pid && c->tid == tid) { c->ready = 0; __sync_lock_release(&c->busy); } }
}

/* Nesting depth of this thread: the chunks it still holds, plus one. A chunk whose frame is at or below the
 * current frame cannot belong to a live ancestor on this stack: it was left by a longjmp out of a handler and
 * is released here, so a leak never counts as depth (review O3-6, F3-15). Frames on another stack are
 * above or below only by accident; the rare handler that switches stacks between traps is accepted (13). */
int nest_enter(pid_t pid, pid_t tid, unsigned long frame)
{
    int n = nchunks, d = 1;
    for (int i = 0; i < n; i++) {
        struct chunk *c = chunks[i];
        if (!c->busy || !c->ready || c->pid != pid || c->tid != tid) continue;   /* ready: a chunk mid-claim by another thread has stale fields */
        if (c->frame <= frame) { c->ready = 0; __sync_synchronize(); __sync_lock_release(&c->busy); } else d++;
    }
    return d;
}
void nest_leave(void) { }
