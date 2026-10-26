/* scratch_test.c — the scratch pool's sweep under the interleaving that handed one chunk to two handlers (DESIGN.md
 * 7.5.4, 13 item 44). Built on the host with src/scratch.c and -DSCRATCH_TEST, which calls scratch_test_between between a
 * sweep's judgement that a chunk's owner is dead and its release. A chunk is left by a process that has exited, as a
 * vfork child that exec'd leaves one; sweep A judges it dead, and before A releases it, sweep B reclaims it and C claims
 * it; A must then leave C's chunk alone. Without the sequence A released it and claimed it, so A and C held one
 * chunk. The launcher's syscalls go through its page, which this program maps as the launcher's startup does. x86-64 and
 * aarch64; prints one line, exit 0 when it holds. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define SC_PAGE 0x7fe00000UL                                  /* src/sys.h */
struct scratch;
struct scratch *scratch_get(int pid, int tid, unsigned long frame);
void scratch_put(struct scratch *s);

static int inside_hook;
static struct scratch *c_chunk;

void scratch_test_between(void *chunk);
void scratch_test_between(void *chunk)                    /* src/scratch.c calls it */
{
    (void)chunk;
    if (inside_hook++) return;                                /* B's own sweep, nested here, runs straight through */
    /* B reclaims the dead owner's chunk and C claims it */
    c_chunk = scratch_get(getpid(), (int)syscall(SYS_gettid), 1);
}

int main(void)
{
    void *m =
        mmap((void *)SC_PAGE, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (m != (void *)SC_PAGE) {
        perror("mmap the syscall page");
        return 1;
    }
#if defined(__x86_64__)
    unsigned char *p = m;
    p[0] = 0x0f;
    p[1] = 0x05;
    p[2] = 0xc3;   /* syscall; ret */
#elif defined(__aarch64__)
    uint32_t *w = m;
    w[0] = 0xd4000001U;
    w[1] = 0xd65f03c0U;       /* svc #0; ret */
    __builtin___clear_cache((char *)m, (char *)m + 8);
#endif
    mprotect(m, 4096, PROT_READ | PROT_EXEC);
    pid_t dead = fork();                                      /* a pid that no longer exists */
    if (dead == 0) _exit(0);
    waitpid(dead, 0, 0);
    struct scratch *left = scratch_get(dead, dead, 0);        /* the chunk the exited process left busy */
    if (!left) {
        printf("FAIL no first chunk\n");
        return 1;
    }
    /* sweep A, with B and C between its judgement and release */
    struct scratch *a = scratch_get(getpid(), (int)syscall(SYS_gettid), 2);
    int ok = c_chunk == left && a && a != c_chunk;
    printf("%s sweep: the dead owner's chunk went to C %s, and A got %s\n", ok ? "PASS" : "FAIL",
           c_chunk == left ? "once" : "not at all",
           !a             ? "nothing"
           : a == c_chunk ? "C's chunk too"
                          : "a chunk of its own");
    return ok ? 0 : 1;
}
