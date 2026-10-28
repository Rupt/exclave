/* cache_test.c — the canonicalisation cache's insert lock across fork (DESIGN.md 7.4.4). The lock lives on a page the
 * kernel wipes at fork, so a child forked while another thread held it starts with it free, where an inherited copy
 * would be held for the child's life and every insert there skipped. Built on the host with src/cache.c and src/str.c
 * under -DHOST_TEST, which adds cache_test_hold and cache_test_release, the lock as a thread mid-insert holds it. The
 * launcher's syscalls go through its page, which this program maps as the launcher's startup does. Prints one line;
 * exit 0 when it holds, and SKIP, exit 0, on a kernel without MADV_WIPEONFORK (before 4.14). */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define SC_PAGE 0x7fe00000UL /* src/sys.h */
#define CK_DIR 2 /* src/common.h */
#ifndef MADV_WIPEONFORK
#define MADV_WIPEONFORK 18
#endif
int cache_get(const char *v, char *link_out);
void cache_put(const char *v, int kind, const char *link);
void cache_init(void);
void cache_test_hold(void);
void cache_test_release(void);
/* src/str.c's arena asks for it; nothing here allocates */
__attribute__((noreturn)) void die(const char *what, const char *detail, long err);
__attribute__((noreturn)) void die(const char *what, const char *detail, long err)
{
    printf("FAIL die: %s %s %ld\n", what, detail ? detail : "", err);
    exit(1);
}
/* cache_classify's wrapper check, which this test never reaches */
int is_wrapper_real(const char *real, char *tmp);
int is_wrapper_real(const char *real, char *tmp)
{
    (void)real;
    tmp[0] = 0; /* no payload */
    return 0;
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
    p[2] = 0xc3; /* syscall; ret */
#elif defined(__aarch64__)
    uint32_t *w = m;
    w[0] = 0xd4000001U;
    w[1] = 0xd65f03c0U; /* svc #0; ret */
    __builtin___clear_cache((char *)m, (char *)m + 8);
#endif
    mprotect(m, 4096, PROT_READ | PROT_EXEC);
    void *probe = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe == MAP_FAILED || madvise(probe, 4096, MADV_WIPEONFORK) != 0) {
        printf("SKIP cache lock: this kernel has no MADV_WIPEONFORK, so a fork child inherits a held lock\n");
        return 0;
    }
    cache_init();
    cache_put("/usr", CK_DIR, 0);
    if (cache_get("/usr", 0) != CK_DIR) {
        printf("FAIL cache lock: an insert with the lock free was not kept\n");
        return 1;
    }
    cache_test_hold(); /* another thread is mid-insert */
    cache_put("/usr/lib", CK_DIR, 0);
    if (cache_get("/usr/lib", 0) != 0) {
        printf("FAIL cache lock: an insert under a held lock was not skipped\n");
        return 1;
    }
    pid_t child = fork();
    if (child == 0) {
        cache_put("/usr/lib", CK_DIR, 0); /* the holder is not in this process: the lock must be free here */
        _exit(cache_get("/usr/lib", 0) == CK_DIR ? 0 : 3);
    }
    int status = -1;
    waitpid(child, &status, 0);
    int child_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    int parent_held = cache_get("/usr/lib", 0) == 0; /* the parent's lock is still the thread's */
    cache_test_release();
    cache_put("/usr/bin", CK_DIR, 0);
    int released_ok = cache_get("/usr/bin", 0) == CK_DIR;
    int ok = child_ok && parent_held && released_ok;
    printf("%s cache lock: the fork child %s, the parent's lock %s, and a release %s\n", ok ? "PASS" : "FAIL",
           child_ok ? "inserts with the lock wiped" : "finds the lock held", parent_held ? "stays held" : "was lost",
           released_ok ? "takes effect" : "does not take effect");
    return ok ? 0 : 1;
}
