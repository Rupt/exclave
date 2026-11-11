/* cache_test.c — the canonicalisation cache's growth from its first table to the full one (16.6 item 9), and its
 * insert lock across fork (DESIGN.md 7.4.4). The lock lives on a page the
 * kernel wipes at fork, so a child forked while another thread held it starts with it free, where an inherited copy
 * would be held for the child's life and every insert there skipped. Built on the host with src/cache.c and src/str.c
 * under -DHOST_TEST, which adds cache_test_hold and cache_test_release, the lock as a thread mid-insert holds it. The
 * launcher's syscalls go through its page, which this program maps as the launcher's startup does. Prints a line
 * for each, and one for each opening of the reserve that fails (13 item 60); exit 0 when all hold, and SKIP, exit 0,
 * on a kernel without MADV_WIPEONFORK (before 4.14). */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define SC_PAGE 0x7fe00000UL /* src/sys.h */
#define CK_DIR 2  /* src/common.h */
#define CK_LINK 3 /* src/common.h */
#define PATH_MAX_TEST 4096 /* PATH_MAX, the buffer a link's text is copied to */
#ifndef MADV_WIPEONFORK
#define MADV_WIPEONFORK 18
#endif
int cache_get(const char *v, char *link_out);
void cache_put(const char *v, int kind, const char *link);
void cache_init(pid_t pid, void *page);
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
struct kstat;
int is_wrapper_st(const char *real, const struct kstat *st, char *tmp);
int is_wrapper_st(const char *real, const struct kstat *st, char *tmp)
{
    (void)real;
    (void)st;
    tmp[0] = 0; /* no payload */
    return 0;
}

/* the first table filled past its share and copied into the full one (16.6 item 9): every entry, before the copy and
 * after, answers with its kind and a link its text, and a name never put is a miss */
static int grows(void)
{
    char v[64], text[PATH_MAX_TEST];
    int n = 3000, bad = 0;
    for (int i = 0; i < n; i++) {
        snprintf(v, sizeof v, "/grow/%d", i);
        snprintf(text, sizeof text, "t%d", i);
        cache_put(v, i % 3 ? CK_DIR : CK_LINK, i % 3 ? 0 : text);
    }
    for (int i = 0; i < n; i++) {
        snprintf(v, sizeof v, "/grow/%d", i);
        snprintf(text, sizeof text, "t%d", i);
        char got[PATH_MAX_TEST] = "";
        int k = cache_get(v, got);
        if (k != (i % 3 ? CK_DIR : CK_LINK) || (k == CK_LINK && strcmp(got, text) != 0)) bad++;
    }
    if (cache_get("/grow/never", 0) != 0) bad++;
    printf("%s cache growth: %d of %d entries wrong after the first table filled\n", bad ? "FAIL" : "PASS", bad, n);
    return !bad;
}

/* An opening of the reserve that fails, as an mprotect under RLIMIT_DATA does (13 item 60), stops the inserts and
 * leaves every entry made before it answering: the strings' second step in one child, the full table's opening when
 * the first table fills in another, each with the cache as a new process has it. */
extern int reserve_test_fail; /* src/str.c under HOST_TEST */
static int fails_closed(const char *what, int before, int after, size_t len)
{
    pid_t child = fork();
    if (child == 0) {
        char v[8192];
        int bad = 0;
        for (int i = 0; i < before + after; i++) {
            if (i == before) reserve_test_fail = 1;
            size_t k = (size_t)snprintf(v, sizeof v, "/%s/%d/", what, i);
            memset(v + k, 'x', len);
            v[k + len] = 0;
            cache_put(v, CK_DIR, 0);
        }
        for (int i = 0; i < before + after; i++) {
            size_t k = (size_t)snprintf(v, sizeof v, "/%s/%d/", what, i);
            memset(v + k, 'x', len);
            v[k + len] = 0;
            /* every entry before the failure kept; the last, the one that failed, and every later one never put */
            if (cache_get(v, 0) != (i < before ? CK_DIR : 0)) bad++;
        }
        _exit(bad ? 1 : 0);
    }
    int status = -1;
    waitpid(child, &status, 0);
    int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    printf("%s cache %s: a failed opening %s\n", ok ? "PASS" : "FAIL", what,
           ok ? "stops the inserts and keeps every entry before it" : "loses an entry or keeps inserting");
    return ok;
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
    cache_init(getpid(), 0);
    /* names of 2 KB: the strings' first 64 KB step holds 31; 224 short names fill the first table to its share */
    if (!fails_closed("strings", 31, 10, 2048) || !fails_closed("table", 224, 10, 0)) return 1;
    if (!grows()) return 1;
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
