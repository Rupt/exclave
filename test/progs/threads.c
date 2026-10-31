/* threads.c — threads and floating point (the clone3 regression), TLS, dlopen, chdir and relative paths, 64 threads
 * calling stat concurrently, each on a directory and a file of the tree of its own, found by their directory entries'
 * types without a stat, so that the launcher's cache takes new components while it answers for others; each answer
 * must be the kind its path names. Prints FAIL lines; exit 1 on any. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int fails;
static __thread int tl = 5;
static void *fp(void *a)
{
    long n = (long)a;
    double s = 0;
    struct stat st;
    for (int i = 1; i <= 1000; i++) {
        s += sqrt((double)i * (double)n);
        if (i % 100 == 0 && stat("/usr/share/exclave-test-marker", &st)) return (void *)1;
    }
    double want = 0;
    for (int i = 1; i <= 1000; i++) want += sqrt((double)i * (double)n);
    tl += (int)n;
    return (s == want && tl == 5 + (int)n) ? 0 : (void *)2;
}
/* the tree's directories and regular files for the stat threads, the suite's two first */
static char dirs[64][512] = {"/usr/share"}, files[64][512] = {"/usr/share/exclave-test-marker"};
static int ndirs = 1, nfiles = 1;
static void find_paths(void)
{
    static const char *const in[] = {"/usr/include", "/usr/share", "/usr/lib", "/usr/bin"};
    /* getdents64 through syscall, since the suite's pruned tree may lack <dirent.h>: struct linux_dirent64 has the
     * record's length at 16, its type at 18 and its name at 19 */
    static char buf[32768];
    for (unsigned i = 0; i < sizeof in / sizeof *in; i++) {
        int d = open(in[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        long n;
        while (d >= 0 && (n = syscall(SYS_getdents64, d, buf, sizeof buf)) > 0)
            for (long off = 0; off < n;) {
                unsigned short len;
                memcpy(&len, buf + off + 16, sizeof len);
                unsigned char type = (unsigned char)buf[off + 18];
                const char *name = buf + off + 19;
                off += len;
                if (name[0] == '.') continue;
                if (type == 4 /* DT_DIR */ && ndirs < 64) snprintf(dirs[ndirs++], sizeof *dirs, "%s/%s", in[i], name);
                if (type == 8 /* DT_REG */ && nfiles < 64)
                    snprintf(files[nfiles++], sizeof *files, "%s/%s", in[i], name);
            }
        if (d >= 0) close(d);
    }
}
static void *many(void *a)
{
    long t = (long)a;
    struct stat st;
    for (int i = 0; i < 2000; i++) {
        const char *p = i & 1 ? dirs[t % ndirs] : files[t % nfiles];
        if (stat(p, &st)) return (void *)1;
        if (!S_ISDIR(st.st_mode) != !(i & 1)) return (void *)2;
    }
    return 0;
}

int main(void)
{
    pthread_t t[64];
    void *r;
    for (long i = 0; i < 8; i++) pthread_create(&t[i], 0, fp, (void *)(i + 1));
    for (int i = 0; i < 8; i++) {
        pthread_join(t[i], &r);
        if (r) {
            fails++;
            printf("FAIL fp thread %d -> %ld\n", i, (long)r);
        }
    }
    if (tl != 5) {
        fails++;
        printf("FAIL main tl=%d\n", tl);
    }
    find_paths();
    for (long i = 0; i < 64; i++) pthread_create(&t[i], 0, many, (void *)i);
    for (int i = 0; i < 64; i++) {
        pthread_join(t[i], &r);
        if (r) {
            fails++;
            printf("FAIL stat thread %d on %s and %s: %s\n", i, dirs[i % ndirs], files[i % nfiles],
                   r == (void *)1 ? "failed" : "the other kind answered");
        }
    }
    void *h = dlopen("libm.so.6", RTLD_NOW);
    double (*f)(double) = h ? (double (*)(double))dlsym(h, "sqrt") : 0;
    if (!f || f(4.0) != 2.0) {
        fails++;
        printf("FAIL dlopen libm: %s\n", h ? "sqrt" : dlerror());
    }
    void *c = dlopen("libc.so.6", RTLD_NOW);
    if (!c || !dlsym(c, "getpid")) {
        fails++;
        printf("FAIL dlopen libc.so.6\n");
    }
    char cwd[4096], *w = getcwd(cwd, sizeof cwd);
    if (!w || w[0] != '/') {
        fails++;
        printf("FAIL getcwd\n");
    }
    if (chdir("/usr/share") || !getcwd(cwd, sizeof cwd) || strcmp(cwd, "/usr/share")) {
        fails++;
        printf("FAIL chdir /usr/share: cwd=%s\n", cwd);
    }
    struct stat st;
    if (stat("exclave-test-marker", &st) || stat("./exclave-test-marker", &st) ||
        stat("../share/exclave-test-marker", &st)) {
        fails++;
        printf("FAIL relative stat after chdir\n");
    }
    if (chdir("..") || !getcwd(cwd, sizeof cwd) || strcmp(cwd, "/usr")) {
        fails++;
        printf("FAIL chdir ..: cwd=%s\n", cwd);
    }
    printf("threads: %d failures\n", fails);
    return fails ? 1 : 0;
}
