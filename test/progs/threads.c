/* threads.c — threads and floating point (the clone3 regression), TLS, dlopen, chdir and relative paths, 64 threads
 * calling stat concurrently. Prints FAIL lines; exit 1 on any. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fails;
static __thread int tl = 5;
static void *fp(void *a)
{
    long n = (long)a; double s = 0; struct stat st;
    for (int i = 1; i <= 1000; i++) { s += sqrt((double)i * n); if (i % 100 == 0 && stat("/usr/share/cont-test-marker", &st)) return (void *)1; }
    double want = 0; for (int i = 1; i <= 1000; i++) want += sqrt((double)i * n);
    tl += (int)n;
    return (s == want && tl == 5 + (int)n) ? 0 : (void *)2;
}
static void *many(void *a) { struct stat st; for (int i = 0; i < 2000; i++) if (stat(i & 1 ? "/usr/share" : "/usr/share/cont-test-marker", &st)) return (void *)1; return 0; }

int main(void)
{
    pthread_t t[64]; void *r;
    for (long i = 0; i < 8; i++) pthread_create(&t[i], 0, fp, (void *)(i + 1));
    for (int i = 0; i < 8; i++) { pthread_join(t[i], &r); if (r) { fails++; printf("FAIL fp thread %d -> %ld\n", i, (long)r); } }
    if (tl != 5) { fails++; printf("FAIL main tl=%d\n", tl); }
    for (int i = 0; i < 64; i++) pthread_create(&t[i], 0, many, 0);
    for (int i = 0; i < 64; i++) { pthread_join(t[i], &r); if (r) { fails++; printf("FAIL stat thread %d\n", i); } }
    void *h = dlopen("libm.so.6", RTLD_NOW); double (*f)(double) = h ? (double (*)(double))dlsym(h, "sqrt") : 0;
    if (!f || f(4.0) != 2.0) { fails++; printf("FAIL dlopen libm: %s\n", h ? "sqrt" : dlerror()); }
    void *c = dlopen("libc.so.6", RTLD_NOW); if (!c || !dlsym(c, "getpid")) { fails++; printf("FAIL dlopen libc.so.6\n"); }
    char cwd[4096], *w = getcwd(cwd, sizeof cwd);
    if (!w || w[0] != '/') { fails++; printf("FAIL getcwd\n"); }
    if (chdir("/usr/share") || !getcwd(cwd, sizeof cwd) || strcmp(cwd, "/usr/share")) { fails++; printf("FAIL chdir /usr/share: cwd=%s\n", cwd); }
    struct stat st; if (stat("cont-test-marker", &st) || stat("./cont-test-marker", &st) || stat("../share/cont-test-marker", &st)) { fails++; printf("FAIL relative stat after chdir\n"); }
    if (chdir("..") || !getcwd(cwd, sizeof cwd) || strcmp(cwd, "/usr")) { fails++; printf("FAIL chdir ..: cwd=%s\n", cwd); }
    printf("threads: %d failures\n", fails);
    return fails ? 1 : 0;
}
