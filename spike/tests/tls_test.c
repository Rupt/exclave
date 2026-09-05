#include <stdio.h>
#include <pthread.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
static __thread int tl = 5;
static void *th(void *a) { tl += (int)(long)a; struct stat st; int r = stat("/usr/include/stdio.h", &st); 
  char buf[256]; ssize_t n = readlink("/proc/self/exe", buf, 255); buf[n>0?n:0]=0;
  printf("thread %ld: tl=%d stat=%d exe=%s\n", (long)a, tl, r, buf); return 0; }
int main(void) {
  pthread_t t[4]; for (long i = 0; i < 4; i++) pthread_create(&t[i], 0, th, (void*)i);
  for (int i = 0; i < 4; i++) pthread_join(t[i], 0);
  void *h = dlopen("libm.so.6", RTLD_NOW); double (*f)(double) = h ? dlsym(h, "sqrt") : 0;
  printf("main: tl=%d dlopen=%s sqrt(2)=%f\n", tl, h ? "ok" : dlerror(), f ? f(2.0) : -1.0);
  char cwd[512]; printf("cwd=%s\n", getcwd(cwd, sizeof cwd));
  if (chdir("/usr/lib/gcc") == 0) { printf("chdir /usr/lib/gcc ok, cwd=%s\n", getcwd(cwd, sizeof cwd));
    struct stat st; printf("relative stat x86_64-linux-gnu/13/crtbegin.o -> %d\n", stat("x86_64-linux-gnu/13/crtbegin.o", &st)); }
  return 0;
}
