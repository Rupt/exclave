#include <sys/stat.h>
#include <stdio.h>
#include <time.h>
int main(void){ struct stat st; struct timespec a,b; clock_gettime(CLOCK_MONOTONIC,&a);
 for (int i=0;i<200000;i++) stat("/usr/include/stdio.h",&st);
 clock_gettime(CLOCK_MONOTONIC,&b); double ns=((b.tv_sec-a.tv_sec)*1e9+(b.tv_nsec-a.tv_nsec))/200000; printf("stat: %.0f ns/call\n", ns);
 clock_gettime(CLOCK_MONOTONIC,&a); for (int i=0;i<200000;i++) (void)0; clock_gettime(CLOCK_MONOTONIC,&b); return 0; }
