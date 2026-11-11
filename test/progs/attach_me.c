/* attach_me.c — a program for a debugger to attach to (DESIGN.md 7.6, 13 item 62). It lets any process of its user
 * trace it, as Yama's ptrace_scope 1 otherwise lets only an ancestor, prints its pid, and makes a trapped call ten
 * times a second until a tracer has appeared and five more calls have been made under it. Exit 0 then, 3 when no
 * tracer comes within 20 seconds. usage: attach_me */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif

static int traced(void)
{
    char line[256];
    int pid = 0;
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    while (fgets(line, sizeof line, f))
        if (strncmp(line, "TracerPid:", 10) == 0) pid = atoi(line + 10);
    fclose(f);
    return pid != 0;
}

int main(void)
{
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    printf("%d\n", (int)getpid());
    fflush(stdout);
    int under = 0;
    for (int i = 0; i < 200 && under < 5; i++) {
        struct stat st;
        struct timespec ts = {0, 100000000};
        if (stat("/etc/passwd", &st)) return 2;
        if (traced()) under++;
        nanosleep(&ts, 0);
    }
    return under >= 5 ? 0 : 3;
}
