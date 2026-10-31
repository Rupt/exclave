/* ljmp.c — the textbook timeout: a blocking open on a FIFO, a 1 ms timer, siglongjmp out of the handler, ROUNDS times;
 * a launcher that kept what a round left behind would pass its nesting limit of 64 (DESIGN.md 7.5.4). usage: ljmp FIFO
 * ROUNDS */
#define _GNU_SOURCE
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
static sigjmp_buf env;
static void h(int s)
{
    (void)s;
    siglongjmp(env, 1);
}
int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    unlink(argv[1]);
    if (mkfifo(argv[1], 0600)) {
        perror("mkfifo");
        return 2;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h;
    sigaction(SIGALRM, &sa, 0);
    int rounds = atoi(argv[2]), done = 0;
    for (int i = 0; i < rounds; i++) {
        if (sigsetjmp(env, 1) == 0) {
            struct itimerval it = {{0, 0}, {0, 1000}};
            setitimer(ITIMER_REAL, &it, 0);
            int fd = open(argv[1], O_RDONLY);
            if (fd >= 0) close(fd);
        } else done++;
    }
    struct stat st;
    if (stat("/usr/share", &st)) {
        printf("FAIL stat after the rounds\n");
        return 1;
    }
    printf("timed out %d of %d rounds\n", done, rounds);
    unlink(argv[1]);
    return done == rounds ? 0 : 1;
}
