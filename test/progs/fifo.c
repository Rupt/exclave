/* fifo.c — a trapped open blocked on a FIFO: an SA_ONSTACK timer handler traps (nested) and unlinks, then the open
 * returns EINTR; then SIGINT from another thread interrupts a second open. usage: fifo HOSTDIR */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

static char tmpf[4096];
static volatile int hits;
static void h(int s)
{
    struct stat st;
    (void)s;
    if (stat("/usr/share", &st) == 0 && unlink(tmpf) == 0) hits++;
}
static void *intr(void *a)
{
    usleep(100000);
    pthread_kill(*(pthread_t *)a, SIGINT);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    char fifo[4096];
    snprintf(fifo, sizeof fifo, "%s/fifo", argv[1]);
    snprintf(tmpf, sizeof tmpf, "%s/tmpf", argv[1]);
    unlink(fifo);
    if (mkfifo(fifo, 0600)) {
        perror("mkfifo");
        return 2;
    }
    int fails = 0;
    static char stk[65536];
    stack_t ss = {stk, 0, sizeof stk};
    sigaltstack(&ss, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h;
    sa.sa_flags = SA_ONSTACK;
    sigaction(SIGALRM, &sa, 0);
    sigaction(SIGINT, &sa, 0);
    close(open(tmpf, O_WRONLY | O_CREAT, 0600));
    struct itimerval it = {{0, 0}, {0, 100000}};
    setitimer(ITIMER_REAL, &it, 0);
    errno = 0;
    int fd = open(fifo, O_RDONLY);
    if (fd >= 0 || errno != EINTR || hits != 1) {
        fails++;
        printf("FAIL fifo open + alarm: fd=%d errno=%d hits=%d\n", fd, errno, hits);
    }
    close(open(tmpf, O_WRONLY | O_CREAT, 0600));
    hits = 0;
    pthread_t self = pthread_self(), t;
    pthread_create(&t, 0, intr, &self);
    errno = 0;
    fd = open(fifo, O_RDONLY);
    if (fd >= 0 || errno != EINTR || hits != 1) {
        fails++;
        printf("FAIL fifo open + SIGINT: fd=%d errno=%d hits=%d\n", fd, errno, hits);
    }
    pthread_join(t, 0);
    unlink(fifo);
    printf("fifo: %d failures\n", fails);
    return fails ? 1 : 0;
}
