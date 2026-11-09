/* unwind_frame.c — an unwind from a signal handler that ran during a trapped call walks into the program's frames at
 * the trap site (DESIGN.md 7.5.7, 13 item 58): a thread blocked in a trapped open of a FIFO cancelled by a deferred
 * pthread_cancel, its cleanup handler pushed in C built with -fexceptions, where glibc's cancellation unwinds from its
 * handler; and a forced unwind of libgcc's own from a handler for a signal that lands in such an open, through a
 * caller holding a cleanup. Built with -fexceptions by its test. usage: unwind_frame HOSTDIR. Prints one line per
 * case, the same in every world where the kernel is the oracle. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <unwind.h>

static char fifo[4096];
static volatile int cleaned;

static void cleanup(void *arg)
{
    (void)arg;
    cleaned = 1;
}
static void *blocked(void *arg)
{
    (void)arg;
    int fd = -1;
    pthread_cleanup_push(cleanup, 0);
    fd = open(fifo, O_RDONLY);
    pthread_cleanup_pop(0);
    if (fd >= 0) close(fd);
    return (void *)1;
}
static void release(void)
{
    int w = open(fifo, O_WRONLY | O_NONBLOCK);
    if (w >= 0) close(w);
}

/* the forced unwind: from the handler, through the signal frame, to the end of the stack */
static int report[2];
static _Unwind_Reason_Code stop(int v, _Unwind_Action a, _Unwind_Exception_Class c, struct _Unwind_Exception *e,
                                struct _Unwind_Context *ctx, void *p)
{
    (void)v;
    (void)c;
    (void)e;
    (void)ctx;
    (void)p;
    if (a & _UA_END_OF_STACK) {
        (void)!write(report[1], "end\n", 4);
        _exit(0);
    }
    return _URC_NO_REASON;
}
static void on_alarm(int sig)
{
    (void)sig;
    static struct _Unwind_Exception e;
    memset(&e, 0, sizeof e);
    _Unwind_ForcedUnwind(&e, stop, 0);
    (void)!write(report[1], "returned\n", 9);
    _exit(1);
}
static void said(int *p)
{
    (void)p;
    (void)!write(report[1], "cleanup\n", 8);
}
__attribute__((noinline)) static void site(void)
{
    int guard __attribute__((cleanup(said))) = 0;
    int fd = open(fifo, O_RDONLY);
    if (fd >= 0) close(fd);
    guard++;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    setvbuf(stdout, 0, _IOLBF, 0);
    snprintf(fifo, sizeof fifo, "%s/fifo", argv[1]);
    mkfifo(fifo, 0600);
#ifndef __EXCEPTIONS
    printf("built without -fexceptions: the cases need it\n");
    return 0;
#endif
    {
        pthread_t t;
        void *r = 0;
        pthread_create(&t, 0, blocked, 0);
        usleep(100000);
        pthread_cancel(t);
        struct timespec until;
        clock_gettime(CLOCK_REALTIME, &until);
        until.tv_sec += 2;
        int late = pthread_timedjoin_np(t, &r, &until) == ETIMEDOUT;
        if (late) {
            release();
            pthread_join(t, &r);
        }
        printf("pthread_cancel in a blocking trapped open: %s%s, the cleanup handler %s\n",
               r == PTHREAD_CANCELED ? "cancelled" : "returned", late ? " once a writer released the open" : "",
               cleaned ? "ran" : "did not run");
    }
    {
        if (pipe(report)) return 0;
        pid_t c = fork();
        if (c == 0) {
            signal(SIGALRM, on_alarm);
            alarm(1);
            site();
            _exit(2);
        }
        close(report[1]);
        char b[64];
        size_t n = 0;
        ssize_t k;
        while (n < sizeof b - 1 && (k = read(report[0], b + n, sizeof b - 1 - n)) > 0) n += (size_t)k;
        b[n] = 0;
        int st = 0;
        waitpid(c, &st, 0);
        for (char *p = b; *p; p++)
            if (*p == '\n') *p = *(p + 1) ? ' ' : 0;
        printf("a forced unwind from a handler during a trapped open: %s\n", *b ? b : "nothing");
    }
    return 0;
}
