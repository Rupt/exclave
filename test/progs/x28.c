/* x28.c — 7.5.3 on aarch64: a Go program without cgo keeps its goroutine in x28, and Go's preemption signal may land
 * in the launcher's handler mid-trap and read the register as it finds it there. Built with -ffixed-x28, as Go's code
 * is, the program holds a sentinel in x28 while it issues trapped syscalls with a bare svc under a 200 µs timer, whose
 * handler reads x28. The kernel keeps a program's registers, so every read finds the sentinel, wherever the signal
 * landed. Prints one line: the timer's signals while armed, how many of them landed during a trap, how many read
 * another value, and how many traps answered other than 0. A signal that lands during a trap is presented the trap
 * site's frame (7.5.7), counter and stack pointer, so the handler tells it by where its own frame lies: natively and
 * outside a trap the context it is given sits one ucontext below the stack pointer that context names; during a trap
 * the trap's frame, the launcher's and the kernel's second frame lie between. Elsewhere than aarch64 it says so and
 * exits 0. */
#define _GNU_SOURCE
#include <stdio.h>

#if defined(__aarch64__)
#include <signal.h>
#include <sys/time.h>
#include <ucontext.h>

#define SENTINEL 0x5e285e285e285e28UL
static volatile long armed, ticks, during, wrong;

static void on_alrm(int s, siginfo_t *si, void *ctx)
{
    unsigned long v, sp = ((ucontext_t *)ctx)->uc_mcontext.sp;
    (void)s;
    (void)si;
    __asm__ volatile("mov %0, x28" : "=r"(v));
    if (!armed) return;
    ticks++;
    /* more than two contexts between this one and the stack it names: other frames lie between */
    if (sp - (unsigned long)ctx > 2 * sizeof(ucontext_t)) during++;
    if (v != SENTINEL) wrong++;
}

/* faccessat(AT_FDCWD, path, F_OK, 0) by a bare svc, outside the syscall page: it traps */
static long svc_faccessat(const char *path)
{
    register long x0 __asm__("x0") = -100;
    register long x1 __asm__("x1") = (long)path;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    register long x8 __asm__("x8") = 48;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
    return x0;
}

int main(void)
{
    struct sigaction sa = {.sa_sigaction = on_alrm, .sa_flags = SA_SIGINFO | SA_RESTART};
    sigaction(SIGALRM, &sa, 0);
    struct itimerval it = {{0, 200}, {0, 200}};
    setitimer(ITIMER_REAL, &it, 0);
    long bad = 0;
    /* only this loop runs while armed: no C library code, which may use x28 as the callee-saved register it is */
    for (int round = 0; round < 2000 && during < 200; round++) {
        __asm__ volatile("mov x28, %0" : : "r"(SENTINEL));
        armed = 1;
        for (int k = 0; k < 100; k++)
            if (svc_faccessat("/usr/share/exclave-test-marker")) bad++;
        armed = 0;
    }
    struct itimerval off = {{0, 0}, {0, 0}};
    setitimer(ITIMER_REAL, &off, 0);
    printf("x28: %ld signals, %ld during a trap, %ld read another value, %ld traps failed\n", ticks, during, wrong,
           bad);
    return 0;
}
#else
int main(void)
{
    printf("x28: not aarch64\n");
    return 0;
}
#endif
