/* sve_frame.c — 7.5.7 on aarch64: the vector state across a trapped call and in the frame a handler is given while
 * one is under way. z8 is set by an SVE instruction before each trapped call, a bare svc under a 1 ms timer, and read
 * after it: the low 128 bits are the program's, and the rest is what the kernel leaves across a system call, zero.
 * The timer's handler reads v8 in its frame's fpsimd record, which holds the program's value wherever the signal
 * landed, and z8's low bits in an SVE record that carries registers; it writes v9 there, and the program finds the
 * value in the register afterwards. A signal that landed during a trap is told as x28.c tells it. Prints one line per
 * case, the same natively and inside but the last, which says whether a signal landed during a trap. Without SVE it
 * says so; elsewhere than aarch64 it says that. The path it asks about is /usr, which every world has. Exit 0
 * always. */
#define _GNU_SOURCE
#include <stdio.h>

#if defined(__aarch64__)
#include <signal.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/time.h>
#include <ucontext.h>

#define FPSIMD_MAGIC_ 0x46508001U
#define SVE_MAGIC_ 0x53564501U
#define HWCAP_SVE_ (1UL << 22)
static volatile long armed, ticks, during, wrong;
static const unsigned char want9[16] = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                                        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};

/* the pattern index z8.b, #1, #1 leaves: byte i holds i + 1 */
static int low_kept(const unsigned char *z)
{
    for (int i = 0; i < 16; i++)
        if (z[i] != i + 1) return 0;
    return 1;
}

static void on_alrm(int s, siginfo_t *si, void *ctx)
{
    ucontext_t *uc = ctx;
    (void)s;
    (void)si;
    if (!armed) return; /* before z8 is first set */
    ticks++;
    if (uc->uc_mcontext.sp - (unsigned long)ctx > 2 * sizeof(ucontext_t)) during++;
    /* the records after the registers, each a magic and a size, to a zero magic: one checked bound */
    unsigned char *r = (unsigned char *)uc->uc_mcontext.__reserved;
    size_t off = 0, room = sizeof uc->uc_mcontext.__reserved;
    int found = 0;
    while (off + 16 <= room) {
        unsigned magic, size;
        memcpy(&magic, r + off, 4);
        memcpy(&size, r + off + 4, 4);
        if (magic == 0 || size < 16 || size > room - off) break;
        if (magic == FPSIMD_MAGIC_ && size >= 16 + 32 * 16) {
            /* fpsr and fpcr, then the 32 vector registers of 16 bytes */
            unsigned char *v = r + off + 16;
            found = 1;
            if (!low_kept(v + 8 * 16)) wrong++;
            memcpy(v + 9 * 16, want9, 16);
        }
        /* an SVE record that carries registers: vl at 8, the z registers from 16, each of vl bytes */
        if (magic == SVE_MAGIC_ && size > 16) {
            unsigned short vl;
            memcpy(&vl, r + off + 8, 2);
            if (vl >= 16 && 16 + 10UL * vl <= size) {
                if (!low_kept(r + off + 16 + 8UL * vl)) wrong++;
                memcpy(r + off + 16 + 9UL * vl, want9, 16);
            }
        }
        off += size;
    }
    if (!found) wrong++;
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
    if (!(getauxval(AT_HWCAP) & HWCAP_SVE_)) {
        printf("sve_frame: no SVE on this machine\n");
        return 0;
    }
    unsigned long vl;
    __asm__ volatile(".arch_extension sve\n rdvl %0, #1" : "=r"(vl));
    printf("vector length a multiple of 16 bytes: %s\n", vl >= 16 && vl % 16 == 0 && vl <= 256 ? "yes" : "no");
    struct sigaction sa = {.sa_sigaction = on_alrm, .sa_flags = SA_SIGINFO | SA_RESTART};
    sigaction(SIGALRM, &sa, 0);
    struct itimerval it = {{0, 1000}, {0, 1000}};
    static unsigned char z[256], q9[16];
    long kept = 0, zero = 0, bad = 0, calls = 0;
    setitimer(ITIMER_REAL, &it, 0);
    /* no C library call between the instruction that sets z8 and the one that stores it; the handler judges from the
     * first setting on */
    __asm__ volatile(".arch_extension sve\n index z8.b, #1, #1" : : : "v8");
    armed = 1;
    for (int round = 0; round < 400 && (during < 20 || round < 40); round++)
        for (int k = 0; k < 50; k++) {
            __asm__ volatile(".arch_extension sve\n index z8.b, #1, #1" : : : "v8");
            if (svc_faccessat("/usr")) bad++;
            __asm__ volatile(".arch_extension sve\n ptrue p0.b\n st1b z8.b, p0, [%0]" : : "r"(z) : "p0", "memory");
            int rest = 1;
            for (unsigned long i = 16; i < vl; i++) rest &= z[i] == 0;
            calls++;
            kept += low_kept(z);
            zero += rest;
        }
    armed = 0;
    struct itimerval off = {{0, 0}, {0, 0}};
    setitimer(ITIMER_REAL, &off, 0);
    __asm__ volatile("str q9, [%0]" : : "r"(q9) : "memory");
    printf("trapped calls answered: %s\n", bad ? "some failed" : "all 0");
    printf("z8's low 128 bits after a trapped call: %s\n", kept == calls ? "kept every time" : "lost");
    printf("z8's bits above them after a trapped call: %s\n", vl == 16        ? "none at this length"
                                                              : zero == calls ? "zero every time"
                                                              : zero          ? "sometimes zero"
                                                                              : "kept");
    printf("v8 in the handler's frame: %s\n", !ticks ? "no signal" : wrong ? "wrong" : "the program's");
    printf("v9 written in the handler's frame: %s\n", memcmp(q9, want9, 16) ? "lost" : "in the register afterwards");
    printf("signals during a trap: %s\n", during ? "some" : "none");
    return 0;
}
#else
int main(void)
{
    printf("sve_frame: not aarch64\n");
    return 0;
}
#endif
