/* sigframe.c — what a program's signal handler finds in its frame when its signal lands during a trapped call
 * (DESIGN.md 7.5.7, 13 item 58): the counter, the stack pointer, the result register, a callee-saved register and a
 * vector register the program set before the call, the signal mask, the floating-point state. A sibling thread
 * sends the signal while the thread is blocked in a trapped open of a FIFO, with and without SA_RESTART; while it
 * spins in a loop of its own, outside any trap; and as a rain on a loop of stats of a long path, so that signals land
 * while the call's path is walked. Then what a query of an action reports of the mask and flags it was given.
 * usage: sigframe HOSTDIR. Prints one line per case, "<case>: <answer>", each field a relation to what the program
 * set, the same in every world where the kernel is the oracle. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#define MARK 0x5eedf00dcafe1234L
#define VMARK 0x0123456789abcdefL
#define PAGE 0x7fe00000UL /* the launcher's syscall page (7.4.2) */

/* the stack pointer at the marked call or loop, written by the asm below */
volatile unsigned long sf_sp;
extern char sf_insn[], sf_after[], sf_loop[], sf_loop_end[];

/* one syscall of three arguments at a known instruction, with a callee-saved register and a vector register set */
__attribute__((noinline, noclone)) static long marked_syscall(long nr, long a, long b, long c)
{
#if defined(__x86_64__)
    long ret;
    register long r10 __asm__("r10") = 0;
    register long r12 __asm__("r12") = MARK;
    __asm__ volatile("movq %[v], %%xmm7\n\t"
                     "movq %%rsp, %[sp]\n\t"
                     ".globl sf_insn\nsf_insn:\n\tsyscall\n\t.globl sf_after\nsf_after:\n\t"
                     : "=a"(ret), [sp] "=m"(sf_sp)
                     : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r12), [v] "r"(VMARK)
                     : "rcx", "r11", "xmm7", "memory");
    return ret;
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = 0;
    register long x19 __asm__("x19") = MARK;
    __asm__ volatile("fmov d7, %[v]\n\t"
                     "mov x9, sp\n\t"
                     "str x9, %[sp]\n\t"
                     ".globl sf_insn\nsf_insn:\n\tsvc #0\n\t.globl sf_after\nsf_after:\n\t"
                     : "+r"(x0), [sp] "=m"(sf_sp)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x19), [v] "r"(VMARK)
                     : "x9", "v7", "memory");
    return x0;
#endif
}
/* a loop of its own, the same registers set, until *flag */
__attribute__((noinline, noclone)) static void marked_loop(volatile int *flag)
{
#if defined(__x86_64__)
    register long r12 __asm__("r12") = MARK;
    __asm__ volatile("movq %[v], %%xmm7\n\t"
                     "movq %%rsp, %[sp]\n\t"
                     ".globl sf_loop\nsf_loop:\n\tcmpl $0, (%[f])\n\tje sf_loop\n\t.globl sf_loop_end\nsf_loop_end:\n\t"
                     : [sp] "=m"(sf_sp)
                     : [f] "r"(flag), "r"(r12), [v] "r"(VMARK)
                     : "xmm7", "memory", "cc");
#elif defined(__aarch64__)
    register long x19 __asm__("x19") = MARK;
    __asm__ volatile(
        "fmov d7, %[v]\n\t"
        "mov x9, sp\n\t"
        "str x9, %[sp]\n\t"
        ".globl sf_loop\nsf_loop:\n\tldr w10, [%[f]]\n\tcbz w10, sf_loop\n\t.globl sf_loop_end\nsf_loop_end:\n\t"
        : [sp] "=m"(sf_sp)
        : [f] "r"(flag), "r"(x19), [v] "r"(VMARK)
        : "x9", "x10", "v7", "memory", "cc");
#endif
}

/* what a handler found */
struct seen {
    unsigned long pc, sp, mark, res, vec, mask;
    int fp;
};
static struct seen frame_of(void *ucv)
{
    ucontext_t *uc = ucv;
    struct seen s;
    memset(&s, 0, sizeof s);
    memcpy(&s.mask, &uc->uc_sigmask, sizeof s.mask);
#if defined(__x86_64__)
    s.pc = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];
    s.sp = (unsigned long)uc->uc_mcontext.gregs[REG_RSP];
    s.mark = (unsigned long)uc->uc_mcontext.gregs[REG_R12];
    s.res = (unsigned long)uc->uc_mcontext.gregs[REG_RAX];
    if (uc->uc_mcontext.fpregs) {
        s.fp = 1;
        s.vec = uc->uc_mcontext.fpregs->_xmm[7].element[0] | (unsigned long)uc->uc_mcontext.fpregs->_xmm[7].element[1]
                                                                 << 32;
    }
#elif defined(__aarch64__)
    s.pc = uc->uc_mcontext.pc;
    s.sp = uc->uc_mcontext.sp;
    s.mark = uc->uc_mcontext.regs[19];
    s.res = uc->uc_mcontext.regs[0];
    /* the records after the registers: magic and size, FPSIMD_MAGIC's with fpsr, fpcr and the 32 vector registers */
    const unsigned char *r = (const unsigned char *)&uc->uc_mcontext.__reserved;
    for (unsigned off = 0; off + 8 <= 4096;) {
        uint32_t magic, size;
        memcpy(&magic, r + off, 4);
        memcpy(&size, r + off + 4, 4);
        if (!magic || size < 8) break;
        if (magic == 0x46508001U) {
            s.fp = 1;
            memcpy(&s.vec, r + off + 16 + 7 * 16, 8);
            break;
        }
        off += size;
    }
#endif
    return s;
}

static volatile int landed;
static struct seen one;
static void on_one(int sig, siginfo_t *si, void *uc)
{
    (void)sig;
    (void)si;
    one = frame_of(uc);
    landed = 1;
}
#define RAIN 4096
static struct seen rain[RAIN];
static volatile int nrain;
static void on_rain(int sig, siginfo_t *si, void *uc)
{
    (void)sig;
    (void)si;
    int i = __atomic_fetch_add(&nrain, 1, __ATOMIC_RELAXED);
    if (i < RAIN) rain[i] = frame_of(uc);
}
static void install(int sig, void (*h)(int, siginfo_t *, void *), int flags)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = h;
    sa.sa_flags = SA_SIGINFO | flags;
    sigaction(sig, &sa, 0);
}
static unsigned long mask_now(void)
{
    sigset_t m;
    unsigned long w = 0;
    pthread_sigmask(SIG_BLOCK, 0, &m);
    memcpy(&w, &m, sizeof w);
    return w;
}

/* the mappings, read before a case's frames are judged: the one holding an address, by its file's base name */
static char maps[1 << 16];
static void read_maps(void)
{
    FILE *f = fopen("/proc/self/maps", "r");
    size_t n = f ? fread(maps, 1, sizeof maps - 1, f) : 0;
    maps[n] = 0;
    if (f) fclose(f);
}
static const char *mapping(unsigned long a, char *out, size_t len)
{
    for (char *l = maps; *l;) {
        char *e = strchr(l, '\n');
        unsigned long lo, hi;
        if (sscanf(l, "%lx-%lx", &lo, &hi) == 2 && a >= lo && a < hi) {
            char *p = e ? e : l + strlen(l);
            char *s = p;
            while (s > l && s[-1] != ' ' && s[-1] != '/') s--;
            snprintf(out, len, "%.*s", (int)(p - s), s);
            if (!*out) snprintf(out, len, "an anonymous mapping");
            return out;
        }
        if (!e) break;
        l = e + 1;
    }
    snprintf(out, len, "no mapping");
    return out;
}

static unsigned long the_mask, nr_called, arg0;
/* where a counter lies, as a relation to the program's own code */
static const char *where(unsigned long pc, char *b, size_t len)
{
    if (pc == (unsigned long)sf_insn) return "at the syscall instruction";
    if (pc == (unsigned long)sf_after) return "after the syscall instruction";
    if (pc >= (unsigned long)sf_loop && pc <= (unsigned long)sf_loop_end) return "in the loop";
    if (pc >> 12 == PAGE >> 12) return "in the launcher's syscall page";
    char m[256], self[256];
    mapping(pc, m, sizeof m);
    mapping((unsigned long)where, self, sizeof self);
    if (!strcmp(m, self)) return "elsewhere in the program";
    snprintf(b, len, "in %s", m);
    return b;
}
static const char *result(unsigned long r)
{
    if ((long)r == -EINTR) return "-EINTR";
    if (r == nr_called) return "the syscall number";
    if (r == arg0) return "the first argument";
    if ((long)r >= 0) return "a result";
    return "another value";
}
static void print_frame(const char *what, const struct seen *s)
{
    char b[300];
    printf("%s: counter %s\n", what, where(s->pc, b, sizeof b));
    printf("%s: result register %s\n", what, result(s->res));
    printf("%s: stack pointer %s\n", what, s->sp == sf_sp ? "the program's" : "another");
    printf("%s: marked register %s\n", what, s->mark == (unsigned long)MARK ? "the value set" : "another value");
    printf("%s: signal mask %s\n", what, s->mask == the_mask ? "the program's" : "another");
    printf("%s: floating-point state %s\n", what,
           !s->fp                           ? "absent"
           : s->vec == (unsigned long)VMARK ? "present, the vector register as set"
                                            : "present, the vector register another value");
}

static char fifo[4096];
static long opened;
static void *blocked_open(void *arg)
{
    (void)arg;
    the_mask = mask_now();
    opened = marked_syscall(SYS_openat, AT_FDCWD, (long)fifo, O_RDONLY);
    if (opened >= 0) close((int)opened);
    return 0;
}
static volatile int stop_loop;
static pid_t loop_tid;
static void *spinning(void *arg)
{
    (void)arg;
    the_mask = mask_now();
    loop_tid = (pid_t)syscall(SYS_gettid);
    marked_loop(&stop_loop);
    return 0;
}
static void wait_landed(void)
{
    for (int i = 0; i < 2000 && !landed; i++) usleep(1000);
}

/* a path of many components inside the tree: the walk is long, the answer the marker's */
static char longpath[4096];
static volatile int raining;
static pid_t stat_tid;
static long stats_ok, stats_other;
static void *stats(void *arg)
{
    (void)arg;
    struct stat st;
    the_mask = mask_now();
    stat_tid = (pid_t)syscall(SYS_gettid);
    while (!raining) usleep(100);
    for (int i = 0; i < 3000 && nrain < RAIN / 2; i++) {
        long r = marked_syscall(SYS_newfstatat, AT_FDCWD, (long)longpath, (long)&st);
        if (r == 0) stats_ok++;
        else stats_other++;
    }
    raining = 0;
    return 0;
}

/* the cases of a handler that decides: it moves the counter, edits the mask, blocks everything, jumps out */
static volatile int went, decided;
static sigjmp_buf back;
__attribute__((noinline)) static void landing(void)
{
    went = 1;
    /* back into the thread's function: nothing returns through the frame the handler invented */
    siglongjmp(back, 2);
}
static void on_move(int sig, siginfo_t *si, void *ucv)
{
    (void)sig;
    (void)si;
    ucontext_t *uc = ucv;
#if defined(__x86_64__)
    /* a call's entry: the stack pointer 8 modulo 16 */
    uc->uc_mcontext.gregs[REG_RSP] = (uc->uc_mcontext.gregs[REG_RSP] & ~15L) - 8;
    uc->uc_mcontext.gregs[REG_RIP] = (long)landing;
#elif defined(__aarch64__)
    uc->uc_mcontext.pc = (unsigned long)landing;
#endif
    decided = 1;
}
static void on_mask(int sig, siginfo_t *si, void *ucv)
{
    (void)sig;
    (void)si;
    sigaddset(&((ucontext_t *)ucv)->uc_sigmask, SIGUSR2);
    decided = 1;
}
static void on_fill(int sig, siginfo_t *si, void *ucv)
{
    (void)sig;
    (void)si;
    sigfillset(&((ucontext_t *)ucv)->uc_sigmask);
    decided = 1;
}
static void on_jump(int sig, siginfo_t *si, void *ucv)
{
    (void)sig;
    (void)si;
    (void)ucv;
    decided = 1;
    siglongjmp(back, 1);
}
static char after[64];
static void *decide_open(void *arg)
{
    long mode = (long)arg;
    if (mode == 0 && sigsetjmp(back, 1)) return 0;
    if (mode == 3 && sigsetjmp(back, 1)) {
        struct stat st;
        snprintf(after, sizeof after, "back, stat %s", stat("/usr/share", &st) == 0 ? "ok" : "failed");
        return 0;
    }
    opened = marked_syscall(SYS_openat, AT_FDCWD, (long)fifo, O_RDONLY);
    if (opened >= 0) close((int)opened);
    sigset_t m;
    pthread_sigmask(SIG_BLOCK, 0, &m);
    if (mode == 1) snprintf(after, sizeof after, "SIGUSR2 %s", sigismember(&m, SIGUSR2) ? "blocked" : "unblocked");
    if (mode == 2) {
        struct stat st;
        int ok = stat("/usr/share", &st) == 0;
        sigemptyset(&m);
        pthread_sigmask(SIG_SETMASK, &m, 0);
        snprintf(after, sizeof after, "stat %s", ok ? "ok" : "failed");
    }
    return 0;
}
/* one blocking open, a signal for the handler h, what the thread did after */
static void decide(const char *what, void (*h)(int, siginfo_t *, void *), long mode)
{
    install(SIGUSR1, h, 0);
    went = decided = 0;
    after[0] = 0;
    opened = 1;
    pthread_t t;
    pthread_create(&t, 0, decide_open, (void *)mode);
    usleep(100000);
    pthread_kill(t, SIGUSR1);
    for (int i = 0; i < 2000 && !decided; i++) usleep(1000);
    usleep(20000);
    int w = open(fifo, O_WRONLY | O_NONBLOCK);
    pthread_join(t, 0);
    if (w >= 0) close(w);
    if (mode == 0) printf("%s: %s\n", what, went ? "the thread went where it was sent" : "the thread did not");
    else if (mode == 3) printf("%s: %s\n", what, after);
    else printf("%s: open %s, %s\n", what, opened == -EINTR ? "EINTR" : opened >= 0 ? "a descriptor" : "failed", after);
}

static void on_count(int sig) { (void)sig; }
/* the action an install replaces, which the kernel reports from what was installed: the action queried is put back
 * as it was, and the replaced one is the answer */
static void replaced(int sig, struct sigaction *old)
{
    struct sigaction q;
    memset(&q, 0, sizeof q);
    sigaction(sig, 0, &q);
    memset(old, 0, sizeof *old);
    sigaction(sig, &q, old);
}
/* a chain: a handler called by another through the action a query returned, with the arguments it was given */
static void (*first)(int, siginfo_t *, void *);
static volatile int chain_sig, chain_same;
static siginfo_t *chain_si;
static void on_first(int sig, siginfo_t *si, void *uc)
{
    (void)uc;
    chain_sig = sig;
    chain_same = si == chain_si;
}
static void on_second(int sig, siginfo_t *si, void *uc)
{
    chain_si = si;
    first(sig, si, uc);
}
static void *installs(void *arg)
{
    struct sigaction a;
    memset(&a, 0, sizeof a);
    sigemptyset(&a.sa_mask);
    sigaddset(&a.sa_mask, (int)(long)arg);
    for (int i = 0; i < 2000; i++) {
        a.sa_handler = i & 1 ? on_count : SIG_IGN;
        sigaction(SIGUSR2, &a, 0);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[2], "query")) {
        struct sigaction old;
        memset(&old, 0, sizeof old);
        sigaction(SIGUSR2, 0, &old);
        printf("an ignored signal queried after execve: %s\n", old.sa_handler == SIG_IGN ? "ignored" : "another");
        return 0;
    }
    if (argc < 2) return 2;
    setvbuf(stdout, 0, _IOLBF, 0);
    snprintf(fifo, sizeof fifo, "%s/fifo", argv[1]);
    mkfifo(fifo, 0600);
    pid_t me = getpid();

    /* 1. blocked in a trapped open of a FIFO, a sibling's signal, with SA_RESTART and without */
    for (int restart = 1; restart >= 0; restart--) {
        const char *what = restart ? "blocking open, SA_RESTART" : "blocking open, no SA_RESTART";
        install(SIGUSR1, on_one, restart ? SA_RESTART : 0);
        landed = 0;
        nr_called = SYS_openat;
        arg0 = (unsigned long)(long)AT_FDCWD;
        pthread_t t;
        pthread_create(&t, 0, blocked_open, 0);
        usleep(100000);
        pthread_kill(t, SIGUSR1);
        wait_landed();
        usleep(20000);
        int w = open(fifo, O_WRONLY | O_NONBLOCK);
        pthread_join(t, 0);
        if (w >= 0) close(w);
        read_maps();
        if (!landed) printf("%s: the handler did not run\n", what);
        else print_frame(what, &one);
        printf("%s: the open %s\n", what,
               opened >= 0        ? "returned a descriptor"
               : opened == -EINTR ? "failed with EINTR"
                                  : "failed otherwise");
    }

    /* 2. outside any trap: a loop of the program's own */
    {
        install(SIGUSR1, on_one, SA_RESTART);
        landed = 0;
        stop_loop = 0;
        pthread_t t;
        pthread_create(&t, 0, spinning, 0);
        usleep(50000);
        pthread_kill(t, SIGUSR1);
        wait_landed();
        stop_loop = 1;
        pthread_join(t, 0);
        read_maps();
        if (!landed) printf("outside a trap: the handler did not run\n");
        else print_frame("outside a trap", &one);
    }

    /* 3. a rain of signals on stats of a long path, so that some land while the path is walked */
    {
        size_t n = (size_t)snprintf(longpath, sizeof longpath, "/usr/share");
        while (n + 32 < sizeof longpath) n += (size_t)snprintf(longpath + n, sizeof longpath - n, "/../share");
        snprintf(longpath + n, sizeof longpath - n, "/exclave-test-marker");
        install(SIGUSR2, on_rain, SA_RESTART);
        nrain = 0;
        raining = 0;
        nr_called = SYS_newfstatat;
        arg0 = (unsigned long)(long)AT_FDCWD;
        pthread_t t;
        pthread_create(&t, 0, stats, 0);
        while (!stat_tid) usleep(100);
        raining = 1;
        while (raining) {
            syscall(SYS_tgkill, me, stat_tid, SIGUSR2);
            struct timespec ts = {0, 30000};
            nanosleep(&ts, 0);
        }
        pthread_join(t, 0);
        read_maps();
        int got = nrain < RAIN ? nrain : RAIN;
        int marks_ok = 1, sps_ok = 1, results_ok = 1, masks_ok = 1, np = 0;
        char *parts[16], b[300];
        /* the landings outside the program and its libraries, by mapping: none where the kernel answers */
        for (int i = 0; i < got; i++) {
            const char *w = where(rain[i].pc, b, sizeof b);
            if (rain[i].mask != the_mask) masks_ok = 0;
            if (rain[i].pc == (unsigned long)sf_insn || rain[i].pc == (unsigned long)sf_after) {
                if (rain[i].mark != (unsigned long)MARK) marks_ok = 0;
                if (rain[i].sp != sf_sp) sps_ok = 0;
                if (rain[i].pc == (unsigned long)sf_after && rain[i].res != 0) results_ok = 0;
                continue;
            }
            if (!strcmp(w, "elsewhere in the program") || strstr(w, ".so") || strstr(w, "[vdso]")) continue;
            int known = 0;
            for (int k = 0; k < np; k++) known |= !strcmp(parts[k], w);
            if (!known && np < 16) parts[np++] = strdup(w);
        }
        for (int i = 1; i < np; i++)
            for (int j = i; j > 0 && strcmp(parts[j - 1], parts[j]) > 0; j--) {
                char *x = parts[j];
                parts[j] = parts[j - 1];
                parts[j - 1] = x;
            }
        printf("stats of a long path under a rain: %s\n", stats_other ? "some failed" : "every stat answered");
        printf("stats of a long path under a rain: landings outside the program and its libraries %s",
               np ? "" : "none");
        for (int i = 0; i < np; i++) printf("%s%s", i ? ", " : "", parts[i]);
        printf("\n");
        /* every landing at the syscall instruction or after it, none counting as every */
        printf("stats of a long path under a rain: at the syscall instruction or after it, %s\n",
               marks_ok && sps_ok && results_ok ? "the program's registers and the stat's result"
                                                : "registers or a result not the program's");
        printf("stats of a long path under a rain: signal mask %s\n",
               masks_ok ? "the program's at every landing" : "another at some");
    }

    /* 4. a query of an action reports what was installed: the mask with SIGSYS in it, the flags */
    {
        struct sigaction sa, old;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = on_one;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigemptyset(&sa.sa_mask);
        sigaddset(&sa.sa_mask, SIGSYS);
        sigaddset(&sa.sa_mask, SIGUSR2);
        sigaction(SIGUSR1, &sa, 0);
        memset(&old, 0, sizeof old);
        sigaction(SIGUSR1, 0, &old);
        printf("query of an installed action: handler %s, mask %s, flags %s\n",
               old.sa_sigaction == on_one ? "the program's" : "another",
               sigismember(&old.sa_mask, SIGSYS) && sigismember(&old.sa_mask, SIGUSR2) ? "as written"
               : sigismember(&old.sa_mask, SIGUSR2)                                    ? "without SIGSYS"
                                                                                       : "another",
               (old.sa_flags & (int)(SA_SIGINFO | SA_RESTART | SA_ONSTACK | SA_NODEFER | SA_RESETHAND)) ==
                       (int)(SA_SIGINFO | SA_RESTART)
                   ? "as written"
                   : "others");
        replaced(SIGUSR1, &old);
        printf("the action an install replaces: handler %s, mask %s\n",
               old.sa_sigaction == on_one ? "the program's" : "another",
               sigismember(&old.sa_mask, SIGSYS) && sigismember(&old.sa_mask, SIGUSR2) ? "as written" : "another");
        install(SIGUSR2, on_first, 0);
        struct sigaction q;
        sigaction(SIGUSR2, 0, &q);
        first = q.sa_sigaction;
        install(SIGUSR2, on_second, 0);
        raise(SIGUSR2);
        printf("a handler called by another through the action a query returned: %s\n",
               chain_sig == SIGUSR2 && chain_same ? "ran with the arguments given" : "did not");
        signal(SIGUSR2, SIG_IGN);
        memset(&old, 0, sizeof old);
        sigaction(SIGUSR2, 0, &old);
        printf("query of an ignored signal: %s\n", old.sa_handler == SIG_IGN ? "ignored" : "another");
        memset(&old, 0, sizeof old);
        sigaction(SIGWINCH, 0, &old);
        printf("query of a signal never installed: %s\n", old.sa_handler == SIG_DFL ? "default" : "another");
    }

    /* 5. a handler that decides, during a blocking trapped open */
    decide("a handler that moves the counter", on_move, 0);
    decide("a handler that blocks SIGUSR2 in its frame", on_mask, 1);
    decide("a handler that blocks every signal in its frame, then a trap", on_fill, 2);
    decide("a handler that siglongjmps out", on_jump, 3);

    /* 6. installs: from two threads at once, from a vfork child, SA_RESETHAND, a bad oldact, across execve */
    {
        pthread_t a, b;
        pthread_create(&a, 0, installs, (void *)(long)SIGHUP);
        pthread_create(&b, 0, installs, (void *)(long)SIGINT);
        pthread_join(a, 0);
        pthread_join(b, 0);
        struct sigaction old;
        replaced(SIGUSR2, &old);
        printf("installs from two threads at once: the last %s\n",
               old.sa_handler == on_count && (sigismember(&old.sa_mask, SIGHUP) || sigismember(&old.sa_mask, SIGINT))
                   ? "installed"
                   : "not one installed");
        install(SIGUSR1, on_one, 0);
        pid_t c = vfork();
        if (c == 0) {
            signal(SIGUSR1, SIG_IGN);
            _exit(0);
        }
        waitpid(c, 0, 0);
        replaced(SIGUSR1, &old);
        printf("an install in a vfork child: the parent's action %s\n",
               old.sa_sigaction == on_one ? "unchanged" : "changed");
        install(SIGUSR1, on_one, (int)SA_RESETHAND);
        landed = 0;
        raise(SIGUSR1);
        sigaction(SIGUSR1, 0, &old);
        printf("SA_RESETHAND: the handler %s, then %s\n", landed ? "ran" : "did not run",
               old.sa_handler == SIG_DFL ? "default" : "another");
        /* the kernel's struct sigaction, so that the libc copies nothing to the bad address itself; never delivered */
        unsigned long k[4] = {(unsigned long)on_count, 0, 0, 0};
        long e = syscall(SYS_rt_sigaction, SIGUSR1, k, (void *)8, 8);
        int err = errno;
        replaced(SIGUSR1, &old);
        printf("a bad oldact: %s, the new action %s\n", e < 0 && err == EFAULT ? "EFAULT" : "another answer",
               old.sa_handler == on_count ? "in force" : "not in force");
        signal(SIGUSR2, SIG_IGN);
        fflush(stdout);
        c = fork();
        if (c == 0) {
            char *av[] = {argv[0], argv[1], "query", 0};
            execv("/proc/self/exe", av);
            _exit(9);
        }
        waitpid(c, 0, 0);
    }
    return 0;
}
