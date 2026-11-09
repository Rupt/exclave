/* tramp.c — the trampolines a program's signal handlers are installed behind (DESIGN.md 7.5.7).
 *
 * Every handler a program installs is recorded in a slot, and the slot's stub is installed in its place. A delivery
 * whose interrupted counter lies outside the launcher jumps straight to the program's handler, the kernel's frame
 * untouched. One that lands during a trapped call gets a frame of the trampoline's own, of the kernel's layout,
 * describing the trap site with the call as it stands, and the handler is called from the page's handler-call slot,
 * so that its return address is the restorer's own instructions and unwinders walk into the program's frames; its
 * return comes back through the filter's refusal of that rt_sigreturn, and what the handler left decides what the
 * program does.
 *
 * The code that runs during a delivery lies in the section exclave_tramp and calls nothing outside it: a signal that
 * lands there counts as outside the launcher, where the reserved register holds the program's value.
 */
#include <stdbool.h>

#include "common.h"

struct tramp_slot exclave_slots[TRAMP_SLOTS];
static unsigned nslots;

/* The stub for the program's handler h with mask: a slot holding both is reused; another is claimed by a
 * compare-and-swap bounded at TRAMP_SLOTS, its mask written first and the handler published last, with release order,
 * so that a reader acquiring a handler finds its mask. With none left, h itself. */
unsigned long tramp_stub_for(unsigned long h, unsigned long mask)
{
    unsigned n = __atomic_load_n(&nslots, __ATOMIC_ACQUIRE);
    for (unsigned i = 0; i < n; i++)
        if ((unsigned long)__atomic_load_n(&exclave_slots[i].h, __ATOMIC_ACQUIRE) == h && exclave_slots[i].mask == mask)
            return (unsigned long)exclave_stubs + i * TRAMP_STUB;
    do
        if (n >= TRAMP_SLOTS) return h;
    while (!__atomic_compare_exchange_n(&nslots, &n, n + 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    exclave_slots[n].mask = mask;
    __atomic_store_n(&exclave_slots[n].h, (void *)h, __ATOMIC_RELEASE);
    return (unsigned long)exclave_stubs + n * TRAMP_STUB;
}

long tramp_slot_of(unsigned long h)
{
    unsigned long d = h - (unsigned long)exclave_stubs;
    if (d >= TRAMP_SLOTS * TRAMP_STUB || d % TRAMP_STUB) return -1;
    long i = (long)(d / TRAMP_STUB);
    return __atomic_load_n(&exclave_slots[i].h, __ATOMIC_ACQUIRE) ? i : -1;
}

/* the block above the presented frame; its offsets are the assembly's below and the handler-call slot's */
struct tramp_block {
    unsigned long magic;     /* 0: TRAMP_MAGIC */
    void *reentry;           /* 8: where the handler-call slot jumps back to */
    char *kframe;            /* 16: the kernel's frame for this delivery, at its restorer's address (x86-64) */
    char *resume;            /* 24: the ucontext the program resumes from */
    unsigned long saved;     /* 32: the reserved register as the delivery found it */
    void *handler;           /* 40 */
    unsigned long entry_x30; /* 48: aarch64, the restorer the kernel set */
    unsigned long fr[2];     /* 56: aarch64, a frame record of the trap site's x29 and x30 */
    unsigned long kind;      /* 72 */
    unsigned long f2pc;      /* 80: the counter the delivery interrupted */
    unsigned long reg_len;   /* 88: aarch64, the bytes of records copied out */
    unsigned long slot;      /* 96 */
    unsigned long sig;       /* 104 */
};
_Static_assert(sizeof(struct tramp_block) == TRAMP_BLOCK, "the block's size is the assembly's");
/* each field the assembly below names by its offset, and the record's, which the re-issue slot and the entry stubs
 * name */
#define AT(f, n) _Static_assert(__builtin_offsetof(struct tramp_block, f) == (n), "the assembly's offset of " #f)
AT(magic, 0);
AT(reentry, 8);
AT(kframe, 16);
AT(saved, 32);
AT(handler, 40);
AT(entry_x30, 48);
AT(fr, 56);
AT(slot, 96);
AT(sig, 104);
#undef AT
_Static_assert(__builtin_offsetof(struct trap, uc) == 8, "the record's frame, as the entry stubs name it");
_Static_assert(__builtin_offsetof(struct trap, answer) == 16, "the record's answer, as the re-issue slot names it");
_Static_assert(__builtin_offsetof(struct trap, redirected) == 24, "the record's flag, as the re-issue slot names it");
#define TRAMP_MAGIC 0x7472616d706f6c31UL
_Static_assert(TRAMP_PRESENTED % 16 == 0 && TRAMP_BLOCK % 16 == 0, "the presented frame keeps the stack's alignment");

/* gcc keeps the name the assembly calls, never a clone's; clang, which only checks this file, has no noclone */
#ifdef __clang__
#define TRAMP __attribute__((section("exclave_tramp"), used, noinline))
#else
#define TRAMP __attribute__((section("exclave_tramp"), used, noinline, noclone))
#endif
#define INL static inline __attribute__((always_inline))

/* the frame's parts, by architecture (7.5.2): the ucontext from the frame's base, the siginfo, the general registers
 * the trampoline presents (x86-64: r8 to r15, rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip and eflags; aarch64: x0 to
 * x30, sp, pc and pstate), each run of them contiguous in the frame */
#if defined(__x86_64__)
#define UC_OF(base) ((base) + 8)
#define INFO_OF(uc) ((uc) + 304)
#define NREGS 18
#define R_PC 16
#define R_SP 15
#define R_ARG2 12
#define R_RESULT 13
#define R_RECORD 7
#define INSN 2
#define UC_HEAD 304 /* the whole kernel ucontext */
#define REISSUE_AFTER 9  /* the re-issue slot's offset past its syscall instruction */
#define REISSUE_SKIP 14  /* its path when a redirect stops the call */
#else
#define UC_OF(base) ((base) + 128)
#define INFO_OF(uc) ((uc) - 128)
#define NREGS 34
#define R_PC 32
#define R_SP 31
#define R_ARG2 2
#define R_RESULT 0
#define R_RECORD 27
#define INSN 4
#define UC_HEAD 184 /* uc_flags to fault_address */
#define RESERVED 464
#define REISSUE_AFTER 12
#define REISSUE_SKIP 20
#define ESR_MAGIC 0x45535201U
#endif
#define UC_STACK 16
#define KIND_STUB 1  /* a second signal onto a handler not yet entered */
#define KIND_ENTRY 2 /* the entry stub, before the record exists */
#define KIND_DONE 3  /* the trap's frame being returned through, the record gone */
#define KIND_TRAP 4  /* anywhere else in the launcher: the record names the trap */
#define AS_IS 0
#define NOT_MADE 1
#define MADE 2

INL unsigned long *regs(char *uc) { return (unsigned long *)(uc + UC_GREGS_OFF); }
INL void copy_words(void *dst, const void *src, unsigned long bytes)
{
    unsigned long *d = dst;
    const unsigned long *s = src;
    for (unsigned long i = 0; i < bytes / 8; i++) d[i] = s[i];
}
INL int seccomp_frame(const char *uc) { return *(const int *)(INFO_OF(uc) + SI_CODE_OFF) == SYS_SECCOMP; }
/* An invariant of the launcher's own broken: said, and the process ends through the page, where no handler of the
 * program's can catch it, as one for SIGILL or SIGTRAP could catch a trap instruction here, the trampoline's own
 * frames counted as outside the launcher, and loop. */
INL __attribute__((noreturn)) void broken(void)
{
    static const char msg[] = "launcher: a signal delivery found the trampoline's state broken\n";
    __sc6(NR_write, 2, (long)msg, sizeof msg - 1, 0, 0, 0);
    for (;;) __sc6(NR_exit_group, 127, 0, 0, 0, 0, 0);
}

/* Where the delivery landed, what the program resumes from, and how its call stands (7.5.7): the redirect flag, then
 * the re-issue slot's counter, then the record's answer. Called twice per delivery on the same inputs. */
TRAMP static int resolve(struct tramp_block *b, long *answer)
{
    char *f2 = UC_OF(b->kframe);
    unsigned long *g2 = regs(f2), pc = b->f2pc;
    unsigned long d = pc - (unsigned long)exclave_stubs;
    if (d < TRAMP_SLOTS * TRAMP_STUB && d % TRAMP_STUB == 0) {
        b->kind = KIND_STUB;
        b->resume = f2;
        return AS_IS;
    }
    if (pc >= (unsigned long)exclave_sigsys_entry && pc < (unsigned long)exclave_sigsys_set) {
        b->kind = KIND_ENTRY;
        b->resume = (char *)g2[R_ARG2];
        return seccomp_frame(b->resume) ? NOT_MADE : AS_IS;
    }
    if (pc == (unsigned long)exclave_sigsys_ret || pc - SC_RESTORER < 16) {
        b->kind = KIND_DONE;
#if defined(__x86_64__)
        b->resume = (char *)g2[R_SP] + (pc == (unsigned long)exclave_sigsys_ret ? 8 : 0);
#else
        b->resume = (char *)g2[R_SP] + 128;
#endif
        return AS_IS;
    }
    struct trap *rec = (struct trap *)b->saved;
    /* an invariant of the launcher's own: in its text, the register names a live record */
    if (!rec || rec->magic != TRAP_MAGIC) broken();
    b->kind = KIND_TRAP;
    b->resume = rec->uc;
    if (!seccomp_frame(b->resume) || rec->redirected) return AS_IS;
    unsigned long r = pc - SC_REISSUE;
    if (r < REISSUE_AFTER) return NOT_MADE;
    if (r < REISSUE_SKIP) {
        *answer = (long)g2[R_RESULT];
        return MADE;
    }
    if (rec->answer != ANSWER_NONE) {
        *answer = rec->answer;
        return MADE;
    }
    return NOT_MADE;
}

/* the general registers presented: the resume frame's, with the counter and the result register as the call stands */
TRAMP static void presented(struct tramp_block *b, int state, long answer, unsigned long *out)
{
    copy_words(out, regs(b->resume), NREGS * 8UL);
    /* a stub landing: the counter is the handler about to run, as natively */
    if (b->kind == KIND_STUB)
        out[R_PC] = (unsigned long)exclave_slots[(b->f2pc - (unsigned long)exclave_stubs) / TRAMP_STUB].h;
    if (state == NOT_MADE) out[R_PC] -= INSN;
    if (state == MADE) out[R_RESULT] = (unsigned long)answer;
}

#if defined(__aarch64__)
/* The records after a frame's registers, read with one checked bound, the 4096 bytes of __reserved less a terminator's
 * 16: each at least 16 bytes and 16-aligned. The bytes of the records before the terminator, or before the first
 * that breaks the bound; esr, set, the offset of an esr_context. */
TRAMP static unsigned long records(const char *res, long *esr)
{
    unsigned long off = 0;
    *esr = -1;
    while (off + 16 <= 4096 - 16) {
        unsigned magic = *(const unsigned *)(res + off), size = *(const unsigned *)(res + off + 4);
        if (magic == 0 || size < 16 || size % 16 || size > 4096 - 16 - off) break;
        if (magic == ESR_MAGIC) *esr = (long)off;
        off += size;
    }
    return off;
}
#endif

TRAMP static void exclave_tramp_present(struct tramp_block *b)
{
    char *f2 = UC_OF(b->kframe), *P = (char *)b - TRAMP_PRESENTED, *puc = UC_OF(P);
    unsigned long *g2 = regs(f2);
    b->f2pc = g2[R_PC];
    b->saved = g2[R_RECORD];
    b->handler = exclave_slots[b->slot].h;
    long answer = 0;
    int state = resolve(b, &answer);
    /* this delivery's own: its siginfo, its frame's fields, its mask */
    copy_words(INFO_OF(puc), INFO_OF(f2), 128);
    copy_words(puc, f2, UC_HEAD);
    unsigned long *pr = regs(puc);
    presented(b, state, answer, pr);
    copy_words(puc + UC_STACK, b->resume + UC_STACK, 24);
#if defined(__x86_64__)
    /* the floating-point state, by the pointer to the resume frame's save area */
    *(unsigned long *)(puc + UC_FPREGS_OFF) = *(unsigned long *)(b->resume + UC_FPREGS_OFF);
#else
    /* the floating-point records, the resume frame's, with this delivery's esr_context */
    long esr1, esr2;
    unsigned long n = records(b->resume + RESERVED, &esr1);
    records(f2 + RESERVED, &esr2);
    copy_words(puc + RESERVED, b->resume + RESERVED, n);
    *(unsigned long *)(puc + RESERVED + n) = 0; /* the terminator */
    *(unsigned long *)(puc + RESERVED + n + 8) = 0;
    if (esr1 >= 0 && esr2 >= 0)
        *(unsigned long *)(puc + RESERVED + esr1 + 8) = *(unsigned long *)(f2 + RESERVED + esr2 + 8);
    b->reg_len = n;
    b->fr[0] = regs(b->resume)[29];
    b->fr[1] = regs(b->resume)[30];
#endif
}

TRAMP static void exclave_tramp_after(struct tramp_block *b)
{
    char *f2 = UC_OF(b->kframe), *P = (char *)b - TRAMP_PRESENTED, *puc = UC_OF(P);
    unsigned long *g2 = regs(f2), *pr = regs(puc), e[NREGS];
    /* a handler that returned with a stack pointer not its own finds no block here */
    if (b->magic != TRAMP_MAGIC) broken();
    long answer = 0;
    int state = resolve(b, &answer);
    presented(b, state, answer, e);
    int changed = 0;
    for (int i = 0; i < NREGS; i++) changed |= pr[i] != e[i];
    /* the mask the handler left, SIGSYS never blocked (7.5.1): the rest of the launcher's handler runs with it, and the
     * program has it after the trap */
    unsigned long mask = *(unsigned long *)(puc + UC_SIGMASK_OFF) & ~SIGSYS_BIT;
    *(unsigned long *)(f2 + UC_SIGMASK_OFF) = mask;
    *(unsigned long *)(b->resume + UC_SIGMASK_OFF) = mask;
    copy_words(b->resume + UC_STACK, puc + UC_STACK, 24);
#if defined(__aarch64__)
    /* exactly the bytes copied out, never a length from headers the handler may have edited */
    copy_words(b->resume + RESERVED, puc + RESERVED, b->reg_len);
#endif
    if (!changed) return;
    copy_words(regs(b->resume), pr, NREGS * 8UL);
    /* a stub landing whose handler left the counter as presented: the stub runs next, its own handler presented */
    if (b->kind == KIND_STUB && pr[R_PC] == e[R_PC]) g2[R_PC] = b->f2pc;
    if (b->kind == KIND_ENTRY) {
        /* no record yet: the trap ends at once, through a return in the page to the launcher's restorer */
#if defined(__x86_64__)
        g2[R_PC] = SC_PAGE + 2;
        g2[R_SP] = (unsigned long)b->resume - 8;
#else
        g2[R_PC] = SC_PAGE + 4;
        g2[R_SP] = (unsigned long)b->resume - 128;
        g2[30] = SC_RESTORER;
#endif
    } else if (b->kind == KIND_TRAP) {
        ((struct trap *)b->saved)->redirected = 1;
        unsigned long r = b->f2pc - SC_REISSUE;
        if (r < REISSUE_AFTER) { /* the re-issue not made, or rewound to be made again: it ends with EINTR */
            g2[R_PC] = SC_REISSUE + REISSUE_AFTER;
            g2[R_RESULT] = (unsigned long)-EINTR;
        }
        if (b->f2pc >= (unsigned long)exclave_sigsys_tail && b->f2pc < (unsigned long)exclave_sigsys_done)
            g2[R_PC] = (unsigned long)exclave_sigsys_done;
    }
}

/* The stubs, then the trampoline: outside the launcher a jump to the program's handler with the kernel's registers,
 * elsewhere the presented frame and the handler called from the page (7.5.7). Offsets: the block at TRAMP_PRESENTED
 * above the presented frame, its fields as struct tramp_block. */
#if defined(__x86_64__)
__asm__(".section exclave_tramp,\"ax\",@progbits\n"
        ".globl exclave_stubs\n"
        ".hidden exclave_stubs, __start_exclave_tramp, __stop_exclave_tramp, __ehdr_start, _etext\n"
        ".balign 16\n"
        "exclave_stubs:\n"
        ".set exclave_stub_i, 0\n"
        ".rept 256\n"
        "  .balign 16\n"
        "  mov $exclave_stub_i, %r11d\n"
        "  jmp exclave_tramp_entry\n"
        "  .set exclave_stub_i, exclave_stub_i + 1\n"
        ".endr\n"
        "exclave_tramp_entry:\n"
        "  mov 168(%rdx), %rax\n" /* the interrupted rip */
        "  lea exclave_stubs(%rip), %rcx\n"
        "  sub %rcx, %rax\n"
        "  cmp $4096, %rax\n"
        "  jae 1f\n"
        "  test $15, %al\n"
        "  jz 2f\n" /* a stub's first instruction */
        "  jmp 3f\n"
        "1:\n"
        "  mov 168(%rdx), %rax\n"
        "  lea __start_exclave_tramp(%rip), %rcx\n"
        "  cmp %rcx, %rax\n"
        "  jb 4f\n"
        "  lea __stop_exclave_tramp(%rip), %rcx\n"
        "  cmp %rcx, %rax\n"
        "  jb 3f\n" /* in the trampoline: as outside */
        "4:\n"
        "  lea __ehdr_start(%rip), %rcx\n"
        "  cmp %rcx, %rax\n"
        "  jb 5f\n"
        "  lea _etext(%rip), %rcx\n"
        "  cmp %rcx, %rax\n"
        "  jb 2f\n" /* in the launcher */
        "5:\n"
        "  sub $0x7fe00000, %rax\n"
        "  cmp $4096, %rax\n"
        "  jae 3f\n" /* not in the page: outside */
        "  sub $48, %rax\n"
        "  cmp $32, %rax\n"
        "  jb 3f\n" /* the handler-call slot: as outside */
        "2:\n"
        "  jmp exclave_tramp_slow\n"
        "3:\n"
        "  shl $4, %r11\n"
        "  lea exclave_slots(%rip), %rax\n"
        "  mov (%rax,%r11), %rax\n"
        "  mov %rax, -8(%rsp)\n" /* below the stack pointer, where a nested frame starts 128 bytes lower */
        "  mov 64(%rdx), %r11\n"
        "  mov 152(%rdx), %rcx\n"
        "  xor %eax, %eax\n"
        "  jmp *-8(%rsp)\n"
        "exclave_tramp_slow:\n"
        "  mov %rsp, %rax\n"
        "  sub $1152, %rsp\n"     /* TRAMP_BLOCK + TRAMP_PRESENTED */
        "  mov %rax, 1056(%rsp)\n" /* kframe */
        "  mov %r11, 1136(%rsp)\n" /* slot */
        "  mov %rdi, 1144(%rsp)\n" /* sig */
        "  movabs $0x7472616d706f6c31, %rax\n"
        "  mov %rax, 1040(%rsp)\n"
        "  lea exclave_tramp_reentry(%rip), %rax\n"
        "  mov %rax, 1048(%rsp)\n"
        "  lea 1040(%rsp), %rdi\n"
        "  sub $8, %rsp\n"
        "  call exclave_tramp_present\n"
        "  add $8, %rsp\n"
        "  lea 8(%rsp), %rdx\n"     /* the presented ucontext */
        "  mov 1080(%rsp), %r11\n" /* handler */
        "  mov 128(%rdx), %rbx\n"
        "  mov 120(%rdx), %rbp\n"
        "  mov 72(%rdx), %r12\n"
        "  mov 80(%rdx), %r13\n"
        "  mov 88(%rdx), %r14\n"
        "  mov 96(%rdx), %r15\n"
        "  mov 1144(%rsp), %edi\n"
        "  lea 304(%rdx), %rsi\n"
        "  mov %rdx, %rsp\n"
        "  xor %eax, %eax\n"
        "  jmp *exclave_hcall(%rip)\n"
        "exclave_tramp_reentry:\n" /* from the handler-call slot, the stack pointer at the presented ucontext */
        "  sub $8, %rsp\n"
        "  mov 1072(%rsp), %r15\n" /* the reserved register as the delivery found it */
        "  lea 1040(%rsp), %rdi\n"
        "  sub $8, %rsp\n"
        "  call exclave_tramp_after\n"
        "  add $8, %rsp\n"
        "  mov 1056(%rsp), %rsp\n"
        "  ret\n" /* through the kernel's frame, into the program's restorer */
        ".balign 8\n"
        "exclave_hcall: .quad 0x7fe00030\n"
        ".text\n");
_Static_assert(TRAMP_PRESENTED == 1040 && TRAMP_BLOCK == 112, "the assembly's offsets");
_Static_assert(SC_HCALL == 0x7fe00030, "the assembly's handler-call slot");
#elif defined(__aarch64__)
__asm__(".section exclave_tramp,\"ax\",%progbits\n"
        ".globl exclave_stubs\n"
        ".hidden exclave_stubs, __start_exclave_tramp, __stop_exclave_tramp, __ehdr_start, _etext\n"
        ".balign 16\n"
        "exclave_stubs:\n"
        ".set exclave_stub_i, 0\n"
        ".rept 256\n"
        "  movz w16, #exclave_stub_i\n"
        "  b exclave_tramp_entry\n"
        "  .set exclave_stub_i, exclave_stub_i + 1\n"
        ".endr\n"
        "exclave_tramp_entry:\n"
        "  sub sp, sp, #16\n"
        "  str x15, [sp]\n"
        "  ldr x17, [sp, #584]\n" /* the interrupted pc: 16 + 128 + 440 */
        "  adrp x15, exclave_stubs\n"
        "  add x15, x15, :lo12:exclave_stubs\n"
        "  sub x15, x17, x15\n"
        "  cmp x15, #2048\n"
        "  b.hs 1f\n"
        "  tst x15, #7\n"
        "  b.eq 2f\n"
        "  b 3f\n"
        "1:\n"
        "  adrp x15, __start_exclave_tramp\n"
        "  add x15, x15, :lo12:__start_exclave_tramp\n"
        "  cmp x17, x15\n"
        "  b.lo 4f\n"
        "  adrp x15, __stop_exclave_tramp\n"
        "  add x15, x15, :lo12:__stop_exclave_tramp\n"
        "  cmp x17, x15\n"
        "  b.lo 3f\n"
        "4:\n"
        "  adrp x15, __ehdr_start\n"
        "  add x15, x15, :lo12:__ehdr_start\n"
        "  cmp x17, x15\n"
        "  b.lo 5f\n"
        "  adrp x15, _etext\n"
        "  add x15, x15, :lo12:_etext\n"
        "  cmp x17, x15\n"
        "  b.lo 2f\n"
        "5:\n"
        "  movz x15, #0x7fe0, lsl #16\n"
        "  sub x17, x17, x15\n"
        "  cmp x17, #4096\n"
        "  b.hs 3f\n"
        "  sub x17, x17, #48\n"
        "  cmp x17, #32\n"
        "  b.lo 3f\n"
        "2:\n"
        "  ldr x15, [sp]\n"
        "  add sp, sp, #16\n"
        "  b exclave_tramp_slow\n"
        "3:\n"
        "  adrp x15, exclave_slots\n"
        "  add x15, x15, :lo12:exclave_slots\n"
        "  add x15, x15, x16, lsl #4\n"
        "  ldr x16, [x15]\n"
        "  ldr x15, [sp]\n"
        "  add sp, sp, #16\n"
        "  ldr x17, [sp, #448]\n" /* x17 as interrupted: 128 + 184 + 17 * 8 */
        "  br x16\n"
        "exclave_tramp_slow:\n"
        "  mov x17, sp\n"
        "  mov x15, #4800\n" /* TRAMP_BLOCK + TRAMP_PRESENTED */
        "  sub sp, sp, x15\n"
        "  mov x15, #4688\n"
        "  add x15, sp, x15\n"
        "  str x17, [x15, #16]\n"
        "  str x16, [x15, #96]\n"
        "  str x0, [x15, #104]\n"
        "  str x30, [x15, #48]\n"
        "  movz x9, #0x6c31\n"
        "  movk x9, #0x706f, lsl #16\n"
        "  movk x9, #0x616d, lsl #32\n"
        "  movk x9, #0x7472, lsl #48\n"
        "  str x9, [x15]\n"
        "  adr x9, exclave_tramp_reentry\n"
        "  str x9, [x15, #8]\n"
        "  mov x0, x15\n"
        "  bl exclave_tramp_present\n"
        "  mov x15, #4688\n"
        "  add x15, sp, x15\n"
        "  add x2, sp, #128\n" /* the presented ucontext */
        "  ldr x18, [x2, #328]\n"
        "  ldp x19, x20, [x2, #336]\n"
        "  ldp x21, x22, [x2, #352]\n"
        "  ldp x23, x24, [x2, #368]\n"
        "  ldp x25, x26, [x2, #384]\n"
        "  ldp x27, x28, [x2, #400]\n"
        "  add x29, x15, #56\n"
        "  ldr x16, [x15, #40]\n"
        "  ldr x0, [x15, #104]\n"
        "  mov x1, sp\n"
        "  movz x9, #0x7fe0, lsl #16\n"
        "  add x9, x9, #48\n"
        "  br x9\n"
        "exclave_tramp_reentry:\n" /* from the handler-call slot, the stack pointer at the presented frame */
        "  mov x15, #4688\n"
        "  add x0, sp, x15\n"
        "  ldr x27, [x0, #32]\n"
        "  bl exclave_tramp_after\n"
        "  mov x15, #4688\n"
        "  add x15, sp, x15\n"
        "  ldr x30, [x15, #48]\n"
        "  ldr x17, [x15, #16]\n"
        "  mov sp, x17\n"
        "  ret\n" /* through the kernel's frame, into the program's restorer */
        ".text\n");
_Static_assert(TRAMP_PRESENTED == 4688 && TRAMP_BLOCK == 112, "the assembly's offsets");
_Static_assert(SC_HCALL == 0x7fe00030, "the assembly's handler-call slot");
#endif
