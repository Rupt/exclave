/* isa_test.c — the x86-64 CPU level check of DESIGN.md 7.7. Built by scripts/gate's unit step with src/isa.c.
 *
 * The decision is fed cpuid words and XCR0 values made up here, so that a kernel which has disabled AVX or AVX-512
 * state is covered on any machine: the CPU's features are not enough when the state is off. Then the launcher's own
 * answer for this machine is compared with gcc's __builtin_cpu_supports, which reads the same cpuid and XCR0.
 * x86-64 only; prints one line per failure and a summary, exit 0 when every case holds. */
#include <stdio.h>
#include <stdlib.h>
#include "../src/common.h"

struct exclave C;
void die(const char *what, const char *detail, long err) { fprintf(stderr, "die: %s %s %ld\n", what, detail ? detail : "", err); exit(99); }

#if defined(__x86_64__)
#define BIT(n) (1u << (n))
/* every feature bit of v2, v3 and v4, in the words isa.c reads */
static const unsigned C1 = BIT(13) | BIT(23) | BIT(0) | BIT(19) | BIT(20) | BIT(9) | BIT(28) | BIT(29) | BIT(12) | BIT(22) | BIT(27);
static const unsigned B7 = BIT(5) | BIT(3) | BIT(8) | BIT(16) | BIT(30) | BIT(28) | BIT(17) | BIT(31);
static const unsigned CX = BIT(0) | BIT(5);

static int fails, cases;
static void expect(int level, unsigned c1, unsigned b7, unsigned cx, unsigned long xcr0, int want, const char *what)
{
    cases++;
    int got = isa_x86_level_ok(level, c1, b7, cx, xcr0);
    if (got != want) { printf("FAIL v%d %s: got %d, want %d\n", level, what, got, want); fails++; }
}

int main(void)
{
    expect(2, C1, B7, CX, 0, 1, "needs no vector state");
    expect(3, C1, B7, CX, 0x7, 1, "SSE and AVX state enabled");
    expect(3, C1, B7, CX, 0x3, 0, "AVX state disabled by the kernel");
    expect(3, C1, B7, CX, 0x5, 0, "SSE state disabled");
    expect(3, C1 & ~BIT(27), B7, CX, 0x7, 0, "no OSXSAVE");
    expect(3, C1, B7 & ~BIT(5), CX, 0x7, 0, "no AVX2");
    expect(4, C1, B7, CX, 0xe7, 1, "AVX-512 state enabled");
    expect(4, C1, B7, CX, 0x7, 0, "AVX-512 state disabled by the kernel");
    expect(4, C1, B7, CX, 0x67, 0, "Hi16_ZMM state disabled");
    expect(4, C1, B7 & ~BIT(16), CX, 0xe7, 0, "no AVX512F");
    __builtin_cpu_init();
    int real[3] = {__builtin_cpu_supports("x86-64-v2"), __builtin_cpu_supports("x86-64-v3"), __builtin_cpu_supports("x86-64-v4")};
    static const char *const name[3] = {"x86-64-v2", "x86-64-v3", "x86-64-v4"};
    for (int i = 0; i < 3; i++) {
        cases++;
        int got = isa_supported(name[i], 0);
        if (got != (real[i] != 0)) { printf("FAIL this machine's %s: the launcher says %d, gcc says %d\n", name[i], got, real[i] != 0); fails++; }
    }
    printf("%s cpu levels: %d cases, %d failures; this machine is v%d\n", fails ? "FAIL" : "PASS", cases, fails,
           real[2] ? 4 : real[1] ? 3 : real[0] ? 2 : 1);
    return fails != 0;
}
#else
int main(void) { printf("PASS cpu levels: x86-64 only, nothing to check here\n"); return 0; }
#endif
