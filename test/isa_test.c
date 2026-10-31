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
void die(const char *what, const char *detail, long err)
{
    fprintf(stderr, "die: %s %s %ld\n", what, detail ? detail : "", err);
    exit(99);
}

#if defined(__x86_64__)
#define BIT(n) (1U << (n))
/* every feature of v2, v3 and v4 as the psABI lists them, by the cpuid word and bit that report it: leaf 1's ecx (C1),
 * leaf 7's ebx (B7) and leaf 0x80000001's ecx (CX); and the XCR0 state each vector level needs */
enum word { C1W, B7W, CXW, XCR0W };
static const struct {
    const char *name;
    enum word word;
    int bit, level;
} FEATURES[] = {
    /* clang-format off */
    {"CMPXCHG16B", C1W, 13, 2}, {"LAHF-SAHF", CXW, 0, 2}, {"POPCNT", C1W, 23, 2}, {"SSE3", C1W, 0, 2},
    {"SSE4.1", C1W, 19, 2}, {"SSE4.2", C1W, 20, 2}, {"SSSE3", C1W, 9, 2},
    {"AVX", C1W, 28, 3}, {"AVX2", B7W, 5, 3}, {"BMI1", B7W, 3, 3}, {"BMI2", B7W, 8, 3}, {"F16C", C1W, 29, 3},
    {"FMA", C1W, 12, 3}, {"LZCNT", CXW, 5, 3}, {"MOVBE", C1W, 22, 3}, {"OSXSAVE", C1W, 27, 3},
    {"SSE state", XCR0W, 1, 3}, {"AVX state", XCR0W, 2, 3},
    {"AVX512F", B7W, 16, 4}, {"AVX512BW", B7W, 30, 4}, {"AVX512CD", B7W, 28, 4}, {"AVX512DQ", B7W, 17, 4},
    {"AVX512VL", B7W, 31, 4}, {"opmask state", XCR0W, 5, 4}, {"ZMM_Hi256 state", XCR0W, 6, 4},
    {"Hi16_ZMM state", XCR0W, 7, 4},
    /* clang-format on */
};
#define NFEATURES (sizeof FEATURES / sizeof *FEATURES)

static int fails, cases;
static void expect(int level, unsigned c1, unsigned b7, unsigned cx, unsigned long xcr0, int want, const char *what)
{
    cases++;
    int got = isa_x86_level_ok(level, c1, b7, cx, xcr0);
    if (got != want) {
        printf("FAIL v%d %s: got %d, want %d\n", level, what, got, want);
        fails++;
    }
}

int main(void)
{
    unsigned all[3] = {0, 0, 0};
    unsigned long xcr0 = 0x1; /* x87 state, which no level asks about */
    for (size_t i = 0; i < NFEATURES; i++)
        if (FEATURES[i].word == XCR0W) xcr0 |= 1UL << FEATURES[i].bit;
        else all[FEATURES[i].word] |= BIT(FEATURES[i].bit);
    for (int level = 2; level <= 4; level++) expect(level, all[C1W], all[B7W], all[CXW], xcr0, 1, "every feature");
    /* each feature missing alone: the lowest level that needs it fails, and so does every level above it, while the
     * levels below hold */
    for (size_t i = 0; i < NFEATURES; i++) {
        unsigned w[3] = {all[0], all[1], all[2]};
        unsigned long x = xcr0;
        if (FEATURES[i].word == XCR0W) x &= ~(1UL << FEATURES[i].bit);
        else w[FEATURES[i].word] &= ~BIT(FEATURES[i].bit);
        char what[64];
        snprintf(what, sizeof what, "without %s", FEATURES[i].name);
        for (int level = 2; level <= 4; level++)
            expect(level, w[C1W], w[B7W], w[CXW], x, level < FEATURES[i].level, what);
    }
    expect(2, all[C1W], all[B7W], all[CXW], 0, 1, "needs no vector state");
    cases += 2;
    if (isa_supported("x86-64-v5", 0) != -1 || isa_supported("", 0) != -1) {
        printf("FAIL an unknown level is not -1\n");
        fails++;
    }
    __builtin_cpu_init();
    int real[3] = {__builtin_cpu_supports("x86-64-v2") ? 1 : 0, __builtin_cpu_supports("x86-64-v3") ? 1 : 0,
                   __builtin_cpu_supports("x86-64-v4") ? 1 : 0};
    static const char *const name[3] = {"x86-64-v2", "x86-64-v3", "x86-64-v4"};
    for (int i = 0; i < 3; i++) {
        cases++;
        int got = isa_supported(name[i], 0);
        if (got != (real[i] != 0)) {
            printf("FAIL this machine's %s: the launcher says %d, gcc says %d\n", name[i], got, real[i] != 0);
            fails++;
        }
    }
    printf("%s cpu levels: %d cases, %d failures; this machine is v%d\n", fails ? "FAIL" : "PASS", cases, fails,
           real[2]   ? 4
           : real[1] ? 3
           : real[0] ? 2
                     : 1);
    return fails != 0;
}
#else
int main(void)
{
    printf("PASS cpu levels: x86-64 only, nothing to check here\n");
    return 0;
}
#endif
