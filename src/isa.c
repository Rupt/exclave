/* isa.c — the CPU feature check (DESIGN.md 7.7): x86-64 psABI levels by cpuid and XCR0; aarch64 levels by AT_HWCAP. */
#include "common.h"

#if defined(__aarch64__)
int isa_supported(const char *isa, const unsigned long *auxv)
{
    if (xstrcmp(isa, "aarch64") == 0 || xstrcmp(isa, "armv8-a") == 0) return 1;
    unsigned long hwcap = 0;
    for (long i = 0; auxv[i * 2] != AT_NULL; i++)
        if (auxv[i * 2] == AT_HWCAP) hwcap = auxv[i * 2 + 1];
    /* HWCAP_ATOMICS (LSE) and HWCAP_CRC32 */
    if (xstrcmp(isa, "armv8.1-a") == 0) return (hwcap >> 8 & 1) && (hwcap >> 7 & 1);
    /* and HWCAP_DCPOP */
    if (xstrcmp(isa, "armv8.2-a") == 0) return (hwcap >> 8 & 1) && (hwcap >> 7 & 1) && (hwcap >> 16 & 1);
    return -1;
}
#else

/* XCR0, the state components the kernel has enabled; xgetbv faults unless cpuid says OSXSAVE */
static unsigned long xgetbv0(void)
{
    unsigned lo, hi;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    return (unsigned long)hi << 32 | lo;
}

/* The decision, from cpuid leaf 1's ecx, leaf 7's ebx, leaf 0x80000001's ecx and XCR0. A vector level needs the
 * CPU's features and the register state the kernel enables, without which its instructions fault: SSE and AVX state
 * for v3, and the AVX-512 opmask and both ZMM halves too for v4, as glibc's cpu_features asks. */
int isa_x86_level_ok(int level, unsigned c1, unsigned b7, unsigned cx, unsigned long xcr0)
{
    /* v2: CMPXCHG16B, LAHF-SAHF, POPCNT, SSE3, SSE4.1, SSE4.2, SSSE3 */
    int v2 =
        (c1 >> 13 & 1) && (cx & 1) && (c1 >> 23 & 1) && (c1 & 1) && (c1 >> 19 & 1) && (c1 >> 20 & 1) && (c1 >> 9 & 1);
    if (level == 2) return v2;
    /* v3: AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, OSXSAVE, and SSE and AVX state enabled */
    int v3 = v2 && (c1 >> 28 & 1) && (b7 >> 5 & 1) && (b7 >> 3 & 1) && (b7 >> 8 & 1) && (c1 >> 29 & 1) &&
             (c1 >> 12 & 1) && (cx >> 5 & 1) && (c1 >> 22 & 1) && (c1 >> 27 & 1) && (xcr0 & 0x6) == 0x6;
    if (level == 3) return v3;
    /* v4: AVX512F, AVX512BW, AVX512CD, AVX512DQ, AVX512VL, and opmask, ZMM_Hi256 and Hi16_ZMM state enabled */
    return v3 && (b7 >> 16 & 1) && (b7 >> 30 & 1) && (b7 >> 28 & 1) && (b7 >> 17 & 1) && (b7 >> 31 & 1) &&
           (xcr0 & 0xe6) == 0xe6;
}

int isa_supported(const char *isa, const unsigned long *auxv)
{
    (void)auxv;
    if (xstrcmp(isa, "x86-64") == 0) return 1;
    int level;
    if (xstrcmp(isa, "x86-64-v2") == 0) level = 2;
    else if (xstrcmp(isa, "x86-64-v3") == 0) level = 3;
    else if (xstrcmp(isa, "x86-64-v4") == 0) level = 4;
    else return -1;
    if (cpuid(0, 0).a < 7) return 0;                         /* the highest leaf */
    unsigned c1 = cpuid(1, 0).c, b7 = cpuid(7, 0).b, cx = cpuid(0x80000001U, 0).c;
    return isa_x86_level_ok(level, c1, b7, cx, (c1 >> 27 & 1) ? xgetbv0() : 0);
}
#endif
