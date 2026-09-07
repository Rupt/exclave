/* isa.c — the CPU feature check (PROPOSAL.md 7.7): x86-64 psABI levels by cpuid; aarch64 levels by AT_HWCAP. */
#include "common.h"

#if defined(__aarch64__)
int isa_supported(const char *isa, unsigned long *auxv)
{
    if (xstrcmp(isa, "aarch64") == 0 || xstrcmp(isa, "armv8-a") == 0) return 1;
    unsigned long hwcap = 0;
    for (long i = 0; auxv[i * 2] != AT_NULL; i++) if (auxv[i * 2] == AT_HWCAP) hwcap = auxv[i * 2 + 1];
    if (xstrcmp(isa, "armv8.1-a") == 0) return (hwcap >> 8 & 1) && (hwcap >> 7 & 1);   /* HWCAP_ATOMICS (LSE) and HWCAP_CRC32 */
    if (xstrcmp(isa, "armv8.2-a") == 0) return (hwcap >> 8 & 1) && (hwcap >> 7 & 1) && (hwcap >> 16 & 1);   /* and HWCAP_DCPOP */
    return -1;
}
#else
static void cpuid(unsigned leaf, unsigned sub, unsigned *a, unsigned *b, unsigned *c, unsigned *d)
{
    __asm__ volatile ("cpuid" : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d) : "a"(leaf), "c"(sub));
}

int isa_supported(const char *isa, unsigned long *auxv)
{
    (void)auxv;
    if (xstrcmp(isa, "x86-64") == 0) return 1;
    int level;
    if (xstrcmp(isa, "x86-64-v2") == 0) level = 2;
    else if (xstrcmp(isa, "x86-64-v3") == 0) level = 3;
    else if (xstrcmp(isa, "x86-64-v4") == 0) level = 4;
    else return -1;
    unsigned a, b, c, d, max;
    cpuid(0, 0, &max, &b, &c, &d);
    if (max < 7) return 0;
    cpuid(1, 0, &a, &b, &c, &d);
    unsigned c1 = c;
    cpuid(7, 0, &a, &b, &c, &d);
    unsigned b7 = b;
    cpuid(0x80000001u, 0, &a, &b, &c, &d);
    unsigned cx = c;
    /* v2: CMPXCHG16B, LAHF-SAHF, POPCNT, SSE3, SSE4.1, SSE4.2, SSSE3 */
    int v2 = (c1 >> 13 & 1) && (cx & 1) && (c1 >> 23 & 1) && (c1 & 1) && (c1 >> 19 & 1) && (c1 >> 20 & 1) && (c1 >> 9 & 1);
    if (level == 2) return v2;
    /* v3: AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, OSXSAVE */
    int v3 = v2 && (c1 >> 28 & 1) && (b7 >> 5 & 1) && (b7 >> 3 & 1) && (b7 >> 8 & 1) && (c1 >> 29 & 1) && (c1 >> 12 & 1) && (cx >> 5 & 1) && (c1 >> 22 & 1) && (c1 >> 27 & 1);
    if (level == 3) return v3;
    /* v4: AVX512F, AVX512BW, AVX512CD, AVX512DQ, AVX512VL */
    return v3 && (b7 >> 16 & 1) && (b7 >> 30 & 1) && (b7 >> 28 & 1) && (b7 >> 17 & 1) && (b7 >> 31 & 1);
}
#endif
