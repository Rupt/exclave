/* fuzz.c — mutation fuzzing of the parsers: the driver of scripts/gate's fuzz step (DESIGN.md 17), linked with a
 * target (test/launcher_fuzz.c) under ASan and UBSan.
 *
 *     fuzz WORK SECONDS SEED...
 *
 * Every seed is run as it is. Then for SECONDS the driver takes a seed, applies one to four mutations (a bit
 * flipped; a byte set to a boundary; a run inserted, deleted or copied; an integer of 2, 4 or 8 bytes set to a
 * boundary; a cut; a splice from another seed) and hands the result to the target in a block of exactly its size,
 * so that a read past it is the sanitiser's to report. A parser answers every input: a refusal is an answer; a
 * sanitiser's finding, a signal or an exit from inside a case is not, and then the input is written to WORK/crash
 * and one line names it with the seed and the case number. SECONDS 0 runs the seeds alone, which is how a crash
 * file is run again. The generator is xorshift from a fixed state, so a run is the same sequence everywhere. The
 * exit status is 1 on a finding, or the sanitiser's. */
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "fuzz.h"

#define CAP (1 << 20) /* the largest input: a parser's bound is tested at far smaller sizes, and a case stays quick */

/* the sanitisers call this before they exit on a finding; absent from a build without them */
extern void __sanitizer_set_death_callback(void (*callback)(void)) __attribute__((weak));

struct seed {
    unsigned char *p;
    size_t n;
};
static struct seed *seeds;
static size_t nseeds;
static unsigned char *buf; /* a case being made, CAP bytes */
static unsigned char *cur; /* the case under way, when in_case */
static size_t curn, seed_of, case_no;
static volatile sig_atomic_t in_case;
static char crash[4096], line[4096 + 128]; /* the line about the case, written before it starts */
static size_t linen;

/* the case's input to WORK/crash and the line about it; called on a sanitiser's finding, a signal or an exit from
 * a case, so it does only what a signal handler may */
static void keep(void)
{
    if (!in_case) return;
    in_case = 0;
    int fd = open(crash, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd >= 0) {
        for (size_t off = 0; off < curn;) {
            ssize_t k = write(fd, cur + off, curn - off);
            if (k <= 0) break;
            off += (size_t)k;
        }
        close(fd);
    }
    (void)!write(2, line, linen);
}

static void on_signal(int sig)
{
    keep();
    signal(sig, SIG_DFL);
    raise(sig);
}

static uint64_t state = 0x9E3779B97F4A7C15ULL;
static uint64_t rnd(void)
{
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return state * 0x2545F4914F6CDD1DULL;
}
static size_t below(size_t n) { return n ? (size_t)(rnd() % n) : 0; }

/* the values a length, an offset or a count is most often wrong at */
static const uint64_t BOUNDARY[] = {
    0,
    1,
    2,
    7,
    8,
    15,
    16,
    31,
    32,
    63,
    64,
    100,
    127,
    128,
    255,
    256,
    511,
    512,
    1023,
    1024,
    4095,
    4096,
    65535,
    65536,
    0x7fffffff,
    0x80000000,
    0xffffffff,
    0x100000000ULL,
    0x7fffffffffffffffULL,
    0x8000000000000000ULL,
    0xffffffffffffffffULL,
};
static const unsigned char BYTES[] = {0, 1, 0x7f, 0x80, 0xff, '\n', '\r', '\t', ' ', '"', '\\', '/', '#', '-', '.'};
#define COUNT(a) (sizeof(a) / sizeof *(a))

/* one mutation of b, m bytes long within CAP: its new length */
static size_t mutate(unsigned char *b, size_t m)
{
    size_t at, k;
    switch (below(8)) {
    case 0: /* a bit */
        if (m) b[below(m)] ^= (unsigned char)(1U << below(8));
        break;
    case 1: /* a byte, at a boundary or anywhere */
        if (m) b[below(m)] = below(4) ? BYTES[below(COUNT(BYTES))] : (unsigned char)rnd();
        break;
    case 2: /* a run inserted: one byte repeated, or random bytes */
        k = 1 + below(below(8) ? 16 : 1024);
        if (m + k > CAP) break;
        at = below(m + 1);
        memmove(b + at + k, b + at, m - at);
        if (below(2)) memset(b + at, below(2) ? BYTES[below(COUNT(BYTES))] : (int)(unsigned char)rnd(), k);
        else
            for (size_t i = 0; i < k; i++) b[at + i] = (unsigned char)rnd();
        m += k;
        break;
    case 3: /* a run deleted */
        if (!m) break;
        at = below(m);
        k = 1 + below(below(8) ? 16 : m - at);
        if (k > m - at) k = m - at;
        memmove(b + at, b + at + k, m - at - k);
        m -= k;
        break;
    case 4: /* a run copied over another place */
        if (!m) break;
        at = below(m);
        k = 1 + below(m - at < 64 ? m - at : 64);
        memmove(b + below(m - k + 1), b + at, k);
        break;
    case 5: { /* an integer of 2, 4 or 8 bytes, little-endian, set to a boundary */
        size_t w = (size_t)2 << below(3);
        if (m < w) break;
        at = below(m - w + 1);
        uint64_t v = BOUNDARY[below(COUNT(BOUNDARY))];
        for (size_t i = 0; i < w; i++) b[at + i] = (unsigned char)(v >> (8 * i));
        break;
    }
    case 6: /* a cut */ m = below(m + 1); break;
    default: { /* a splice: a run of another seed inserted */
        const struct seed *o = &seeds[below(nseeds)];
        if (!o->n) break;
        size_t from = below(o->n);
        k = 1 + below(o->n - from < 256 ? o->n - from : 256);
        if (m + k > CAP) break;
        at = below(m + 1);
        memmove(b + at + k, b + at, m - at);
        memcpy(b + at, o->p + from, k);
        m += k;
    }
    }
    return m;
}

static void run(const unsigned char *data, size_t n)
{
    cur = malloc(n ? n : 1); /* a block of exactly n bytes: a read past it is the sanitiser's */
    if (!cur) {
        fputs("fuzz: out of memory\n", stderr);
        exit(2);
    }
    memcpy(cur, data, n);
    curn = n;
    int k = snprintf(line, sizeof line, "fuzz: %s: case %zu from seed %zu did not answer; its input is at %s\n",
                     fuzz_target, case_no, seed_of, crash);
    linen = k > 0 && (size_t)k < sizeof line ? (size_t)k : sizeof line - 1;
    in_case = 1;
    fuzz_one(cur, n);
    in_case = 0;
    free(cur);
    case_no++;
}

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fputs("usage: fuzz WORK SECONDS SEED...\n", stderr);
        return 2;
    }
    const char *work = argv[1];
    double seconds = strtod(argv[2], NULL);
    snprintf(crash, sizeof crash, "%s/crash", work);
    nseeds = (size_t)argc - 3;
    seeds = calloc(nseeds, sizeof *seeds);
    buf = seeds ? malloc(CAP) : NULL;
    if (!buf) {
        fputs("fuzz: out of memory\n", stderr);
        return 2;
    }
    for (size_t i = 0; i < nseeds; i++) {
        FILE *f = fopen(argv[3 + i], "rb");
        if (!f) {
            perror(argv[3 + i]);
            return 2;
        }
        size_t n = fread(buf, 1, CAP, f);
        fclose(f);
        seeds[i].p = malloc(n ? n : 1);
        if (!seeds[i].p) {
            fputs("fuzz: out of memory\n", stderr);
            return 2;
        }
        memcpy(seeds[i].p, buf, n);
        seeds[i].n = n;
    }
    fuzz_init(work);
    atexit(keep);
    if (__sanitizer_set_death_callback) __sanitizer_set_death_callback(keep);
    else { /* without the sanitisers the signals are the process's own to catch */ signal(SIGSEGV, on_signal);
        signal(SIGBUS, on_signal);
        signal(SIGFPE, on_signal);
        signal(SIGILL, on_signal);
    }
    signal(SIGABRT, on_signal);

    double start = now();
    for (seed_of = 0; seed_of < nseeds; seed_of++) run(seeds[seed_of].p, seeds[seed_of].n);
    while (seconds > 0) {
        for (int i = 0; i < 32; i++) {
            seed_of = below(nseeds);
            size_t m = seeds[seed_of].n;
            memcpy(buf, seeds[seed_of].p, m);
            size_t times = 1 + below(4);
            for (size_t t = 0; t < times; t++) m = mutate(buf, m);
            run(buf, m);
        }
        if (now() - start >= seconds) break;
    }
    printf("fuzz: %s: %zu cases from %zu seeds in %.0f s, 0 findings\n", fuzz_target, case_no, nseeds, now() - start);
    return 0;
}
