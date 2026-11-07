/* launcher_fuzz.c — the launcher's parsers as a fuzz target (test/fuzz.c): the manifest parser, the #! line and the
 * wrapping of a program's seccomp filter, built for the host with HOST_TEST as test/manifest_test.c is. The
 * launcher's die is its refusal, one line and the end of the process, so here it ends the case: the arena the
 * manifest's strings go to is bounded, and a manifest that fills it is refused, not a finding. */
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include "../src/common.h"
#include "fuzz.h"

const char *const fuzz_target = "the launcher's parsers";
static jmp_buf refused;

void die(const char *what, const char *detail, long err)
{
    (void)what;
    (void)detail;
    (void)err;
    longjmp(refused, 1);
}

void arena_reset(void);

static void filter_case(const unsigned char *data, size_t size);

void fuzz_init(const char *work) { (void)work; }

void fuzz_one(const unsigned char *data, size_t n)
{
    arena_reset();
    struct exclave c;
    memset(&c, 0, sizeof c);
    char err[256];
    if (!setjmp(refused)) manifest_parse((const char *)data, n, &c, err, sizeof err);
    /* the first BINPRM_BUF_SIZE bytes of a file, as the kernel reads them for a #! line, in the buffer the function
     * asks for: one byte more, which it pads */
    char line[BINPRM_BUF_SIZE + 1], script[] = "script", one[] = "one", two[] = "two";
    long k = n < BINPRM_BUF_SIZE ? (long)n : BINPRM_BUF_SIZE;
    memcpy(line, data, (size_t)k);
    char *argv[] = {script, one, two, NULL}, *nargv[8];
    if (!setjmp(refused)) shebang_argv(line, k, script, argv, 3, nargv, 8);
    filter_case(data, n);
}

/* ---------- filter_wrap (src/filter.c, 7.4.2): a program's filter, built around ---------- */
struct sd {
    uint32_t nr, arch;
    uint64_t ip, args[6];
};
#define OTHER 0xffffffffffffffffULL /* a body the small interpreter does not model: no answer to compare */
/* the instructions the kernel admits in a seccomp filter that this interpreter models; OTHER for any other, which the
 * kernel refuses or this does not need, and for a load past seccomp_data */
static uint64_t interpret(const struct sock_filter *p, long n, const struct sd *d)
{
    uint32_t A = 0, X = 0, M[16] = {0};
    for (long pc = 0; pc < n;) {
        const struct sock_filter *f = &p[pc++];
        switch (f->code) {
        case 0x20: /* LD W ABS */
            if (f->k == 0) A = d->nr;
            else if (f->k == 4) A = d->arch;
            else if (f->k == 8) A = (uint32_t)d->ip;
            else if (f->k == 12) A = (uint32_t)(d->ip >> 32);
            else if (f->k >= 16 && f->k < 64 && !(f->k & 3)) {
                uint64_t v = d->args[(f->k - 16) / 8];
                A = f->k & 4 ? (uint32_t)(v >> 32) : (uint32_t)v;
            } else return OTHER;
            break;
        case 0x00: A = f->k; break;
        case 0x01: X = f->k; break;
        case 0x60:
            if (f->k >= 16) return OTHER;
            A = M[f->k];
            break;
        case 0x61:
            if (f->k >= 16) return OTHER;
            X = M[f->k];
            break;
        case 0x02:
            if (f->k >= 16) return OTHER;
            M[f->k] = A;
            break;
        case 0x03:
            if (f->k >= 16) return OTHER;
            M[f->k] = X;
            break;
        case 0x04: A += f->k; break;
        case 0x54: A &= f->k; break;
        case 0x44: A |= f->k; break;
        case 0x07: X = A; break;
        case 0x87: A = X; break;
        case 0x05: pc += (long)f->k; break;
        case 0x15: pc += A == f->k ? f->jt : f->jf; break;
        case 0x25: pc += A > f->k ? f->jt : f->jf; break;
        case 0x35: pc += A >= f->k ? f->jt : f->jf; break;
        case 0x45: pc += A & f->k ? f->jt : f->jf; break;
        case 0x1d: pc += A == X ? f->jt : f->jf; break;
        case 0x06: return f->k;
        case 0x16: return A;
        default: return OTHER;
        }
    }
    return OTHER; /* off the end: the kernel refuses it */
}

static void filter_case(const unsigned char *data, size_t size)
{
    static struct sock_filter body[BPF_MAXINSNS], out[BPF_MAXINSNS];
    long n = (long)(size / sizeof body[0]);
    if (n > BPF_MAXINSNS) n = BPF_MAXINSNS;
    memcpy(body, data, (size_t)n * sizeof body[0]);
    long r = filter_wrap(body, n, out);
    if (r <= 0) {
        if (r != -EINVAL && r != -ENOSYS) abort();
        return;
    }
    /* the output: at most BPF_MAXINSNS, every jump inside it, a return at its end */
    if (r > BPF_MAXINSNS || (out[r - 1].code != 0x06 && out[r - 1].code != 0x16)) abort();
    for (long i = 0; i < r; i++) {
        if ((out[i].code & 7) != 5) continue;
        if (out[i].code == 0x05 ? out[i].k >= (uint32_t)(r - i - 1) : i + 1 + out[i].jt >= r || i + 1 + out[i].jf >= r)
            abort();
    }
    /* the built filter answers what the body does from a program's address and from the judge slot, and allows a call
     * from the rest of the syscall page; the probe, uname with MAGIC, is the prologue's and left out */
    struct sd d;
    memset(&d, 0, sizeof d);
    d.arch = AUDIT_ARCH_NATIVE;
    d.ip = 0x401000;
    for (int c = 0; c < 4; c++) {
        d.nr = size > (size_t)c ? data[size - 1 - (size_t)c] : (uint32_t)c;
        d.args[0] = d.args[1] = size > 8 ? (uint64_t)data[c] << 8 | data[size / 2] : 0;
        if (d.nr == NR_uname) continue;
        uint64_t b = interpret(body, n, &d);
        if (b == OTHER) continue;
        static const uint64_t ips[] = {0x401000, SC_JUDGE + 2, SC_PAGE + 2, SC_RESTORER + 7};
        for (int j = 0; j < 4; j++) {
            d.ip = ips[j];
            uint64_t w = interpret(out, r, &d);
            /* ALLOW with data, the body's own return kept, is the kernel's ALLOW */
            if (j < 2 ? w != b : (w & SECCOMP_RET_ACTION_FULL) != SECCOMP_RET_ALLOW) abort();
        }
    }
}
