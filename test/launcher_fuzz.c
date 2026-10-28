/* launcher_fuzz.c — the launcher's parsers as a fuzz target (test/fuzz.c): the manifest parser and the #! line,
 * built for the host with HOST_TEST as test/manifest_test.c is. The launcher's die is its refusal, one line and the
 * end of the process, so here it ends the case: the arena the manifest's strings go to is bounded, and a manifest
 * that fills it is refused, not a finding. */
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
}
