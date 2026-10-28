/* fuzz.h — a fuzz target's side of test/fuzz.c, the driver of scripts/gate's fuzz step (DESIGN.md 17). */
#pragma once
#include <stddef.h>

/* what the target parses, for the driver's lines */
extern const char *const fuzz_target;
/* once, before the cases: work is the step's directory, for a parser that must be given its bytes as a file */
void fuzz_init(const char *work);
/* one case: every parser of the target on data, which it may read and must answer, a refusal being an answer; a
 * sanitiser's finding, a signal or an exit is not, and the driver keeps the input */
void fuzz_one(const unsigned char *data, size_t n);
