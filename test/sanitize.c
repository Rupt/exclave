/* sanitize.c — linked into every unit test (scripts/gate's unit step) and into build/exclave-asan (scripts/build). A
 * sanitiser's finding exits 99 rather than its default 1, which a caller reads as an answer: the command's 1 is "the
 * check found errors" (test/readers_test.py). */
const char *__asan_default_options(void);
const char *__ubsan_default_options(void);
const char *__asan_default_options(void) { return "exitcode=99"; }
const char *__ubsan_default_options(void) { return "exitcode=99"; }
