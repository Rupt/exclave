/* sanitize.c — linked into every unit test and fuzz harness (scripts/gate's unit step, scripts/extra's fuzz step). A
 * sanitiser's finding exits 99 rather than its default 1, which a caller reads as an answer. */
const char *__asan_default_options(void);
const char *__ubsan_default_options(void);
const char *__asan_default_options(void) { return "exitcode=99"; }
const char *__ubsan_default_options(void) { return "exitcode=99"; }
