/* sanitize.c — linked into every unit test (scripts/gate's unit step). A sanitiser's finding exits 99 rather than its
 * default 1, which a test's caller reads as an answer: manifest_test's 1 is "the manifest is refused"
 * (test/grammar_test.py). */
const char *__asan_default_options(void);
const char *__ubsan_default_options(void);
const char *__asan_default_options(void) { return "exitcode=99"; }
const char *__ubsan_default_options(void) { return "exitcode=99"; }
