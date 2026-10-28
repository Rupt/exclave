/* tool_fuzz.c — the command's parsers as a fuzz target (test/fuzz.c): the grammar of the manifest and the hashes
 * file, the ELF reader, the ld.so.cache reader and the EXCLAVE_LOG reader, each on every input. The three that take
 * a file by name are given the bytes as a file under the work directory; the cache as etc/ld.so.cache of a tree
 * there, which is how the reader finds it. */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../tool/tool.h"
#include "fuzz.h"

const char *const fuzz_target = "the command's parsers";
static char *file, *root, *cache; /* WORK/file; WORK/root, whose etc/ld.so.cache is the cache */

void fuzz_init(const char *work)
{
    file = path_join(work, "file");
    root = path_join(work, "root");
    char *etc = path_join(root, "etc");
    if ((mkdir(root, 0755) && errno != EEXIST) || (mkdir(etc, 0755) && errno != EEXIST)) fail_errno(etc);
    cache = path_join(etc, "ld.so.cache");
    free(etc);
}

static void put(const char *path, const unsigned char *data, size_t n)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) fail_errno(path);
    while (n) {
        ssize_t k = write(fd, data, n);
        if (k <= 0) fail_errno(path);
        data += k;
        n -= (size_t)k;
    }
    close(fd);
}

void fuzz_one(const unsigned char *data, size_t n)
{
    static const enum kind KINDS[] = {KIND_MANIFEST, KIND_HASHES};
    for (size_t i = 0; i < sizeof KINDS / sizeof *KINDS; i++) {
        struct records rs;
        char err[GRAMMAR_ERR];
        if (grammar_parse((const char *)data, n, KINDS[i], &rs, err) == 0) {
            struct buf out = {0};
            grammar_dump(&rs, KINDS[i], &out);
            records_free(&rs);
            free(out.p);
        }
    }
    put(file, data, n);
    struct elf e;
    char why[ELF_WHY];
    elf_read(file, &e, why);
    elf_free(&e);
    put(cache, data, n);
    struct cache c;
    read_cache(root, &c);
    cache_free(&c);
    struct log_line *lines;
    size_t k = read_log(file, &lines);
    free_log(lines, k);
}
