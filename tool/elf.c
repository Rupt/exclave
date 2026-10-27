/* elf.c — the parts of an ELF file and of glibc's ld.so.cache that the checks read (DESIGN.md 10.3). */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tool.h"

enum { PT_LOAD = 1, PT_DYNAMIC = 2, PT_INTERP = 3 };
enum { DT_NULL = 0, DT_NEEDED = 1, DT_STRTAB = 5, DT_STRSZ = 10, DT_SONAME = 14, DT_RPATH = 15, DT_RUNPATH = 29 };

static uint64_t get(const unsigned char *p, int n)
{
    uint64_t v = 0;
    for (int i = n - 1; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

/* up to n bytes of the file from off, as many as there are */
static char *read_at(int fd, uint64_t off, uint64_t n, size_t *got)
{
    struct buf b = {0};
    char chunk[1 << 16];
    while (n) {
        size_t want = n < sizeof chunk ? (size_t)n : sizeof chunk;
        ssize_t k = pread(fd, chunk, want, (off_t)off);
        if (k <= 0) break;
        buf_add(&b, chunk, (size_t)k);
        off += (uint64_t)k;
        n -= (uint64_t)k;
    }
    *got = b.n;
    buf_add(&b, "", 1);
    return b.p;
}

static char *copy_str(const char *s, size_t n)
{
    char *p = xrealloc(NULL, n + 1);
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

void elf_free(struct elf *e)
{
    free(e->loads);
    free(e->interp);
    for (size_t i = 0; i < e->nneeded; i++) free(e->needed[i]);
    free(e->needed);
    free(e->rpath);
    free(e->runpath);
    free(e->soname);
    *e = (struct elf){0};
}

static int bad(struct elf *e, char why[ELF_WHY], const char *what, int kind)
{
    elf_free(e);
    snprintf(why, ELF_WHY, "%s", what);
    return kind;
}

int elf_read(const char *path, struct elf *e, char why[ELF_WHY])
{
    *e = (struct elf){0};
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return ELF_OS;
    size_t n;
    char *hp = read_at(fd, 0, 64, &n);
    const unsigned char *h = (const unsigned char *)hp;
    int rc = ELF_OK;
    if (n < 16 || memcmp(h,
                         "\x7f"
                         "ELF",
                         4) != 0) {
        rc = bad(e, why, "not ELF64 LE", ELF_BAD);
    } else if (h[4] != 2 || h[5] != 1) {
        rc = bad(e, why, "ELF32 or big-endian: a foreign object, not checked (13)", ELF_FOREIGN);
    } else if (n < 64) {
        rc = bad(e, why, "truncated ELF header", ELF_BAD);
    } else {
        e->type = (int)get(h + 16, 2);
        e->machine = (int)get(h + 18, 2);
        uint64_t phoff = get(h + 32, 8), phentsize = get(h + 54, 2), phnum = get(h + 56, 2), dynoff = 0, dynsz = 0;
        int has_dyn = 0;
        size_t phn;
        char *php = read_at(fd, phoff, phentsize * phnum, &phn);
        const unsigned char *ph = (const unsigned char *)php;
        for (uint64_t i = 0; i < phnum && rc == ELF_OK; i++) {
            if (i * phentsize + 56 > phn) {
                rc = bad(e, why, "truncated or malformed ELF: its program headers run past the end of the file",
                         ELF_BAD);
                break;
            }
            const unsigned char *p = ph + i * phentsize;
            uint64_t type = get(p, 4), off = get(p + 8, 8), vaddr = get(p + 16, 8), filesz = get(p + 32, 8);
            if (type == PT_LOAD) {
                e->loads = xrealloc(e->loads, (e->nloads + 1) * sizeof *e->loads);
                e->loads[e->nloads++] = (struct elf_load){vaddr, off, filesz};
            } else if (type == PT_INTERP && filesz < 2) {
                /* a separate debug file (objcopy --only-keep-debug, /usr/lib/debug) keeps a program's headers but
                 * not the bytes they map; its PT_INTERP is empty in the file, which the kernel refuses (ENOEXEC),
                 * so it is no program */
                e->debug_only = 1;
            } else if (type == PT_INTERP) {
                size_t k;
                char *s = read_at(fd, off, filesz, &k);
                while (k && !s[k - 1]) k--;
                free(e->interp);
                e->interp = copy_str(s, k);
                free(s);
            } else if (type == PT_DYNAMIC) {
                has_dyn = 1;
                dynoff = off;
                dynsz = filesz;
            }
        }
        free(php);
        if (rc == ELF_OK && has_dyn) {
            size_t dn;
            char *dp = read_at(fd, dynoff, dynsz, &dn);
            const unsigned char *d = (const unsigned char *)dp;
            size_t ntags = 0;
            uint64_t strtab = 0, strsz = 1 << 20;
            int has_strtab = 0;
            for (size_t i = 0; i + 16 <= dn; i += 16, ntags++) {
                uint64_t tag = get(d + i, 8), val = get(d + i + 8, 8);
                if (tag == DT_NULL) break;
                if (tag == DT_STRTAB) has_strtab = 1, strtab = val;
                if (tag == DT_STRSZ) strsz = val;
            }
            if (has_strtab) {
                uint64_t off = 0;
                int found = 0;
                for (size_t i = 0; i < e->nloads && !found; i++)
                    if (e->loads[i].vaddr <= strtab && strtab < e->loads[i].vaddr + e->loads[i].filesz) {
                        off = e->loads[i].off + strtab - e->loads[i].vaddr;
                        found = 1;
                    }
                if (!found) {
                    rc = bad(e, why, "address not in a loaded segment", ELF_BAD);
                } else {
                    size_t tn;
                    char *table = read_at(fd, off, strsz, &tn);
                    for (size_t i = 0; i < ntags; i++) {
                        uint64_t tag = get(d + 16 * i, 8), val = get(d + 16 * i + 8, 8);
                        if (tag != DT_NEEDED && tag != DT_RPATH && tag != DT_RUNPATH && tag != DT_SONAME) continue;
                        size_t start = val < tn ? (size_t)val : tn;
                        const char *end = memchr(table + start, 0, tn - start);
                        char *s = copy_str(table + start, end ? (size_t)(end - (table + start)) : tn - start);
                        if (tag == DT_NEEDED) {
                            e->needed = xrealloc(e->needed, (e->nneeded + 1) * sizeof *e->needed);
                            e->needed[e->nneeded++] = s;
                        } else {
                            char **slot = tag == DT_RPATH ? &e->rpath : tag == DT_RUNPATH ? &e->runpath : &e->soname;
                            free(*slot);
                            *slot = s;
                        }
                    }
                    free(table);
                }
            }
            free(dp);
        }
    }
    free(hp);
    close(fd);
    return rc;
}

/* ---------------------------------------------------------------- ld.so.cache */
/* the NUL-terminated string at data[at], strict UTF-8, or NULL */
static const char *cache_str(const char *data, size_t n, uint64_t at)
{
    if (at >= n) return NULL;
    const char *end = memchr(data + at, 0, n - at);
    if (!end || !utf8_valid(data + at, (size_t)(end - (data + at)))) return NULL;
    return data + at;
}

/* The tree's /etc/ld.so.cache in the glibc-ld.so.cache1.1 format: each soname's paths in the cache's order, entries
 * for a hardware capability left out. Returns 0 when the tree has no cache, 1 otherwise, an unreadable or truncated
 * cache having no entries. */
int read_cache(const char *root, struct cache *c)
{
    *c = (struct cache){0};
    char *r = tree_resolve(root, "/etc/ld.so.cache", 1, NULL);
    if (!r) return 0;
    char *real = tree_real(root, r);
    free(r);
    struct stat st;
    if (stat(real, &st) || !S_ISREG(st.st_mode)) return free(real), 0;
    size_t n;
    char *data = read_file(real, &n);
    free(real);
    static const char magic[] = "glibc-ld.so.cache1.1";
    const char *m = memmem(data, n, magic, sizeof magic - 1);
    if (!m || (size_t)(m - data) + 48 > n) return free(data), 1;
    size_t off = (size_t)(m - data), entries = off + 48;
    uint64_t nlibs = get((const unsigned char *)data + off + 20, 4);
    if (entries + 24 * nlibs > n) return free(data), 1;
    /* offsets are from the header; failing that, from the string table */
    uint64_t bases[2] = {off, entries + 24 * nlibs};
    for (int b = 0; b < 2; b++) {
        cache_free(c);
        int ok = 1;
        for (uint64_t i = 0; i < nlibs; i++) {
            const unsigned char *en = (const unsigned char *)data + entries + 24 * i;
            const char *k = cache_str(data, n, bases[b] + get(en + 4, 4));
            const char *v = k ? cache_str(data, n, bases[b] + get(en + 8, 4)) : NULL;
            if (!k || !v || v[0] != '/') {
                ok = 0;
                break;
            }
            if (get(en + 16, 8) == 0) {
                c->e = xrealloc(c->e, (c->n + 1) * sizeof *c->e);
                c->e[c->n++] = (struct cache_entry){copy_str(k, strlen(k)), copy_str(v, strlen(v))};
            }
        }
        if (ok) break;
    }
    free(data);
    return 1;
}

void cache_free(struct cache *c)
{
    for (size_t i = 0; i < c->n; i++) {
        free(c->e[i].soname);
        free(c->e[i].path);
    }
    free(c->e);
    *c = (struct cache){0};
}
