/* elf.h — the ELF64 structures the loader and the probe need. */
#pragma once
#include <stdint.h>

typedef struct {
    unsigned char e_ident[16]; uint16_t e_type, e_machine; uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff; uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} Ehdr;
typedef struct { uint32_t p_type, p_flags; uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align; } Phdr;

#define ET_EXEC 2
#define ET_DYN 3
#define EM_X86_64 62
#define EM_AARCH64 183
#define PT_LOAD 1
#define PT_INTERP 3
#define PT_NOTE 4
#define PT_PHDR 6
#define PF_X 1
#define PF_W 2
#define PF_R 4
#define ELFCLASS64 2
