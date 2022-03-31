#ifndef ELF_PARSING_H
#define ELF_PARSING_H

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/user.h>

#define ELF_MIN_ALIGN PAGE_SIZE
#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN - 1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN - 1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

typedef struct elf_t
{
    FILE *file;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdrs;
} elf_t;

int set_prot(Elf64_Word p_flags);
void elf_parse(elf_t *p_elft, char* file_name);
void elf_free(elf_t *p_elft);
void elf_load_segs(elf_t *p_elft);
void elf_load_segs_without_bss(elf_t *p_elft);
Elf64_Ehdr *elf_parse_phdrs(Elf64_Ehdr *ehdr, FILE *efile);
u_int64_t elf_map_seg(int fd, int prot, int flags, Elf64_Phdr *elf_phdr);
u_int64_t elf_map_page(elf_t *p_elft, u_int64_t addr);
#endif /* ELF_PARSING_H */