#include "elf.h"
#include "common.h"
#include <elf.h>
#include <unistd.h>
#include <sys/auxv.h>

static inline DEBUG_PHDR(Elf64_Phdr *elf_phdr)
{
    DEBUG_PRINT(
        (
            "The Program Header: \n type: 0x%08x,\n flags: 0x%08x,\n offset: 0x%08x,\n vaddr: 0x%08x,\n paddr: 0x%08x,\n filesz: 0x%08x,\n memsz: 0x%08x,\n align: 0x%08x\n",
            elf_phdr->p_type,
            elf_phdr->p_flags,
            elf_phdr->p_offset,
            elf_phdr->p_vaddr,
            elf_phdr->p_paddr,
            elf_phdr->p_filesz,
            elf_phdr->p_memsz,
            elf_phdr->p_align));
}

int set_prot(Elf64_Word p_flags)
{
    int prot = 0;
    if (p_flags & PF_R)
        prot |= PROT_READ;
    if (p_flags & PF_W)
        prot |= PROT_WRITE;
    if (p_flags & PF_X)
        prot |= PROT_EXEC;
    return prot;
}

void elf_parse(elf_t *p_elft, char *file_name)
{
    int err = 0;
    p_elft->file = fopen(file_name, "r");

    //  Initialize the elf header
    p_elft->ehdr = malloc(sizeof(Elf64_Ehdr));
    fread(p_elft->ehdr, sizeof(Elf64_Ehdr), 1, p_elft->file);
    if (p_elft->ehdr->e_type != ET_EXEC) //  By default, the test are all executable files
        exit(-1);

    p_elft->phdrs = elf_parse_phdrs(p_elft->ehdr, p_elft->file);
}

void elf_free(elf_t *p_elft)
{
    free(p_elft->ehdr);
    free(p_elft->phdrs);
    fclose(p_elft->file);
}

void elf_load_segs_without_bss(elf_t *p_elft)
{
    int fd = fileno(p_elft->file);
    Elf64_Phdr *elf_phdr;
    int i;
    for (i = 0, elf_phdr = p_elft->phdrs; i < p_elft->ehdr->e_phnum; i++, elf_phdr = elf_phdr + 1)
    {
        if (elf_phdr->p_type != PT_LOAD) //  Don't need to load into memory
            continue;

        int prot = set_prot(elf_phdr->p_flags);
        int elf_flags = MAP_FIXED | MAP_PRIVATE;

        u_int64_t addr = elf_phdr->p_vaddr;
        unsigned long size = elf_phdr->p_filesz + ELF_PAGEOFFSET(elf_phdr->p_vaddr);
        unsigned long off = elf_phdr->p_offset - ELF_PAGEOFFSET(elf_phdr->p_vaddr);
        addr = ELF_PAGESTART(addr);
        size = ELF_PAGEALIGN(size);
        if (!size)
            continue;

        u_int64_t map_addr = mmap(addr, size, prot, elf_flags, fd, off);
        if (map_addr == -1)
            ERROR_PRINT;
        if (elf_phdr->p_memsz > elf_phdr->p_filesz)
        { //  We still need to deal with bbs because we need to zero
          //  all memory in bss part
            unsigned long bss_size = ELF_PAGEALIGN(elf_phdr->p_memsz) - size;
            u_int64_t bss_start_addr = elf_phdr->p_vaddr + elf_phdr->p_filesz;
            DEBUG_PRINT(("BSS Start: %x\n", bss_start_addr));
            memset(bss_start_addr, 0, ELF_PAGEALIGN(bss_start_addr) - bss_start_addr);
        }
    }
}

void elf_load_segs(elf_t *p_elft)
{
    int fd = fileno(p_elft->file);
    Elf64_Phdr *elf_phdr;
    int i;
    for (i = 0, elf_phdr = p_elft->phdrs; i < p_elft->ehdr->e_phnum; i++, elf_phdr = elf_phdr + 1)
    {
        if (elf_phdr->p_type != PT_LOAD) //  Don't need to load into memory
            continue;
        int prot = set_prot(elf_phdr->p_flags);
        int elf_flags = MAP_FIXED | MAP_PRIVATE;
        u_int64_t map_addr = elf_map_seg(fd, prot, elf_flags, elf_phdr);
        if (map_addr == -1)
            ERROR_PRINT;
    }
}

Elf64_Ehdr *elf_parse_phdrs(Elf64_Ehdr *ehdr, FILE *efile)
{
    Elf64_Phdr *elf_phdata = NULL;
    int retval, err = -999;
    unsigned int size;

    if (ehdr->e_phentsize != sizeof(Elf64_Phdr)) //  Maybe a wrong elf version
        goto out;

    if (ftell(efile) != ehdr->e_phoff) //  Wrong offset
        goto out;

    size = sizeof(Elf64_Ehdr) * (ehdr->e_phnum);
    if (size == 0 || size > 65536)
        goto out;

    elf_phdata = malloc(size);
    if (!elf_phdata)
        goto out;

    //  Read in the program headers
    retval = fread(elf_phdata, sizeof(Elf64_Phdr), ehdr->e_phnum, efile);
    if (retval != ehdr->e_phnum)
    {
        err = retval < 0 ? retval : -retval;
        goto out;
    }

    err = 0;
out:
    if (err)
    {
        DEBUG_PRINT(("Something wrong!\n"));
        DEBUG_PRINT(("Error code is %d\n", err));
        free(elf_phdata);
        elf_phdata = NULL;
    }
    return elf_phdata;
}

u_int64_t elf_map_seg(int fd, int prot, int flags, Elf64_Phdr *elf_phdr)
{
    Elf32_Addr addr = elf_phdr->p_vaddr;
    unsigned long size = elf_phdr->p_filesz + ELF_PAGEOFFSET(elf_phdr->p_vaddr);
    unsigned long off = elf_phdr->p_offset - ELF_PAGEOFFSET(elf_phdr->p_vaddr);
    addr = ELF_PAGESTART(addr);
    size = ELF_PAGEALIGN(size);
    if (!size)
        return addr;

    u_int64_t map_addr = mmap(addr, size, prot, flags, fd, off);

    if (elf_phdr->p_memsz > elf_phdr->p_filesz)
    {
        DEBUG_PRINT(("Found a bss segment: \n"));
        unsigned long bss_size = ELF_PAGEALIGN(elf_phdr->p_memsz) - size;
        u_int64_t bss_map_addr = mmap(map_addr + size, bss_size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        memset(elf_phdr->p_vaddr + elf_phdr->p_filesz, 0, bss_size);
        if (bss_map_addr == -1)
            ERROR_PRINT;
    }
    return map_addr;
}

//  Find the page in elf, and load it to memory
u_int64_t elf_map_page(elf_t *p_elft, u_int64_t addr)
{
    int fd = fileno(p_elft->file);
    Elf64_Phdr *elf_phdr;
    int ret = 0;
    int i;
    for (i = 0, elf_phdr = p_elft->phdrs; i < p_elft->ehdr->e_phnum; i++, elf_phdr = elf_phdr + 1)
    {
        if (elf_phdr->p_type != PT_LOAD)
            continue;

        u_int64_t start_addr = elf_phdr->p_vaddr;
        u_int64_t end_addr = start_addr + elf_phdr->p_memsz;
        if (start_addr > addr || end_addr <= addr) //  Out of range
            continue;

        u_int64_t map_addr = ELF_PAGESTART(addr);
        int prot = set_prot(elf_phdr->p_flags);
        int elf_flags = MAP_FIXED_NOREPLACE | MAP_PRIVATE;
        unsigned long off = elf_phdr->p_offset - ELF_PAGEOFFSET(start_addr) + map_addr - ELF_PAGESTART(start_addr);

        if (elf_phdr->p_memsz > elf_phdr->p_filesz)
        {
            u_int64_t bss_addr = start_addr + elf_phdr->p_filesz; //  The starting position of bss section
            if (addr >= bss_addr)                                 //  It's already in bss
            {
                if (map_addr < bss_addr)
                {
                    //  The former half part is not bss
                    DEBUG_PRINT(("Accessing bss segment 1: "));
                    DEBUG_PRINT(("\tmmap: 0x%08x, offset: 0x%08x\n", map_addr, off));
                    ret = mmap(map_addr, PAGE_SIZE, prot, elf_flags, fd, off);
                    if (ret == -1)
                        ERROR_PRINT;
                    off = PAGE_SIZE - (bss_addr - ELF_PAGESTART(bss_addr));
                    DEBUG_PRINT(("\tmemset: 0x%08x, size: 0x%08x\n", bss_addr, off));
                    ret = memset(bss_addr, 0, off);
                    if (ret == -1)
                        ERROR_PRINT;
                    return 0;
                }
                else
                {
                    DEBUG_PRINT(("Accessing bss segment 2: "));
                    DEBUG_PRINT(("\tmmap: 0x%08x\n", map_addr));
                    ret = mmap(map_addr, PAGE_SIZE, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                    if (ret == -1)
                        ERROR_PRINT;
                    ret = memset(map_addr, 0, PAGE_SIZE);
                    if (ret == -1)
                        ERROR_PRINT;
                    return 0;
                }
            }
            else if (map_addr + PAGE_SIZE > bss_addr) //  Latter part of this page is in bss seg
            {
                DEBUG_PRINT(("Accessing bss segment 3: "));
                DEBUG_PRINT(("\tmmap: 0x%08x, offset: 0x%08x\n", map_addr, off));
                ret = mmap(map_addr, PAGE_SIZE, prot, elf_flags, fd, off);
                if (ret == -1)
                    ERROR_PRINT;
                off = ELF_PAGESTART(bss_addr) + PAGE_SIZE - (bss_addr);
                DEBUG_PRINT(("\tmemset: 0x%08x, size: 0x%08x\n", bss_addr, off));
                ret = memset(bss_addr, 0, off);
                if (ret == -1)
                    ERROR_PRINT;
                return 0;
            }
            else
                goto common;
        }
        else
        {
        common:
            DEBUG_PRINT(("Accessing LOAD segment: "));
            DEBUG_PRINT(("\tmmap: 0x%08x, offset: 0x%08x\n", map_addr, off));
            ret = mmap(map_addr, PAGE_SIZE, prot, elf_flags, fd, off);
            if (ret == -1)
                ERROR_PRINT;
            return 0;
        }
    }
    return -1;
}
