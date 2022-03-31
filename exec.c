#include "elf.h"
#include "common.h"
#include "exec.h"
#include <sys/auxv.h>

extern char **environ;
//  DEBUG_PRINT(("Pushing word %016lx, %016lx\n", rsp - 1, val));

#define PUSH_WORD(rsp, val) \
    do                      \
    {                       \
        rsp -= 1;           \
        *rsp = val;         \
    } while (0)

#define PUSH_AUX_ENT(rsp, a_type, a_val) \
    do                                   \
    {                                    \
        PUSH_WORD(rsp, a_val);           \
        PUSH_WORD(rsp, a_type);          \
    } while (0)

#define PUSH_DEFAULT_AUX_ENT(rsp, a_type)    \
    do                                       \
    {                                        \
        u_int64_t a_val = getauxval(a_type); \
        PUSH_AUX_ENT(rsp, a_type, a_val);    \
    } while (0)

void __attribute__((noinline)) _entry_point_(void *entry, void *rsp)
{
    __asm__(
        "movq %rsi, %rsp;"
        "xor %rax, %rax;"
        "xor %rbx, %rbx;"
        "xor %rcx, %rcx;"
        "xor %rdx, %rdx;"
        "xor %rsi, %rsi;"
        "xor %r8, %r8;"
        "xor %r9, %r9;"
        "xor %r10, %r10;"
        "xor %r11, %r11;"
        "xor %r12, %r12;"
        "xor %r13, %r13;"
        "xor %r14, %r14;"
        "xor %r15, %r15;"
        "jmp *%rdi;");
}

u_int64_t init_stack(u_int64_t stack_bottom, elf_t *p_elft, u_int64_t size, int argc, char **argv)
{
    //  First, we need to mmap the stack memory area
    u_int64_t stack_top = stack_bottom - size;
    size = ELF_PAGEALIGN(size + ELF_PAGEOFFSET(stack_top));
    stack_top = ELF_PAGESTART(stack_top);
    u_int64_t map_addr = mmap(stack_top, size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map_addr == -1)
        ERROR_PRINT;
    //  DEBUG_PRINT(("Stack map to 0x%08x\n", map_addr));

    u_int64_t *rsp = stack_bottom;

    //  Setup stack
    PUSH_WORD(rsp, 0);
    PUSH_WORD(rsp, 0);
    PUSH_WORD(rsp, 0);
    u_int64_t *random_addr = rsp;

    PUSH_DEFAULT_AUX_ENT(rsp, AT_NULL);
    PUSH_DEFAULT_AUX_ENT(rsp, AT_PLATFORM);
    PUSH_DEFAULT_AUX_ENT(rsp, AT_EXECFN);
    PUSH_DEFAULT_AUX_ENT(rsp, AT_HWCAP2);
    //  PUSH_AUX_ENT(rsp, AT_RANDOM,random_addr);
    PUSH_DEFAULT_AUX_ENT(rsp, AT_RANDOM);
    PUSH_DEFAULT_AUX_ENT(rsp, AT_SECURE);
    PUSH_DEFAULT_AUX_ENT(rsp, AT_EGID);
    PUSH_DEFAULT_AUX_ENT(rsp, AT_GID);
    PUSH_DEFAULT_AUX_ENT(rsp, AT_EUID);
    PUSH_DEFAULT_AUX_ENT(rsp, AT_UID);
    PUSH_AUX_ENT(rsp, AT_ENTRY, p_elft->ehdr->e_entry);
    PUSH_AUX_ENT(rsp, AT_FLAGS, 0);
    PUSH_AUX_ENT(rsp, AT_BASE, 0);
    PUSH_AUX_ENT(rsp, AT_PHNUM, p_elft->ehdr->e_phnum);
    PUSH_AUX_ENT(rsp, AT_PHENT, p_elft->ehdr->e_phentsize);
    PUSH_AUX_ENT(rsp, AT_PHDR, p_elft->phdrs[0].p_vaddr + p_elft->ehdr->e_phoff);
    PUSH_DEFAULT_AUX_ENT(rsp, AT_CLKTCK);
    PUSH_DEFAULT_AUX_ENT(rsp, AT_PAGESZ);
    PUSH_AUX_ENT(rsp, AT_HWCAP, 0xbfebfbff);
    // PUSH_DEFAULT_AUX_ENT(rsp, AT_MINSIGSTKSZ);
    PUSH_DEFAULT_AUX_ENT(rsp, AT_SYSINFO_EHDR);

    PUSH_WORD(rsp, 0);
    int n_env = 0;
    while (environ[n_env] != NULL)
    {
        n_env++;
    }
    for (int i = n_env - 1; i >= 0; i--)
    {
        PUSH_WORD(rsp, (u_int64_t)environ[i]);
    }

    PUSH_WORD(rsp, 0);

    for (int i = argc - 1; i >= 0; i--)
    {
        PUSH_WORD(rsp, (u_int64_t)argv[i]);
    }
    PUSH_WORD(rsp, (u_int64_t)argc);

    return rsp;
}