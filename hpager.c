#include "common.h"
#include "elf.h"
#include "exec.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define __USE_GNU 1 //  For the use of $RIP
#include <signal.h>
#include <bits/sigaction.h>
#include <sys/ucontext.h>

elf_t *pelft;
int prefetch_num;

void segsegv_handler(int signo, siginfo_t *info, ucontext_t *extra)
{
    //  DEBUG_PRINT(("Signal %d received\n", signo));
    u_int64_t rip = extra->uc_mcontext.gregs[REG_RIP];
    u_int64_t segv_addr = info->si_addr;

    DEBUG_PRINT(("siginfo address=%x\n", segv_addr));
    DEBUG_PRINT(("rip = %x\n", rip));

    if (segv_addr == 0)
    {
        if (rip == 0) //  HLT
            exit(0);
        else
            abort();
    }
    //  Loop through all the program hdrs, and find the correct one
    elf_map_page(pelft, segv_addr);
    if (prefetch_num == 1)
    {
        elf_map_page(pelft, segv_addr + PAGE_SIZE);
    }
    else
    {
        elf_map_page(pelft, segv_addr + PAGE_SIZE);
        elf_map_page(pelft, segv_addr - PAGE_SIZE);
    }

    return;
}

int main(int argc, char **argv)
{
    prefetch_num = argv[2];
    elf_t elft;
    pelft = &elft;

    elf_parse(pelft, argv[1]);
    elf_load_segs_without_bss(pelft); //  Only map text and initialized data

    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_flags = SA_ONSTACK | SA_SIGINFO;
    action.sa_sigaction = segsegv_handler;
    sigaction(SIGSEGV, &action, NULL);

    u_int64_t stack_bottom = STACK_BASE_ADDR;
    u_int64_t rsp = init_stack(stack_bottom, pelft, STACK_SIZE, argc - 1, argv + 1);
    DEBUG_PRINT(("RSP set to 0x%08x\n", rsp));
    void *entry = (void *)pelft->ehdr->e_entry;

    print_maps();
    _entry_point_(entry, rsp);
    print_maps();
}