#include "elf.h"
#include "common.h"
#include "exec.h"

int main(int argc, char **argv)
{
    elf_t elft;
    elf_t *pelft = &elft;
    elf_parse(pelft, argv[1]);
    elf_load_segs(pelft);

    u_int64_t stack_bottom = STACK_BASE_ADDR;
    u_int64_t rsp = init_stack(stack_bottom, pelft, STACK_SIZE, argc - 1, argv + 1);
    DEBUG_PRINT(("RSP set to 0x%08x\n", rsp));
    
    elf_free(pelft);
    print_maps();
    void *entry = pelft->ehdr->e_entry;
    _entry_point_(entry, rsp);
    return 0;
}