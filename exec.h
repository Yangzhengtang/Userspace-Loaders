#ifndef EXEC_H
#define EXEC_H

#include "elf.h"

#define STACK_SIZE 1 << 23
#define STACK_BASE_ADDR 0x20000000
u_int64_t init_stack(u_int64_t stack_bottom, elf_t *p_elft, unsigned long size, int argc, char **argv);

void __attribute__((noinline)) _entry_point_(void *entry, void *rsp);

#endif