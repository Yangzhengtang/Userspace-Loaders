#ifndef COMMON_H
#define COMMON_H

#ifdef DEBUG
#define DEBUG_PRINT(x) printf x
#include <errno.h>
#include <string.h>
#define ERROR_PRINT printf("Something wrong: %s\n", strerror(errno))
#else
#define DEBUG_PRINT(x) \
    do                 \
    {                  \
    } while (0)
#define ERROR_PRINT \
    do              \
    {               \
    } while (0)
#endif

#ifdef DEBUG
#include <stdio.h>
static void print_maps(void)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (f)
    {
        char buf[1024];
        size_t sz;
        while ((sz = fread(buf, 1, sizeof buf, f)) > 0)
            fwrite(buf, 1, sz, stdout);
        fclose(f);
    }
}
#else
static void print_maps(void) {}
#endif
#endif /* COMMON_H */