#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <stdio.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

#define ARR_SIZE 1024 * 1024 * 32
unsigned int arr[ARR_SIZE];

void printRusage()
{
    struct rusage myrusage;
    struct rusage *ru = &myrusage;
	getrusage(RUSAGE_SELF, ru);

    /* printf("CPU time (microsecs):      user=%lu; system=%lu\n",
            ru->ru_utime.tv_sec * 1000000 + ru->ru_utime.tv_usec,
            ru->ru_stime.tv_sec * 1000000 + ru->ru_stime.tv_usec);
    printf("Max resident set size:     %ld\n", ru->ru_maxrss); */
    printf("%lu, %lu, %ld\n",           //  user, system, maxset
            ru->ru_utime.tv_sec * 1000000 + ru->ru_utime.tv_usec,
            ru->ru_stime.tv_sec * 1000000 + ru->ru_stime.tv_usec,
            ru->ru_maxrss);
}

int main(){
    srand(time(NULL));
    arr[rand() % ARR_SIZE] = rand();
    printRusage();
}