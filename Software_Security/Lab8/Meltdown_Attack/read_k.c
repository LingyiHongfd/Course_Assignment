
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <emmintrin.h>
#include <x86intrin.h>

int main()
{
    char *kernel_data_addr = (char *)0xf9f85000;  // own address
    char kernel_data = *kernel_data_addr;
    printf("I have reached here.\n");
    return 0;
}
