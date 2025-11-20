#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main() {
    unsigned long addr;
    unsigned long value;

    printf("Address to write (hex, e.g., 0x1234abcd): ");
    scanf("%lx", &addr);

    printf("Value to write (hex): ");
    scanf("%lx", &value);

    unsigned long *ptr = (unsigned long *)addr;

    printf("Writing 0x%lx to address %p ...\n", value, (void*)ptr);

    *ptr = value;

    printf("Done!\n");
    return 0;
}