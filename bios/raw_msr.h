#include <stdint.h>

#ifndef __RAW_MSR__
#define __RAW_MSR__

#define wrmsr(msr, val) asm volatile("wrmsr\n" : : "a"((uint32_t) (val)), "d"((uint32_t) ((val)>>32)), "c"(msr));

static uint64_t rdmsr(uint32_t msr)
{
    uint64_t lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((hi<<32) | lo);
}

#endif