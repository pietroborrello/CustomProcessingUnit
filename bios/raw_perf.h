#include <stdint.h>
#include "raw_msr.h"

/* PERF EVENT DEFS */
#define IA32_PERFEVTSEL0 0x186
#define IA32_PERFEVTSEL1 0x187
#define IA32_PERFEVTSEL2 0x188
#define IA32_PERFEVTSEL3 0x189

#define IA32_PMC0 0xc1
#define IA32_PMC1 0xc2
#define IA32_PMC2 0xc3
#define IA32_PMC3 0xc4

#define IA32_FIXED_CTR0 0x309 // Counts number of retired instructions
#define IA32_FIXED_CTR1 0x30a // Counts number of core cycles while the processor is not halted
#define IA32_FIXED_CTR2 0x30b // Counts number of timestamp counts (TSC) while the processor is not halted

#define IA32_FIXED_CTR_CTRL 0x38d
#define IA32_PERF_GLOBAL_STATUS 0x38e
#define IA32_PERF_GLOBAL_CTRL 0x38f
#define IA32_PERF_GLOBAL_STATUS_RESET 0x390
#define IA32_DEBUGCTL 0x1d9

#define PERF_USER_MODE (1<<16)
#define PERF_OS_MODE (1<<17)
#define PERF_ANY_THREAD (1<<21)
#define PERF_ENABLE (1<<22)

#define PERF_UOPS_DISPATCHED 0xa1
#define PERF_UOPS_PORT0 1
#define PERF_UOPS_PORT1 2
#define PERF_UOPS_PORT2 4
#define PERF_UOPS_PORT3 8
#define PERF_UOPS_PORT4 0x10
#define PERF_UOPS_PORT5 0x20
#define PERF_UOPS_PORT6 0x40
#define PERF_UOPS_PORT7 0x80

uint64_t pmc0 = -1, pmc1 = -1, pmc2 = -1, pmc3 = -1, pmc_fixed_1 = -1;

#define APIC_LVTPC 0x340
#define APIC_DM_NMI 0x00400

/*END PERF EVENT DEFS*/

static inline __attribute__((always_inline)) void perf_disable_globally(){
    // wrmsr(IA32_PERF_GLOBAL_CTRL, 0);
    asm volatile("wrmsr" : : "a"(0), "d"(0), "c"(IA32_PERF_GLOBAL_CTRL));
}

static inline __attribute__((always_inline)) void perf_enable_globally(){
    /* enable IA32_PMC0 to IA32_PMC3 and fixed PMC#1 to count cycles*/
    // wrmsr(IA32_PERF_GLOBAL_CTRL, 0x20000000f);
    asm volatile("wrmsr" : : "a"(0xf), "d"(0x2), "c"(IA32_PERF_GLOBAL_CTRL));
}

static inline __attribute__((always_inline)) void perf_program_event(uint32_t pmc_idx, uint32_t event, uint32_t umask) {
    uint64_t event_mask = (umask << 8) | event | PERF_ENABLE | PERF_OS_MODE | PERF_USER_MODE;
    /* program the counter*/
    wrmsr(IA32_PERFEVTSEL0 + pmc_idx, event_mask);
    /* reset the counter */
    wrmsr(IA32_PMC0 + pmc_idx, 0uL);
}

static inline __attribute__((always_inline)) void perf_program_fixed_1(uint64_t initial_value) {
    /* program the counter: enable OS + PMI */
    wrmsr(IA32_FIXED_CTR_CTRL, 0x90uL);
    /* reset the counter */
    wrmsr(IA32_FIXED_CTR1, initial_value);
    wrmsr(IA32_PERF_GLOBAL_STATUS_RESET, (1UL<<33UL) | (1UL<<59));
}

static inline __attribute__((always_inline)) uint64_t perf_read_fixed_1() {
    return rdmsr(IA32_FIXED_CTR1);
}

static inline __attribute__((always_inline)) uint64_t perf_read(uint32_t pmc_idx) {
    return rdmsr(IA32_PMC0 + pmc_idx);
}

static inline __attribute__((always_inline)) void perf_freeze_pmc_on_pmi() {
    wrmsr(IA32_DEBUGCTL, rdmsr(IA32_DEBUGCTL) | (1UL<<12));
}