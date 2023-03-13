static void test_int1(void) {
    Print(L"[int1]\n");
    #define ITS 0x100ff
    UINTN resA=0; UINTN resB=0; UINTN resC=0; UINTN resD=0;
    init_match_and_patch();
    stgbuf_write(0xba00, (UINTN) ids);
    #include "ucode_patches/fastbp.h"
    Print(L"patching addr: %08lx - ram: %08lx\n", addr, ucode_addr_to_patch_addr(addr));
    patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));
    hook_match_and_patch(0, 0xc40, 0x7c00);
    uint64_t start = rdtscp();
    int i;
    for(i = 0; i < ITS; i++) {
        // if (try_except(&exception_jmp_buf) == 0) {
            asm volatile(
                ".byte 0xf1\n"
            );
        // }
    }
    uint64_t end = rdtscp();
    init_match_and_patch();
    for (int j = 0; j < 0x10000; j++)
        if (ids[j])
          Print(L"%lx: %lx\n", j, ids[j]);
    Print(L"%lx %lx %lx %lx\n", resA, resB, resC, resD);
    Print(L"its: %lx %lx\n", stgbuf_read(0xba00), i);
    Print(L"start: %lx end: %lx\n", start, end);
    Print(L"[done]: %ld, %ld\n", end-start, (end-start)/ITS);
}

static void test_int3(void) {
    Print(L"[int3]\n");
    #define ITS 0x100ff
    uint64_t start = rdtscp();
    int i;
    for(i = 0; i < ITS; i++) {
        // if (try_except(&exception_jmp_buf) == 0) {
            asm volatile(
                ".byte 0xcc\n"
            );
        // }
    }
    uint64_t end = rdtscp();
    for (int j = 0; j < 0x10000; j++)
        if (int3_ids[j])
          Print(L"%lx: %lx\n", j, int3_ids[j]);
    Print(L"start: %lx end: %lx\n", start, end);
    Print(L"[done]: %ld, %ld\n", end-start, (end-start)/ITS);
}

static void test_HBREAKCC(void) {
    Print(L"[HBREAKCC]\n");
    Print(L"func: %lx\n", func);
    UINTN resA = 0;
    init_match_and_patch();
    #include "ucode_patches/condhwbp.h"
    Print(L"patching addr: %08lx - ram: %08lx\n", addr, ucode_addr_to_patch_addr(addr));
    patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));
    Print(L"hooking entry: %02lx, addr: %04lx, hook_addr: %04lx\n", hook_entry, addr, hook_address);
    hook_match_and_patch(hook_entry, hook_address, addr);

    // setup hw bp on func
    asm volatile(
        "mov %%rax, %%dr0\n"
        "mov %%dr7, %%rax\n"
        "or $1, %%rax\n"
        "mov %%rax, %%dr7\n"
        : "=a"(resA)
        : "a" (func)
    );
    Print(L"func(0)\n");
    func(0);
    Print(L"func(0x1337)\n");
    func(0x1337);
    Print(L"[done]: %lx\n", resA);
}

#undef ITS
#define ITS 0x10000
static void div(unsigned long a, unsigned long d, unsigned long b) {
    uint64_t res = 0;
    uint64_t rem = 0;
    uint64_t start = rdtscp();
    for(int i = 0; i < ITS; i++) {
        asm volatile(
            "div %%rcx\n"
            "lfence\n"
            : "=a"(res), "=d"(rem)
            : "a"(a), "d"(d), "c"(b)
        );
    }
    uint64_t end = rdtscp();
    Print(L"div(0x%lx, 0x%0lx, 0x%lx) = %lx\n", a, d, b, res);
    Print(L"elapsed: %ld\n", (end-start)/ITS);
}

static void ctdiv(unsigned long a, unsigned long d, unsigned long b) {
    uint64_t res = 0;
    uint64_t rem = 0;
    uint64_t start = rdtscp();
    for(int i = 0; i < ITS; i++) {
        asm volatile(
            ".byte 0xf1\n"
            "lfence\n"
            : "=a"(res), "=d"(rem)
            : "a"(a), "d"(d), "c"(b)
        );
    }
    uint64_t end = rdtscp();
    uint64_t expected = 0;
    asm volatile(
        "div %%rcx\n"
        : "=a"(expected), "=d"(rem)
        : "a"(a), "d"(d), "c"(b)
    );
    Print(L"ctdiv(0x%lx, 0x%0lx, 0x%lx) = %lx (%lx)\n", a, d, b, res, expected);
    Print(L"elapsed: %ld\n", (end-start)/ITS);
}

#define cmov(cond, res, other) asm volatile ("test %2, %2\ncmove %1, %0\n":"+r"(res):"r"(other), "r"(cond): "cc")
static void swdiv(unsigned long a, unsigned long d, unsigned long b) {
    uint64_t res = 0;
    uint64_t rem = 0;
    uint64_t start = rdtscp();
    for(int i = 0; i < ITS; i++) {
        unsigned long long quotient = 0, temp = 0;
        const unsigned long long size = 8;
        unsigned long long dividend = a;
        unsigned long long divisor = b;
        // test down from the highest bit and
        // accumulate the tentative value for
        // valid bit
        for (int i = size*8-1; i >= 0; --i) {
            temp = (temp << 1uLL) | ((dividend >> i) & 1);
            char cmp = (temp >= divisor);
            unsigned long long temp1 = divisor;
            unsigned long long zero = 0;
            cmov(cmp, temp1, zero);
            temp -= temp1;
            unsigned long long temp2 = 1uLL << i;
            cmov(cmp, temp2, zero);
            quotient |= temp2;
        }
        res = quotient;
        lfence();
    }
    uint64_t end = rdtscp();
    uint64_t expected = 0;
    asm volatile(
        "div %%rcx\n"
        : "=a"(expected), "=d"(rem)
        : "a"(a), "d"(d), "c"(b)
    );
    Print(L"swdiv(0x%lx, 0x%0lx, 0x%lx) = %lx (%lx)\n", a, d, b, res, expected);
    Print(L"elapsed: %ld\n", (end-start)/ITS);
}

static void test_CTDIV(void) {
#define PKE_BIT 22
    Print(L"[CTDIV]\n");

    init_match_and_patch();
    #include "ucode_patches/ctdiv.h"
    Print(L"patching addr: %08lx - ram: %08lx\n", addr, ucode_addr_to_patch_addr(addr));
    patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));
    Print(L"hooking entry: %02lx, addr: %04lx, hook_addr: %04lx\n", hook_entry, addr, hook_address);
    hook_match_and_patch(hook_entry, hook_address, addr);

    swdiv(0, 0, 1);
    swdiv(0x11223344556677uL, 0, 0x13377);

    ctdiv(0, 0, 1);
    ctdiv(0x11223344556677uL, 0, 0x13377);

    div(0, 0, 1);
    div(0x11223344556677uL, 0, 0x13377);

    Print(L"[done]\n");
}

#define pac_sign(ptr, ctx) ({ \
    uint64_t pac_ptr; \
    asm volatile(".byte 0xf1\n": "=a"(pac_ptr): "a"(ptr), "c"(ctx));\
    pac_ptr; })

#define pac_auth(pac_ptr, ctx) ({ \
    uint64_t ptr; \
    asm volatile(".byte 0xcc\n": "=a"(ptr) : "a"(pac_ptr), "c"(ctx));\
    ptr; })

#define fix_branch_history() {for(int __i = 0; __i < 128; __i++){asm volatile("nop");}}
#define clflush(p) { asm volatile("clflush 0(%0)\n" : : "c"(p)); }

#define time_access(ptr)({\
    register uint32_t delta;\
    asm volatile(\
      "mov %%rax, %%r10\n"\
      "mfence\n"\
      "rdtscp\n"\
      "mov %%rax, %%r11\n"\
      "mov (%%rbx), %%rcx\n"\
      "lfence\n"\
      "rdtscp\n"\
      "sub %%rax, %%r11\n"\
      "mov %%r10, %%rax\n"\
      "neg %%r11\n"\
      "mov %%r11, %%rcx"\
      : "=c" (delta)\
      : "b" (ptr)\
      : "rdx", "r11", "r10"\
    );\
    delta;})

static void test_PAC(void) {
    Print(L"[PAC]\n");
    init_match_and_patch();
    {
        #include "ucode_patches/pac_sign.h"
        Print(L"patching addr: %08lx - ram: %08lx\n", addr, ucode_addr_to_patch_addr(addr));
        patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));
        Print(L"hooking entry: %02lx, addr: %04lx, hook_addr: %04lx\n", hook_entry, addr, hook_address);
        hook_match_and_patch(hook_entry, hook_address, addr);
    }
    {
        #include "ucode_patches/pac_verify.h"
        Print(L"patching addr: %08lx - ram: %08lx\n", addr, ucode_addr_to_patch_addr(addr));
        patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));
        Print(L"hooking entry: %02lx, addr: %04lx, hook_addr: %04lx\n", hook_entry, addr, hook_address);
        hook_match_and_patch(hook_entry, hook_address, addr);
    }

    UINTN ptr = 0xcafebabe;
    UINTN ctx = 0xdeadbeef;
    UINTN pac_ptr = 0;

    {
        uint64_t start = rdtscp();
        for(int i = 0; i < ITS; i++) {
            //  hook int1 for PAC computation
            asm volatile(
                ".byte 0xf1\n"
                : "=a"(pac_ptr)
                : "a"(ptr), "c"(ctx)
            );
        }
        uint64_t end = rdtscp();
        Print(L"pac(0x%lx, 0x%0lx) = %lx\n", ptr, ctx, pac_ptr);
        Print(L"elapsed: %ld\n", (end-start)/ITS);
    }
    {
        uint64_t start = rdtscp();
        for(int i = 0; i < ITS; i++) {
            //  hook int1 for PAC computation
            asm volatile(
                ".byte 0xcc\n"
                : "=a"(ptr)
                : "a"(pac_ptr), "c"(ctx)
            );
        }
        uint64_t end = rdtscp();
        Print(L"auth(0x%lx, 0x%0lx) = %lx\n", pac_ptr, ctx, ptr);
        Print(L"elapsed: %ld\n", (end-start)/ITS);
    }

    init_match_and_patch();
}

uint64_t __attribute__((aligned (0x200))) cond = 0;
uint64_t* __attribute__((aligned (0x200))) cond1 = &cond;
uint64_t** __attribute__((aligned (0x200))) cond2 = &cond1;
uint64_t*** __attribute__((aligned (0x200))) cond3 = &cond2;
uint64_t**** __attribute__((aligned (0x200))) cond4 = &cond3;
uint64_t __attribute__((aligned (0x200))) obj1 = 0x112233;
uint64_t __attribute__((aligned (0x200))) obj2 = 0x223355;

// This gadget does not seem to work, probably due to the limited ROB size on GLM
// which is 56 entries, and the pac_auth microcode has ~50 uops
// This works if we use the `_weak` versions of pac_sign/auth with reduced uops (~25)
static __attribute__ ((noinline)) uint64_t pacman_gadget1(uint64_t* pac_ptr) {
    // pointer chasing for big speculation window
    if (****cond4) {
        uint64_t* ptr = (uint64_t*) pac_auth(pac_ptr, 0xdeadbeef);
        return *ptr++;
    }
    return 0;
}

// Simpler pacman gadget where the auth operation is not in the speculative path,
// only the access
static __attribute__ ((noinline)) uint64_t pacman_gadget2(uint64_t* pac_ptr) {
    uint64_t* ptr = (uint64_t*) pac_auth(pac_ptr, 0xdeadbeef);
    if (cond) {
        return *ptr;
    }
    return 0;
}

static void test_PACMAN(void) {
    Print(L"[PACMAN]\n");
    init_match_and_patch();
    {
        #include "ucode_patches/pac_sign_weak.h"
        // Print(L"patching addr: %08lx - ram: %08lx\n", addr, ucode_addr_to_patch_addr(addr));
        patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));
        // Print(L"hooking entry: %02lx, addr: %04lx, hook_addr: %04lx\n", hook_entry, addr, hook_address);
        hook_match_and_patch(hook_entry, hook_address, addr);
    }
    {
        #include "ucode_patches/pac_verify_weak.h"
        // Print(L"patching addr: %08lx - ram: %08lx\n", addr, ucode_addr_to_patch_addr(addr));
        patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));
        // Print(L"hooking entry: %02lx, addr: %04lx, hook_addr: %04lx\n", hook_entry, addr, hook_address);
        hook_match_and_patch(hook_entry, hook_address, addr);
    }

    uint64_t known_ptr = (uint64_t)  &obj1;
    uint64_t target_ptr = (uint64_t) &obj2;
    uint64_t* known_pac_ptr = (uint64_t*) pac_sign(known_ptr, ctx);
    uint64_t target_pac_ptr = pac_sign(target_ptr, ctx);
    uint64_t target_pac = target_pac_ptr >> 48;;
    uint64_t min_time = 10000000;
    uint64_t best_value = 0;
    Print(L"known PAC ptr: 0x%lx\n", known_pac_ptr);
    Print(L"target ptr: 0x%lx\n", target_ptr);
    Print(L"correct target PAC ptr: 0x%lx\n", target_pac_ptr);

    obj2 += 1;
    Print(L"access: %ld\n", time_access(&obj2));
    clflush(&obj2);
    Print(L"flush: %ld\n", time_access(&obj2));

    // bruteforce PAC
    Print(L"[+] bruteforcing...\n");
    for (uint64_t pac_value = 0; pac_value <= 0xffff; pac_value++) {
        uint64_t* pac_test = (uint64_t*)(target_ptr | (pac_value << 48));
        for (int i = 0; i < 100; i++) {
            barrier();
            // gadget training phase
            cond = 1;
            for (int j = 0; j < 10; j++) {
                fix_branch_history();
                dummy += pacman_gadget1(known_pac_ptr);
            }

            // test
            cond = 0;
            clflush(&cond);
            clflush(&obj2);
            fix_branch_history();
            barrier();
            dummy += pacman_gadget1(pac_test);
            barrier();

            // test if speculatively hit obj2
            uint64_t time = time_access(&obj2);
            if (time < min_time) {
                best_value = (uint64_t) pac_test;
                min_time = time;
            }
        }
    }

    Print(L"best PAC guess: 0x%lx (access time: %ld)\n", best_value, min_time);
    Print(L"auth best guess: 0x%lx\n", pac_auth(best_value, ctx));


    init_match_and_patch();
}