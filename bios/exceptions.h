#ifndef __EXCEPTIONS_H__
#define __EXCEPTIONS_H__

#ifndef _EFI_MP_
#include <efi.h>
#include <lib.h>
#include <efilib.h>
#endif

#include <unistd.h>
#include <stdint.h>

// from SGX-step

/* IA-64: 16-byte gate (from Linux kernel arch/x86/include/asm/desc_defs.h) */
typedef struct {
    uint16_t offset_low;
    uint16_t segment;
    unsigned ist : 3, zero0 : 5, type : 5, dpl : 2, p : 1;
    uint16_t offset_middle;
    uint32_t offset_high;
    uint32_t zero1;
} __attribute__((packed)) gate_desc_t;

enum {
    GATE_INTERRUPT = 0xE,
    GATE_TRAP = 0xF,
    GATE_CALL = 0xC,
    GATE_TASK = 0x5,
};

typedef struct {
    uint32_t offset;
    uint16_t segment;
} __attribute__((packed)) call_gate_pt_t;

#define PTR_LOW(x) ((unsigned long long)(x) & 0xFFFF)
#define PTR_MIDDLE(x) (((unsigned long long)(x) >> 16) & 0xFFFF)
#define PTR_HIGH(x) ((unsigned long long)(x) >> 32)

#define gate_offset(g) ((g)->offset_low | ((unsigned long)(g)->offset_middle << 16) | ((unsigned long)(g)->offset_high << 32))
#define gate_ptr(base, idx) ((gate_desc_t*) (((void*) base) + idx*sizeof(gate_desc_t)))

/*
 * From Linux kernel arch/x86/include/asm/segment.h 
 *                   arch/x86/include/asm/desc_defs.h
 */
#define KERNEL_DPL          0
#define USER_DPL            3
#define GDT_ENTRY_USER_CS   6
#define GDT_ENTRY_KERNEL_CS 2

typedef enum {
    KERNEL_CS = GDT_ENTRY_KERNEL_CS*8+KERNEL_DPL,
    USER_CS   = GDT_ENTRY_USER_CS*8+USER_DPL,
} cs_t;

typedef struct {
    uint16_t size;
    uint64_t base;
} __attribute__((packed)) dtr_t;

typedef struct {
    gate_desc_t *base;
    size_t     entries;
} idt_t;

typedef struct {
    unsigned long rip;
    unsigned long cs;
    unsigned long rflags;
} idt_ctx_t;

typedef struct jmp_buf_data_s {
    unsigned long __rip;
    unsigned long __rsp;
    unsigned long __rbp;
    unsigned long __rbx;
    unsigned long __r12;
    unsigned long __r13;
    unsigned long __r14;
    unsigned long __r15;
} jmp_buf_data;

typedef void (*irq_cb_t)(idt_ctx_t *ctx);

#define dump_dtr(dtr, entries)                          \
    Print(L"DTR.base=0x%lx/size=%lx (%d entries)\n", \
        (void*) (dtr)->base, (dtr)->size, entries);

#define assert(status, s) do { \
  if (!(status)) {\
    Print(L"ERROR: %s\n", s);\
    Exit(0, 0, NULL);\
  } \
} while (0)

void read_idt(idt_t *idt)
{
    dtr_t idtr = {0};
    int entries;

    asm volatile ("sidt %0\n"
                  :"=m"(idtr) :: );
    entries = (idtr.size+1)/sizeof(gate_desc_t);
    // dump_dtr(&idtr, entries);

    assert( idtr.base, L"failed to get IDT base\n");
    idt->base = (gate_desc_t*) idtr.base;
    idt->entries = entries;
}

static void DumpBufferHex (void* Buf, UINTN Size);
void dump_gate(gate_desc_t *gate, int idx)
{
    Print(L"IDT[%3d] @0x%lx = 0x%lx (seg sel 0x%x); p=%d; dpl=%d; type=%02d; ist=%d\n",
        idx, gate, (void*) gate_offset(gate), gate->segment, gate->p, gate->dpl, gate->type, gate->ist);
    DumpBufferHex((void*) gate_offset(gate), 0x10);
}


void dump_idt(idt_t *idt)
{
    int i;

    Print(L"---------------------------------------------\n");
    for (i =0; i < 0x10; i++)
        dump_gate(gate_ptr(idt->base, i), i);
    Print(L"---------------------------------------------\n");
}

// setjmp, but the compiler messes it up if uses the name
__attribute_noinline__ int try_except(jmp_buf_data *jmp_buf);
asm (
    ".global try_except\n"
"try_except:\n"
    "pop %rcx\n"
    "movq %rcx,   (%rdi)\n" /* Return address */
    "movq %rsp,  8(%rdi)\n"
    "movq %rbp, 16(%rdi)\n"
    "movq %rbx, 24(%rdi)\n"
    "movq %r12, 32(%rdi)\n"
    "movq %r13, 40(%rdi)\n"
    "movq %r14, 48(%rdi)\n"
    "movq %r15, 56(%rdi)\n"

    "xorq %rax, %rax\n" /* Direct invocation returns 0 */
    "jmpq *%rcx\n"
);

// longjmp, but the compiler messes it up if uses the name
__attribute_noinline__ void except_resume(jmp_buf_data *jmp_buf);
asm (
    ".global except_resume\n"
"except_resume:\n"
    "movq   (%rdi), %rcx\n" /* Return address */
    "movq  8(%rdi), %rsp\n"
    "movq 16(%rdi), %rbp\n"
    "movq 24(%rdi), %rbx\n"
    "movq 32(%rdi), %r12\n"
    "movq 40(%rdi), %r13\n"
    "movq 48(%rdi), %r14\n"
    "movq 56(%rdi), %r15\n"
    "xorq %rax, %rax\n"
    "incq %rax\n" /* Return 1 instead */
    "jmpq *%rcx\n"
);

void irq_handler_c(idt_ctx_t *ctx);

// assembly exception handlers that calls the C exception handler, saving/restoring the context
void irq_handler(void);
asm (
    ".global irq_handler\n"
"irq_handler:\n"
    "cli\n"
    "push %rax\n"
    "mov %rsp, %rax\n"
    "add $8,%rax\n" /* rax points to stack frame */
    "push %rbx\n"
    "push %rcx\n"
    "push %rdx\n"
    "push %rbp\n"
    "push %rsi\n"
    "push %rdi\n"
    "push %r8\n"
    "push %r9\n"
    "push %r10\n"
    "push %r11\n"
    "push %r12\n"
    "push %r13\n"
    "push %r14\n"
    "push %r15\n"

    "mov %rax, %rdi\n" /* pass stack frame to handler so that he can modify it*/
    "call irq_handler_c\n"

    "pop %r15\n"
    "pop %r14\n"
    "pop %r13\n"
    "pop %r12\n"
    "pop %r11\n"
    "pop %r10\n"
    "pop %r9\n"
    "pop %r8\n"
    "pop %rdi\n"
    "pop %rsi\n"
    "pop %rbp\n"
    "pop %rdx\n"
    "pop %rcx\n"
    "pop %rbx\n"
    "pop %rax\n"
    "iretq\n"
);

void irq_handler_err_code(void);
asm (
    ".global irq_handler_err_code\n"
"irq_handler_err_code:\n"
    "cli\n"
    "mov %rax, (%rsp)\n" /* save rax over the error code*/
    "mov %rsp, %rax\n"
    "add $8,%rax\n" /* rax points to stack frame */
    "push %rbx\n"
    "push %rcx\n"
    "push %rdx\n"
    "push %rbp\n"
    "push %rsi\n"
    "push %rdi\n"
    "push %r8\n"
    "push %r9\n"
    "push %r10\n"
    "push %r11\n"
    "push %r12\n"
    "push %r13\n"
    "push %r14\n"
    "push %r15\n"

    "mov %rax, %rdi\n" /* pass stack frame to handler so that he can modify it*/
    "call irq_handler_c\n"

    "pop %r15\n"
    "pop %r14\n"
    "pop %r13\n"
    "pop %r12\n"
    "pop %r11\n"
    "pop %r10\n"
    "pop %r9\n"
    "pop %r8\n"
    "pop %rdi\n"
    "pop %rsi\n"
    "pop %rbp\n"
    "pop %rdx\n"
    "pop %rcx\n"
    "pop %rbx\n"
    "pop %rax\n"
    "iretq\n"
);

//
// Error code flag indicating whether or not an error code will be
// pushed on the stack if an exception occurs.
//
// 1 means an error code will be pushed, otherwise 0
//
CONST UINT32 mErrorCodeFlag = 0x20227d00uL;

void set_irq_handler(idt_t *idt, int vector)
{
    assert(vector >= 0 && vector < idt->entries, L"invalid vector\n");
    
    void *asm_handler;
    if (((mErrorCodeFlag >> vector) & 1) == 0) {
        asm_handler = irq_handler;
    } else {
        asm_handler = irq_handler_err_code;
    }


    gate_desc_t *gate = gate_ptr(idt->base, vector);
    gate->offset_low    = PTR_LOW(asm_handler);
    gate->offset_middle = PTR_MIDDLE(asm_handler);
    gate->offset_high   = PTR_HIGH(asm_handler);
}


jmp_buf_data exception_jmp_buf;
unsigned long exception_last_rip;
// exception handler, either longjump if setup, or aborts
void except_irq(void) {
    jmp_buf_data local_jmp_buf = exception_jmp_buf;
    exception_jmp_buf.__rip = 0;
    if (local_jmp_buf.__rip != 0) {
        except_resume(&local_jmp_buf);
    } else {
        CONST CHAR16 error[] = L"ABORTED";
        UINTN size = sizeof(error);
        void* ExitData = AllocatePool(size);
        StrCpy(ExitData, error);
        Exit(EFI_ABORTED, size, ExitData);
    }
}

// hijack the return address from the exception to make it point to our exception handler
void irq_handler_c(idt_ctx_t *ctx) {
    exception_last_rip = ctx->rip;

    // this ties the handler to longjmp machinery, but it seems the print crashes
    // the system if put in except_irq, not sure why
    if (exception_jmp_buf.__rip == 0) {
        Print(L"[-] IRQ ABORTED\n");
    }

    ctx->rip = (unsigned long)except_irq;
}

// register exception handlers to avoid hlt
void setup_exceptions(void) {
    idt_t idt = {0};
    read_idt(&idt);
    // dump_idt(&idt);

    set_irq_handler(&idt, EXCEPT_X64_DIVIDE_ERROR);
    set_irq_handler(&idt, EXCEPT_X64_GP_FAULT);
    set_irq_handler(&idt, EXCEPT_X64_PAGE_FAULT);
    // dump_idt(&idt);
    return;
}

#endif