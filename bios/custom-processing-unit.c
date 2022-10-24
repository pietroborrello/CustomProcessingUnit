#include <efi.h>
#include <lib.h>
#include <efilib.h>
#define _EFI_MP_
#include "efi-mp.h"
#include "raw_msr.h"
#include "raw_perf.h"
#include "goldmont_core_perf_counters.h"
#include "exceptions.h"

#define CHECK(status, s) do { \
  if (EFI_ERROR(status)) {\
    CHAR16 ErrorString[0x100] = {0};\
    StatusToString(ErrorString, status);\
    Print(L"ERROR: %s - %s\n", s, ErrorString);\
    Exit(EFI_SUCCESS, 0, NULL);\
  } \
} while (0)


#define EFI_SHELL_INTERFACE_GUID \
   (EFI_GUID) {0x47c7b223, 0xc42a, 0x11d2, {0x8e,0x57,0x00,0xa0,0xc9,0x69,0x72,0x3b}}

#define SHELL_VARIABLE_GUID \
   (EFI_GUID) {0x158def5a, 0xf656, 0x419c, {0xb0,0x27,0x7a,0x31,0x92,0xc0,0x79,0xd2}}

// goldomnt version that we analyzed
#define GLM_OLD 0x506c9
#define GLM_NEW 0x506ca
UINTN current_glm_version=0;

#define BUFSIZE 2048

// ucode update msrs
#define IA32_BIOS_SIGN_ID 0x8B
#define IA32_BIOS_UPDT_TRIG 0x79
// ucode patches to trace
// this will define two variables: bios_glm_intel_ucode_06_5c_09 and bios_glm_intel_ucode_06_5c_09_len
#include "glm-intel-ucode/06-5c-09.h"
// this will define two variables: bios_glm_intel_ucode_06_5c_0a and bios_glm_intel_ucode_06_5c_0a_len
#include "glm-intel-ucode/06-5c-0a.h"
unsigned char* ucode_data;
unsigned int   ucode_size;


typedef enum {
    ARG_NO_ATTRIB         = 0x0,
    ARG_IS_QUOTED         = 0x1,
    ARG_PARTIALLY_QUOTED  = 0x2,
    ARG_FIRST_HALF_QUOTED = 0x4,
    ARG_FIRST_CHAR_IS_ESC = 0x8
} EFI_SHELL_ARG_INFO_TYPES;

struct _EFI_SHELL_ARG_INFO {
    UINT32 Attributes;
} __attribute__((packed)) __attribute__((aligned (1)));
typedef struct _EFI_SHELL_ARG_INFO EFI_SHELL_ARG_INFO;

struct _EFI_SHELL_INTERFACE {
    EFI_HANDLE           ImageHandle;
    EFI_LOADED_IMAGE    *Info;
    CHAR16             **Argv;
    UINTN                Argc;
    CHAR16             **RedirArgv;
    UINTN                RedirArgc;
    EFI_FILE            *StdIn;
    EFI_FILE            *StdOut;
    EFI_FILE            *StdErr;
    EFI_SHELL_ARG_INFO  *ArgInfo;
    BOOLEAN              EchoOn;
} __attribute__((packed)) __attribute__((aligned (1)));
typedef struct _EFI_SHELL_INTERFACE EFI_SHELL_INTERFACE;

EFI_FILE_PROTOCOL *gRootFS = NULL;

static EFI_STATUS
get_args(EFI_HANDLE image, UINTN *argc, CHAR16 ***argv)
{
    EFI_STATUS status;
    EFI_SHELL_INTERFACE *shell;
    EFI_GUID gEfiShellInterfaceGuid = EFI_SHELL_INTERFACE_GUID;

    status = uefi_call_wrapper(BS->OpenProtocol, 6,
                               image, &gEfiShellInterfaceGuid,
                               (VOID **)&shell, image, NULL,
                               EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR(status))
        return status;

    *argc = shell->Argc;
    *argv = shell->Argv;

    status = uefi_call_wrapper(BS->CloseProtocol, 4, image,
                               &gEfiShellInterfaceGuid, image, NULL);
    return status;
}

static BOOLEAN
is_number(CHAR16* str)
{
    CHAR16 *s = str;

    while (*s) {
        if (*s  < L'0' || *s > L'9')
            return FALSE;
        s++;
    }

    return TRUE;
}

static uint64_t inline rdtscp(void) {
  uint64_t a, d;
  asm volatile("rdtscp" : "=a"(a), "=d"(d)::"rcx");
  a = (d << 32) | a;
  return a;
}

static uint64_t inline rdtsc(void) {
  uint64_t a, d;
  asm volatile("rdtsc" : "=a"(a), "=d"(d)::);
  a = (d << 32) | a;
  return a;
}

static uint32_t rdrand(void) {
    uint32_t rnd32 = 0;
    asm volatile("rdrand %0\n":"=r"(rnd32):);
    return rnd32;
}

// from https://wiki.osdev.org/Loading_files_under_UEFI
EFI_STATUS get_current_rootfs(EFI_HANDLE image, EFI_FILE_HANDLE* Root) {
    EFI_LOADED_IMAGE *loaded_image = NULL;                  /* image interface */
    EFI_GUID lipGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;      /* image interface GUID */
    EFI_FILE_IO_INTERFACE *IOVolume;                        /* file system interface */
    EFI_GUID fsGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID; /* file system interface GUID */
    EFI_STATUS Status = 0;
    
    /* get the loaded image protocol interface for our "image" */
    Status = uefi_call_wrapper(BS->HandleProtocol, 3, image, &lipGuid, (void **) &loaded_image);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /* get the volume handle */
    Status = uefi_call_wrapper(BS->HandleProtocol, 3, loaded_image->DeviceHandle, &fsGuid, (VOID*)&IOVolume);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    Status = uefi_call_wrapper(IOVolume->OpenVolume, 2, IOVolume, Root);
    return Status;
}

EFI_STATUS 
open_file(CHAR16* Filename, EFI_FILE_PROTOCOL **File)
{
    EFI_STATUS  Status = 0;
    UINTN BufSize;
    if (gRootFS == NULL) {
        // initialize RootFS
        Status = get_current_rootfs(LibImageHandle, &gRootFS);
        if (EFI_ERROR(Status)) {
            Print(L"ERROR: Getting RootFS: %d\n", Status);
            return Status;
        }
    }

    Status = uefi_call_wrapper(gRootFS->Open, 5, 
            gRootFS, 
            File,
            Filename, 
            EFI_FILE_MODE_CREATE | EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
            0);

    return Status;
}

EFI_STATUS 
delete_file(CHAR16* Filename)
{
    EFI_STATUS  Status = 0;
    UINTN BufSize;
    if (gRootFS == NULL) {
        // initialize RootFS
        Status = get_current_rootfs(LibImageHandle, &gRootFS);
        if (EFI_ERROR(Status)) {
            Print(L"ERROR: Getting RootFS: %d\n", Status);
            return Status;
        }
    }

    EFI_FILE_PROTOCOL *File = 0;
    // Delete file it it exists
    Status = uefi_call_wrapper(gRootFS->Open, 5, 
            gRootFS, 
            &File,
            Filename, 
            EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
            0);
    if (File && !EFI_ERROR(Status)) {
        uefi_call_wrapper(File->Delete, 1, File);
    }

    return Status;
}

EFI_STATUS 
write_file(CHAR8 *Buf, EFI_FILE_PROTOCOL *File, INTN Position)
{
    Print(L"\r[...] Dumping to file\n");
    EFI_STATUS  Status = 0;
    UINTN BufSize;

    if (Position >= 0) {
        Status = uefi_call_wrapper(File->SetPosition, 2, File, Position);
        if (EFI_ERROR(Status)) {
            return Status;
        }
    }

    BufSize = strlena(Buf);
    UINTN TmpSize;
    UINTN TmpOff = 0;
    Print(L"Writing %lu bytes in total\n", BufSize);
    while (BufSize > 0)
    {
        if (BufSize > 0x800) TmpSize = 0x800;
        else TmpSize = BufSize;
        Print(L"Writing %lu bytes\n", TmpSize);
        Status = uefi_call_wrapper(File->Write, 3, File, &TmpSize, Buf + TmpOff);
        if (EFI_ERROR(Status)) {
            return Status;
        }
        TmpOff  += TmpSize;
        BufSize -= TmpSize;
    }

    return Status;
}

EFI_STATUS 
flush_file(EFI_FILE_PROTOCOL *File)
{
    EFI_STATUS  Status = 0;
    Status = uefi_call_wrapper(File->Flush, 1, File);
    return Status;
}

EFI_STATUS 
close_file(EFI_FILE_PROTOCOL *File)
{
    EFI_STATUS  Status = 0;
    Status = uefi_call_wrapper(File->Close, 1, File);
    return Status;
}

EFI_STATUS 
open_write_close_file(CHAR8 *Buf, CHAR16* Filename)
{
    Print(L"\r[...] Dumping to file\n");
    EFI_STATUS  Status = 0;
    UINTN BufSize;
    if (gRootFS == NULL) {
        // initialize RootFS
        Status = get_current_rootfs(LibImageHandle, &gRootFS);
        if (EFI_ERROR(Status)) {
            Print(L"ERROR: Getting RootFS: %d\n", Status);
            return Status;
        }
    }

    EFI_FILE_PROTOCOL *File = 0;
    // Delete file it it exists
    Status = uefi_call_wrapper(gRootFS->Open, 5, 
            gRootFS, 
            &File,
            Filename, 
            EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
            0);
    if (File && !EFI_ERROR(Status)) {
        uefi_call_wrapper(File->Delete, 1, File);
    }

    // Now reopen and write it
    File = 0;
    Status = uefi_call_wrapper(gRootFS->Open, 5, 
            gRootFS, 
            &File,
            Filename, 
            EFI_FILE_MODE_CREATE | EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
            0);

    if (EFI_ERROR(Status)) {
        return Status;
    }

    if( File && !EFI_ERROR(Status)) {
        BufSize = strlena(Buf);
        UINTN TmpSize;
        UINTN TmpOff = 0;
        Print(L"Total %lu bytes\n", BufSize);
        while (BufSize > 0)
        {
            if (BufSize > 0x800) TmpSize = 0x800;
            else TmpSize = BufSize;
            Print(L"Writing %lu bytes\n", TmpSize);
            Status = uefi_call_wrapper(File->Write, 3, File, &TmpSize, Buf + TmpOff);
            if (EFI_ERROR(Status)) {
                return Status;
            }
            TmpOff  += TmpSize;
            BufSize -= TmpSize;
        }
        
        Status = uefi_call_wrapper(File->Close, 1, File);
        if (EFI_ERROR(Status)) {
            return Status;
        }
    }

    return Status;
}

static void
usage(void)
{
    Print(L"Usage:\n"
    "  patch:        <tool> p\n"
    "  patch & exec: <tool> x\n"
    "  perf:         <tool> f\n"
    "  zero out m&p: <tool> z\n"
    "  hook:         <tool> h  [m&p idx] [uop addr] [patch addr]\n"
    "  template:     <tool> m\n"
    "  dump imms:    <tool> di\n"
    "  dump rom:     <tool> dr\n"
    "  dump msrs:    <tool> dm\n"
    "  dump SMM:     <tool> ds [address] [size]\n"
    "  read value:   <tool> v  [address]\n"
    "  cpuid:        <tool> c  [rax] [rcx]\n"
    "  rdmsr:        <tool> rm [msr]\n"
    "  wrmsr:        <tool> wm [msr]\n"
    "  read:         <tool> r  [cmd] [addr]\n"
    "  write:        <tool> w  [cmd] [addr] [value]\n"
    "  invoke:       <tool> i  [addr]\n"
    "  update ucode: <tool> u  [size]\n"
    "  ldat read:    <tool> lr [port] [array] [bank] [idx] [addr] [optional size]\n"
    "  ldat write:   <tool> lw [port] [array] [bank] [idx] [addr] [value]\n");
}

#define mfence() asm volatile("mfence\n")
#define lfence() asm volatile("lfence\n")
#define lmfence() asm volatile("lfence\n mfence\n")
#define wbinvd() asm volatile("wbinvd\n")
#define padding_cpuid() asm volatile("xor %%rax, %%rax\n xor %%rcx, %%rcx\n cpuid\n":::"cc", "rax", "rbx", "rcx", "rdx")

static void activate_udebug_insts(void) {
    wrmsr(0x1e6uL, 0x200uL);
}

static UINTN udebug_read(UINTN command, UINTN address) {
    UINTN res_high=0, res_low=0;
    lmfence();
    asm volatile(
      ".byte 0x0f, 0x0e\n"
      : "=b" (res_high), "=d" (res_low)
      : "c" (command), "a" (address)
      : "memory"
    );
    lmfence();
    return (res_high << 32) | res_low;
}

static void udebug_write(UINTN command, UINTN address, UINTN value) {
    unsigned int val_high=value >> 32, val_low= (unsigned int)value;
    lmfence();
    asm volatile(
      ".byte 0x0f, 0x0f\n"
      :
      : "c" (command), "a" (address), "b" (val_high), "d" (val_low)
      : "memory"
    );
    lmfence();
}

static void udebug_invoke(UINTN address, UINTN* resA, UINTN* resB, UINTN* resC, UINTN* resD) {
    lmfence();
    asm volatile(
      ".byte 0x0f, 0x0f\n"
      : "=a" (*resA), "=b" (*resB), "=c" (*resC), "=d" (*resD)
      : "c" (0xd8), "a" (address), "b" (0), "d" (0)
      : "memory"
    );
    lmfence();
}

static UINTN crbus_read(UINTN address) {
    return udebug_read(0, address);
}

static UINTN crbus_write(UINTN address, UINTN value) {
    udebug_write(0, address, value);
    return udebug_read(0, address);
}

static void stgbuf_write(UINTN address, UINTN value) {
    udebug_write(0x80, address, value);
}

static UINTN stgbuf_read(UINTN address) {
    return udebug_read(0x80, address);
}

static void ldat_array_write(UINTN pdat_reg, UINTN array_sel, UINTN bank_sel, UINTN dword_idx, UINTN fast_addr, UINTN val) {
    // maybe signal that we are patching (seen in U2270)
    UINTN prev = crbus_read(0x692);
    crbus_write(0x692, prev | 1);

    crbus_write(pdat_reg + 1, 0x30000 | ((dword_idx & 0xf) << 12) | ((array_sel & 0xf) << 8) | (bank_sel & 0xf));
    crbus_write(pdat_reg, 0x000000 | (fast_addr & 0xffff));
    crbus_write(pdat_reg + 4, val & 0xffffffff);
    crbus_write(pdat_reg + 5, (val >> 32) & 0xffff);
    crbus_write(pdat_reg + 1, 0);

    crbus_write(0x692, prev);
}

static inline void cpuid(UINTN *eax, UINTN *ebx, UINTN *ecx, UINTN *edx)
{
    asm("cpuid"
            : "=a" (*eax),
            "=b" (*ebx),
            "=c" (*ecx),
            "=d" (*edx)
            : "a" (*eax), "c" (*ecx));
}

static inline void read_cr3(UINTN *res)
{
    asm("mov %%cr3, %%rax\n"
            : "=a" (*res):);
}

static inline void read_cr0(UINTN *res)
{
    asm("mov %%cr0, %%rax\n"
            : "=a" (*res):);
}

static inline void write_cr0(UINTN value)
{
    asm("mov %%rax, %%cr0\n"
            :: "a" (value));
}

void flush(void *p) { asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax"); }

UINTN utoi(const CHAR16 *str) {
    if (str[0] == L'0' && (str[1] == L'x' || str[1] == L'X')) {
        return xtoi(str + 2);
    }  else {
        return Atoi(str);
    }
}

UINTN detect_goldomnt_version(void) {
    UINTN rax = 0x1, rbx = 0, rcx = 0, rdx = 0;
    cpuid(&rax, &rbx, &rcx, &rdx);
    return rax;
}

void ms_array_write(UINTN array_sel, UINTN bank_sel, UINTN dword_idx, UINTN fast_addr, UINTN val) {
    ldat_array_write(0x6a0, array_sel, bank_sel, dword_idx, fast_addr, val);
}

void ms_patch_ram_write(UINTN addr, UINTN val) {
    ms_array_write(4, 0, 0, addr, val);
}

void ms_match_patch_write(UINTN addr, UINTN val) {
    ms_array_write(3, 0, 0, addr, val);
}

void ms_const_write(UINTN addr, UINTN val) {
    ms_array_write(2, 0, 0, addr, val);
}

UINTN ucode_addr_to_patch_addr(UINTN addr) {
    UINTN base = addr - 0x7c00;
    // the last *4 does not make any sense but the CPU divides the address where
    // to write by for, still unkown reasons
    return ((base%4) * 0x80 + (base/4)) * 4; 
}

UINTN patch_addr_to_ucode_addr(UINTN addr) {
    // NOTICE: the ucode_addr_to_patch_addr has a *4 more, so this will not be 
    // the inverse
    UINTN mul = addr % 0x80;
    UINTN off = addr / 0x80;
    return 0x7c00 + mul*4 + off;
}

UINTN ucode_addr_to_patch_seqword_addr(UINTN addr) {
    UINTN base = addr - 0x7c00;
    UINTN seq_addr = ((base%4) * 0x80 + (base/4));
    return seq_addr % 0x80;
}

void patch_ucode(UINTN addr, unsigned long ucode_patch[][4], int n) {
    // format: uop0, uop1, uop2, seqword 
    // uop3 is fixed to a nop and cannot be overridden

    for(int i=0; i < n; i++) {
        // patch ucode
        ms_patch_ram_write(ucode_addr_to_patch_addr(addr + i*4),   ucode_patch[i][0]);
        ms_patch_ram_write(ucode_addr_to_patch_addr(addr + i*4)+1, ucode_patch[i][1]);
        ms_patch_ram_write(ucode_addr_to_patch_addr(addr + i*4)+2, ucode_patch[i][2]);

        // patch seqword
        ms_const_write(ucode_addr_to_patch_seqword_addr(addr) + i, ucode_patch[i][3]);
    }
}

// assumes that ucode_routine points to the ldat_read 
// ucode function that we previously installed, and calls it
static UINTN ldat_read(UINTN ucode_routine, UINTN pdat_reg, UINTN array_sel, UINTN bank_sel, UINTN dword_idx, UINTN fast_addr) {
    UINTN resA = 0;
    UINTN resB = 0;
    UINTN resC = 0;
    UINTN resD = 0;

    UINTN array_bank_sel = 0x10000 | ((dword_idx & 0xf) << 12) | ((array_sel & 0xf) << 8) | (bank_sel & 0xf);

    stgbuf_write(0xb800, pdat_reg);  // write pdat to tmp0
    stgbuf_write(0xb840, array_bank_sel); // write array_bank_sel to tmp1
    stgbuf_write(0xb880, 0xc00000 | fast_addr); // write array_bank_sel to tmp2
    
    udebug_invoke(ucode_routine, &resA, &resB, &resC, &resD);
    
    stgbuf_write(0xb800, 0); // restore tmp0
    stgbuf_write(0xb840, 0); // restore tmp1
    stgbuf_write(0xb880, 0); // restore tmp2

    return resA;
}

void enable_match_and_patch(void) {
    UINTN mp = crbus_read(0x692);
    crbus_write(0x692, mp & ~1uL);
}

void disable_match_and_patch(void) {
    UINTN mp = crbus_read(0x692);
    crbus_write(0x692, mp | 1uL);
}

void init_match_and_patch(void) {
    if (current_glm_version == GLM_OLD) {
        // Move the patch at U7c5c to U7dfc, since it seems important for the CPU
        unsigned long existing_patch[][4] = {
            // U7dfc: WRITEURAM(tmp5, 0x0037, 32) m2=1, NOP, NOP, SEQ_GOTO U60d2
            {0xa04337080235, 0, 0, 0x2460d200},
        };
        patch_ucode(0x7dfc, existing_patch, sizeof(existing_patch) / sizeof(existing_patch[0]));

        // write and execute the patch that will zero out match&patch moving
        // the 0xc entry to last entry, which will make the hook call our moved patch
        #include "ucode_patches/match_patch_init.h"
        patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));

        UINTN resA = 0;
        UINTN resB = 0;
        UINTN resC = 0;
        UINTN resD = 0;
        udebug_invoke(addr, &resA, &resB, &resC, &resD);
        if (resA != 0x0000133700001337uL) {
            Print(L"[init FAILED]\n");
            Print(L"invoke(%08lx) = %016lx, %016lx, %016lx, %016lx\n", addr, resA, resB, resC, resD);
            Exit(EFI_SUCCESS, 0, NULL);
        }
    } else if (current_glm_version == GLM_NEW) {
        // write and execute the patch that will zero out match&patch
        #include "ucode_patches/match_patch_init_glm_new.h"
        patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));

        UINTN resA = 0;
        UINTN resB = 0;
        UINTN resC = 0;
        UINTN resD = 0;
        udebug_invoke(addr, &resA, &resB, &resC, &resD);
        if (resA != 0x0000133700001337uL) {
            Print(L"[init FAILED]\n");
            Print(L"invoke(%08lx) = %016lx, %016lx, %016lx, %016lx\n", addr, resA, resB, resC, resD);
            Exit(EFI_SUCCESS, 0, NULL);
        }
    } else {
        Print(L"[init FAILED]\nunsupported GLM\n");
        Exit(EFI_SUCCESS, 0, NULL);
    }
    enable_match_and_patch();
}

void hook_match_and_patch(UINTN entry_idx, UINTN ucode_addr, UINTN patch_addr) {
    if (ucode_addr % 2 != 0) {
        Print(L"[-] uop address must be even\n");
        Exit(EFI_SUCCESS, 0, NULL);
    }
    if (patch_addr % 2 != 0 || patch_addr < 0x7c00) {
        Print(L"[-] patch uop address must be even and >0x7c00\n");
        Exit(EFI_SUCCESS, 0, NULL);
    }

    //TODO: try to hook odd addresses!!
    UINTN poff = (patch_addr - 0x7c00) / 2;
    UINTN patch_value = 0x3e000000 | (poff << 16) | ucode_addr | 1;


    #include "ucode_patches/match_patch_hook.h"
    patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));

    UINTN resA = 0;
    UINTN resB = 0;
    UINTN resC = 0;
    UINTN resD = 0;
    stgbuf_write(0xb800, patch_value); // write value to tmp0
    stgbuf_write(0xb840, entry_idx*2); // write idx to tmp1

    udebug_invoke(addr, &resA, &resB, &resC, &resD);
    
    stgbuf_write(0xb800, 0); // restore tmp0
    stgbuf_write(0xb840, 0); // restore tmp1
    
    if (resA != 0x0000133700001337uL) {
        Print(L"[hook FAILED]");
        Print(L"invoke(%08lx) = %016lx, %016lx, %016lx, %016lx\n", addr, resA, resB, resC, resD);
    }
}

UINTN parity0(UINTN value) {
    UINTN parity = 0;
    while (value) {
        parity ^= (value & 1);
        value = value >> 2;
    }
    return parity;
}

UINTN parity1(UINTN value) {
    UINTN parity = 0;
    value = value >> 1;
    while (value) {
        parity ^= (value & 1);
        value = value >> 2;
    }
    return parity;
}

#define END_UNKOWN_UOP (0x125600000000uL)
#define NOP_SEQWORD (0x0000300000c0uL)
#define END_SEQWORD (0x130000f2)
// #define END_SEQWORD (0x197ec80)
// Will generate a seqword that makes the uop2 goto the target address
UINTN make_seqw_goto(UINTN target_addr) {
    UINTN seqw =  0x1800080 | ((target_addr & 0x7fff) << 8);
    return seqw | (parity0(seqw) << 28) | (parity1(seqw) << 29);
}

// Will generate a seqword that makes the uop2 goto the target address with a SYNCFULL
UINTN make_seqw_goto_syncfull(UINTN target_addr) {
    UINTN seqw =  0x9000080 | ((target_addr & 0x7fff) << 8);
    return seqw | (parity0(seqw) << 28) | (parity1(seqw) << 29);
}

void insert_trace(UINTN tracing_addr) {
    // Install the tracing patch to addr
    #include "ucode_patches/trace_and_resume.h"

    // make the last SEQWORD a GOTO to the original address, so that the trace can remove itself
    UINTN n_tetrads = sizeof(ucode_patch) / sizeof(ucode_patch[0]);
    UINTN seqw_goto = make_seqw_goto_syncfull(tracing_addr);
    UINTN curr_seqw = ucode_patch[n_tetrads-1][3];
    if (curr_seqw != END_SEQWORD) {
        Print(L"[-] The tracing patch has no simple END_SEQWORD at the end\n");
        Exit(EFI_SUCCESS, 0, NULL);
    }
    ucode_patch[n_tetrads-1][3] = seqw_goto;

    // remove the END_UNKOWN_UOP `unk_256() !m1` instruction since it seems to 
    // mess up with the tracer
    if (ucode_patch[n_tetrads-1][0] != END_UNKOWN_UOP && ucode_patch[n_tetrads-1][1] != END_UNKOWN_UOP && ucode_patch[n_tetrads-1][2] != END_UNKOWN_UOP) {
        Print(L"[-] The tracing patch has no END_UNKOWN_UOP at the end\n");
        Exit(EFI_SUCCESS, 0, NULL);
    }
    if (ucode_patch[n_tetrads-1][0] == END_UNKOWN_UOP) ucode_patch[n_tetrads-1][0] = 0;
    if (ucode_patch[n_tetrads-1][1] == END_UNKOWN_UOP) ucode_patch[n_tetrads-1][1] = 0;
    if (ucode_patch[n_tetrads-1][2] == END_UNKOWN_UOP) ucode_patch[n_tetrads-1][2] = 0;

    patch_ucode(addr, ucode_patch, n_tetrads);

    // install the hook
    hook_match_and_patch(0, tracing_addr, addr);
}

void insert_read_trace_value(UINTN tracing_addr) {
    // Install the tracing patch to addr
    #include "ucode_patches/get_value_and_resume.h"

    // make the last SEQWORD a GOTO to the original address, so that the trace can remove itself
    UINTN n_tetrads = sizeof(ucode_patch) / sizeof(ucode_patch[0]);
    UINTN seqw_goto = make_seqw_goto_syncfull(tracing_addr);
    UINTN curr_seqw = ucode_patch[n_tetrads-1][3];
    if (curr_seqw != END_SEQWORD) {
        Print(L"[-] The tracing patch has no simple END_SEQWORD at the end\n");
        Exit(EFI_SUCCESS, 0, NULL);
    }
    ucode_patch[n_tetrads-1][3] = seqw_goto;

    // remove the END_UNKOWN_UOP `unk_256() !m1` instruction since it seems to 
    // mess up with the tracer
    if (ucode_patch[n_tetrads-1][0] != END_UNKOWN_UOP && ucode_patch[n_tetrads-1][1] != END_UNKOWN_UOP && ucode_patch[n_tetrads-1][2] != END_UNKOWN_UOP) {
        Print(L"[-] The tracing patch has no END_UNKOWN_UOP at the end\n");
        Exit(EFI_SUCCESS, 0, NULL);
    }
    if (ucode_patch[n_tetrads-1][0] == END_UNKOWN_UOP) ucode_patch[n_tetrads-1][0] = 0;
    if (ucode_patch[n_tetrads-1][1] == END_UNKOWN_UOP) ucode_patch[n_tetrads-1][1] = 0;
    if (ucode_patch[n_tetrads-1][2] == END_UNKOWN_UOP) ucode_patch[n_tetrads-1][2] = 0;

    patch_ucode(addr, ucode_patch, n_tetrads);

    // install the hook
    hook_match_and_patch(0, tracing_addr, addr);
}

UINTN get_opcode(UINTN uop) {
    return (uop >> 32) & 0xfff;
}

// return true if the ucode operation at `address` is in the blacklist
#include "ucode_dump.h"
BOOLEAN blacklisted_instruction(UINTN address) {
    UINTN opcode = get_opcode(ucode_dump[address]);
    if (opcode == 0xfef) return TRUE; // LBSYNC

    // new GLM
    if (address == 0x1544) return TRUE; 
    if (address == 0x2280) return TRUE; 
    if (address == 0x2282) return TRUE; 
    if (address == 0x368c) return TRUE; 
    if (address == 0x36c2) return TRUE; 
    if (address == 0x6004) return TRUE; 
    if (address == 0x6016) return TRUE; 

    // ucode update instructions
    if (address == 0x0010) return TRUE; // SAVEUIP(0x01, U0352) m0=1 SEQW GOTO U0911
    if (address == 0x0058) return TRUE; // SAVEUIP( , 0x01, U0c79) m0=1 SEQW GOTO U06f1
    if (address == 0x0138) return TRUE; // LDZX_DSZ16_ASZ32_SC1(DS, r64base, r64idx, IMM_MACRO_ALIAS_DISPLACEMENT, mode=0x18) m0=1
    if (address == 0x033c) return TRUE; // SYNCFULL-> UJMP( , U2e3d)
    if (address == 0x03f2) return TRUE; // r64dst:= ZEROEXT_DSZ32N(tmp0, r64dst) !m1 SEQW UEND0
    if (address == 0x0492) return TRUE; // tmp0:= unk_f3f(rsp) m0=1 m1=1
    if (address == 0x09da) return TRUE; // AETTRACE( , 0x08, IMM_MACRO_ALIAS_INSTRUCTION) !m0
    if (address == 0x09dc) return TRUE; // rsp:= ADD_DSZN(IMM_MACRO_ALIAS_DATASIZE, rsp) !m0,m1
    if (address == 0x09de) return TRUE; // STAD_DSZN_ASZ32_SC1(tmp1,  , mode=0x18, tmp0) !m1 SEQW UEND0
    if (address == 0x0a94) return TRUE; // MOVETOCREG_DSZ64(tmp10, CORE_CR_CR0) m2=1
    if (address == 0x0ba8) return TRUE; // tmp1:= RDSEGFLD(SEG_V0, SEL+FLGS+LIM) SEQW GOTO U08ea
    if (address == 0x0bc8) return TRUE; // tmp0:= unk_206( , 0x00000001)
    if (address == 0x0c74) return TRUE; // LFNCEWAIT-> STADPPHYSTICKLE_DSZ64_ASZ64_SC1(tmp12, tmp9, tmp7)
    if (address == 0x182c) return TRUE; // tmp1:= MOVE_DSZ64(tmp5) SEQW GOTO U2431
    if (address == 0x281c) return TRUE; // BTUJB_DIRECT_NOTTAKEN(tmp0, 0x00000014, patch_runs_load_loop) !m2 SEQW GOTO U281a
    if (address == 0x2a98) return TRUE; // tmp2:= ZEROEXT_DSZ32(0x00000000) SEQW GOTO U43ae
    if (address == 0x2ad8) return TRUE; // tmp2:= LDPPHYS_DSZ16_ASZ32_SC4( , tmp8, 0x00000004, mode=0x0f) SEQW GOTO U3a14
    if (address == 0x2b14) return TRUE; // SAVEUIP( , 0x01, U21fe) !m0
    if (address == 0x32cc) return TRUE; // SAVEUIP( , 0x01, U324d) !m0
    if (address == 0x5794) return TRUE; // tmp4:= SAVEUIP( , 0x01, U079d) !m0 SEQW GOTO U5cfc
    if (address == 0x57fc) return TRUE; // mm7:= FMOV( , tmm1) !m0 SEQW GOTO uend
    if (address == 0x5a0c) return TRUE; // tmp5:= LDPPHYSTICKLE_DSZ64_ASZ64_SC1(tmp1, tmp2) SEQW GOTO U3026
    if (address == 0x5b24) return TRUE; // tmp13:= MOVEFROMCREG_DSZ64( , 0x287, 32) !m1 SEQW GOTO U1b0c
    /*manual uend*/
    if (address == 0x5b26) return TRUE; // tmp8:= MOVEFROMCREG_DSZ64( , 0x0b1)
    if (address == 0x5b28) return TRUE; // BTUJNB_DIRECT_NOTTAKEN(tmp8, 0x00000005, U5b29) !m2 SEQW GOTO U2d21
    if (address == 0x5b2a) return TRUE; // MOVETOCREG_DSZ64( , 0x00000000, 0x10a) !m2
    if (address == 0x5b2c) return TRUE; // BTUJNB_DIRECT_NOTTAKEN(tmp5, 0x00000008, U2d0e) !m1
    if (address == 0x5be4) return TRUE; // SYNCFULL-> UJMP( , tmp7)
    if (address == 0x5c9e) return TRUE; // tmpv2:= MOVEFROMCREG_DSZ64( , 0x529)
    if (address == 0x5ca0) return TRUE; // LFNCEMARK-> tmpv1:= READURAM( , 0x0052, 64)
    if (address == 0x5ca2) return TRUE; // tmpv0:= SUB_DSZ64(tmpv1, tmpv0)
    if (address == 0x5ca4) return TRUE; // tmpv0:= SELECTCC_DSZ32_CONDNZ(tmpv0, 0x00000001)
    if (address == 0x5ca6) return TRUE; // tmpv1:= BT_DSZ32(tmpv1, 0x00000007)
    /*---------------*/
    if (address == 0x5d74) return TRUE; // WRITEURAM(tmp1, 0x0070, 64) !m2 SEQW GOTO U35fd
    if (address == 0x5e04) return TRUE; // tmp3:= LDPPHYSTICKLE_DSZ8_ASZ64_SC1(tmp4, 0x00000080, mode=0x1c) SEQW GOTO U0c72
    if (address == 0x5e20) return TRUE; // BTUJB_DIRECT_NOTTAKEN(tmp2, 0x00000017, U590c) !m0,m2 SEQW GOTO U05fc
    if (address == 0x5ed4) return TRUE; // WRITEURAM(tmp4, 0x001f, 32) !m2 SEQW GOTO do_smm_vmexit
    if (address == 0x6018) return TRUE; // PORTOUT_DSZ8_ASZ16_SC1(tmp2,  , tmp1) SEQW GOTO U66d2
    if (address == 0x6160) return TRUE; // MOVETOCREG_OR_DSZ64(tmp1, tmp2, 0x104) SEQW GOTO U3230
    if (address == 0x619c) return TRUE; // SYNCWAIT-> tmp14:= READURAM( , 0x0043, 64) SEQW GOTO U4ded
    if (address == 0x621c) return TRUE; // tmp11:= READURAM( , 0x000f, 64) SEQW GOTO U3c98
    if (address == 0x68ac) return TRUE; // tmp11:= ZEROEXT_DSZ32(0x00020101) SEQW GOTO U669a

    // // instruction that freezes the CPU AFTER tracing all
    if (address == 0x208c) return TRUE; // tmp9:= AND_DSZ64(0x00000800, tmp9) SEQW GOTO U4b22


    // UDBGRD/UDBWR instructions
    if (address == 0x4052) return TRUE;
    if (address == 0x4054) return TRUE;
    if (address == 0x4064) return TRUE;
    if (address == 0x4066) return TRUE;
    if (address == 0x4092) return TRUE;

    // unknown reason why it crashes here (rdmsr)
    if (address == 0x3ce0) return TRUE;

    // faulty readmsr
    if (address == 0x0ea0) return TRUE;
    if (address == 0x2684) return TRUE;
    if (address == 0x38c8) return TRUE;
    if (address == 0x3bfc) return TRUE;
    if (address == 0x3d64) return TRUE;
    if (address == 0x3d88) return TRUE;
    if (address == 0x4d50) return TRUE;

    // unknown reason why it crashes here (wrmsr(0x1b))
    if (address == 0x008e) return TRUE;
    if (address == 0x69d0) return TRUE;

    // ud2
    if (address == 0xdc0) return TRUE;

    // int3
    if (address == 0x3a2c) return TRUE; // LFNCEWAIT-> MOVETOCREG_DSZ64(tmpv0, 0x6c0)
    if (address == 0x33e4) return TRUE; // SYNCFULL-> MOVETOCREG_DSZ64(tmp1, 0x7f5) !m2
    if (address == 0x3d34) return TRUE; // tmp14:= SAVEUIP(0x01, U0664) !m0 SEQW GOTO U5d81
    if (address == 0x3e70) return TRUE; // NOP SEQW GOTO U1f9a
    if (address == 0x605c) return TRUE; // GENARITHFLAGS(tmp0, tmp7) !m2 SEQW UEND

    // int1
    if (address == 0x3e94) return TRUE; // MOVETOCREG_DSZ64(tmp0, 0x070)


    // The next addresses in the black list where crashing if the match&patch was not
    // reinitialized at every iteration. Keep them for future reference
    // if (address == 0x3c8) return TRUE;
    // if (address == 0x490) return TRUE;
    // if (address == 0x492) return TRUE;
    // if (address == 0x6c8) return TRUE;
    // if (address == 0x6ca) return TRUE;
    return FALSE;
}

INTN unwrap_clock(UINTN value) {
    return (value &  0xffffffffffffffL) * 0x39 + (value >> 0x37);
}

#define STGBUF_COUNTER (0xba00)
#define CRBUS_CLOCK (0x2000 | 0x2d7)
INTN get_trace_clock_at(UINTN tracing_addr) {
    unsigned char* _ucode_data = ucode_data;
    // reset value
    stgbuf_write(STGBUF_COUNTER, 0);
    insert_trace(tracing_addr);
    UINTN before = crbus_read(CRBUS_CLOCK);

    // [TRACED INSTRUCTION HERE]

    if (try_except(&exception_jmp_buf) == 0) {
        asm volatile("int3\n");
    }

    // [-----------------------]

    UINTN after = stgbuf_read(STGBUF_COUNTER);
    // reset match&patch in case it didn't trigger
    ms_match_patch_write(0, 0);
    INTN elapsed = -1;
    if (after != 0) {
        elapsed = unwrap_clock(after) - unwrap_clock(before);
    }
    return elapsed;
}

UINTN read_trace_value(UINTN tracing_addr) {
    unsigned char* _ucode_data = ucode_data;
    // reset value
    stgbuf_write(STGBUF_COUNTER, 0);
    insert_read_trace_value(tracing_addr);

    // [TRACED INSTRUCTION HERE]

    wrmsr(IA32_BIOS_UPDT_TRIG, (unsigned long)(_ucode_data+48));

    // [-----------------------]

    UINTN value = stgbuf_read(STGBUF_COUNTER);
    // reset match&patch in case it didn't trigger
    ms_match_patch_write(0, 0);
    INTN elapsed = -1;
    return value;
}

UINTN AsciiSPrint (OUT CHAR8 *Str, IN UINTN StrSize,IN CONST CHAR8 *fmt, ...)
{
    va_list          args;
    UINTN            len;

    va_start (args, fmt);
    len = AsciiVSPrint(Str, StrSize, fmt, args);
    va_end (args);

    return len;
}

static void DumpBufferHex (void* Buf, UINTN Size)
{
    UINT8* Buffer = (UINT8*)Buf;
    UINTN  i, j, k;
    char Line[80] = "";
    
    for (i = 0; i < Size; i += 16) {
        if (i != 0) {
            AsciiPrint("%a\n", Line);
        }
        Line[0] = 0;
        AsciiSPrint (&Line[strlena(Line)], 80 - strlena(Line), "  %08x  ", i);
        for (j = 0, k = 0; k < 16; j++, k++) {
            if (i + j < Size) {
                AsciiSPrint (&Line[strlena(Line)], 80 - strlena(Line), "%02x", Buffer[i + j]);
            } else {
                AsciiSPrint (&Line[strlena(Line)], 80 - strlena(Line), "  ");
            }
            AsciiSPrint (&Line[strlena(Line)], 80 - strlena(Line), " ");
        }
        AsciiSPrint (&Line[strlena(Line)], 80 - strlena(Line), " ");
        for (j = 0, k = 0; k < 16; j++, k++) {
            if (i + j < Size) {
                if ((Buffer[i + j] < 32) || (Buffer[ i + j] > 126)) {
                    AsciiSPrint (&Line[strlena(Line)], 80 - strlena(Line), ".");
                } else {
                    AsciiSPrint (&Line[strlena(Line)], 80 - strlena(Line), "%c", Buffer[i + j]);
                }
            }
        }
    }
    AsciiPrint("%a\n", Line);
}

// update to the included ucode
static void update_ucode(void) {
    wrmsr(IA32_BIOS_UPDT_TRIG, (unsigned long)(ucode_data+48));
}

#define ACCESS_REPETITIONS (100000)
uint64_t access_time(void* ptr) {
    uint64_t sum = 0;

    #include "ucode_patches/time_access_hook.h"
    patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));

    for (int i = 0; i < ACCESS_REPETITIONS; i++) {
        
        UINTN resA = 0;
        UINTN resB = 0;
        UINTN resC = 0;
        UINTN resD = 0;
        stgbuf_write(0xb800, (unsigned long) ptr & ~0xfffuL); // write addr to tmp0
        udebug_invoke(addr, &resA, &resB, &resC, &resD);
        stgbuf_write(0xb800, 0); // restore tmp0

        UINTN start = unwrap_clock(resA);
        UINTN end   = unwrap_clock(resB);
        sum += (end - start);
    }

    return (uint64_t)(sum / ACCESS_REPETITIONS);
}

int access_time_flush(void* ptr) {
    uint64_t sum = 0;

    #include "ucode_patches/time_access_hook.h"
    patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));

    for (int i = 0; i < ACCESS_REPETITIONS; i++) {
        
        UINTN resA = 0;
        UINTN resB = 0;
        UINTN resC = 0;
        UINTN resD = 0;
        stgbuf_write(0xb800, (unsigned long) ptr & ~0xfffuL); // write addr to tmp0
        flush((void*)((unsigned long)ptr & ~0xfffuL));
        udebug_invoke(addr, &resA, &resB, &resC, &resD);
        stgbuf_write(0xb800, 0); // restore tmp0

        UINTN start = unwrap_clock(resA);
        UINTN end   = unwrap_clock(resB);
        sum += (end - start);
    }

    return (uint64_t)(sum / ACCESS_REPETITIONS);
}

uint8_t ids[0x10000] = {0};
static void test1(void) {
    Print(L"[test1]: %lx\n", test1);
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

static void test2(void) {
    Print(L"[test2]: %lx\n", test2);
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

EFI_STATUS
EFIAPI
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *SystemTable)
{
    UINTN argc;
    CHAR16 **argv;
    EFI_STATUS status;
    EFI_GUID gEfiGlobalVariableGuid = SHELL_VARIABLE_GUID;

    InitializeLib(image, SystemTable);

    current_glm_version = detect_goldomnt_version();
    if (current_glm_version != GLM_NEW && current_glm_version != GLM_OLD) {
        Print(L"[-] Unsupported GLM version: %08lx\n", current_glm_version);
        return EFI_SUCCESS;
    }
    if (current_glm_version == GLM_OLD) {
        ucode_data = bios_glm_intel_ucode_06_5c_09;
        ucode_size = sizeof(bios_glm_intel_ucode_06_5c_09);
    } else if (current_glm_version == GLM_NEW) {
        ucode_data = bios_glm_intel_ucode_06_5c_0a;
        ucode_size = sizeof(bios_glm_intel_ucode_06_5c_0a);
    }

    Print(L"[START]\n");

    status = get_args(image, &argc, &argv);
    if (EFI_ERROR(status)) {
        Print(L"ERROR: Parsing command line arguments: %d\n", status);
        return status;
    }

    setup_exceptions();
    activate_udebug_insts();
    enable_match_and_patch();

    if (argc < 2) {
        // usage();
        test1();
        test2();
        return EFI_SUCCESS;
    } else if (argc > 1) {
        if (argv[1][0] == L'c') {
            Print(L"[cpuid]\n");

            if (argc < 4) {
                Print(L"[-] missing parameters\n");
                return EFI_SUCCESS;
            }

            UINTN prev_rax  = utoi(argv[2]);
            UINTN prev_rcx = utoi(argv[3]);
            UINTN rax = prev_rax, rbx = 0, rcx = prev_rcx, rdx = 0;

            cpuid(&rax, &rbx, &rcx, &rdx);
            Print(L"cpuid(%08lx, %08lx) = %08lx, %08lx, %08lx, %08lx\n", prev_rax, prev_rcx, rax, rbx, rcx, rdx);

        } else if (argv[1][0] == L'r' && argv[1][1] == L'm') {
            Print(L"[rdmsr]\n");

            if (argc < 3) {
                Print(L"[-] missing parameters\n");
                return EFI_SUCCESS;
            }

            UINTN msr  = utoi(argv[2]);

            if (try_except(&exception_jmp_buf) == 0) {
                UINTN res = rdmsr(msr);
                Print(L"rdmsr(%08lx) = %08lx\n", msr, res);
            } else {
                Print(L"rdmsr(%08lx) failed\n", msr);
            }
            Print(L"[rdmsr done]\n");

        } else if (argv[1][0] == L'w' && argv[1][1] == L'm') {
            Print(L"[wrmsr]\n");

            if (argc < 4) {
                Print(L"[-] missing parameters\n");
                return EFI_SUCCESS;
            }

            UINTN msr    = utoi(argv[2]);
            UINTN value  = utoi(argv[3]);

            if (try_except(&exception_jmp_buf) == 0) {
                wrmsr(msr, value);
                Print(L"wrmsr(%08lx,%08lx)\n", msr, value);
            } else {
                Print(L"wrmsr(%08lx,%08lx) failed\n", msr, value);
            }
            Print(L"[wrmsr done]\n");

        } else if (StrCmp(argv[1], L"r") == 0) {
            Print(L"[udbgrd]\n");

            if (argc < 4) {
                Print(L"[-] missing parameters\n");
                return EFI_SUCCESS;
            }

            UINTN cmd  = utoi(argv[2]);
            UINTN addr = utoi(argv[3]);

            UINTN res = udebug_read(cmd, addr);
            Print(L"read(%08lx, %08lx) = %016lx\n", cmd, addr, res);

        } else if (StrCmp(argv[1], L"w") == 0) {
            Print(L"[udbgwr]\n");

            if (argc < 5) {
                Print(L"[-] missing parameters\n");
                return EFI_SUCCESS;
            }

            UINTN cmd  = utoi(argv[2]);
            UINTN addr = utoi(argv[3]);
            UINTN val  = utoi(argv[4]);

            udebug_write(cmd, addr, val);
            Print(L"write(%08lx, %08lx, %016lx)\n",cmd, addr, val);
        } else if (argv[1][0] == L'i') {
            Print(L"[udbg invoke]\n");

            if (argc < 3) {
                Print(L"[-] missing parameters\n");
                return EFI_SUCCESS;
            }

            UINTN addr  = utoi(argv[2]);

            UINTN resA = 0;
            UINTN resB = 0;
            UINTN resC = 0;
            UINTN resD = 0;
            udebug_invoke(addr, &resA, &resB, &resC, &resD);
            Print(L"invoke(%08lx) = %016lx, %016lx, %016lx, %016lx\n", addr, resA, resB, resC, resD);

        } else if (argv[1][0] == L'l' && argv[1][1] == L'r') {
            Print(L"[ldat read]\n");

            if (argc < 7) {
                Print(L"[-] missing parameters\n");
                return EFI_SUCCESS;
            }

            UINTN port  = utoi(argv[2]);
            UINTN array = utoi(argv[3]);
            UINTN bank  = utoi(argv[4]);
            UINTN idx   = utoi(argv[5]);
            UINTN target_addr  = utoi(argv[6]);

            UINTN size = 1;
            if (argc > 7) {
                size = utoi(argv[7]);
            }

            // write the ldat_read function
            #include "ucode_patches/ldat_read.h"
            patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));

            Print(L"ldat_read(%08lx, %08lx, %08lx, %08lx, %08lx)\n", port, array, bank, idx, target_addr);
            for (UINTN i=0; i < size; i++) {
                if (i && i % 4 == 0) Print(L"\n");

                UINTN res = ldat_read(addr, port, array, bank, idx, target_addr+i);
                Print(L"%016lx ", res);
            }

        } else if (argv[1][0] == L'l' && argv[1][1] == L'w') {
            Print(L"[ldat write]\n");

            if (argc < 8) {
                Print(L"[-] missing parameters\n");
                return EFI_SUCCESS;
            }

            UINTN port  = utoi(argv[2]);
            UINTN array = utoi(argv[3]);
            UINTN bank  = utoi(argv[4]);
            UINTN idx   = utoi(argv[5]);
            UINTN addr  = utoi(argv[6]);
            UINTN value = utoi(argv[7]);

            ldat_array_write(port, array, bank, idx, addr, value);
            Print(L"ldat_write(%08lx, %08lx, %08lx, %08lx, %08lx, %016lx)\n", port, array, bank, idx, addr, value);
        } else if (argv[1][0] == L'u') {
            Print(L"[updating ucode]\n");

            // Print(L"[Invalidating signature]\n");
            // /* Invalidate ucode update RSA signature (starting at 0x1b4)*/
            // ucode_data[0x1c0] = 0;

            wrmsr(IA32_BIOS_SIGN_ID, 0uL);
            asm volatile("mov $1, %%eax\n cpuid\n"::: "eax","ebx","ecx","edx", "memory");
            UINTN rev = rdmsr(IA32_BIOS_SIGN_ID);

            Print(L"old ucode revision: %08lx\n", rev);

            update_ucode();

            wrmsr(IA32_BIOS_SIGN_ID, 0uL);
            asm volatile("mov $1, %%eax\n cpuid\n"::: "eax","ebx","ecx","edx", "memory");
            UINTN rev2 = rdmsr(IA32_BIOS_SIGN_ID);

            Print(L"new ucode revision: %08lx\n", rev2);


        } else if (argv[1][0] == L'p') {
            Print(L"[patch]\n");

            #include "ucode_patches/ucode_patch.h"
            Print(L"patching addr: %08lx - ram: %08lx\n", addr, ucode_addr_to_patch_addr(addr));
            patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));

            Print(L"patched addr: %08lx\n", addr);
        } else if (argv[1][0] == L'x') {
            Print(L"[patch & exec]\n");

            UINTN param = 0;
            if (argc >= 3) {
                param  = utoi(argv[2]);
            }

            
            #include "ucode_patches/ucode_patch.h"
            Print(L"patching addr: %08lx - ram: %08lx\n", addr, ucode_addr_to_patch_addr(addr));
            patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));
            
            Print(L"patched, now exec with param: %08lx\n", param);
            stgbuf_write(0xb800, param); // write param to tmp0

            UINTN resA = 0;
            UINTN resB = 0;
            UINTN resC = 0;
            UINTN resD = 0;
            udebug_invoke(addr, &resA, &resB, &resC, &resD);
            Print(L"invoke(%08lx) = %016lx, %016lx, %016lx, %016lx\n", addr, resA, resB, resC, resD);
        }  else if (argv[1][0] == L'f') {
            Print(L"[patch & exec & perf]\n");

            
            #include "ucode_patches/ucode_patch.h"
            Print(L"patching addr: %08lx - ram: %08lx\n", addr, ucode_addr_to_patch_addr(addr));
            patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));
            
            Print(L"patched, now exec\n");

            UINTN resA = 0;
            UINTN resB = 0;
            UINTN resC = 0;
            UINTN resD = 0;
            #define TEST_TIMES 128
            uint64_t pmc0 = 0, pmc1 = 0, pmc2 = 0, pmc3 = 0, pmc_fixed_1 = 0;
            
            #define PMC0_EVENT INST_RETIRED_ANY_P
            #define PMC0_EVENT_NAME "INST_RETIRED_ANY_P"

            #define PMC1_EVENT UOPS_ISSUED_ANY
            #define PMC1_EVENT_NAME "UOPS_ISSUED_ANY"

            #define PMC2_EVENT UOPS_RETIRED_MS
            #define PMC2_EVENT_NAME "UOPS_RETIRED_MS"

            #define PMC3_EVENT MACHINE_CLEARS_ALL
            #define PMC3_EVENT_NAME "MACHINE_CLEARS_ALL"

            for (int i = 0; i < TEST_TIMES; i++) {

                perf_disable_globally();
                perf_program_event(0, PMC0_EVENT & 0xff, PMC0_EVENT >> 8);
                perf_program_event(1, PMC1_EVENT & 0xff, PMC1_EVENT >> 8);
                perf_program_event(2, PMC2_EVENT & 0xff, PMC2_EVENT >> 8);
                perf_program_event(3, PMC3_EVENT & 0xff, PMC3_EVENT >> 8);

                perf_program_fixed_1(0);

                perf_enable_globally();

                udebug_invoke(addr, &resA, &resB, &resC, &resD);

                perf_disable_globally();

                pmc0 += perf_read(0);
                pmc1 += perf_read(1);
                pmc2 += perf_read(2);
                pmc3 += perf_read(3);
                pmc_fixed_1 += perf_read_fixed_1();
            }
            Print(L"invoke(%08lx) = %016lx, %016lx, %016lx, %016lx\n", addr, resA, resB, resC, resD);
            Print(L"Clocks: %8lu\n", pmc_fixed_1/TEST_TIMES);
            Print(L""PMC0_EVENT_NAME": %lu\n", pmc0/TEST_TIMES);
            Print(L""PMC1_EVENT_NAME": %lu\n", pmc1/TEST_TIMES);
            Print(L""PMC2_EVENT_NAME": %lu\n", pmc2/TEST_TIMES);
            Print(L""PMC3_EVENT_NAME": %lu\n", pmc3/TEST_TIMES);
        } else if (argv[1][0] == L'z') {
            Print(L"[zero out match&patch]\n"); 

            init_match_and_patch();
            Print(L"[zeroed]\n");
        } else if (argv[1][0] == L'h') {
            Print(L"[hook]\n"); 

            if (argc < 5) {
                Print(L"[-] missing parameters\n");
                return EFI_SUCCESS;
            }

            UINTN idx  = utoi(argv[2]);
            UINTN uaddr = utoi(argv[3]);
            UINTN paddr  = utoi(argv[4]);
            Print(L"hooking: 0x%lx -> 0x%lx\n", uaddr, paddr);

            if (uaddr % 2 != 0) {
                Print(L"[-] uop address must be even\n");
                return EFI_SUCCESS;
            }
            if (paddr % 2 != 0 || paddr < 0x7c00) {
                Print(L"[-] patch uop address must be even and >0x7c00\n");
                return EFI_SUCCESS;
            }

            hook_match_and_patch(idx, uaddr, paddr);
            Print(L"[hooked]\n");
        } else if (argv[1][0] == L't') {
            Print(L"[trace]\n");

            if (argc < 3) {
                Print(L"[-] missing parameters\n");
                return EFI_SUCCESS;
            }

            UINTN tracing_addr = utoi(argv[2]);

            insert_trace(tracing_addr);

            Print(L"[inserted tracer]\n");
        } else if (argv[1][0] == L'm') {
            Print(L"[template]\n");

            UINTN start_trace = 0x0000;
            UINTN end_trace   = 0x7c00;

            #define TRACE_SIZE (0x7c00 * 40)
            char trace[TRACE_SIZE] = {0};

            EFI_FILE_PROTOCOL *File;
            CHAR16* FileName = L"EFI\\trace.txt";

            Print(L"[Invalidating signature]\n");
            /* Invalidate ucode update RSA signature (starting at 0x1b4)*/
            ucode_data[0x1c0] = 0;

            // Initialize all the match and patch to zero
            init_match_and_patch();

            for (UINTN tracing_addr = start_trace; tracing_addr < end_trace; tracing_addr += 2) {
                // if (tracing_addr && ((tracing_addr & 0xfff) == 0)) {
                //     status = open_write_close_file(trace, FileName);
                //     if (EFI_ERROR(status)) {
                //         Print(L"ERROR: Writing file: %d\n", status);
                //         CHAR16 ErrorString[0x100] = {0};
                //         StatusToString(ErrorString, status);
                //         Print(L"ERROR: Writing file: %s\n", ErrorString);
                //         return status;
                //     }
                // }
                if (blacklisted_instruction(tracing_addr)) continue;
                Print(L"\r%04x ", tracing_addr);

                #define TRIES 128
                INTN total_elapsed = 0;

                for (int i=0; i < TRIES; ++i) {
                    INTN elapsed = get_trace_clock_at(tracing_addr);
                    if (elapsed < 0) {
                        total_elapsed = -1;
                        break;
                    }
                    total_elapsed += elapsed;
                }
            
                if (total_elapsed > 0) {
                    Print(L"[%ld] \n", total_elapsed/TRIES);
                    INTN len = strlena(trace);
                    if (TRACE_SIZE <= len + 40) { // safety check
                        Print(L"[-] The tracing buffer is not big enough\n");
                        return EFI_SUCCESS;
                    }
                    AsciiSPrint(
                        &trace[len], TRACE_SIZE - len, 
                        "%04x %ld\n", tracing_addr, total_elapsed/TRIES
                    );
                }
            }
            Print(L"\r[Completed]\n");
            status = open_write_close_file(trace, FileName);
            if (EFI_ERROR(status)) {
                Print(L"ERROR: Writing file: %d\n", status);
                CHAR16 ErrorString[0x100] = {0};
                StatusToString(ErrorString, status);
                Print(L"ERROR: Writing file: %s\n", ErrorString);
                return status;
            }

            Print(L"[end templating]\n");
        } else if (argv[1][0] == L'd' && argv[1][1] == L'i') {
            Print(L"[dump immediates]\n");

            char imm_dump[TRACE_SIZE] = {0};

            EFI_FILE_PROTOCOL *File;
            CHAR16* FileName = L"EFI\\imms.txt";

            for (UINTN imm = 0; imm < 0x400; imm ++) {
                unsigned long addr = 0x7da0;
                unsigned long ucode_patch[][4] = {
                    // U7da0: rax:= ZEROEXT_DSZ64(IMM), NOP, SEQ_END
                    {0x4800020010, 0x125600000000, 0x0, 0x130000f2},
                };

                // set the immediate number
                ucode_patch[0][0] |= (((imm & 0xff) << 24) | ((imm & 0x300) << 10));
                ucode_patch[0][0] |= (parity1(ucode_patch[0][0]) << 45) | (parity0(ucode_patch[0][0]) << 46);

                patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));

                UINTN res = 0;
                UINTN resB = 0;
                UINTN resC = 0;
                UINTN resD = 0;
                udebug_invoke(addr, &res, &resB, &resC, &resD);

                Print(L"\r%04x ", imm);

                INTN len = strlena(imm_dump);
                if (TRACE_SIZE <= len + 40) { // safety check
                    Print(L"[-] The tracing buffer is not big enough\n");
                    return EFI_SUCCESS;
                }
                AsciiSPrint(
                    &imm_dump[len], TRACE_SIZE - len, 
                    "0x%04lx\n", res
                );
            }
            Print(L"\r[Completed]\n");
            status = open_write_close_file(imm_dump, FileName);
            if (EFI_ERROR(status)) {
                Print(L"ERROR: Writing file: %d\n", status);
                CHAR16 ErrorString[0x100] = {0};
                StatusToString(ErrorString, status);
                Print(L"ERROR: Writing file: %s\n", ErrorString);
                return status;
            }

            Print(L"[end immediate dump]\n");
        } else if (argv[1][0] == L'd' && argv[1][1] == L'r') {
            Print(L"[dump rom]\n");

            char imm_dump[TRACE_SIZE] = {0};

            EFI_FILE_PROTOCOL *File;
            CHAR16* FileName = L"EFI\\rom.txt";

            for (UINTN imm = 0; imm < 0x200; imm ++) {

                // set address
                stgbuf_write(0xb800, imm);  // write addr to tmp0

                unsigned long addr = 0x7da0;
                unsigned long ucode_patch[][4] = {
                    // U7da0: tmm5:= FPREADROM_DTYPENOP(tmp0), tmp10:= PINTMOVDTMM2I_DSZ64(tmm5), rax:= MOVE_DSZ64(tmp10), SEQ_NOP
                    {0x87160003d030, 0x76c0003a03d, 0xc0490002003a, 0x300000c0},
                    // U7da4: unk_256() !m1, NOP, NOP, SEQ_END
                    {0x125600000000, 0x0, 0x0, 0x130000f2},
                };

                patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));

                UINTN res = 0;
                UINTN resB = 0;
                UINTN resC = 0;
                UINTN resD = 0;
                udebug_invoke(addr, &res, &resB, &resC, &resD);

                Print(L"\r%04x ", imm);

                INTN len = strlena(imm_dump);
                if (TRACE_SIZE <= len + 40) { // safety check
                    Print(L"[-] The tracing buffer is not big enough\n");
                    return EFI_SUCCESS;
                }
                AsciiSPrint(
                    &imm_dump[len], TRACE_SIZE - len, 
                    "0x%04lx\n", res
                );
            }
            stgbuf_write(0xb800, 0);  // restore tmp0
            Print(L"\r[Completed]\n");
            status = open_write_close_file(imm_dump, FileName);
            if (EFI_ERROR(status)) {
                Print(L"ERROR: Writing file: %d\n", status);
                CHAR16 ErrorString[0x100] = {0};
                StatusToString(ErrorString, status);
                Print(L"ERROR: Writing file: %s\n", ErrorString);
                return status;
            }

            Print(L"[end rom dump]\n");
        } else if (argv[1][0] == L'd' && argv[1][1] == L'm') {
            Print(L"[dump msrs]\n");

            char dump[2*TRACE_SIZE] = {0};

            EFI_FILE_PROTOCOL *File;
            CHAR16* FileName = L"EFI\\msrs.txt";

            for (UINTN imm = 0x0; imm < 0xfff; imm ++) {

                // set address
                stgbuf_write(0xb800, imm);  // write addr to tmp0

                #include "ucode_patches/msr2cr_dump.h"
                patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));

                UINTN resA = 0;
                UINTN resB = 0;
                UINTN resC = 0;
                UINTN resD = 0;
                udebug_invoke(addr, &resA, &resB, &resC, &resD);

                // compute the write params
                UINTN wr_chk_func = ((resA >> 3) & 0x78) | 0x3700 | 0x80;
                UINTN wr_func = ((resA >> 0x16) & 0x3fc)| 0x3000;
                UINTN wr_addr1 = ((resA >> 10) & 0x7ff);
                UINTN wr_addr2 = ((resA >> 10) & 0x3fff) << 2;
                UINTN wr_ustate = (resA & 0x3f) << 2;
                
                // compute the read params
                UINTN rd_chk_func = ((resB >> 3) & 0x78) | 0x3700;
                UINTN rd_func = ((resB >> 0x16) & 0x3fc)| 0x3000;
                UINTN rd_addr1 = ((resB >> 10) & 0x7ff);
                UINTN rd_addr2 = ((resB >> 10) & 0x3fff) << 2;
                UINTN rd_ustate = (resB & 0x3f) << 2;

                // try rdmsr
                BOOLEAN rd_fault = TRUE;
                if (try_except(&exception_jmp_buf) == 0) {
                    rdmsr(imm);
                    rd_fault = FALSE;
                }
                
                // Print(L"msr(%08lx) = %016lx, %016lx, %016lx, %016lx\n", imm, resA, resB, resC, resD);
                // Print(L"%08lx %08lx %08lx %08lx\n", wr_chk_func, wr_func, wr_addr1, wr_addr2);
                // Print(L"%08lx %08lx %08lx %08lx\n", rd_chk_func, rd_func, rd_addr1, rd_addr2);

                Print(L"\r%04x ", imm);

                INTN len = strlena(dump);
                if (TRACE_SIZE <= len + 40) { // safety check
                    Print(L"[-] The tracing buffer is not big enough\n");
                    return EFI_SUCCESS;
                }
                AsciiSPrint(
                    &dump[len], TRACE_SIZE - len, 
                    "RDMSR: 0x%04lx, CHK: 0x%04lx, FUNC: 0x%04lx, ADDR1: 0x%04lx, ADDR2: 0x%04lx, USTATE: 0x%02lx (0x%02lx), FAULT:%d\n"
                    "WRMSR: 0x%04lx, CHK: 0x%04lx, FUNC: 0x%04lx, ADDR1: 0x%04lx, ADDR2: 0x%04lx, USTATE: 0x%02lx (0x%02lx)\n",
                    imm, rd_chk_func, rd_func, rd_addr1, rd_addr2, rd_ustate, rd_ustate & 0xe4, rd_fault,
                    imm, wr_chk_func, wr_func, wr_addr1, wr_addr2, wr_ustate, wr_ustate & 0xe4
                );
            }
            stgbuf_write(0xb800, 0);  // restore tmp0
            Print(L"\r[Completed]\n");
            status = open_write_close_file(dump, FileName);
            if (EFI_ERROR(status)) {
                Print(L"ERROR: Writing file: %d\n", status);
                CHAR16 ErrorString[0x100] = {0};
                StatusToString(ErrorString, status);
                Print(L"ERROR: Writing file: %s\n", ErrorString);
                return status;
            }

            Print(L"[end rom dump]\n");
        } else if (argv[1][0] == L'd' && argv[1][1] == L's') {
            Print(L"[dump SMM memory]\n");

            if (argc < 4) {
                Print(L"[-] missing parameters\n");
                return EFI_SUCCESS;
            }

            UINTN mem_addr  = utoi(argv[2]);
            UINTN size  = utoi(argv[3]);
            if (size > 0x1000) {
                Print(L"[-] size: max 4Kb\n");
                return EFI_SUCCESS;
            }

            #include "ucode_patches/dump_smm.h"
            Print(L"patching addr: %08lx - ram: %08lx\n", addr, ucode_addr_to_patch_addr(addr));
            patch_ucode(addr, ucode_patch, sizeof(ucode_patch) / sizeof(ucode_patch[0]));

            UINTN buf[0x1000] = {0};
            for (int i=0; i < size/8; i++) {
                stgbuf_write(0xb800, mem_addr+i*8); // write mem_addr to tmp0

                UINTN resA = 0;
                UINTN resB = 0;
                UINTN resC = 0;
                UINTN resD = 0;
                udebug_invoke(addr, &resA, &resB, &resC, &resD);
                buf[i] = resA;
            }
            DumpBufferHex(buf, size);

            Print(L"[end dump]\n");
        } else if (argv[1][0] == L'v') {
            Print(L"[read trace value]\n");

            if (argc < 3) {
                Print(L"[-] missing parameters\n");
                return EFI_SUCCESS;
            }

            UINTN tracing_addr = utoi(argv[2]);

            if (blacklisted_instruction(tracing_addr)) {
                Print(L"[-] address is blacklisted\n");
                return EFI_SUCCESS;
            }

            Print(L"[Invalidating signature]\n");
            /* Invalidate ucode update RSA signature (starting at 0x1b4)*/
            ucode_data[0x1c0] = 0;

            stgbuf_write(STGBUF_COUNTER + 0x140, 0);
            stgbuf_write(STGBUF_COUNTER + 0x180, 0);
            stgbuf_write(STGBUF_COUNTER + 0x1c0, 0);
            stgbuf_write(STGBUF_COUNTER + 0x200, 0);
            stgbuf_write(STGBUF_COUNTER + 0x240, 0);
            stgbuf_write(STGBUF_COUNTER + 0x280, 0);
            stgbuf_write(STGBUF_COUNTER + 0x2c0, 0);

            // Initialize all the match and patch to zero
            init_match_and_patch();

            UINTN value = read_trace_value(tracing_addr);
            Print(L"ucode: %016lx\n", ucode_data);
            UINTN rc4_key[8] = {0};
            Print(L"value: %016lx\n", value);
            rc4_key[0] = value;
            rc4_key[1] = stgbuf_read(STGBUF_COUNTER + 0x140);
            rc4_key[2] = stgbuf_read(STGBUF_COUNTER + 0x180);
            rc4_key[3] = stgbuf_read(STGBUF_COUNTER + 0x1c0);
            rc4_key[4] = stgbuf_read(STGBUF_COUNTER + 0x200);
            rc4_key[5] = stgbuf_read(STGBUF_COUNTER + 0x240);
            rc4_key[6] = stgbuf_read(STGBUF_COUNTER + 0x280);
            rc4_key[7] = stgbuf_read(STGBUF_COUNTER + 0x2c0);
            DumpBufferHex(rc4_key, 8*8);
        } else {
            Print(L"Unkown option: %s\n", argv[1]);
        }
    }

  return EFI_SUCCESS;
}