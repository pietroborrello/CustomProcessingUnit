# Custom Processing Unit

<img src="./images/cpu_logo.svg" width=150>

Custom Processing Unit is the first dynamic analysis framework able to hook, patch and trace CPU microcode at the software level.

It works by leveraging [undocumented instructions](https://github.com/chip-red-pill/udbgInstr) in Intel CPUs that allow access to the CRBUS.
Using our [microcode decompiler](https://github.com/pietroborrello/ghidra-atom-microcode) we reverse engineered how the CPU uses the CRBUS and by replicating the interactions we have full control of the CPU.

Find the static analysis framework at https://github.com/pietroborrello/ghidra-atom-microcode.

**Note**: Custom Processing Unit requires a Red-Unlocked CPU: currently, only [Goldmont CPUs](https://en.wikipedia.org/wiki/Goldmont) (GLM) have a [public Red Unlock](https://github.com/ptresearch/IntelTXE-PoC). We tested Gigabyte GB-BPCE-3350C with CPU stepping 0x9 and 0xa (cpuid 0x000506C9 and 0x000506CA).

Custom Processing Unit is made up of a UEFI application and a few libraries. The UEFI application interacts with the GLM CPU, while the libraries provide different helpers to compile microcode into the UEFI application and analyze its output.

## Prerequisites

1. Follow the steps to red unlock your Goldmont CPU from https://github.com/ptresearch/IntelTXE-PoC.
2. Create a bootable USB key with an EFI shell
3. Install [gnu-efi](https://wiki.osdev.org/GNU-EFI) on your main host

## Setup

```
GNU_EFI_DIR=<path_to_gnu_efi> make
```

This will build the source microcode files and the UEFI application into `cpu.efi`.
Copy `cpu.efi` into the `\EFI\` folder of the USB key, plug it in the GLM and boot into the EFI shell.

Run `map -r` in the efi shell to identify the USB key device and `<deviceid>:` to mount it.

## Run Custom Processing Unit

Run `./cpu.efi` to print the help:

```
Usage:
  patch:        <tool> p
  patch & exec: <tool> x
  perf:         <tool> f
  zero out m&p: <tool> z
  hook:         <tool> h  [m&p idx] [uop addr] [patch addr]
  template:     <tool> m
  dump imms:    <tool> di
  dump rom:     <tool> dr
  dump msrs:    <tool> dm
  dump SMM:     <tool> ds [address] [size]
  cpuid:        <tool> c  [rax] [rcx]
  rdmsr:        <tool> rm [msr]
  wrmsr:        <tool> wm [msr]
  read:         <tool> r  [cmd] [addr]
  write:        <tool> w  [cmd] [addr] [value]
  invoke:       <tool> i  [addr]
  update ucode: <tool> u  [size]
  ldat read:    <tool> lr [port] [array] [bank] [idx] [addr] [optional size]
  ldat write:   <tool> lw [port] [array] [bank] [idx] [addr] [value]
```

### Simple instructions

`cpu` provides helpers to run simple instructions from the command line:
* cpuid
* rdmsr
* wrmsr

### Complex actions
`cpu` provides interfaces to complex CPU routines that are interesting to execute to study cpu behavior:
* `u`: update the CPU ucode with the provided (signed) patch
* `f`: collect performance counters while running microcode

### Raw udbgrd and udbwr

`cpu` provides raw interfaces to the undocumented instructions `udbrd` and `udbgwr`.
The most interesting commands they provide are:
* 0x0:  access CRBUS
* 0x10: access UROM
* 0x40: access stgbuf
* 0xd8: invoke ucode routine from address

### LDAT access
`cpu` exposes LDAT access routines to read and write. Specify the parameters  `[port] [array] [bank] [idx] [addr]` to read or write there.
Interesting ports are:
* 0x6a0: microcode sequencer, which has access to the internal the ucode ROM and RAM
* 0x120: load/store buffers
* 0x3c0: instruction cache
* 0x630: ITLB

Please notice that accessing some of these internal components may cause the CPU to freeze.

### Patch microcode

`cpu` provides functionalities to install patches in the microcode. 
1. Write your microcode patch in `bios/ucode_patches/ucode_patch.u` (look at the other patches for examples)
2. Build the UEFI application
3. Execute `cpu.efi p` to install the patch at the address provided in `.org`.

Notice that in the microcode, only the addresses between 0x7c00 and 0x7e00 are writable and meaningful to patch.

Running `cpu.efi x`, it will also execute the microcode patched and print the `rax, rbx, rcx, rdx` registers as result.

### Match & Patch

To automatically execute microcode at certain CPU events or microcode points, `cpu` leverages the Match and Patch. 
It defines a microcode address to hook and the microcode address to jump to when the hook is triggered.

* `z`: resets all the match & patch.
* `h`: installs an hook, given an index (0-0x20), an address to hook (0-0x7c00) and a target address to execute (0x7c00-0x7e00).

### Tracing microcode

By installing multiple hooks and continuously executing an instruction, `cpu` is able to trace the microoperations performed by such an instruction, and dump them. To trace:

1. Write the instruction to be traced after the `// [TRACED INSTRUCTION HERE]` in `get_trace_clock_at()`.
2. Build the UEFI application.
3. Trace with: `cpu.efi m`.
It will create a `trace.txt` file that contains all the addresses that have been hit.
4. Execute `uasm-lib/uasm.py -t trace.txt > parsed_trace.txt`.
It will generate a full trace of the microcode executed during the instruction.

Notice that `uasm.py` will leverage the `ms_arrayX.txt` files in its folder to generate a disassembly of the microinstructions executed. These are for GLM with stepping 0x9 (cpuid 0x000506C9). Please generate the proper arrays in case you have a different stepping.
You can use the LDAT dump functionalities for this purpose.

### Secret memory dumpers

The CPU has different inaccessible buffers from the architecture, for which we provide routines to dump:
* `smm`: SMROM (or any other address while disabling SMM protection)
* `rom`: internal ROM
* `imms`: CPU hardcoded immediates
* `msrs`: internal MSRs configurations

### Writing microcode patches

We provide an assembler that generates header files to be compiled into the `cpu.efi` UEFI application.
Look into the provided patches in `bios/ucode_patches` for the syntax.
It supports simple operations and labels.
Assemble a microcode patch with `uasm.py -i ucode_patch.u -o ucode_patch.h`.
`cpu.efi` will be compiled and automatically include the microcode patch that you want to apply.

#### Example

file: `code_patch.u`
```
.org 0x7c00

rax:= ZEROEXT_DSZ32(0x00001337)
rbx:= ZEROEXT_DSZ32(0x00001337)
rcx:= ZEROEXT_DSZ32(0x00001337)
rdx:= ZEROEXT_DSZ32(0x00001337)
```

recompile, then run in the GLM:
```
cpu.efi z # zero out match & patch
cpu.efi p # apply the patch
cpu.efi h 0 0x0428 0x7c00 # rdrand entry point
```
now every time `rdrand` is executed, it will return `0x1337` in the registers.