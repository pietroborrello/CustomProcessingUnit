## Ldat write
By reversing the ucode (0x1eb4 routine) we understood the right protocol to use with LDAT from the CPU Core.
This protocol is different than the one documented in the SVT helpers:

``` c
static void ldat_array_write(unsigned long pdat_reg, unsigned long array_sel, unsigned long bank_sel, unsigned long dword_idx, unsigned long fast_addr, unsigned long val) {
    crbus_write(pdat_reg + 1, 0x30000 | ((dword_idx & 0xf) << 12) | ((array_sel & 0xf) << 8) | (bank_sel & 0xf));
    crbus_write(pdat_reg, 0x000000 | (fast_addr & 0xffff));
    crbus_write(pdat_reg + 4, val & 0xffffffff);
    crbus_write(pdat_reg + 5, (val >> 32) & 0xffff);
    crbus_write(pdat_reg + 1, 0);
}
```
The SDAT command is 0x30000 and not 0x10000. Probably enables "async" writes? The PDAT command is 0x000000, not sure how to signal it for reads.
It first writes the selectors in the SDAT, then the address to the PDAT and finally the values to write in memory that trigger the LDAT write. The last 0 is for cleanup.

# ROM & RAM aliasing
ms_array0 (ucode rom) at address 0x7c00 aliases with ms_array4 (ucode patch ram) at address 0, with a custom mapping.
``` c
UINTN ucode_addr_to_patch_addr(UINTN addr) {
    UINTN base = addr - 0x7c00;
    // the last *4 does not make any sense but the CPU divides the address where
    // to write by four, still unkown reasons
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
```

**NOTICE**: any fourth address (0x3) is not writable.

# RAM instruction

All the ucode instructions in the patch ram, have a CRC value in bits 47 and 46, which is computed as follows:
```python
def get_even_bits(v):
    bits = f'{v:048b}'
    return [int(i) for i in bits[::2]]

def get_odd_bits(v):
    bits = f'{v:048b}'
    return [int(i) for i in bits[1::2]]

f_parity = lambda a,b: a^b
crc1 = reduce(f_parity, get_even_bits(uop))
crc2 = reduce(f_parity, get_odd_bits(uop))
uop |= (crc1 << 47)
uop |= (crc2 << 46)
```

I.E. bit 47 is the parity bit of bits in even position, while bit 46 is the parity bits for bits in odd position.

Also SEQUENCE_WORDS have the same parity bits in position 28 and 29.

# match/patch RAM

Every entry is in the form of `0x3e[patch:8][match:16]` the target is computed as `target = patch*2 + 0x7c00`. Last bit (bit 0) of match is always set and probably ignored.
Writing to the CRBUS to write on the match/patch, the address gets divided by 2.


# LDAT arrays
## 0x6a0 microcode sequencer:

0: ucode ROM

1: seqword ROM

2: seqword RAM

3: match & patch

4: ucode RAM

To read from the LDAT the MOVEFROMCREG_DSZ64 should have the m2 bit set

Before programming the PDAT to read, with command 0x10000 (0x30000 seems not working) we have to read the PDAT itself with a MOVEFROMCREG_DSZ64, and then can write to it.

# Staging buffer

The staging buffer (udbgrd 0x80) at address 0x7ac0 contains a copy of the ucode patch. From address 0xaac0 it contains a copy of the match&patch, but with only the lower 3 bytes matching. The upper bytes have unknown meaning.

# UEND
There is something strange while ending the instructions. Uften the microsequences end with a SEQW GOTO UEND, where UEND is the address:

```
uend:
U17ec: 125600000000    LFNCEWAIT-> unk_256() !m1
           022a9170                SEQW UEND0
```

It performs an unknown operation and then exits. The unknown operation seems fundamental, since if we replicate the uend without the unkown operation, we incur in a 59M cycles slowdown per instruction. 
Analysis of the perf counter shows 62 Machine clears, of which 60 are due to Self-Modifying-Code. It is unclear whether it is a bug in the UEFI application, since code there is actually writable.

Therefore all ucode patches should end with the sequence: `LFNCEWAIT-> unk_256() !m1 SEQW UEND0`. 
However while using the tracer, inserting the sequence seems to make it more unstable: i.e. it crashes on more operations. So we remove the `unk_256()` in the tracing ucode patch.

# EFLAGS
Every temporary register has its own arithmetic flags, that get updated when the register is used as a destination for arithmetic operations. The shape is:
```
+---+---+---+---+---+---+---+---+
| _ | _ | O | S | Z | _ | P | C |
|---+---+---+---+---+---+---+---+
| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
```

# UCODE UPDATE

Trigger the ucode update with `wrmsr(IA32_BIOS_UPDT_TRIG, (unsigned long)(_ucode_data+48))`.
Steps:

1. Compute SHA256 of the public key (`ucode[0xb0:0xb0 + 0x100]`) and compare it with `a1b4b7417f0fdcdb0feaa26eb5b78fb2cb86153f0ce98803f5cb84ae3a45901d`.
2. Check that the RSA exponent (`ucode[0x1b0:0x1b0 + 4]`) is 0x11.
3. TODO: It places the data for the ucode update at physical address 0xfeb00000, and loads the ucode update at 0xfeb01000. Can it be read?
4. Take the seed (`ucode[0x90:0x90 + 32]`) in the ucode update to generate the key
5. Generate the initial RC4 seed with `GLM_secret | ucode_seed | GLM_secret`, with `GLM_SECRET = 0E 77 B2 9D 9E 91 76 5D A2 66 48 99 8B 68 13 AB`, Ermolov here had scraped away the correct GLM secret from the released disasm.
6. Expand the RC4 seed to 256 bytes, by computing 8 times the SHA256 of the seed. The SHA computation here is non-standard, it does not uses the padding, and returns the results in little endian, i.e. it returns the internal state of SHA 256. Every result is the update of the state with always the seed, like it would be `seed * 8` in input. So `key[0:32] = sha256.start(seed).get_state(); key[32:64] = sha256.update(seed).get_state(); key[64:96] = sha256.update(seed).get_state(); ...`
7. Discard the first 0x200 bytes of the keystream
8. Decrypt `ucode[0x2b4: 0x2b4 + size]` with the remaining keystream. `size` is computed from `ucode[0x4c:0x4c+4] * 4 - 0x284`. 0x284 is the size from the beginning of the second header (which is the one passed to the CPU at 0x30) to the start of the ucode update encrypted part at 0x2b4.
9. Compute the sha256 of the decrypted ucode and the header `sha(ucode[0x30:0x30+0x80] + decrypted)`.
    `ucode[0x30:0x30+0x80]` contains among others:
        - microcode revision number (0x3c)
        - release date (0x48)
        - real len of the update (0x4c)
        - processor signature to which the update applied (0x54)
        - ucode seed (0x90)
        - more info: https://github.com/platomav/MCExtractor/wiki/Intel-Microcode-Extra-Undocumented-Header
    **Notice**: these fields are actually used before being verified, so may be vulnerable to something?
10. Check that the hash matches the value taken from the exponentiation of the signature (`ucode[0x1b4:0x1b4+0x100]`) to the RSA public key.
    Also check the padding from the resulting signature encryption.
11. Parse the ucode update. A ucode update is an interpreted language with different opcodes that send commands to the CPU to write different parts, like CRBUS, URAM, STGBUG, and Microcode Sequencer. They can also call the routines that they just wrote.

## ucode update buffer

The buffer on which the ucode update is temporary saved to be decrypted, and the address of temporary values computed during the update (as decryption keys) is controlled by CRBUS 0x51b.
For GLM the registers hold the value `0xfeb00000`, which is a physical address that is not mapped or known from the linux kernel. Reading from it always returns -1. To enable it set the last bit to 1.
For GLM the ucode update is saved and decrypted at `CRBUS[0x51b] + 0x1000 = 0xfeb01000`, while the decryption keys, and other temp variables are at `0xfeb00000`.

Accessing the `0xfeb00000` physical address when is not enabled takes ~90 clock cycles with rdtscp, and always returns -1, when it is enables it becomes faster, being accessed in ~30 clock cycles, near a L1 hit.
The two cores do not seem to share the content of the `0xfeb00000` memory area, writing from a core, the other core does not see the value updated, even if the `CRBUS[0x51b]` is enabled on both cores.
The `0xfeb00000` region is 256Kb in theory, but writing more than 64Kb of data makes it lose some of the data. Is there a replacement policy? The maximum hardcoded size of ucode update is 63Kb, maybe for this reason.

The `0xfeb00000` region is actually an alias to L2 cache when enabled. And the ucode data actually contends cache lines with normal processor usage, so that's why a ucode update invalidates and disables the caches while performing the update. Otherwise, we observed that using the cache while holding ucode data there may evict some of such data, and since they are not memory backed they are just lost. 
We also saw self evictions while reading the ucode data in case the caches are not invalidated before, so the state of the PLRU replacement policy still affects that buffer. 
We confirmed that the buffer is actually a cache buffer by timing an array stride that fills L2 before and after using the ucode buffer, that evicts our cache lines.

# strange ucode update opcode
The opcode 0x14 (routine 0x22bc) seems to start another update from the data in the `crbus[0x51b]` without checking again the public key. Like nested updates. It sets tmp13 carry flag that is checked in `gen_key_step` and jumps to `0x7c4` instead of `0x8c4`, which decrypts the update with different offsets (since no pubkey to check), and a custom key, and then continues to parse se original ucode buffer.
The custom key is read form `uram[0x46,0x47,0x48,0x2c]`.