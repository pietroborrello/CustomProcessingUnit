#!/usr/bin/env python3

from struct import pack, unpack
from Crypto.PublicKey.RSA import construct
from hashlib import sha256
import sys
from custom_sha import generate_hash

from uasm import uop_disassemble, process_seqword

def KSA(key):
    keylength = len(key)
    S = bytearray(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % keylength]) % 256
        S[i], S[j] = S[j], S[i]  # swap
    return S


def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # swap
        K = S[(S[i] + S[j]) % 256]
        yield K

def RC4(key):
    S = KSA(key)
    return PRGA(S)

def sha(b):
    h2 = sha256()
    h2.update(b)
    return h2.digest()

def ms_array_dump(array, size, file):
    str_line = ""
    for fast_addr in range(0, size):
        if fast_addr and fast_addr % 4 == 0:
            print("%04x: %s" % ((fast_addr // 4 - 1) * 4, str_line), file=file)
            str_line = ""
        val = array[fast_addr]
        str_line += " %012x" % val
    print("%04x: %s" % ((fast_addr // 4) * 4, str_line), file=file)

def parse_decrypted_ucode(ucode, output, description):
    print(f'[+] dumping parsed ucode to {output}')
    with open(f'{output}', 'w') as f:

        def fprint(s):
            print(s, file=f)

        i = 0
        # patch -> match
        current_patches = dict()
        current_raw_patches = list()
        fprint(description)
        fprint(f"UCODE:")
        while True:
            if ucode[i] == 0x0:
                fprint(f'[{i:04x}] END')
                i += 1
                return True

            if ucode[i] == 0x1:
                fprint(f'[{i:04x}] initialize arrays')
                i += 1

            elif ucode[i] == 0x2:
                addr = unpack("<H", ucode[i+1: i+3])[0]
                size = unpack("<H", ucode[i+3: i+5])[0]

                patch_off = i
                fprint(f'[{i:04x}] install addr: 0x{addr:04x} - size 0x{size:04x}')
                i += 5

                curr_seqword = 0
                uops = []
                seqwords = []
                for uop_idx in range(size):
                    value = unpack("<Q", ucode[i:i+8])[0]

                    # unpack sequence words from uop and build it
                    uop = value & 0xffffffffffff
                    partial_seqw = (value >> 48) & 0x3ff
                    curr_seqword = curr_seqword | (partial_seqw << ((uop_idx%3) * 10))

                    # fprint(f'    {uop:012x}')
                    uops.append(uop)
                    if uop_idx%3 == 2:
                        # fprint(f'      {curr_seqword:04x}')
                        uops.append(0)
                        seqwords.append(curr_seqword)
                        curr_seqword = 0
                    i += 8
                if uop_idx%3 != 2:
                    # fprint(f'      {curr_seqword:04x}')
                    uops.append(0)
                    seqwords.append(curr_seqword)

                for uop_idx,uop in enumerate(uops):

                    uaddr = uop_idx + addr
                    seqword = seqwords[uop_idx // 4]

                    if (uop_idx & 3 != 3):
                        disasm_uop         = uop_disassemble(uop, uaddr).strip()
                        disasm_seqw_before = process_seqword(uaddr, uop, seqword, True).strip()
                        disasm_seqw_after  = process_seqword(uaddr, uop, seqword, False).strip()
                        if uaddr in current_patches:
                            patch = uaddr
                            match = current_patches[patch]
                            fprint(f'  <match & patch: 0x{match:04x} -> 0x{patch:04x}>')
                        fprint(f'    [{uop:012x}] U{uaddr:04x}: {disasm_seqw_before} {disasm_uop} {disasm_seqw_after}')
                    else:
                        fprint(f'      [{seqword:08x}]')

                # save patch as file to be parsed
                print(f'{output.replace(".txt", f".patch_{patch_off:04x}.txt")}')
                with open(f'{output.replace(".txt", f".patch_{patch_off:04x}.txt")}', 'w') as patch_f:
                    patch_array = [0] * 0x40
                    for off, patch in enumerate(current_raw_patches):
                        if patch & 1:
                            patch_array[off] = patch & 0x3fffffff
                    ms_array_dump(patch_array,  0x40, patch_f)
                    ms_array_dump(uops + [0]*0x200, 0x200, patch_f)
                    ms_array_dump(seqwords + [0]*0x80, 0x80, patch_f)

            elif ucode[i] == 0x3:
                size = unpack("<H", ucode[i+1: i+3])[0]

                fprint(f'[{i:04x}] write match & patch - size: 0x{size:04x}')
                i += 3

                patches = []
                # patch -> match
                current_patches = dict()
                current_raw_patches = list()
                for _ in range(size):
                    value = unpack("<Q", ucode[i:i+8])[0]
                    patches.append(value)
                    # fprint(f'    {value:08x}')
                    i += 8
                for _raw_patch in patches:
                    def parse_patch(raw_patch):
                        mode = (raw_patch >> 24) & 0xff
                        match = raw_patch & 0xfffe
                        patch = 0x7c00 + ((raw_patch >> 16) & 0xff) * 2
                        current_patches[patch] = match
                        current_raw_patches.append(raw_patch)
                        return mode, match, patch
                    if _raw_patch & 1:
                        mode1, match1, patch1 = parse_patch(_raw_patch & 0x7fffffff)
                        mode2, match2, patch2 = parse_patch(_raw_patch >> 0x1f)
                        fprint(f'    [{_raw_patch:016x}] 0x{mode1:02x}: 0x{match1:04x} -> 0x{patch1:04x}, 0x{mode2:02x}: 0x{match2:04x} -> 0x{patch2:04x}')
                    else:
                        fprint(f'    [{_raw_patch:016x}]')

            elif ucode[i] == 0x5:
                size = unpack("<H", ucode[i+1: i+3])[0]
                fprint(f'[{i:04x}] write stgbuf - size: 0x{size:04x}')
                i += 3

                for _ in range(size):
                    addr = unpack("<H", ucode[i: i+2])[0]
                    and_mask = unpack("<Q", ucode[i+2: i+10])[0]
                    or_value = unpack("<Q", ucode[i+10: i+18])[0]

                    fprint(f'    stgbuf[0x{addr:04x}] = (stgbuf[0x{addr:04x}] & 0x{and_mask:016x}) | 0x{or_value:x}')
                    i += 18

            elif ucode[i] == 0x6:
                size = unpack("<H", ucode[i+1: i+3])[0]
                fprint(f'[{i:04x}] write crbus - size: 0x{size:04x}')
                i += 3

                for _ in range(size):
                    addr = unpack("<I", ucode[i: i+4])[0]
                    and_mask = unpack("<Q", ucode[i+4: i+12])[0]
                    or_value = unpack("<Q", ucode[i+12: i+20])[0]

                    fprint(f'    crbus[0x{addr:04x}] = (crbus[0x{addr:04x}] & 0x{and_mask:016x}) | 0x{or_value:x}')
                    i += 20

            elif ucode[i] == 0x7:
                size = unpack("<H", ucode[i+1: i+3])[0]
                fprint(f'[{i:04x}] write uram - size: 0x{size:04x}')
                i += 3

                for _ in range(size):
                    addr = unpack("<I", ucode[i: i+4])[0]
                    and_mask = unpack("<Q", ucode[i+4: i+12])[0]
                    or_value = unpack("<Q", ucode[i+12: i+20])[0]

                    fprint(f'    uram[0x{addr:04x}] = (uram[0x{addr:04x}] & 0x{and_mask:016x}) | 0x{or_value:x}')
                    i += 20

            elif ucode[i] == 0x8:
                size = unpack("<H", ucode[i+1: i+3])[0]
                fprint(f'[{i:04x}] write crbus with SYNC on crbus[0x289] - size: 0x{size:04x}')
                i += 3

                for _ in range(size):
                    addr = unpack("<I", ucode[i: i+4])[0]
                    and_mask = unpack("<Q", ucode[i+4: i+12])[0]
                    or_value = unpack("<Q", ucode[i+12: i+20])[0]

                    fprint(f'    crbus[0x{addr:04x}] = (crbus[0x{addr:04x}] & 0x{and_mask:016x}) | 0x{or_value:x}')
                    i += 20

            elif ucode[i] == 0x9:
                v1 = unpack("<B", ucode[i+1: i+2])[0]
                v2 = unpack("<I", ucode[i+2: i+6])[0]
                fprint(f'[{i:04x}] if (stgbuf[0x1a0] >> 32) & {v1:02x} skip to 0x{v2+i+6:04x}')
                i += 6

            elif ucode[i] == 0xa:
                addr = unpack("<H", ucode[i+1: i+3])[0]
                fprint(f'[{i:04x}] invoke addr: 0x{addr:04x}')
                i += 3

            elif ucode[i] == 0x0b:
                size = unpack("<H", ucode[i+1: i+3])[0]
                fprint(f'[{i:04x}] portout(0x40, 2) - size: 0x{size:04x}')
                i += 3

                for _ in range(size):
                    addr = unpack("<I", ucode[i: i+4])[0]
                    and_mask = unpack("<I", ucode[i+4: i+8])[0]
                    or_value = unpack("<I", ucode[i+8: i+12])[0]

                    fprint(f'    port[0x{addr:04x}] = (port[0x{addr:04x}] & 0x{and_mask:016x}) | 0x{or_value:x}')
                    i += 12

            elif ucode[i] == 0xc:
                v1 = unpack("<I", ucode[i+1: i+5])[0]
                v2 = unpack("<I", ucode[i+5: i+9])[0]
                fprint(f'[{i:04x}] if send_op_pcu_mailbox(0x1, 0x{v1:04x}) skip to 0x{v2+i+9:04x}')
                i += 9

            elif ucode[i] == 0x0d:
                fprint(f'[{i:04x}] send_op_pcu_mailbox(0xf, ??)')
                i += 1

            elif ucode[i] == 0x0e:
                fprint(f'[{i:04x}] portout(0x4910) END')
                i += 1

            elif ucode[i] == 0x0f:
                v1 = unpack("<H", ucode[i+1: i+3])[0]
                v2 = unpack("<H", ucode[i+3: i+5])[0]
                size = unpack("<H", ucode[i+5: i+7])[0]
                fprint(f'[{i:04x}] portout(0x4910, 0x{v1:02x}, 0x{v2:04x})')
                i += 7
                for _ in range(size):
                    value = unpack("<Q", ucode[i: i+8])[0]
                    fprint(f'    {value:016x}')
                    i += 8

            elif ucode[i] == 0x11:
                v1 = unpack("<B", ucode[i+1: i+2])[0]
                v2 = unpack("<I", ucode[i+2: i+6])[0]
                fprint(f'[{i:04x}] send_op_pcu_mailbox(0x{v1:02x}, 0x{v2:04x})')
                i += 6

            elif ucode[i] == 0x10:
                size = unpack("<H", ucode[i+1: i+3])[0]
                fprint(f'[{i:04x}] send_op_pcu_mailboxes - size: 0x{size:04x}')
                i += 3

                for _ in range(size):
                    v1 = unpack("<H", ucode[i: i+2])[0]
                    v2 = unpack("<I", ucode[i+2: i+6])[0]
                    v3 = unpack("<I", ucode[i+6: i+10])[0]

                    fprint(f'    send_op_pcu_mailbox(0x7, {v3:04x} | ({v2:04x} & send_op_pcu_mailbox(0x5, {v1:04x})))')
                    i += 10

            elif ucode[i] == 0x1c:
                val = unpack("<I", ucode[i+1: i+5])[0]
                fprint(f'[{i:04x}] if (uram[0x53] >> 2) & 1 skip to 0x{val+i+5:04x}')
                i += 5

            elif ucode[i] == 0x1d:
                val = unpack("<I", ucode[i+1: i+5])[0]
                fprint(f'[{i:04x}] if TESTUSTATE( , SYS, !0xc000) skip to 0x{val+i+5:04x}')
                i += 5

            elif ucode[i] == 0x1e:
                val = unpack("<I", ucode[i+1: i+5])[0]
                fprint(f'[{i:04x}] if TESTUSTATE( , SYS, !0x4000) skip to 0x{val+i+5:04x}')
                i += 5

            else:
                fprint(f'[-] unkown opcode 0x{ucode[i]:02x} at i=0x{i:04x} (routine at: 0x{0x226c + ucode[i]*4:04x})')
                return False


HEADER_OFF = 0x30
HEADER_SIZE = 0x80
EXTRA_HEADER_SIZE_OFF = 0x34
REV_OFF = 0x3c
VCN_OFF = 0x40
REL_DATE_OFF = 0x8
DATE_OFF = 0x48
SIZE_OFF = 0x4c
CPU_SIG_OFF = 0x54
SEED_OFF = 0x90
SEED_SIZE = 0x20
RSA_MOD_OFF = 0xb0
RSA_MOD_SIZE = 0x100
RSA_EXP_OFF = 0x1b0
RSA_EXP_SIZE = 0x4
RSA_SIG_OFF = 0x1b4
RSA_SIG_SIZE = 0x100
ENC_UCODE_OFF = 0x2b4

# parse and decrypt a ucode file, save it and decode in case of success
def parse_ucode_file(f_ucode):
    with open(f_ucode, 'rb') as f:
        ucode = bytearray(f.read())

    extra_header_size = unpack("<H", ucode[EXTRA_HEADER_SIZE_OFF:EXTRA_HEADER_SIZE_OFF+2])[0]
    cpu_signature = unpack("<I", ucode[CPU_SIG_OFF:CPU_SIG_OFF+4])[0]
    if (extra_header_size != 0xa1):
        print(f"""
[{f_ucode}]
    CPU: 0x{cpu_signature:x}
    extra_header_size: 0x{extra_header_size:x}
    [-] unsupported extra header size
""")
        return False

    ucode_patch_words = unpack("<I", ucode[SIZE_OFF:SIZE_OFF+4])[0]
    ucode_patch_size = ucode_patch_words * 4
    ucode_size = ucode_patch_size - (ENC_UCODE_OFF - HEADER_OFF)

    ucode_revision = unpack("<I", ucode[REV_OFF:REV_OFF+4])[0]
    ucode_version = unpack("<I", ucode[VCN_OFF:VCN_OFF+4])[0]
    ucode_release_date = unpack("<I", ucode[REL_DATE_OFF:REL_DATE_OFF+4])[0]
    ucode_date = unpack("<I", ucode[DATE_OFF:DATE_OFF+4])[0]
    ucode_seed = ucode[SEED_OFF:SEED_OFF+SEED_SIZE]

    rsa_modulus = int(bytearray(reversed(ucode[RSA_MOD_OFF:RSA_MOD_OFF+RSA_MOD_SIZE])).hex(), 16)
    rsa_exp = unpack("<I", ucode[RSA_EXP_OFF:RSA_EXP_OFF+RSA_EXP_SIZE])[0]

    rsa_sig = bytes(reversed(ucode[RSA_SIG_OFF:RSA_SIG_OFF+RSA_SIG_SIZE]))

    pubkey = construct((rsa_modulus, rsa_exp))
    plain_rsa_sig = pubkey.encrypt(rsa_sig, None)[0]
    desc = f"""
[{f_ucode}]
    CPU: 0x{cpu_signature:x}
    size: 0x{ucode_size:x}
    rev: 0x{ucode_revision:x}
    VCN: 0x{ucode_version:x}
    release date: {ucode_release_date & 0xffff :04x}-{(ucode_release_date >> 24) & 0xff :02x}-{(ucode_release_date >> 16) & 0xff :02x}
    compilation date: {(ucode_date >> 16) & 0xffff:04x}-{(ucode_date >> 8) & 0xff:02x}-{(ucode_date) & 0xff:02x}
    RC4 nonce: {ucode_seed.hex()}
    RSA mod: {hex(rsa_modulus)}
    RSA exp: {rsa_exp}
    RSA sig: {rsa_sig.hex()}
    plain sig: {plain_rsa_sig.hex()}
"""
    print(desc)
    GLM_secret = bytes.fromhex('0E 77 B2 9D 9E 91 76 5D A2 66 48 99 8B 68 13 AB')
    seed = GLM_secret + ucode_seed + GLM_secret
    print(f'    decryption seed: {seed.hex()}')

    rc4_key = b''
    h = seed
    for i in range(8):
        h = generate_hash(seed, padding=False, result_endianess='little', update=(i != 0))
        rc4_key += h

    keystream = RC4(rc4_key)

    # dump the first 0x200 bytes
    for k in range(0x200):
        next(keystream)
        pass

    decrypted = b''
    full_key = b''
    for b in ucode[ENC_UCODE_OFF: ENC_UCODE_OFF + ucode_size]:
        k = next(keystream)
        decrypted += bytes([b ^ k])
        full_key += bytes([k])


    decrypt_sha = bytes(reversed(sha(ucode[HEADER_OFF: HEADER_OFF + HEADER_SIZE] + decrypted)))

    if(decrypt_sha == plain_rsa_sig[-32:]):
        print('[+] decryption successful, signature matches')
        correct = True
    else:
        print('[-] decryption failed')
        correct = False
    
    if not correct:
        return False
    
    print(f'[+] dumping decrypted to {f_ucode}.dec')
    with open(f'{f_ucode}.dec', 'wb') as f:
        f.write(decrypted)

    # with open(f'{f_ucode}.key', 'wb') as f:
    #     f.write(full_key)

    # parse it
    parse_decrypted_ucode(decrypted, f'{f_ucode}.txt', desc)
    return True

if __name__ == '__main__':
    ucodes = sys.argv[1:]
    for f_ucode in ucodes:
        parse_ucode_file(f_ucode)