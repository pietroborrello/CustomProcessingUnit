#!/usr/bin/env python3

import sys
import os
import click
import re
from functools import reduce

# some of the code is taken from https://github.com/chip-red-pill/uCodeDisasm
g_opcodes = {}
g_opcodes_to_id = {}
g_hard_imms = ()

g_idq_src_dst_mnem = (
 ("rax", "xmm0"),       # 0x20
 ("rcx", "xmm1"),       # 0x21
 ("rdx", "xmm2"),       # 0x22
 ("rbx", "xmm3"),       # 0x23
 ("rsp", "xmm4"),       # 0x24
 ("rbp", "xmm5"),       # 0x25
 ("rsi", "xmm6"),       # 0x26
 ("rdi", "xmm7"),       # 0x27
 ("r8", "xmm8"),        # 0x28
 ("r9", "xmm9"),        # 0x29
 ("r10", "xmm10"),      # 0x2a
 ("r11", "xmm11"),      # 0x2b
 ("r12", "xmm12"),      # 0x2c
 ("r13", "xmm13"),      # 0x2d
 ("r14", "xmm14"),      # 0x2e
 ("r15", "xmm15"),      # 0x2f
 ("tmp0", "mm0"),       # 0x30
 ("tmp1", "mm1"),       # 0x31
 ("tmp2", "mm2"),       # 0x32
 ("tmp3", "mm3"),       # 0x33
 ("tmp4", "mm4"),       # 0x34
 ("tmp5", "mm5"),       # 0x35
 ("tmp6", "mm6"),       # 0x36
 ("tmp7", "mm7"),       # 0x37
 ("tmp8", "tmm0"),      # 0x38
 ("tmp9", "tmm1"),      # 0x39
 ("tmp10", "tmm2"),     # 0x3a
 ("tmp11", "tmm3"),     # 0x3b
 ("tmp12", "tmm4"),     # 0x3c
 ("tmp13", "tmm5"),     # 0x3d
 ("tmp14", "tmm6"),     # 0x3e
 ("tmp15", "tmm7"))     # 0x3f

g_reg_to_id = {}
g_reg_to_id[''] = 0
for i, (reg, mreg) in enumerate(g_idq_src_dst_mnem):
    g_reg_to_id[reg] = 0x20 + i

g_src_mnem = (
 ("", ""),              # 0x00
 ("r64dst", "xmmdst"),  # 0x01
 ("r64src", "xmmsrc"),  # 0x02
 ("rdi", "xmm7"),       # 0x03
 ("r64base", ""),       # 0x04
 ("r64idx", ""),        # 0x05
 ("rdx", "xmm2"),       # 0x06
 ("rdx", "xmm2"),       # 0x07
 ("", ""),              # 0x08
 ("", ""),              # 0x09
 ("", ""),              # 0x0a
 ("", ""),              # 0x0b
 ("", ""),              # 0x0c
 ("", ""),              # 0x0d
 ("", ""),              # 0x0e
 ("", ""),              # 0x0f
 ("", ""),              # 0x10
 ("tmp2", "mm2"),       # 0x11
 ("tmp0", "mm0"),       # 0x12
 ("tmp7", "mm7"),       # 0x13
 ("tmpv0", "tmmv0"),    # 0x14
 ("tmpv1", "tmmv1"),    # 0x15
 ("tmpv2", "tmmv2"),    # 0x16
 ("tmpv3", "tmmv3"),    # 0x17
 ("", ""),              # 0x18
 ("", ""),              # 0x19
 ("", ""),              # 0x1a
 ("", ""),              # 0x1b
 ("", ""),              # 0x1c
 ("", ""),              # 0x1d
 ("", ""),              # 0x1e
 ("", ""))              # 0x1f
g_src_mnem += g_idq_src_dst_mnem

g_dst_mnem = (
 ("", ""),              # 0x00
 ("r64dst", "xmm2"),    # 0x01
 ("rax", "xmm0"),       # 0x02
 ("rdi", "xmm7"),       # 0x03
 ("rax", "xmm0"),       # 0x04
 ("rax", "xmm0"),       # 0x05
 ("rdx", "xmm2"),       # 0x06
 ("rdx", "xmm2"),       # 0x07
 ("tmp0", "mm0"),       # 0x08
 ("tmp7", "mm7"),       # 0x09
 ("tmp0", "mm0"),       # 0x0a
 ("tmp0", "mm0"),       # 0x0b
 ("tmp0", "mm0"),       # 0x0c
 ("tmp7", "mm7"),       # 0x0d
 ("tmp0", "mm0"),       # 0x0e
 ("tmp0", "mm0"),       # 0x0f
 ("", ""),              # 0x10
 ("tmp2", "mm2"),       # 0x11
 ("tmp0", "mm0"),       # 0x12
 ("tmp7", "mm7"),       # 0x13
 ("tmpv0", "tmmv0"),    # 0x14
 ("tmpv1", "tmmv1"),    # 0x15
 ("tmpv2", "tmmv2"),    # 0x16
 ("tmpv3", "tmmv3"),    # 0x17
 ("tmp0", "mm0"),       # 0x18
 ("tmp7", "mm7"),       # 0x19
 ("tmp0", "mm0"),       # 0x1a
 ("tmp0", "mm0"),       # 0x1b
 ("tmp0", "mm0"),       # 0x1c
 ("tmp7", "mm7"),       # 0x1d
 ("tmp0", "mm0"),       # 0x1e
 ("tmp0", "mm0"))       # 0x1f
g_dst_mnem += g_idq_src_dst_mnem

g_uop_lables = {}
g_uop_cregs = {}
g_uop_fscp_regs = {}
g_uop_ioregs = {}

def glm_ucode_disasm_init():
    global g_opcodes
    global g_opcodes_to_id
    g_opcodes = {}
    g_opcodes_to_id = {'NOP': 0}
    dir_path = os.path.dirname(os.path.realpath(__file__))
    fi = open(os.path.join(dir_path, "opcodes.txt"), "r")
    str_opcodes = fi.read()
    fi.close()
    for str_opcode in str_opcodes.split("\n"):
        opcode_mnem = str_opcode.split(":")
        if opcode_mnem[0] == "":
            assert(len(opcode_mnem) == 1)
            continue
        assert(len(opcode_mnem) == 2)
        g_opcodes[int(opcode_mnem[0], 16)] = opcode_mnem[1].strip()
        g_opcodes_to_id[opcode_mnem[1].strip()] = int(opcode_mnem[0], 16)
    
    global g_hard_imms
    g_hard_imms = []
    fi = open(os.path.join(dir_path, "hard_imm.txt"), "r")
    str_hard_imms = fi.read()
    fi.close()
    for str_hard_imm in str_hard_imms.split("\n"):
        str_hard_imm = str_hard_imm.strip()
        if len(str_hard_imm):
            g_hard_imms.append(int(str_hard_imm, 16))

def get_uop_opcode(uop):
    return (uop >> 32) & 0xfff

def get_src0_sel(uop):
    return uop & 0x3f

def get_src1_sel(uop):
    return (uop >> 6) & 0x3f

def get_dst_sel(uop):
    return (uop >> 12) & 0x3f

def is_src_imm_sel(sel):
    imm_sels = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, \
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]
    return sel in imm_sels

def get_uop_imm_sel(uop):
    src0_sel = get_src0_sel(uop)
    src1_sel = get_src1_sel(uop)
    assert(is_src_imm_sel(src0_sel) or is_src_imm_sel(src1_sel))
    imm_sel = src1_sel if is_src_imm_sel(src1_sel) else src0_sel
    return imm_sel

def is_uop_macro_imm(uop, is_special_imm = False):
    assert(is_special_imm or is_src_imm_sel(get_uop_imm_sel(uop)))
    special_opcodes = [0x00a, 0x00b, 0x00c, 0x00d, 0x00e, \
                       0x04a, \
                       0x4b4]
    opcode = get_uop_opcode(uop)
    return opcode not in special_opcodes and uop & 0x800000

def is_uop_lin_ldstad(uop):
    lin_ldstad_opcode_bits = [0xc00, 0xc03, 0xc08, 0xc09, 0xc0a,
                               0xd00, 0xd03, 0xd08, 0xd09, 0xd0a]
    opcode = get_uop_opcode(uop)
    return opcode & 0xf3f in lin_ldstad_opcode_bits

def is_uop_log_ldstad(uop):
    log_ldstad_opcode_bits = [0x81f, 0x83f,
                                  0xc10, 0xc13, 0xc18, 0xc19, 0xc1a,
                                  0xc30, 0xc33, 0xc38, 0xc39, 0xc3a,
                                  0xd10, 0xd13, 0xd18, 0xd19, 0xd1a]
    opcode = get_uop_opcode(uop)
    return (opcode & 0xf3f in log_ldstad_opcode_bits)

def is_uop_log_simd_ldstad(uop):
    log_simd_ldstad_opcodes = [0xc0e, 0xc2e, 0xc5e]
    opcode = get_uop_opcode(uop)
    return opcode in log_simd_ldstad_opcodes 

def is_uop_phys_ldstad(uop):
    ldstad_opcode_bits = [0xe00, 0xe08, 0xe0a, 0xe0d, \
                          0xe20, 0xe25, 0xe28, 0xe2a, 0xe2d, 0xe2e, \
                          0xe30, 0xe38, 0xe3a, \
                          0xf00, 0xf08, 0xf0a, 0xf20, 0xf28, 0xf2a]
    opcode = get_uop_opcode(uop)
    return opcode >= 0xe00 and opcode <= 0x1000 and opcode & 0xf3f in ldstad_opcode_bits

def is_uop_staging_buffer_ldstad(uop):
    staging_buffer_ldstad_opcodes = [0xe75, 0xe7d, 0xeae, 0xeee]
    
    opcode = get_uop_opcode(uop)
    return opcode in staging_buffer_ldstad_opcodes

def is_uop_phys_stg_buf_ldstad(uop):
    is_phys_ldstad = is_uop_phys_ldstad(uop) or is_uop_staging_buffer_ldstad(uop)
    return is_phys_ldstad

def is_uop_ldstad(uop):
    is_ldstad = is_uop_lin_ldstad(uop) or is_uop_log_simd_ldstad(uop) or \
                is_uop_log_ldstad(uop) or is_uop_phys_stg_buf_ldstad(uop)
    return is_ldstad

def is_uop_stad(uop):
    sta_opcode_bits = [0x08, 0x0d, 0x28, 0x2d, 0x2e, 0x18]
    opcode = get_uop_opcode(uop)
    return opcode >= 0xc00 and opcode <= 0x1000 and opcode & 0x1f in sta_opcode_bits

def is_uop_port_out(uop):
    opcode = get_uop_opcode(uop)
    return opcode & 0xf3f == 0xd0f

def is_uop_staging_buffer_stad(uop):
    opcode = get_uop_opcode(uop)
    staging_buffer_stad_opcodes = [0xe7d, 0xeae, 0xeee]
    return opcode in staging_buffer_stad_opcodes

def is_uop_dst_src2(uop):
    uop_dst_src2_test_funcs = [is_uop_stad, is_uop_port_out, is_uop_staging_buffer_stad]
    for test_func in uop_dst_src2_test_funcs:
        if test_func(uop):
            return True
    return False

def is_uop_common_special_imm(uop):
    common_special_imm_opcodes = [0x0fef]
    opcode = get_uop_opcode(uop)
    return opcode in common_special_imm_opcodes

def is_uop_alu(uop):
    alu_opcodes_gen = [0x000, 0x001, 0x004, 0x005, 0x006, 0x007, 0x008, \
                       0x014, 0x015, 0x016, 0x017, \
                       0x024, 0x025, 0x02c, 0x02d, 0x02e]
    opcode = get_uop_opcode(uop)
    return (opcode & 0xf3f) in alu_opcodes_gen

def is_uop_cmpujcc(uop):
    cmpujcc_opcodes = [0x86a, 0x86b, 0x928, 0x929]
    
    opcode = get_uop_opcode(uop)
    return opcode in cmpujcc_opcodes

def is_uop_creg_move_fromto(uop):
    creg_move_fromto_opcodes = [0x062, 0x042]
    opcode = get_uop_opcode(uop)
    return opcode in creg_move_fromto_opcodes

def is_uop_creg_xxx(uop):
    opcode = get_uop_opcode(uop)
    return opcode >= 0x800 and opcode <= 0xb00 and opcode & 0xff == opcode & 0xe2

def is_uop_xxx_uip_regovr(uop):
    xxx_uip_flgs_opcodes = [0x00c, 0x00d, 0x04c, 0x08c, 0x0cc, 0x108]
    opcode = get_uop_opcode(uop)
    return opcode in xxx_uip_flgs_opcodes

def is_uop_uram_rw(uop):
    uram_rw_opcodes = [0x043, 0x063]
    opcode = get_uop_opcode(uop)
    return opcode in uram_rw_opcodes

def is_uop_xxx_ustate(uop):
    xxx_ustate_opcodes = [0x000a, 0x000b, 0x004a]
    opcode = get_uop_opcode(uop)
    return opcode in xxx_ustate_opcodes

def is_uop_uflow_ctrl(uop):
    uflow_ctrl_opcodes = [0x0142]
    opcode = get_uop_opcode(uop)
    return opcode in uflow_ctrl_opcodes

def is_uop_rw_segfield(uop):
    rw_segfld_opcodes = [0xc4b, 0xc6b, 0xc7b]
    opcode = get_uop_opcode(uop)
    return opcode in rw_segfld_opcodes

def is_uop_aet_trace(uop):
    aet_trace_opcodes = [0x143]
    opcode = get_uop_opcode(uop)
    return opcode in aet_trace_opcodes

def is_uop_uret(uop):
    uret_opcodes = [0x148]
    opcode = get_uop_opcode(uop)
    return opcode in uret_opcodes

def is_uop_rw_ioport(uop):
    rwio_opcodes = [0xd0b, 0xd0f]
    opcode = get_uop_opcode(uop)
    return (opcode & 0xf3f) in rwio_opcodes

def get_str_uop_phys_stg_buf_ldstad_special_imms(uop, uaddr):
    str_special_imms = ()
    
    src0_sel = get_src0_sel(uop)
    src1_sel = get_src1_sel(uop)
    is_src0_imm = is_src_imm_sel(src0_sel)
    is_src1_imm = is_src_imm_sel(src1_sel)
    imm_sel = src0_sel if is_src0_imm else \
              src1_sel if is_src1_imm else 0
    is_stg_buf_uop = is_uop_staging_buffer_ldstad(uop)
    
    special_idx_case = imm_sel == 0x10 and not is_src0_imm and is_src1_imm
    if special_idx_case:
        str_special_imms += "tmp5",
    
    if is_uop_macro_imm(uop, True):
        str_special_imms += get_str_uop_macro_imm(uop, True),
    else:
        if imm_sel == 0x00 or special_idx_case: # sign extended byte imm
            special_imm = (uop & 0xff000000) >> 24
            special_imm |= 0xffffffffffffff00 if special_imm & 0x80 else 0
        elif is_stg_buf_uop:
            special_imm = ((imm_sel & 0x07) << 13) | ((uop & 0x7c0000) >> 10) | \
                          ((uop & 0xff000000) >> 24)
        else:
            special_imm = ((imm_sel & 0x10) << 7) | ((imm_sel & 0x07) << 8) | \
                          ((uop & 0xff000000) >> 24)
        
        allow_zero_imm = src0_sel == 0x00 and src1_sel != 0x00
        if special_imm or allow_zero_imm:
            str_special_imms += ("0x%016x" if special_imm >= 0x100000000 else "0x%08x") % special_imm,
    
    if not is_stg_buf_uop:
        mode = (uop & 0x7c0000) >> 18
        if mode != 0:
            str_special_imms += "mode=0x%02x" % mode,
    
    return str_special_imms

def get_str_uop_lin_ldstad_special_imms(uop, uop_addr):
    str_special_imms = get_str_uop_phys_stg_buf_ldstad_special_imms(uop, uop_addr)
    return str_special_imms

def get_str_uop_log_ldstad_special_imms(uop, uop_addr):
    str_special_imms = ()
    
    str_segs = ["DS", "DS", "", "SS"]
    seg_sel = (uop & 0x003000000000) >> 36
    str_seg = str_segs[seg_sel]
    assert(str_seg != "")
    str_special_imms += str_seg, "$"
    
    str_special_imms += get_str_uop_phys_stg_buf_ldstad_special_imms(uop, uop_addr)
    return str_special_imms

def get_str_uop_cmpujcc_special_imms(uop, uaddr):
    src1_sel = get_src1_sel(uop)
    
    first_imm = 0
    if is_src_imm_sel(src1_sel) and src1_sel != 0x10:
        first_imm = ((src1_sel & 0x10) << 1) | ((src1_sel & 0x07) << 2) | ((uop & 0xc00000) >> 22)
    
    if src1_sel == 0x10:
        hard_imm_idx = ((uop & 0xc0000) >> 10) | ((uop & 0xff000000) >> 24)
        assert(hard_imm_idx <= len(g_hard_imms))
        hard_imm = g_hard_imms[hard_imm_idx] & 0x7ff
        first_imm = hard_imm >> 15
        second_imm = (hard_imm & 0x7fff) | 0x20
    else:
        second_imm = ((uop & 0x10000) >> 2) | ((uop & 0x100000000000) >> 31) | ((uop & 0x200000000000) >> 33) | \
                     ((uop & 0x3c0000) >> 10) | ((uop & 0xff000000) >> 24)
    
    str_special_imms = ()
    if src1_sel == 0 or is_src_imm_sel(src1_sel):
       str_special_imms += "0x%08x" % first_imm,
    str_special_imms += get_str_uaddr(second_imm),
    return str_special_imms

def get_str_uop_creg_move_fromto_special_imms(uop, uaddr):
    src0_sel = get_src0_sel(uop)
    src1_sel = get_src1_sel(uop)
    is_src0_imm = is_src_imm_sel(src0_sel)
    is_src1_imm = is_src_imm_sel(src1_sel)
    imm_sel = src1_sel if is_src1_imm else \
              src0_sel if is_src0_imm else 0
    
    str_macro_imm = ""
    is_macro_imm = False
    special_imm = 0
    if imm_sel:
        if is_uop_macro_imm(uop):
            str_macro_imm = get_str_uop_macro_imm(uop),
            is_macro_imm = True
        elif imm_sel == 0x10:
            hard_imm_idx = ((uop & 0xc0000) >> 10) | ((uop & 0xff000000) >> 24)
            assert(hard_imm_idx <= len(g_hard_imms))
            special_imm = g_hard_imms[hard_imm_idx] & 0x7ff
        else:
            special_imm |= ((imm_sel & 0x07) << 13) | ((uop & 0x7c0000) >> 10) | ((uop & 0xff000000) >> 24)
    
    str_special_imms = ()
    
    opcode = get_uop_opcode(uop)
    if opcode == 0x042 and (src0_sel == 0 or is_src0_imm):
        if is_src0_imm and is_macro_imm:
            str_special_imms += str_macro_imm,
        else:
            data_imm = special_imm if src0_sel else 0
            str_special_imms += "0x%08x" % data_imm,
    
    if is_src1_imm or src1_sel == 0:
        if is_macro_imm:
            str_special_imms += str_macro_imm,
        else:
            creg_imm = special_imm if is_src1_imm else 0
            str_special_imms += get_str_creg(creg_imm & 0x7ff),
            mode_imm = (creg_imm >> 11) & 0xf
            assert(mode_imm == 0 or mode_imm == 0x04)
            if mode_imm == 0x04:
                str_special_imms += "32",
    
    return str_special_imms

def get_str_uop_creg_xxx_special_imms(uop, uaddr):
    src1_sel = get_src1_sel(uop)
    
    if src1_sel == 0x10:
        hard_imm_idx = ((uop & 0xc0000) >> 10) | ((uop & 0xff000000) >> 24)
        assert(hard_imm_idx <= len(g_hard_imms))
        second_imm = g_hard_imms[hard_imm_idx] & 0x7ff
    else:
        second_imm = ((uop & 0x1c0000) >> 10) | ((uop & 0xff000000) >> 24)
    
    first_imm = 0
    if is_src_imm_sel(src1_sel):
        first_imm = ((src1_sel & 0x10) << 1) | ((src1_sel & 0x07) << 2) | ((uop & 0xc00000) >> 22)
    
    str_special_imms = ()
    if first_imm:
        str_special_imms += "0x%08x" % first_imm,
    assert(second_imm < 0x800)
    str_special_imms += get_str_creg(second_imm),
    return str_special_imms

def get_str_uop_xxx_uip_regovr_special_imms(uop, uaddr):
    opcode = get_uop_opcode(uop)
    src0_sel =  get_src0_sel(uop)
    src1_sel =  get_src1_sel(uop)
    dst_sel = get_dst_sel(uop)
    is_src0_imm = is_src_imm_sel(src0_sel)
    is_src1_imm = is_src_imm_sel(src1_sel)
    imm_sel = src1_sel if is_src0_imm and is_src1_imm else \
              src0_sel if is_src0_imm else 0
    
    first_imm = (uop & 0x800000) >> 23
    str_special_imms = "0x%02x" % first_imm,
    
    # assert(opcode != 0x108 or src0_sel == 0x10)
    if opcode == 0x108: # READUIP
        return str_special_imms
    
    second_imm = ((src1_sel & 0x07) << 13) | ((uop & 0x7c0000) >> 10) | ((uop & 0xff000000) >> 24)
    if opcode & 0xf3f == 0x00c: # SAVEUIP
        str_special_imms += get_str_uaddr(second_imm),
    else:
        next_uaddr = uaddr + (2 if uaddr & 0x03 == 0x02 else 1)
        str_special_imms += get_str_uaddr(next_uaddr),
        str_special_imms += "0x%04x" % second_imm,
    
    is_third_imm = imm_sel != 0 and ((imm_sel & 0x07) != (src1_sel & 0x07) or (imm_sel & 0xfff0) != 0)
    if dst_sel != 0 and is_third_imm:
        str_special_imms += get_str_uop_common_imm(uop, imm_sel),
    
    return str_special_imms

def get_str_uop_uram_rw_special_imms(uop, uaddr):
    src0_sel =  get_src0_sel(uop)
    src1_sel =  get_src1_sel(uop)
    is_src0_imm = is_src_imm_sel(src0_sel)
    is_src1_imm = is_src_imm_sel(src1_sel)
    imm_sel = src1_sel if is_src1_imm else \
              src0_sel if is_src0_imm else 0
    
    special_imm = 0
    if imm_sel == 0x10:
        hard_imm_idx = ((uop & 0xc0000) >> 10) | ((uop & 0xff000000) >> 24)
        assert(hard_imm_idx <= len(g_hard_imms))
        special_imm = g_hard_imms[hard_imm_idx] & 0x7ff
    else:
        special_imm = 0xffffffffffff0000 if imm_sel & 0x10 else 0
        special_imm |= ((imm_sel & 0x07) << 13) | ((uop & 0x7c0000) >> 10) | ((uop & 0xff000000) >> 24)
    
    str_special_imms = ()
    
    opcode = get_uop_opcode(uop)
    is_write_uop = opcode == 0x043
    if not src0_sel and is_write_uop:
        str_special_imms += "0x%08x" % 0x00000000,
    
    if is_src0_imm and (not is_src1_imm or src0_sel != 0x10):
        first_imm = special_imm
        str_special_imms += ("0x%016x" if first_imm >= 0x100000000 else "0x%08x") % first_imm,
    
    if is_src1_imm:
        second_imm = special_imm & 0x1ff
        third_imm = 32 if (special_imm & 0x200) == 0x200 else 64
        str_special_imms += get_str_uram_addr(second_imm),
        str_special_imms += "%d" % third_imm,
    
    return str_special_imms

g_str_ustates = {
    0: "UCODE", \
    1: "SYS", \
    2: "VMX"};

g_str_ustate_bits = (
    {
        0x0001: "UST_MSLOOPCTR_NONZERO" \
    }, \
    {
        0x0001: "UST_VMX_DIS", \
        0x0002: "UST_USER_MODE", \
        0x0004: "UST_8086_MODE", \
        0x0008: "UST_OP_SIZE_32BIT", \
        0x0010: "UST_ADDR_SIZE_64BIT", \
        0x0020: "UST_SMM", \
        0x0040: "UST_VMX_DUAL_MON", \
        0x0080: "UST_VMX_GUEST", \
        0x0100: "UST_VMX_OP_DIS" \
    }, \
    {})

def get_str_uop_xxx_ustate_special_imms(uop, uaddr):
    src0_sel =  get_src0_sel(uop)
    src1_sel =  get_src1_sel(uop)
    is_src0_imm = is_src_imm_sel(src0_sel)
    is_src1_imm = is_src_imm_sel(src1_sel)
    assert((not is_src0_imm or src0_sel == src1_sel) and \
            is_src1_imm and src1_sel != 0x10)
    
    opcode = get_uop_opcode(uop)
    
    special_imm = ((src1_sel & 0x07) << 13) | ((uop & 0x7c0000) >> 10) | ((uop & 0xff000000) >> 24)
    mode_not = (uop & 0x800000) >> 23
    
    str_special_imms = ()
    if is_src0_imm:
        str_special_imms += "0x%08x" % special_imm,
    
    str_special_imms = ()
    is_test_ustate = opcode == 0x00a or opcode == 0x04a
    
    if is_test_ustate:
        ustate_idx = (uop & 0x300000000000) >> 44
        str_state_bits = ""
        for bit_idx in range(0x10):
            bit_val = 1 << bit_idx
            if special_imm & bit_val:
                assert(ustate_idx < len(g_str_ustate_bits))
                if bit_val in g_str_ustate_bits[ustate_idx]:
                    str_state_bits +=  g_str_ustate_bits[ustate_idx][bit_val] + " | "
                    special_imm &= ~bit_val
        str_state_bits = str_state_bits.rstrip(" |")
        if special_imm != 0:
            if str_state_bits != "":
                str_state_bits += " | "
            str_state_bits += "0x%04x" % special_imm
        
        assert(ustate_idx < len(g_str_ustates))
        str_special_imms += g_str_ustates[ustate_idx],
        not_prefix = "!" if mode_not else ""
        str_special_imms += not_prefix + str_state_bits,
    else:
        assert(opcode == 0x00b)
        special_imm = (special_imm & 0x3f) << 2
        not_prefix = "!" if mode_not else ""
        str_special_imms += not_prefix + "0x%02x" % special_imm,
    
    return str_special_imms

g_str_uflow_ctrl_tgt = { \
    0x01: "UNK", \
    0x0a: "URET0", \
    0x0b: "URET1", \
    0x0d: "LDAT_IN", \
    0x0e: "MSLOOPCTR", \
    0x0f: "USTATE"}

def get_str_uop_uflow_ctrl_special_imms(uop, addr):
    src0_sel =  get_src0_sel(uop)
    src1_sel =  get_src1_sel(uop)
    is_src0_imm = is_src_imm_sel(src0_sel)
    is_src1_imm = is_src_imm_sel(src1_sel)
    assert(not is_src0_imm and not is_src1_imm)
    
    special_imm = (uop & 0x0f000000) >> 24
    assert(special_imm in g_str_uflow_ctrl_tgt)
    return "$", g_str_uflow_ctrl_tgt[special_imm], "$"

g_str_seg_field_ids = { \
    0x0: "LIMIT_VAL", \
    0x2: "BASE", \
    0x4: "FLGS", \
    0x6: "LIMIT", \
    0x8: "SEL", \
    0xa: "SEL+FLGS+LIM", \
    0xc: "UNK_FLD_0c", \
    0xe: "UNK_FLD_0e"}

g_str_segs = { \
    0x00: "DS_32bit", \
    0x02: "CS", \
    0x03: "SS", \
    0x04: "UNK_SEG_04", \
    0x05: "DS_16bit", \
    0x06: "GDT", \
    0x07: "LDT", \
    0x08: "ES", \
    0x09: "UNK_SEG_09", \
    0x0a: "SS_USERM", \
    0x0b: "DS", \
    0x0c: "FS", \
    0x0d: "GS", \
    0x0e: "IDT", \
    0x0f: "TSS", \
    0x10: "UNK_SEG_10", \
    0x11: "UNK_SEG_11", \
    0x18: "SS_KERNM", \
    0x19: "DS_KERNM", \
    0x1b: "UNK_SEG_1b", \
    0x1c: "SEG_V0"}

def get_str_uop_rw_segfield_special_imms(uop, addr):
    src0_sel =  get_src0_sel(uop)
    opcode = get_uop_opcode(uop)
    special_imm = ((uop & 0x7c0000) >> 10) | ((uop & 0xff000000) >> 24)
    
    is_write_uop = opcode & 0x020
    seg_sel = special_imm & 0x0f if is_write_uop else ((special_imm & 0x1f00) >> 8)
    fld_sel = (special_imm & 0xf0) >> 4
    is_special_mode = uop & 0x800000 | uop & 0x300000000000
    is_multi_flds_write = is_write_uop and (fld_sel in (0x3, 0xb))
    
    assert(is_special_mode or is_multi_flds_write or \
           (seg_sel in g_str_segs and fld_sel in g_str_seg_field_ids))
    
    str_special_imms = ()
    if is_write_uop and src0_sel == 0:
        str_special_imms += "0x%08x" % 0x00000000,
    
    if not is_special_mode and not is_multi_flds_write:
        str_special_imms += g_str_segs[seg_sel],
        str_special_imms += g_str_seg_field_ids[fld_sel],
    else:
        assert(is_write_uop)
    return str_special_imms

def get_str_uop_aet_trace_special_imms(uop, addr):
    src0_sel = get_src0_sel(uop)
    dst_sel = get_dst_sel(uop)
    
    str_special_imms = ()
    
    first_imm = (uop & 0x003c0000) >> 18
    
    if (dst_sel != 0 and src0_sel == 0):
        str_special_imms += "0x%08x" % 0x00000000, "0x%02x" % first_imm, "$"
    else:
        str_special_imms = "$", "0x%02x" % first_imm, "$"
    
    if is_uop_macro_imm(uop, True):
        str_special_imms += get_str_uop_macro_imm(uop),
    
    return str_special_imms

def get_str_uop_uret_special_imms(uop, uaddr):
    src0_sel = get_src0_sel(uop)
    is_src0_imm = is_src_imm_sel(src0_sel)
    src1_sel = get_src1_sel(uop)
    assert(src1_sel == 0x00)
    
    str_special_imms = ()
    if is_src0_imm:
        str_special_imms += get_str_uop_common_imm(uop, get_uop_imm_sel(uop)),
    
    uret_idx = (uop & 0x000000800000) >> 23
    str_special_imms += "0x%02x" % uret_idx,
    return str_special_imms

def get_str_uop_rw_ioport_special_imms(uop, uaddr):
    src0_sel = get_src0_sel(uop)
    src1_sel = get_src1_sel(uop)
    is_src0_imm = is_src_imm_sel(src0_sel)
    is_src1_imm = is_src_imm_sel(src1_sel)
    assert(not is_src1_imm)
    
    str_special_imms = ()
    if is_src0_imm:
        assert((src0_sel & 0x10) == 0)
        special_imm = ((src0_sel & 0x07) << 13) | ((uop & 0x7c0000) >> 10) | ((uop & 0xff000000) >> 24)
        str_special_imms += get_str_ioreg(special_imm), "$"
    
    return str_special_imms

def get_str_uop_common_special_imms(uop, uaddr):
    special_imm = (uop & 0xff000000) >> 24
    str_special_imms = "0x%08x" % special_imm,
    return str_special_imms

g_uop_special_imms_process_funcs = ( \
    (is_uop_phys_stg_buf_ldstad, get_str_uop_phys_stg_buf_ldstad_special_imms), \
    (is_uop_lin_ldstad, get_str_uop_lin_ldstad_special_imms), \
    (is_uop_log_ldstad, get_str_uop_log_ldstad_special_imms), \
    (is_uop_cmpujcc, get_str_uop_cmpujcc_special_imms), \
    (is_uop_creg_move_fromto, get_str_uop_creg_move_fromto_special_imms), \
    (is_uop_creg_xxx, get_str_uop_creg_xxx_special_imms), \
    (is_uop_xxx_uip_regovr, get_str_uop_xxx_uip_regovr_special_imms), \
    (is_uop_uram_rw, get_str_uop_uram_rw_special_imms), \
    (is_uop_xxx_ustate, get_str_uop_xxx_ustate_special_imms), \
    (is_uop_uflow_ctrl, get_str_uop_uflow_ctrl_special_imms), \
    (is_uop_rw_segfield, get_str_uop_rw_segfield_special_imms), \
    (is_uop_aet_trace, get_str_uop_aet_trace_special_imms), \
    (is_uop_uret, get_str_uop_uret_special_imms), \
    (is_uop_rw_ioport, get_str_uop_rw_ioport_special_imms), \
    (is_uop_common_special_imm, get_str_uop_common_special_imms))

def is_uop_special_imms(uop):
    for proc_funcs in g_uop_special_imms_process_funcs:
        if proc_funcs[0](uop):
            return True
    return False

def get_str_uop_special_imms(uop, uaddr):
    for proc_funcs in g_uop_special_imms_process_funcs:
        if proc_funcs[0](uop):
            return proc_funcs[1](uop, uaddr)
    assert(False)

def get_str_uop_macro_imm(uop, is_special_imm = False):
    assert(is_uop_macro_imm(uop, is_special_imm))
    if not is_special_imm:
        imm_sel = get_uop_imm_sel(uop)
    macro_imm_sel = (uop & 0xff000000) >> 24
    if macro_imm_sel == 0x00:
        if is_uop_log_ldstad(uop):
            return "IMM_MACRO_ALIAS_DISPLACEMENT"
        else:
            return "IMM_MACRO_ALIAS_IMMEDIATE"
    elif macro_imm_sel == 0x04:
        return "IMM_MACRO_ALIAS_RIP"
    elif macro_imm_sel == 0x05:
        return "IMM_MACRO_ALIAS_STi"
    elif macro_imm_sel == 0x08:
        return "IMM_MACRO_ALIAS_MSLOOPCTR"
    elif macro_imm_sel == 0x0b:
        return "IMM_MACRO_ALIAS_DATASIZE"
    elif macro_imm_sel == 0x10:
        return "IMM_MACRO_ALIAS_INSTRUCTION"
    return "IMM_MACRO_%02x" % macro_imm_sel

def get_str_uop_common_imm(uop, imm_sel):
    if imm_sel == 0x10: # hardcoded imm
        hard_imm_idx = ((uop & 0xc0000) >> 10) | ((uop & 0xff000000) >> 24)
        assert(hard_imm_idx <= len(g_hard_imms))
        imm = g_hard_imms[hard_imm_idx]
    else: # word imm
        imm = 0xffffffffffff0000 if imm_sel & 0x10 else 0
        imm |= ((imm_sel & 0x07) << 13) | ((uop & 0x7c0000) >> 10) | ((uop & 0xff000000) >> 24)
    
    if is_uop_uaddr_imm(uop):
        assert(imm_sel in range(0x08, 0x10))
        str_imm = get_str_uaddr(imm)
    else:
        str_imm = ("0x%016x" if imm >= 0x100000000 else "0x%08x") % imm 
    return str_imm

def get_str_uop_imm(uop):
    if is_uop_macro_imm(uop):
        return get_str_uop_macro_imm(uop)
    imm_sel = get_uop_imm_sel(uop)
    return get_str_uop_common_imm(uop, imm_sel)

def get_src_mnem(sel, is_xmm):
    assert((sel & ~((1 << 6) - 1)) == 0)
    assert(sel < len(g_src_mnem))
    str_mnem = g_src_mnem[sel][0 if not is_xmm else 1]
    assert(str_mnem != "")
    return str_mnem

def get_dst_mnem(sel, is_xmm):
    assert((sel & ~((1 << 6) - 1)) == 0)
    assert(sel < len(g_dst_mnem))
    str_mnem = g_dst_mnem[sel][0 if not is_xmm else 1]
    assert(str_mnem != "")
    return str_mnem

def get_idq_src_dst_mnem(sel, is_xmm):
    assert((sel & ~((1 << 5) - 1)) == 0)
    assert(sel < len(g_idq_src_dst_mnem))
    str_mnem = g_idq_src_dst_mnem[sel][0 if not is_xmm else 1]
    assert(str_mnem != "")
    return str_mnem

def is_uop_mmxmm(uop):
    opcode = get_uop_opcode(uop)
    non_mmxmm_opcodes = [0x52b, 0x608, 0x646, 0x685, 0x68a, 0x6a0, 0x6ed,
                         0x720, 0x722, 0x723, 0x7b8, 0x7ed]
    mmxmm_opcodes = [0xcfe, 0xeae, 0xeee]
    if opcode in non_mmxmm_opcodes:
        return False
    if opcode >= 0x400 and opcode < 0x800:
        return True
    return opcode in mmxmm_opcodes

def is_mmxmm_uop_src_mmxmm(uop):
    assert(is_uop_mmxmm(uop))
    opcode = get_uop_opcode(uop)
    non_mmxmm_src_opcodes = [0x705, 0x716, 0x745]
    return opcode not in non_mmxmm_src_opcodes

def is_mmxmm_uop_dst_mmxmm(uop):
    assert(is_uop_mmxmm(uop))
    opcode = get_uop_opcode(uop)
    non_mmxmm_dst_opcodes = [0x72c, 0x72d]
    return (opcode & 0xfbf) not in non_mmxmm_dst_opcodes

def is_uop_two_src(uop):
    two_src_opcodes = [0x000, 0x001, 0x004, 0x005, 0x006, 0x007,
                        0x014, 0x015, 0x016, 0x017, 0x021, 0x024, 0x025, 0x02c, 0x02d, 0x02e,
                        0x030, 0x031, 0x032, 0x033, 0x034, 0x035, 0x036, 0x037,
                        0x130, 0x131, 0x132, 0x133, 0x134, 0x135, 0x136, 0x137,
                        0x230, 0x231, 0x232, 0x233, 0x234, 0x235, 0x236, 0x237,
                        0x330, 0x331, 0x332, 0x333, 0x334, 0x335, 0x336, 0x337]
    
    opcode = get_uop_opcode(uop)
    return opcode in two_src_opcodes or (opcode & 0xf3f) in two_src_opcodes

def is_uop_uaddr_imm(uop):
    opcode = get_uop_opcode(uop)
    ujmpcc_opcodes = [0x050, 0x051, 0x052, 0x053]
    other_opcodes = [0x15d, 0x15f]
    return (opcode & 0x0ff) in ujmpcc_opcodes or opcode in other_opcodes

def is_uop_testustate(uop):
    opcode = get_uop_opcode(uop)
    return (opcode & 0xf3f) == 0x00a

def get_str_uaddr(uaddr):
    if uaddr in g_uop_lables:
        return g_uop_lables[uaddr]
    return "U%04x" % uaddr

def get_str_creg(creg):
    if creg in g_uop_cregs:
        return g_uop_cregs[creg]
    return "0x%03x" % creg

def get_str_uram_addr(uram_addr):
    if uram_addr in g_uop_fscp_regs:
        return g_uop_fscp_regs[uram_addr]
    return "0x%04x" % uram_addr

def get_str_ioreg(ioreg):
    if ioreg in g_uop_ioregs:
        return g_uop_ioregs[ioreg]
    return "0x%04x" % ioreg

def uop_disassemble(uop, uaddr):
    src0_sel = get_src0_sel(uop)
    src1_sel = get_src1_sel(uop)
    dst_sel = get_dst_sel(uop)

    m0 = extract_bits(uop, 23, 24)
    m1 = extract_bits(uop, 44, 45)
    m2 = extract_bits(uop, 45, 46)
    
    is_src0 = src0_sel != 0x00
    is_src1 = src1_sel != 0x00
    is_src2 = is_uop_dst_src2(uop)
    is_dst = not is_src2 and dst_sel != 0x00 and dst_sel != 0x10
    
    is_src0_imm = is_src_imm_sel(src0_sel)
    is_src1_imm = is_src_imm_sel(src1_sel)
    assert(is_src0 or not is_src0_imm and is_src1 or not is_src1_imm)
    is_special_imms = is_uop_special_imms(uop)
    
    opcode = get_uop_opcode(uop)
    is_src_xmm = not is_uop_ldstad(uop) and is_uop_mmxmm(uop) and is_mmxmm_uop_src_mmxmm(uop)
    is_dst_xmm = is_uop_mmxmm(uop) and is_mmxmm_uop_dst_mmxmm(uop)
    
    str_src0 = ""
    str_src1 = ""
    str_src2 = ""
    str_dst = ""
    if is_src0 and not is_src0_imm:
        str_src0 = get_src_mnem(src0_sel, is_src_xmm)
    if is_src1 and not is_src1_imm:
        str_src1 = get_src_mnem(src1_sel, is_src_xmm)
    if is_src2:
        str_src2 = get_dst_mnem(dst_sel, is_dst_xmm) if dst_sel else "0x%08x" % 0
    elif is_dst:
        str_dst = get_dst_mnem(dst_sel, is_dst_xmm)
    
    str_imms = ""
    zero_imm = "0x%08x" % 0
    if is_special_imms:
        str_imms = ", ".join(get_str_uop_special_imms(uop, uaddr))
    elif is_src1_imm:
        str_src1 = get_str_uop_imm(uop)
    elif is_src0_imm:
        str_src0 = get_str_uop_imm(uop)
    # elif not is_src0 and not is_src1:
    #     str_imms = zero_imm
    
    if not is_src0 and is_src1 and is_uop_two_src(uop):
        assert(not is_special_imms)
        str_src0 = zero_imm
    elif not is_src0 and is_src1:
        # signal the case where the input is in source1
        # assert(not is_special_imms)
        str_src0 = " "
    if not is_src1 and is_src2:
        str_src1 = " "

    str_imms = re.split("\$\, |\, \$\, |\, \$", str_imms)
    str_imms_first = str_imms[0] if len(str_imms) > 0 else ""
    str_imms_second = str_imms[1] if len(str_imms) > 1 else ""
    str_imms_last = str_imms[2] if len(str_imms) > 2 else ""
    str_srcs_list = [str_src0, str_imms_first, str_src1, str_imms_second, str_src2, str_imms_last]
    str_non_empty_srcs_list = [str_src for str_src in str_srcs_list if str_src != ""]
    str_srcs = ", ".join(str_non_empty_srcs_list)
    
    is_nop = False
    if (opcode == 0 or opcode == 8) and not is_src0 and not is_src1 and not is_dst:
        str_opcode_mnem = "NOP"
        is_nop = True
    elif opcode in g_opcodes:
        str_opcode_mnem = g_opcodes[opcode]
    else:
        str_opcode_mnem = "unk_%03x" % opcode
    
    is_special_mode1 = uop & 0x300000000000 == 0x100000000000
    if (is_uop_alu(uop) or is_uop_ldstad(uop)) and is_special_mode1:
        repl_dsz_mnem = r"DSZ\1N" if opcode & 0xf3f == 0x008 else "DSZN"
        str_opcode_mnem = re.sub("DSZ(8|16|32|64)", repl_dsz_mnem, str_opcode_mnem)
    
    str_uop = str_dst + ":= " if is_dst else ""
    str_uop += str_opcode_mnem
    str_uop += "(" + str_srcs + ")" if not is_nop else ""

    m_str = ','.join(s for m,s in [(m0, 'm0'), (m1, 'm1'), (m2, 'm2')] if m)
    if m_str:
        str_uop += (' !' + m_str)

    return str_uop

def idq_entry_disassemble(addr, idq_uop, idq_imm):
    opcode = ((idq_uop >> 46) & 0xfff)
    src_bits = ((idq_uop >> 40) & 0xf)
    is_src0 = (src_bits & 0xa) != 0
    is_src1 = (src_bits & 0x5) != 0
    is_xmm = (src_bits & 0x3) != 0
    str_src0 = ""
    str_src1 = ""
    if is_src0:
        str_src0 = get_idq_src_dst_mnem((idq_uop >> 29) & 0x1f, is_xmm)
    if is_src1:
        str_src1 = get_idq_src_dst_mnem((idq_uop >> 34) & 0x1f, is_xmm)
    str_dst = get_idq_src_dst_mnem((idq_uop >> 14) & 0x1f, is_xmm)
    
    str_opcode_mnem = ""
    if opcode == 0 and not is_src0 and not is_src1:
        str_opcode_mnem = "NOP"
    elif opcode in g_opcodes:
        str_opcode_mnem = g_opcodes[opcode]
    else:
        str_opcode_mnem = "unk_%03x" % opcode
    
    str_imm = ("0x%016x" if idq_imm >= 0x100000000 else "0x%08x") % idq_imm
    str_srcs = \
        str_src0 + ", " + str_src1 if is_src0 and is_src1 else \
        str_imm + ", " + str_src1 if not is_src0 and is_src1 else \
        str_src0 + ", " + str_imm if is_src0 and not is_src1 else \
        str_imm
    
    str_uop = ""
    if str_opcode_mnem == "NOP":
        str_uop = str_opcode_mnem
    else:
        str_uop = str_dst + ":= " + str_opcode_mnem + "(" + str_srcs + ")"
    
    return "%02x: " % addr + "%016x: " % idq_uop + "%03x: " % opcode + str_uop

class idq_entry_t:
    def __init__(self, uop, imm):
        self.uop = uop
        self.imm = imm

def idq_disassembler_print(idq_ents):
    str_disasm = ""
    for idx, idq_entry in enumerate(idq_ents):
        str_disasm += idq_entry_disassemble(idx, idq_entry.uop, idq_entry.imm)
        str_disasm += "\n"
    print(str_disasm)

def idq_disassemble():
    ms_debug_defeature_val = crbus_read(0x38c)
    crbus_write(0x38c, 0)
    
    idq_ents = []
    for addr in range(32):
        idq_ents.append(idq_entry_t( \
            ldat_array_read(0x10, 1, 0, 0, addr).ToUInt64(), \
            ldat_array_read(0x10, 2, 0, 0, addr).ToUInt64()))
    
    crbus_write(0x38c, ms_debug_defeature_val)
    
    idq_disassembler_print(idq_ents)

def load_ms_array_str_data(file_name):
    fi = open(file_name, "r")
    str_array = fi.read()
    fi.close()
    
    array_vals = []
    str_lines = str_array.split("\n")
    for str_line in str_lines:
        addr_four_vals = str_line.split(":")
        if len(addr_four_vals) != 2:
            continue
        four_vals = addr_four_vals[1].strip()
        four_vals_seq = four_vals.split()
        if len(four_vals_seq) != 4:
            continue
        for val in four_vals_seq:
            array_vals.append(int(val, 16))
    return array_vals

def load_id_names_str_data(file_name):
    id_names = {}
    fi = open(file_name, "r")
    str_id_names = fi.read()
    fi.close()
    
    str_id_name_lines = str_id_names.split("\n")
    for id_name in str_id_name_lines:
        id_name_seq = id_name.split(":")
        if len(id_name_seq) != 2:
            continue
        str_id, str_name = id_name_seq
        if str_id == "" or str_name == "":
            continue
        id = int(str_id, 16)
        if id not in id_names:
            id_names[id] = str_name.strip()
    return id_names

def process_seqword(uaddr, uop, seqword, before_uop):
    uop_ctrl = (seqword & 0x3c) >> 2
    uop_ctrl_uidx = seqword & 0x03
    
    tetrad_ctrl_uidx = (seqword & 0xc0) >> 6
    tetrad_ctrl_next_uaddr = (seqword & 0x7fff00) >> 8
    
    sync_ctrl = (seqword & 0xe000000) >> 25
    sync_ctrl_uidx = (seqword & 0x1800000) >> 23
    
    uret_uop_ctrls = (2, 3)
    uend_uop_ctrls = (0xc, 0xd, 0xe, 0xf)
    exec_flow_uop_ctrls = uret_uop_ctrls + uend_uop_ctrls
    save_uip_uop_ctrls = (4, 5, 6, 7)
    save_uip_reg_ovr_uop_ctrls = (6, 7)
    misc_exec_ctrl_uop_ctrls = (8, 9, 0xb)
    
    lfence_sync_ctrls = (1, 2, 3)
    oooe_sync_ctrls = (4, 5, 6, 7)
    
    # assert(uop_ctrl != 1 and uop_ctrl_uidx != 0x03)
    # assert(sync_ctrl_uidx != 0x03 or sync_ctrl == 0)
    assert(uop_ctrl_uidx == 0 or uop_ctrl != 0)
    
    opcode = get_uop_opcode(uop)
    is_testustate_uop = is_uop_testustate(uop)
    uidx = uaddr & 0x03
    assert(uidx != 0x03)
    after_uop = not before_uop
    res = ""
    exec_flow_stop = False
    
    if uop_ctrl_uidx == uidx and after_uop:
        if uop_ctrl in uret_uop_ctrls:
            assert(tetrad_ctrl_uidx != uidx)
            str_cond = "? " if is_testustate_uop else ""
            res = str_cond + "SEQW URET%i" % (uop_ctrl - 2)
            exec_flow_stop = not is_testustate_uop
        elif uop_ctrl in uend_uop_ctrls:
            assert(tetrad_ctrl_uidx != uidx and opcode != 0x00a)
            res = "SEQW UEND%i" % (uop_ctrl - 0xc)
            exec_flow_stop = True
        elif uop_ctrl in save_uip_uop_ctrls:
            str_cond = "? " if is_testustate_uop else ""
            next_uaddr = uaddr + (2 if uaddr & 3 == 2 else 1)
            res = str_cond + "SEQW SAVEUIP%i U%04x" % ((uop_ctrl & 1), next_uaddr)
    
    special_tetrad_ctrl_case = uidx == 2 and tetrad_ctrl_uidx == 3 and is_testustate_uop and \
        (uop_ctrl_uidx != 2 or (uop_ctrl not in exec_flow_uop_ctrls))
    if (tetrad_ctrl_uidx == uidx or special_tetrad_ctrl_case) and after_uop:
        assert(special_tetrad_ctrl_case or uop_ctrl_uidx != uidx or \
               uop_ctrl == 0 or uop_ctrl not in exec_flow_uop_ctrls)
        
        str_cond = "? " if is_testustate_uop else ""
        res += str_cond + "SEQW GOTO " + get_str_uaddr(tetrad_ctrl_next_uaddr)
        exec_flow_stop = not is_testustate_uop and opcode != 0x00d and \
            (uop_ctrl_uidx != uidx or uop_ctrl not in save_uip_uop_ctrls)
    
    if uop_ctrl_uidx == uidx and uop_ctrl in save_uip_reg_ovr_uop_ctrls and before_uop:
        res = "ROVR<-"
    
    if sync_ctrl_uidx == uidx and sync_ctrl in lfence_sync_ctrls and before_uop:
        lfence_ctrl_mnems = ("LFNCEWAIT", "LFNCEMARK", "LFNCEWTMRK")
        assert(sync_ctrl - 1 < len(lfence_ctrl_mnems))
        res += "%s->" % lfence_ctrl_mnems[sync_ctrl - 1]
    if sync_ctrl_uidx == uidx and sync_ctrl in oooe_sync_ctrls and before_uop:
        oooe_sync_ctrl_mnems = ("SYNCFULL", "SYNCWAIT", "SYNCMARK", "SYNCWTMRK")
        sync_mnem_idx = sync_ctrl - oooe_sync_ctrls[0]
        assert(sync_mnem_idx < len(oooe_sync_ctrl_mnems))
        res += "%s->" % oooe_sync_ctrl_mnems[sync_mnem_idx]
    if uop_ctrl_uidx == uidx and uop_ctrl in misc_exec_ctrl_uop_ctrls and before_uop:
        misc_ctrl_mnems = ("WRTAGW", "MSLOOP", "", "MSSTOP")
        misc_ctrl_mnem_idx = uop_ctrl - misc_exec_ctrl_uop_ctrls[0]
        assert(misc_ctrl_mnem_idx < len(misc_ctrl_mnems))
        res += "%s->" % misc_ctrl_mnems[misc_ctrl_mnem_idx]
    
    return res

# end is not inclusive
# e.g., extract_bits(0x123456, 0, 4) = 6
def extract_bits(value, start, end):
    mask = (1 << (end - start)) - 1
    return (value >> start) & mask

def dump_uop(uop):
    src0 = extract_bits(uop, 0, 6)
    src1 = extract_bits(uop, 6, 12)
    dst  = extract_bits(uop, 12, 18)

    opcode = extract_bits(uop, 32, 44)
    imm0   = extract_bits(uop, 24, 32)
    imm1   = extract_bits(uop, 18, 23)
    m0     = extract_bits(uop, 23, 24)
    m1     = extract_bits(uop, 44, 45)
    m2     = extract_bits(uop, 45, 46)

    crc    = extract_bits(uop, 46, 48)

    dump = f'''48       44   40       32       24 23    18 16   12   8  6      0
|---+--+--+----|--------|--------|--+-----+--|----+----|--+------|
|{crc:02x} |{m2:02x}|{m1:02x}|      {opcode:04x}   |   {imm0:03x}  |{m0:02x}| {imm1:03x} |   {dst:02x}  |   {src1:02x}  |   {src0:02x} |
|crc|m2|m1|    opcode   |  imm0  |m0| imm1|  dst  | src1  | src0 |
|---+--+--+----|--------|--------|--+-----+--|----+----|--+------|
    '''
    return dump

def dump_seqword(seqword):
    uop_ctrl = (seqword & 0x3c) >> 2 # eflow -> URET, UEND, SAVEUIP
    uop_ctrl_uidx = seqword & 0x03   # up0
    
    tetrad_ctrl_uidx = (seqword & 0xc0) >> 6           # up1
    tetrad_ctrl_next_uaddr = (seqword & 0x7fff00) >> 8 # uaddr -> GOTO
    
    sync_ctrl = (seqword & 0xe000000) >> 25      # sync
    sync_ctrl_uidx = (seqword & 0x1800000) >> 23 # up2

    unknown = (seqword) >> 28

    dump =  f'''
+-----+------+-----+---------+-----+-------+-----+
| {unknown:02x}  |  {sync_ctrl:02x}  | {sync_ctrl_uidx:02x}  |  {tetrad_ctrl_next_uaddr:04x}   | {tetrad_ctrl_uidx:02x}  | {uop_ctrl:02x}    | {uop_ctrl_uidx:02x}  |
| crc | sync | up2 |  uaddr  | up1 | eflow | up0 |
+-----+------+-----+---------+-----+-------+-----+
'''

    for i in range(3):
        dump += process_seqword(i, 0, seqword, True) + f' [uop{i}] ' + process_seqword(i, 0, seqword, False) + "\n"
    return dump.strip()

def get_even_bits(v):
    bits = f'{v:048b}'
    return [int(i) for i in bits[::2]]

def get_odd_bits(v):
    bits = f'{v:048b}'
    return [int(i) for i in bits[1::2]]

def is_label(uop):
    return uop.startswith('<') and uop.endswith('>')

def is_empty(uop):
    return uop.strip() == '' or uop.startswith('#')

def is_three_sources(opcode):
    for op in  {'STAD_', 'STADPPHYS_', 'STADPPHYSTICKLE_', 'PORTOUT_', 'STADSTGBUF_'}:
        if opcode.startswith(op):
            return True
    return False

def incorrect_label(uop):
    return uop.startswith('<') and not uop.endswith('>')

def normalize(instruction):
    instruction = re.sub(' ', '', instruction)
    instruction = re.sub('U([a-f0-9]{4})', '0x\g<1>', instruction)
    instruction = re.sub('0x0+', '0x', instruction)
    return instruction

def ldat_gen_base():
    return 0xd << 24

g_special_opcodes = {
    'LDAT_IN': 0x142
}

g_special_opcodes_func = {
    'LDAT_IN' : ldat_gen_base
}

def assemble_uop(uop, modifiers, labels):
    # has a destination?
    if len(uop.split(':=')) > 1:
        dest = uop.split(':=')[0].strip()
        instr = uop.split(':=')[1].strip()
    else:
        dest = ''
        instr = uop.strip()
    dest_id = g_reg_to_id[dest]

    opcode = instr.split('(')[0].strip()
    if opcode.startswith('unk_'):
        opcode_id = int(opcode.replace('unk_', ''), 16)
    else:
        opcode_id = g_opcodes_to_id[opcode] if opcode not in g_special_opcodes else g_special_opcodes[opcode]

    operands = instr.split('(')[1].split(')')[0].strip() if '(' in instr else ''

    m0 = 1 if 'm0' in modifiers else 0
    m1 = 1 if 'm1' in modifiers else 0
    m2 = 1 if 'm2' in modifiers else 0
    
    src0 = operands.split(',')[0].strip() if len(operands.split(',')) > 0 else ''
    if src0 in labels:
        src0_id = labels[src0]
        src0_is_imm = True
    elif src0 in g_reg_to_id:
        # reg operand
        src0_id = g_reg_to_id[src0]
        src0_is_imm = False
    else:
        # imm operand
        src0_id = int(src0, 16)
        src0_is_imm = True

    src1 = operands.split(',')[1].strip() if len(operands.split(',')) > 1 else ''
    if src1 in labels:
        src1_id = labels[src1]
        src1_is_imm = True
    elif src1 in g_reg_to_id:
        # reg operand
        src1_id = g_reg_to_id[src1]
        src1_is_imm = False
    else:
        # imm operand
        src1_id = int(src1, 16)
        src1_is_imm = True

    src2 = ""
    if is_three_sources(opcode):
        src2 = operands.split(',')[2].strip()
    src2_id = g_reg_to_id[src2]

    if opcode == "UJMP" and src1_id == 0 and src1 == '':
        print("[ERROR] invalid UJMP, destination must be in src1")
        exit(1)

    uop_bin = 0 if opcode not in g_special_opcodes else g_special_opcodes_func[opcode]()
    
    # assign the opcode
    uop_bin |= (opcode_id & 0xfff) << 32

    # assign the destination
    uop_bin |= ((dest_id | src2_id) & 0x3f) << 12

    # assign src0
    if src0_is_imm:
        if src0_id > 0xffff:
            print('[ERROR] immediates must be 16 bits')
            exit(1)
        
        # reversed from get_str_uop_common_imm
        encoded_imm = ((src0_id & 0xff) << 24) | ((src0_id & 0x1f00)<< 10) | ((src0_id & 0xe000) >> 13) | (1 << 3)
        uop_bin |= encoded_imm
    else:
        uop_bin |= (src0_id & 0x3f)

    # assign src1
    if src1_is_imm:
        if src1_id > 0xffff:
            print('[ERROR] immediates must be 16 bits')
            exit(1)
        
        # reversed from get_str_uop_common_imm
        encoded_imm = ((src1_id & 0xff) << 24) | ((src1_id & 0x1f00)<< 10) | ((src1_id & 0xe000) >> 7) | (1 << 9)
        uop_bin |= encoded_imm
    else:
        uop_bin |= (src1_id & 0x3f) << 6

    # add m0, m1, m2 bits if required
    uop_bin |= (m0 << 23)
    uop_bin |= (m1 << 44)
    uop_bin |= (m2 << 45)

    return uop_bin

NOP_SEQWORD = 0x0000300000c0
# END_SEQWORD = 0x197ec80 # GOTO uend in glm old
END_SEQWORD = 0x130000f2 # LFENCEWAIT + UEND0
END_UNKOWN_UOP = 'unk_256() !m1'
def assemble_ucode(ucode, output):
    triads = [[]]
    instructions = [[]]
    labels = dict()
    uops = ucode.split('\n')[1:]
    org = ucode.split('\n')[0]
    if not org.startswith('.org'):
        print(f'[ERROR] ucode should start with .org directive')
        exit(1)
    address = int(org.replace('.org ', ''), 16)
    # visit first the instructions to gather labels
    _address = address

    # add the unknown operation before the uend to make it fast
    # FAST IN THE SENSE THAT TAKES 300 CYCLES INSTEAD OF 59 MILLIONS CYCLES
    # SO DO NOT REMOVE THIS
    if uops[-1] != END_UNKOWN_UOP:
        uops.append(END_UNKOWN_UOP)

    for uop in uops:
        uop = uop.strip()
        if is_empty(uop):
            continue
        # check correctly formed labels
        if incorrect_label(uop):
            print(f'[ERROR] label "{uop}" malformed')
            exit(1)
        if is_label(uop):
            if uop in labels:
                print(f'[ERROR] label "{uop}" defined multiple times')
                exit(1)
            labels[uop] = _address
            continue

        _address += 1
        if _address & 3 == 3:
            # skip fixed-nop uops slot
            _address += 1

    # now assemble
    for uop_str in uops:
        uop = uop_str.split('!')[0].split('#')[0].strip()
        modifiers = uop_str.split('!')[1].split('#')[0].strip() if '!' in uop_str else ''

        # skip labels
        if is_empty(uop) or is_label(uop):
            continue

        # deal with raw instructions
        if uop.startswith('$'):
            raw_uop = True
            uop_bin = int(uop[1:], 16)
        else:
            raw_uop = False
            uop_bin = assemble_uop(uop, modifiers, labels)

        # add both CRCs
        f_parity = lambda a,b: a^b
        crc1 = reduce(f_parity, get_even_bits(uop_bin))
        crc2 = reduce(f_parity, get_odd_bits(uop_bin))
        uop_bin |= (crc1 << 47)
        uop_bin |= (crc2 << 46)

        uop_nolabels = uop + ((' !' + modifiers) if modifiers else '')
        for label in labels:
            uop_nolabels = uop_nolabels.replace(label, f'U{labels[label]:04x}')
        if not raw_uop and normalize(uop_disassemble(uop_bin, 0)) != normalize(uop_nolabels):
            print('[ERROR] something went wrong while compiling:')
            print(f'    input:  {uop_nolabels}')
            print(f'    output: {hex(uop_bin)}')
            print(f'    disass:  {uop_disassemble(uop_bin, 0)}')
            # if opcode not in g_special_opcodes:
            exit(1)

        if len(triads[-1]) == 3:
            triads.append([])
            instructions.append([])
        
        triads[-1].append(uop_bin)
        instructions[-1].append(uop_nolabels)

    def tee(s, mode='a'):
        if output:
            with open(output, mode) as f:
                print(s, file=f)
        print(s)
    
    tee(f'unsigned long addr = 0x{address:04x};', mode='w')
    tee('unsigned long ucode_patch[][4] = {')
    for i, (triad, instruction) in enumerate(zip(triads, instructions)):
        seqword = NOP_SEQWORD if i < len(triads)-1 else END_SEQWORD
        uop0 = triad[0] if len(triad)>0 else 0
        uop1 = triad[1] if len(triad)>1 else 0
        uop2 = triad[2] if len(triad)>2 else 0

        iseqword = 'SEQ_NOP' if i < len(triads)-1 else 'SEQ_END'
        addr = address + i*4
        instr0 = instruction[0] if len(instruction)>0 else 'NOP'
        instr1 = instruction[1] if len(instruction)>1 else 'NOP'
        instr2 = instruction[2] if len(instruction)>2 else 'NOP'
        tee(f'    // U{addr:04x}: {instr0}, {instr1}, {instr2}, {iseqword}')
        tee(f'    {{{hex(uop0)}, {hex(uop1)}, {hex(uop2)}, {hex(seqword)}}},')
    tee('};')

# We are able to trace only the first and third instruction for each tetrad
# (the fourth is always a nop)
# Add the second instruction for each tetrad in the trace, which may or may not have
# been executed
def interpolate_trace(trace):
    res_trace = []
    uaddrs = {t[1] for t in trace}
    for clock, uaddr in trace:
        # if third instruction in a tetrad
        if uaddr & 3 == 2 and (uaddr-2) not in uaddrs:
            res_trace.append((0, uaddr - 1))

        res_trace.append((clock, uaddr))

        # if first instruction in a tetrad
        if uaddr & 3 == 0:
            res_trace.append((0, uaddr + 1))
    return res_trace

def load_labels(filename):
    with open(filename) as f:
        raw_labels = f.read().strip().split('\n')
    labels = {}
    for label_addr in raw_labels:
        label = label_addr.split(',')[0]
        addr = int(label_addr.split(',')[1], 16)
        labels[addr] = label
    return labels

def print_trace(tracefile):
    arrays_dump_dir = os.path.dirname(os.path.realpath(__file__))
    ucode = load_ms_array_str_data(os.path.join(arrays_dump_dir, cpuid_, "ms_array0.txt"))
    seqwords = load_ms_array_str_data(os.path.join(arrays_dump_dir, cpuid_, "ms_array1.txt"))
    labels = load_labels(os.path.join(arrays_dump_dir, "labels.csv"))

    with open(tracefile, 'r') as f:
        raw_trace = f.read().strip().split('\n')
    tuple_trace = []
    uaddr_to_clock = {}
    for t in raw_trace:
        clock = int(t.split(' ')[1])
        uaddr = int(t.split(' ')[0], 16)
        uaddr_to_clock[uaddr] = clock
        tuple_trace.append((clock, uaddr))
    tuple_trace.sort()
    # print(raw_trace)

    trace = interpolate_trace(tuple_trace)
    
    for clock, uaddr in trace:
        assert(uaddr < 0x7c00)
        uop = ucode[uaddr]
        seqword = seqwords[uaddr // 4 * 4]

        disasm_uop         = uop_disassemble(uop, uaddr).strip()
        disasm_seqw_before = process_seqword(uaddr, uop, seqword, True).strip()
        disasm_seqw_after  = process_seqword(uaddr, uop, seqword, False).strip()
        if uaddr in labels:
            print(f'{labels[uaddr]}:')
        print(f'[{clock:6d}] U{uaddr:04x}: {disasm_seqw_before} {disasm_uop} {disasm_seqw_after}')

def print_patches():
    patches = [0x00003e573a3b, 0x00003e8f6ef7, 0x00003e8c6217,
        0x00003eaa29a3, 0x00003e5d69ef, 0x00003e1b18b3, 0x00003e1f2833,
        0x00003e27549b, 0x00003e2f23ab, 0x00003e042011, 0x00003e0018dd,
        0x00003e2e4589, 0x00003e854c33, 0x00003e553a03, 0x00003e533603,
        0x00003e6d31a5, 0x00003e77758f]

    arrays_dump_dir = os.path.dirname(os.path.realpath(__file__))
    ucode = load_ms_array_str_data(os.path.join(arrays_dump_dir, cpuid_, "ms_array0.txt"))
    seqwords = load_ms_array_str_data(os.path.join(arrays_dump_dir, cpuid_, "ms_array1.txt"))

    for patch in patches:
        uaddr = patch & 0xfffe
        assert(uaddr < 0x7c00)
        uop = ucode[uaddr]
        seqword = seqwords[uaddr // 4 * 4]

        disasm_uop         = uop_disassemble(uop, uaddr).strip()
        disasm_seqw_before = process_seqword(uaddr, uop, seqword, True).strip()
        disasm_seqw_after  = process_seqword(uaddr, uop, seqword, False).strip()
        print(f'U{uaddr:04x}: {disasm_seqw_before} {disasm_uop} {disasm_seqw_after}')

cpuid_ = ''
@click.command()
@click.option('-c', '--cpuid', type=str, default='0x000506C9', help='the cpuid of the target CPU')
@click.option('-d', '--disasm', is_flag=True)
@click.option('-s','--seqwords', type=str, default=None)
@click.option('-u','--uops',type=str,default=None)
@click.option('-t','--tracefile',type=str,default=None)
@click.option('-i','--ucodefile',type=str,default=None)
@click.option('-o','--output',type=str,default=None)
def main(cpuid, disasm, seqwords, uops, tracefile, ucodefile, output):

    global cpuid_
    cpuid_ = cpuid

    if disasm:
        if seqwords is not None:
            for i, seqword in enumerate(seqwords.split(',')):
                seqword = int(seqword, 16)
                print(dump_seqword(seqword))

        if uops is not None:
            for i,uop in enumerate(uops.split(',')):
                uop = int(uop, 16)
                print(dump_uop(uop))
                print(f'uop{i}:',uop_disassemble(uop, 0))
    elif tracefile:
        print_trace(tracefile)
    else:
        if ucodefile is None:
            print('[ERROR] need an input file to assemble')
            exit(1)
        with open(ucodefile, 'r') as f:
            ucode = f.read()
        assemble_ucode(ucode, output)

glm_ucode_disasm_init()
if __name__ == '__main__':
    main()