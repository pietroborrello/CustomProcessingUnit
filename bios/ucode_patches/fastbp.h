unsigned long addr = 0x7c00;
unsigned long ucode_patch[][4] = {
    // U7c00: tmp1:= LDSTGBUF_DSZ64_ASZ16_SC1(0xba00), tmp2:= ZEROEXT_DSZ64(0x1), tmp0:= ZEROEXT_DSZ64(IMM_MACRO_ALIAS_RIP) !m0, SEQ_NOP
    {0x8e75006b100d, 0x404801032008, 0x404804830008, 0x300000c0},
    // U7c04: tmp0:= AND_DSZ64(0xffff, tmp0), tmp2:= LDPPHYS_DSZ8_ASZ64_SC1(tmp1, tmp0), tmp2:= ADD_DSZ64(0x1, tmp2), SEQ_NOP
    {0x4044ff7f0c0f, 0xeea00032c31, 0x804001032c88, 0x300000c0},
    // U7c08: STADPPHYS_DSZ8_ASZ64_SC1(tmp1, tmp0, tmp2), NOP, NOP, SEQ_END
    {0x8ee800032c31, 0x0, 0x0, 0x130000f2},
};
