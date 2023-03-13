unsigned long addr = 0x7da0;
unsigned long ucode_patch[][4] = {
    // U7da0: tmp0:= ZEROEXT_DSZ32(0x00000000); tmp1:= ZEROEXT_DSZ32(0x00000020); tmp9:= ZEROEXT_DSZ32(0x00000303)
    {0xc00800030008, 0x820031008, 0x8030f9008, 0x300000c0},
    // U7da4: tmp9:= SHL_DSZ32(tmp9, 0x00000008); MOVETOCREG_DSZ64(tmp9, 0x6a1) !m2; MOVETOCREG_DSZ64(tmp0, 0x6a0) !m2
    {0xc02408039239, 0x6042a1180239, 0xe042a0180230, 0x300000c0},
    // U7da8: MOVETOCREG_DSZ64(tmp0, 0x6a4) !m2; MOVETOCREG_DSZ64(tmp0, 0x6a4) !m2; tmp1:= SUB_DSZ32(0x00000001, tmp1)
    {0xa042a4180230, 0xa042a4180230, 0xc00501031c48, 0x300000c0},
    // U7dac: UJMPCC_DIRECT_NOTTAKEN_CONDNZ(tmp1, U7da8); MOVETOCREG_DSZ64(tmp0, 0x6a1) !m2; rax:= ZEROEXT_DSZ32(0x00001337)
    {0x8151a87402f1, 0xa042a1180230, 0x4008374e0008, 0x300000c0},
    // U7db0: rax:= CONCAT_DSZ32(rax, 0x00001337); unk_256() !m1; NOP SEQW LFNCEWAIT, UEND0
    {0x8021374e0220, 0x125600000000, 0x0, 0x130000f2},
};
