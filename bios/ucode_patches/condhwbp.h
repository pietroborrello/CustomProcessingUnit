unsigned long addr = 0x7c00;
unsigned long hook_address = 0x1ee4;
unsigned long hook_entry = 0x00;
unsigned long ucode_patch[][4] = {
    // U7c00: tmp10:= SUB_DSZ64(0x1337, rdi); UJMPCC_DIRECT_NOTTAKEN_CONDNZ(tmp10, U7c08); tmp10:= SHL_DSZ32(0x00000000, tmp8)
    {0xc045374fa9c8, 0x8151087002fa, 0xc0240003ae08, 0x300000c0},
    // U7c04: tmp10:= SELECTCC_DSZ32_CONDNZ(tmp5, tmp10); tmp10:= SELECTCC_DSZ32_CONDNB(tmp12, tmp10); UJMP(, 0x1ee8)
    {0x1310003aeb5, 0x330003aebc, 0x815de8780200, 0x300000c0},
    // U7c08: UJMP(, 0x270d); NOP; NOP SEQW LFNCEWAIT, UEND0
    {0x15d0d1c0240, 0x0, 0x0, 0x130000f2},
};
