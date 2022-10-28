unsigned long addr = 0x7c00;
unsigned long hook_address = 0x0c40;
unsigned long hook_entry = 0x00;
unsigned long ucode_patch[][4] = {
    // U7c00: tmp0 := ZEROEXT_DSZ64(0x0), tmp1 := ZEROEXT_DSZ64(0x0), tmp2 := ZEROEXT_DSZ64(0x3f), SEQ_NOP
    {0x804800030008, 0xc04800031008, 0xc0483f032008, 0x300000c0},
    // U7c04: UJMPCC_DIRECT_NOTTAKEN_CONDB(tmp2, U7c14), tmp3:= SHL_DSZ64(tmp1, 0x1), tmp4:= SHR_DSZ64(rax, tmp2), SEQ_NOP
    {0x52147002f2, 0xc06401033231, 0x806500034ca0, 0x300000c0},
    // U7c08: tmp4:= AND_DSZ64(tmp4, 0x1), tmp1 := OR_DSZ64(tmp3, tmp4), tmp6  := SUB_DSZ64(rcx, tmp1), SEQ_NOP
    {0xc04401034234, 0x4100031d33, 0x4500036c61, 0x300000c0},
    // U7c0c: tmp5:= SELECTCC_DSZ64_CONDB(tmp6, rcx), tmp1 := SUB_DSZ64(tmp5, tmp1), tmp7:= SHL_DSZ64(0x1, tmp2), SEQ_NOP
    {0x7200035876, 0x804500031c75, 0x406401037c88, 0x300000c0},
    // U7c10: tmp8:= SELECTCC_DSZ64_CONDB(tmp6, tmp7), tmp0 := OR_DSZ64(tmp0, tmp8), tmp2 := SUB_DSZ64(0x1, tmp2), GOTO(0x7c04)
    {0x7200038df6, 0x404100030e30, 0x804501032c88, 0x11fc0480},
    // U7c14: rax := ZEROEXT_DSZ64(tmp0), rdx := ZEROEXT_DSZ64(0x0), unk_256() !m1, SEQ_END
    {0x804800020030, 0x404800022008, 0x125600000000, 0x130000f2},
};
