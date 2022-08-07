unsigned long addr = 0x7da0;
unsigned long ucode_patch[][4] = {
    // U7da0: tmp1:= ZEROEXT_DSZ64(tmp0), tmp1:= OR_DSZ32(0x00004000, tmp1), tmp2:= ZEROEXT_DSZ64(0x8000), SEQ_NOP
    {0x804800031030, 0x400100031c4a, 0x40480003200c, 0x300000c0},
    // U7da4: tmp2:= CONCAT_DSZ16(0x0001, tmp2), tmp1:= NOTAND_DSZ32(tmp2, tmp1), rax:= MSR2CR( , tmp1), SEQ_NOP
    {0x80a101032c88, 0xc00700031c72, 0x822800020c40, 0x300000c0},
    // U7da8: tmp1:= ZEROEXT_DSZ64(tmp0), tmp2:= ZEROEXT_DSZ64(0xc000), tmp2:= CONCAT_DSZ16(0x0001, tmp2), SEQ_NOP
    {0x804800031030, 0xc0480003200e, 0x80a101032c88, 0x300000c0},
    // U7dac: tmp1:= NOTAND_DSZ32(tmp2, tmp1), rbx:= MSR2CR( , tmp1), tmp1:= ZEROEXT_DSZ64(tmp0), SEQ_NOP
    {0xc00700031c72, 0x422800023c40, 0x804800031030, 0x300000c0},
    // U7db0: tmp1:= OR_DSZ32(0x0000c000, tmp1), rcx:= MSR2CR( , tmp1), tmp1:= ZEROEXT_DSZ64(tmp0), SEQ_NOP
    {0x100031c4e, 0xc22800021c40, 0x804800031030, 0x300000c0},
    // U7db4: tmp2:= ZEROEXT_DSZ64(0x4000), tmp2:= CONCAT_DSZ16(0x0001, tmp2), tmp1:= OR_DSZ32(tmp2, tmp1), SEQ_NOP
    {0x80480003200a, 0x80a101032c88, 0x100031c72, 0x300000c0},
    // U7db8: rdx:= MSR2CR( , tmp1), unk_256() !m1, NOP, SEQ_END
    {0x22800022c40, 0x125600000000, 0x0, 0x130000f2},
};
