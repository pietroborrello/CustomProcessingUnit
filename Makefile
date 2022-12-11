GNU_EFI_DIR?=/home/user/gnu-efi

all: build-ucode build-cpu

build-ucode:
	uasm-lib/uasm.py -i bios/ucode_patches/ucode_patch.u --avoid_unk_256 -o ./bios/ucode_patches/ucode_patch.h
	uasm-lib/uasm.py -i bios/ucode_patches/dump_smm.u -o ./bios/ucode_patches/dump_smm.h
	uasm-lib/uasm.py -i bios/ucode_patches/match_patch_init.u -o ./bios/ucode_patches/match_patch_init.h
	uasm-lib/uasm.py -i bios/ucode_patches/match_patch_init_glm_new.u -o ./bios/ucode_patches/match_patch_init_glm_new.h
	uasm-lib/uasm.py -i bios/ucode_patches/match_patch_hook.u -o ./bios/ucode_patches/match_patch_hook.h
	uasm-lib/uasm.py -i bios/ucode_patches/ldat_read.u -o ./bios/ucode_patches/ldat_read.h
	uasm-lib/uasm.py -i bios/ucode_patches/trace_and_resume.u -o ./bios/ucode_patches/trace_and_resume.h
	uasm-lib/uasm.py -i bios/ucode_patches/get_value_and_resume.u -o ./bios/ucode_patches/get_value_and_resume.h
	uasm-lib/uasm.py -i bios/ucode_patches/time_access_hook.u -o ./bios/ucode_patches/time_access_hook.h
	uasm-lib/uasm.py -i bios/ucode_patches/msr2cr_dump.u -o ./bios/ucode_patches/msr2cr_dump.h
	uasm-lib/uasm.py -i bios/ucode_patches/fastbp.u --avoid_unk_256 -o ./bios/ucode_patches/fastbp.h
	uasm-lib/uasm.py -i bios/ucode_patches/condhwbp.u --avoid_unk_256 -o ./bios/ucode_patches/condhwbp.h
	uasm-lib/uasm.py -i bios/ucode_patches/ctdiv.u -o ./bios/ucode_patches/ctdiv.h
	uasm-lib/uasm.py -i bios/ucode_patches/pac_sign.u --avoid_unk_256 -o ./bios/ucode_patches/pac_sign.h
	uasm-lib/uasm.py -i bios/ucode_patches/pac_verify.u --avoid_unk_256 -o ./bios/ucode_patches/pac_verify.h

build-cpu:
	xxd -i bios/glm-intel-ucode/06-5c-09 > bios/glm-intel-ucode/06-5c-09.h
	xxd -i bios/glm-intel-ucode/06-5c-0a > bios/glm-intel-ucode/06-5c-0a.h
	gcc -mno-sse -mno-sse2 -mno-mmx -mno-avx -Ibios -I$(GNU_EFI_DIR)/inc -fpic -ffreestanding -fno-stack-protector -fno-stack-check -fshort-wchar -mno-red-zone -maccumulate-outgoing-args -c bios/custom-processing-unit.c -o bios/custom-processing-unit.o
	ld -shared -Bsymbolic -L$(GNU_EFI_DIR)/x86_64/gnuefi -L$(GNU_EFI_DIR)/x86_64/lib -T$(GNU_EFI_DIR)/gnuefi/elf_x86_64_efi.lds $(GNU_EFI_DIR)/x86_64/gnuefi/crt0-efi-x86_64.o bios/custom-processing-unit.o -o bios/custom-processing-unit.so -lgnuefi -lefi
	objcopy -j .text -j .sdata -j .data -j .dynamic -j .dynsym  -j .rel -j .rela -j .rel.* -j .rela.* -j .reloc --target efi-app-x86_64 --subsystem=10 bios/custom-processing-unit.so bios/cpu.efi

.PHONY: build-cpu build-ucode