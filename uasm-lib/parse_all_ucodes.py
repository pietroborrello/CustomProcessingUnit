#!/usr/bin/env python3

import os
import sys
from git import Repo
from glob import glob
from ucode_parser import parse_ucode_file
from subprocess import check_call
import shutil

if len(sys.argv) < 3:
    print('usage: %s <CPUMicrocodes repo path> <decrypted microcodes folder>')
    exit(1)

CPUMicrocodes_path = sys.argv[1]
output_dir = sys.argv[2]
repo = Repo(CPUMicrocodes_path)

# iterate over all commits and parse all the ucode patches
for commit in reversed(list(repo.iter_commits())):
    repo.git.checkout(commit)
    print(repo.commit())

    for ucode_f in glob(f'{CPUMicrocodes_path}/Intel/cpu506*.bin'):
        success = parse_ucode_file(ucode_f)
        if success:
            dst_filename = os.path.join(output_dir, os.path.basename(ucode_f))
            shutil.copy(f'{ucode_f}',     f'{dst_filename}')
            shutil.move(f'{ucode_f}.dec', f'{dst_filename}.dec')
            shutil.move(f'{ucode_f}.txt', f'{dst_filename}.txt')
            print(f'[+] {ucode_f}')
