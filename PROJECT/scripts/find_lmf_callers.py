"""
Find where the LMF decompressor (0x5B2400) is actually called.
Search for BL instructions to it in the ENTIRE text section.
Also check who calls functions that call it.
"""

import struct

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    data = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

TARGET = 0x5B2400

# Collect ALL BL targets in the text section, find who calls TARGET
callers_of_target = set()
all_bl_targets = {}  # target -> list of callers

for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 4, 4):
    instr = struct.unpack_from('<I', data, file_off)[0]
    if (instr >> 26) == 0x25:  # BL
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000:
            imm26 -= 0x4000000
        addr = TEXT_ADDR + (file_off - TEXT_OFF)
        target = addr + (imm26 << 2)
        
        if TEXT_ADDR <= target < TEXT_ADDR + TEXT_SIZE:
            if target not in all_bl_targets:
                all_bl_targets[target] = []
            all_bl_targets[target].append(addr)
            
            if target == TARGET:
                callers_of_target.add(addr)

print('=== Callers of LMF decompressor (0x5B2400) ===')
if callers_of_target:
    for addr in sorted(callers_of_target):
        print('  BL from 0x{:x}'.format(addr))
        # Show context
        off = addr - TEXT_ADDR + TEXT_OFF
        for co in range(max(TEXT_OFF, off-20), min(TEXT_OFF+TEXT_SIZE, off+24), 4):
            ci = struct.unpack_from('<I', data, co)[0]
            ca = TEXT_ADDR + (co - TEXT_OFF)
            marker = ' <-- CALL' if co == off else ''
            print('    0x{:x}: {:08x}{}'.format(ca, ci, marker))
else:
    print('  No direct BL callers found')
    print()

    # Maybe called via BLR? Check for ADRP to its page
    page = TARGET & ~0xFFF
    page_offset = TARGET & 0xFFF
    print('  Searching for ADRP to page 0x{:x} (offset 0x{:x})...'.format(page, page_offset))
    
    for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 12, 4):
        instr = struct.unpack_from('<I', data, file_off)[0]
        addr = TEXT_ADDR + (file_off - TEXT_OFF)
        
        if (instr >> 24) == 0x90:  # ADRP
            Rd = instr & 0x1F
            immhi = (instr >> 5) & 0x7FFFF
            immlo = (instr >> 29) & 3
            if immhi >= 0x40000:
                immhi |= 0xFFF80000
            imm = (immhi << 2) | immlo
            target_page = (addr & ~0xFFF) + (imm << 12)
            
            if target_page == page:
                # Check next few instructions for ADD + BLR
                for look in range(1, 8):
                    check_off = file_off + look * 4
                    if check_off >= TEXT_OFF + TEXT_SIZE:
                        break
                    ci = struct.unpack_from('<I', data, check_off)[0]
                    if (ci >> 24) == 0x91:  # ADD
                        add_Rd = ci & 0x1F
                        add_Rn = (ci >> 5) & 0x1F
                        add_imm12 = (ci >> 10) & 0xFFF
                        if add_Rn == Rd and add_Rd == Rd and add_imm12 == page_offset:
                            # Found ADRP+ADD, now look for BLR
                            for look2 in range(look+1, look+10):
                                check2 = file_off + look2 * 4
                                if check2 >= TEXT_OFF + TEXT_SIZE:
                                    break
                                ci2 = struct.unpack_from('<I', data, check2)[0]
                                blr_addr = TEXT_ADDR + (check2 - TEXT_OFF)
                                if (ci2 & 0xFFFFFC00) == 0xD63F0000 and (ci2 & 0x1F) == Rd:
                                    print('    Found ADRP+ADD+BLR at 0x{:x} targeting LMF'.format(blr_addr))
                                    for co in range(max(TEXT_OFF, file_off-8), min(TEXT_OFF+TEXT_SIZE, check2+8), 4):
                                        ci3 = struct.unpack_from('<I', data, co)[0]
                                        ca3 = TEXT_ADDR + (co - TEXT_OFF)
                                        marker = ' <--' if co == file_off else (' <-- BLR' if co == check2 else '')
                                        print('      0x{:x}: {:08x}{}'.format(ca3, ci3, marker))

# Also: check the FIRST function in the Antm pipeline (0xC828A0)
print('\n=== Function 0xC828A0 (first called in pipeline) ===')
off = 0xC828A0 - TEXT_ADDR + TEXT_OFF
for i in range(30):
    instr = struct.unpack_from('<I', data, off + i*4)[0]
    addr = 0xC828A0 + i*4
    if (instr >> 26) == 0x25:
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000:
            imm26 -= 0x4000000
        target = addr + (imm26 << 2)
        print('  0x{:x}: BL 0x{:x}'.format(addr, target))
    elif instr == 0xD65F03C0:
        print('  0x{:x}: RET'.format(addr))
        # Check for function prologue after
        next_instr = struct.unpack_from('<I', data, off + (i+1)*4)[0]
        if (next_instr & 0xFF000000) == 0xA9000000 or (next_instr & 0xFF000000) == 0xA8000000:
            print('  (next appears to be new function at 0x{:x})'.format(addr+4))
        break
    else:
        print('  0x{:x}: {:08x}'.format(addr, instr))

# Check what function contains 0xC828A0
# Go backwards to find STP X29, X30 prologue
print('\n=== Finding function start for 0xC828A0 ===')
lookoff = off
for lookback in range(1, 200):
    check_off = off - lookback * 4
    check_addr = 0xC828A0 - lookback * 4
    if check_off < TEXT_OFF:
        break
    instr = struct.unpack_from('<I', data, check_off)[0]
    # STP X29, X30, [SP, ...]!
    if (instr & 0xFF000000) == 0xA8000000 or (instr & 0xFF000000) == 0xA9000000:
        rt = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        rt2 = (instr >> 10) & 0x1F
        if rt == 29 and rt2 == 30 and rn == 31:
            print('  Function prologue at 0x{:x}'.format(check_addr))
            # Now trace what's in this function
            print()
            print('=== Function content (0x{:x}+) ==='.format(check_addr))
            for j in range(50):
                ci = struct.unpack_from('<I', data, check_off + j*4)[0]
                ca = check_addr + j*4
                if (ci >> 26) == 0x25:
                    imm26 = ci & 0x03FFFFFF
                    if imm26 >= 0x2000000:
                        imm26 -= 0x4000000
                    tgt = ca + (imm26 << 2)
                    print('  0x{:x}: BL 0x{:x}'.format(ca, tgt))
                elif ci == 0xD65F03C0:
                    print('  0x{:x}: RET'.format(ca))
                    break
                else:
                    # Just show first few instructions
                    if j < 15:
                        print('  0x{:x}: {:08x}'.format(ca, ci))
            break
