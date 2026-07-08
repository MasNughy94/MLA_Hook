"""
Find call sites to the LMF decompressor at 0x5B2400.
Also search for functions that load/read .mt files to trace the buffer flow.
"""

import struct

so = open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb').read()

# Executable section: addr=0x3fc000, off=0x3fc000, size=0x9fa1ec
TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

TARGET_ADDR = 0x5B2400

# Method 1: Direct BL instructions
call_sites = []
for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 4, 4):
    instr = struct.unpack_from('<I', so, file_off)[0]
    if (instr >> 26) == 0x25:  # BL opcode
        imm26 = instr & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 |= 0xFC000000
        target = TEXT_ADDR + (file_off - TEXT_OFF) + (imm26 << 2)
        if target == TARGET_ADDR:
            func_addr = TEXT_ADDR + (file_off - TEXT_OFF)
            call_sites.append(('BL', func_addr, file_off))

print('=== Direct BL calls to 0x{:x} ==='.format(TARGET_ADDR))
if call_sites:
    for kind, addr, off in call_sites:
        print('  {} at 0x{:x} (file offset 0x{:x})'.format(kind, addr, off))
        ctx_start = max(TEXT_OFF, off - 32)
        ctx_end = min(TEXT_OFF + TEXT_SIZE, off + 24)
        for co in range(ctx_start, ctx_end, 4):
            ci = struct.unpack_from('<I', so, co)[0]
            ca = TEXT_ADDR + (co - TEXT_OFF)
            marker = ' <-- CALL' if co == off else ''
            print('    0x{:x}: {:08x}{}'.format(ca, ci, marker))
else:
    print('  None found')

# Method 2: Search for ADRP to page of 0x5B2400
page = TARGET_ADDR & ~0xFFF  # 0x5B2000
print('\n=== ADRP to page 0x{:x}, then ADD to get 0x{:x} ==='.format(page, TARGET_ADDR))

for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 8, 4):
    instr = struct.unpack_from('<I', so, file_off)[0]
    addr = TEXT_ADDR + (file_off - TEXT_OFF)
    
    # ADRP: bits[31:24] = 10010000 = 0x90
    if (instr >> 24) == 0x90:
        immhi = (instr >> 5) & 0x7FFFF
        immlo = (instr >> 29) & 3
        if immhi & 0x40000:
            immhi |= 0xFFF80000
        imm = (immhi << 2) | immlo
        target_page = (addr & ~0xFFF) + (imm << 12)
        
        if target_page == page:
            Rd = instr & 0x1F
            
            # Check next instruction for ADD
            next_instr = struct.unpack_from('<I', so, file_off + 4)[0]
            next_addr = addr + 4
            
            # ADD immediate: SF=1, op=0, S=0 => top byte usually 0x91
            if (next_instr >> 24) == 0x91:
                add_Rd = next_instr & 0x1F
                add_Rn = (next_instr >> 5) & 0x1F
                add_imm12 = (next_instr >> 10) & 0xFFF
                add_sh = (next_instr >> 22) & 0x3
                
                if add_Rn == Rd:
                    offset_val = add_imm12  # shift of 0
                    if add_sh == 1:  # LSL #12
                        offset_val = add_imm12 << 12
                    total = target_page + offset_val
                    
                    if total == TARGET_ADDR:
                        print('  ADRP X{} at 0x{:x} + ADD X{}, X{}, #0x{:x} => 0x{:x}'.format(
                            Rd, addr, add_Rd, add_Rn, offset_val, total))
                        # Show context
                        ctx_start = max(TEXT_OFF, file_off - 20)
                        ctx_end = min(TEXT_OFF + TEXT_SIZE, file_off + 28)
                        for co in range(ctx_start, ctx_end, 4):
                            ci = struct.unpack_from('<I', so, co)[0]
                            ca = TEXT_ADDR + (co - TEXT_OFF)
                            marker = ' <-- LEAFUNC' if co == file_off else ''
                            print('    0x{:x}: {:08x}{}'.format(ca, ci, marker))

# Method 3: Search for BLR with register loaded by ADRP+ADD to target
print('\n=== BLR after loading 0x{:x} ==='.format(TARGET_ADDR))
for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 16, 4):
    # Look for BLR (opcode: 1101011 0001 11111 000000 00000 Rn) where Rn is the register
    instr = struct.unpack_from('<I', so, file_off)[0]
    # BLR encoding: bits[31:24] = 11010110, bits[23:21] = 001, bits[20:16] = 11111, bits[15:10] = 000000, bits[9:5] = 00000, bits[4:0] = Rn
    # Simplified: opcode = 110101100011111100000000000Rn
    # Check: 0xD63F0000 | (Rn << 5) | 0x100  -- wait, that's not right
    # BLR: 0xD63F0000 | (Rn << 5) -- wait, let me think carefully
    # BLR <Xn>:
    # 31-24  | 23-21 | 20-16 | 15-10 | 9-5 | 4-0
    # 1101011 | 0 0 1 | 1 1 1 1 1 | 0 0 0 0 0 0 | 0 0 0 0 0 | Rn
    # That's: 0xD6 << 24 | 0x3F << 16 | Rn
    # 0xD63F0000 | (Rn)
    if (instr & 0xFFFFFC00) == 0xD63F0000:  # BLR any register
        Rn = instr & 0x1F
        # Check if a few instructions before, we loaded this register with ADRP+ADD
        for lookback in range(2, 6):  # Check 2-5 instructions before
            if file_off >= lookback * 4 + TEXT_OFF:
                prev_off = file_off - lookback * 4
                prev_instr = struct.unpack_from('<I', so, prev_off)[0]
                prev_addr = TEXT_ADDR + (prev_off - TEXT_OFF)
                
                if (prev_instr >> 24) == 0x90:  # ADRP
                    p_Rd = prev_instr & 0x1F
                    if p_Rd == Rn:
                        p_immhi = (prev_instr >> 5) & 0x7FFFF
                        p_immlo = (prev_instr >> 29) & 3
                        if p_immhi & 0x40000:
                            p_immhi |= 0xFFF80000
                        p_imm = (p_immhi << 2) | p_immlo
                        p_target_page = (prev_addr & ~0xFFF) + (p_imm << 12)
                        
                        if p_target_page == page:
                            blr_addr = TEXT_ADDR + (file_off - TEXT_OFF)
                            # Check for ADD between ADRP and BLR
                            for check_off in range(prev_off + 4, file_off, 4):
                                ci = struct.unpack_from('<I', so, check_off)[0]
                                if (ci >> 24) == 0x91:  # ADD
                                    add_Rd = ci & 0x1F
                                    add_Rn = (ci >> 5) & 0x1F
                                    add_imm12 = (ci >> 10) & 0xFFF
                                    if add_Rn == Rn and add_Rd == Rn and add_imm12 == (TARGET_ADDR & 0xFFF):
                                        print('  ADRP+ADD+BLR at 0x{:x} targeting 0x{:x}'.format(blr_addr, TARGET_ADDR))
                                        for co in range(max(TEXT_OFF, prev_off - 4), min(TEXT_OFF + TEXT_SIZE, file_off + 8), 4):
                                            ci2 = struct.unpack_from('<I', so, co)[0]
                                            ca2 = TEXT_ADDR + (co - TEXT_OFF)
                                            marker = ' <-- BLR' if co == file_off else ' <-- ADRP' if co == prev_off else ''
                                            print('    0x{:x}: {:08x}{}'.format(ca2, ci2, marker))
