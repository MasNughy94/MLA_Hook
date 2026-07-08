"""
Find all callers of the Antm checker function at 0xC82A80.
Then trace the pipeline: who calls the callers?
"""

import struct

so = open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb').read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def find_bl_callers(target):
    """Find all BL instructions targeting target address."""
    callers = []
    for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 4, 4):
        instr = struct.unpack_from('<I', so, file_off)[0]
        if (instr >> 26) == 0x25:  # BL
            imm26 = instr & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 |= 0xFC000000
            target_addr = TEXT_ADDR + (file_off - TEXT_OFF) + (imm26 << 2)
            if target_addr == target:
                callers.append(TEXT_ADDR + (file_off - TEXT_OFF))
    return callers

def find_branch_callers(target, max_search=0x10000):
    """Find BLR after ADRP+ADD that loads target address."""
    callers = []
    target_page = target & ~0xFFF
    target_offset = target & 0xFFF
    
    for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 16, 4):
        instr = struct.unpack_from('<I', so, file_off)[0]
        addr = TEXT_ADDR + (file_off - TEXT_OFF)
        
        # Check for BLR
        if (instr & 0xFFFFFC00) == 0xD63F0000:
            Rn = instr & 0x1F
            # Look back 5-20 instructions for ADRP loading the page, then ADD
            for lookback in range(5, 25):
                if file_off >= lookback * 4:
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
                            p_page = (prev_addr & ~0xFFF) + (p_imm << 12)
                            
                            if p_page == target_page:
                                # Check for ADD in between with offset matching target_offset
                                for check_off in range(prev_off + 4, file_off, 4):
                                    ci = struct.unpack_from('<I', so, check_off)[0]
                                    if (ci >> 24) == 0x91:  # ADD
                                        add_Rd = ci & 0x1F
                                        add_Rn = (ci >> 5) & 0x1F
                                        add_imm12 = (ci >> 10) & 0xFFF
                                        if add_Rn == Rn and add_Rd == Rn and add_imm12 == target_offset:
                                            callers.append(addr)
                                            break
    return callers

# Find callers of Antm checker (0xC82A80)
print('=== Callers of Antm checker (0xC82A80) ===')
antm_checker = 0xC82A80
callers = find_bl_callers(antm_checker)
print('Direct BL callers: {}'.format(len(callers)))
for addr in callers:
    print('  BL from 0x{:x}'.format(addr))

# Also look for ADRP+ADD+BLR
blur_callers = find_branch_callers(antm_checker)
if blur_callers:
    print('Indirect BLR callers:')
    for addr in blur_callers:
        print('  BLR at 0x{:x}'.format(addr))

# For each caller, show context
for caller in callers:
    file_off = caller - TEXT_ADDR + TEXT_OFF
    print('\nContext at caller 0x{:x}:'.format(caller))
    for co in range(max(TEXT_OFF, file_off - 16), min(TEXT_OFF + TEXT_SIZE, file_off + 24), 4):
        ci = struct.unpack_from('<I', so, co)[0]
        ca = TEXT_ADDR + (co - TEXT_OFF)
        marker = ' <-- BL' if co == file_off else ''
        print('  0x{:x}: {:08x}{}'.format(ca, ci, marker))

# Also: find the lmF@ loading sequence
# Search for MOVZ loading 0x466D or other values that could be "lmF@"
print('\n=== Searching for lmF@ (0x40466D6C) in code section ===')
# "lmF@" = 6C 6D 46 40 = 0x40466D6C (LE)
# Lower 16: 0x6D6C, Upper 16: 0x4046
# Check 1: MOVZ + MOVK for 0x40466D6C
for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 8, 4):
    instr = struct.unpack_from('<I', so, file_off)[0]
    if ((instr >> 29) & 3) == 2 and (instr & 0x1F000000) == 0:  # MOVZ 32-bit
        hw = (instr >> 21) & 3
        imm16 = (instr >> 5) & 0xFFFF
        Rd = instr & 0x1F
        if hw == 0 and imm16 == 0x6D6C:
            next_instr = struct.unpack_from('<I', so, file_off + 4)[0]
            if ((next_instr >> 29) & 3) == 3:  # MOVK
                next_hw = (next_instr >> 21) & 3
                next_imm16 = (next_instr >> 5) & 0xFFFF
                next_Rd = next_instr & 0x1F
                if Rd == next_Rd and next_hw == 1 and next_imm16 == 0x4046:
                    addr = TEXT_ADDR + (file_off - TEXT_OFF)
                    print('  Found: MOVZ W{}, #0x6D6C; MOVK W{}, #0x4046, LSL #16 => 0x{:08x} (lmF@) at 0x{:x}'.format(
                        Rd, Rd, (0x4046 << 16) | 0x6D6C, addr))
                    for co in range(max(TEXT_OFF, file_off - 8), min(TEXT_OFF + TEXT_SIZE, file_off + 20), 4):
                        ci = struct.unpack_from('<I', so, co)[0]
                        ca = TEXT_ADDR + (co - TEXT_OFF)
                        marker = ' <--' if co >= file_off and co < file_off + 8 else ''
                        print('    0x{:x}: {:08x}{}'.format(ca, ci, marker))

# Check 2: MOVZ + MOVK for 0x40466D6C with different value ordering
for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 8, 4):
    instr = struct.unpack_from('<I', so, file_off)[0]
    if ((instr >> 29) & 3) == 2 and (instr & 0x1F000000) == 0:  # MOVZ 32-bit
        hw = (instr >> 21) & 3
        imm16 = (instr >> 5) & 0xFFFF
        Rd = instr & 0x1F
        if hw == 0 and imm16 == 0x4046:
            next_instr = struct.unpack_from('<I', so, file_off + 4)[0]
            if ((next_instr >> 29) & 3) == 3:  # MOVK
                next_hw = (next_instr >> 21) & 3
                next_imm16 = (next_instr >> 5) & 0xFFFF
                next_Rd = next_instr & 0x1F
                if Rd == next_Rd and next_hw == 1 and next_imm16 == 0x6D6C:
                    addr = TEXT_ADDR + (file_off - TEXT_OFF)
                    print('  Found (reversed): MOVZ W{}, #0x4046; MOVK W{}, #0x6D6C, LSL #16 => 0x{:08x} at 0x{:x}'.format(
                        Rd, Rd, (0x6D6C << 16) | 0x4046, addr))

# Also search for be "lmF@" = 0x6C6D4640
for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 8, 4):
    instr = struct.unpack_from('<I', so, file_off)[0]
    if ((instr >> 29) & 3) == 2 and (instr & 0x1F000000) == 0:
        hw = (instr >> 21) & 3
        imm16 = (instr >> 5) & 0xFFFF
        Rd = instr & 0x1F
        if hw == 0 and imm16 == 0x4640:
            next_instr = struct.unpack_from('<I', so, file_off + 4)[0]
            if ((next_instr >> 29) & 3) == 3:
                next_hw = (next_instr >> 21) & 3
                next_imm16 = (next_instr >> 5) & 0xFFFF
                next_Rd = next_instr & 0x1F
                if Rd == next_Rd and next_hw == 1 and next_imm16 == 0x6C6D:
                    addr = TEXT_ADDR + (file_off - TEXT_OFF)
                    print('  Found (BE): MOVZ W{}, #0x4640; MOVK W{}, #0x6C6D, LSL #16 => 0x{:08x} at 0x{:x}'.format(
                        Rd, Rd, (0x6C6D << 16) | 0x4640, addr))
