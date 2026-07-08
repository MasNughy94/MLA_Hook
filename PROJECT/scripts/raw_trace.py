"""
Simply dump raw hex and decode BL/B targets from the pipeline functions.
Focus on the call chain from cocos2dx_lua_loader -> 0xC82944 -> ???
"""

import struct

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    data = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def dump_func(addr, count=30):
    off = addr - TEXT_ADDR + TEXT_OFF
    BL_targets = set()
    for i in range(count):
        if off + i*4 >= TEXT_OFF + TEXT_SIZE: break
        instr = struct.unpack_from('<I', data, off + i*4)[0]
        a = addr + i*4
        
        # BL check (all branch encodings)
        if (instr >> 26) in (0x05, 0x25):  # B or BL
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000: imm26 -= 0x4000000
            target = a + (imm26 << 2)
            if 0x200000 <= target <= 0x1200000:  # plausible code address
                m = 'BL' if (instr >> 26) == 0x25 else 'B '
                BL_targets.add(target)
                print('  0x{:x}: {} -> 0x{:x} (offset {:+#x})'.format(a, m, target, imm26<<2))
            else:
                print('  0x{:x}: {:08x} {} -> 0x{:x} (OUT OF RANGE)'.format(a, instr, 
                    'BL' if (instr >> 26) == 0x25 else 'B ', target))
        elif instr == 0xD65F03C0:
            print('  0x{:x}: {:08x} RET'.format(a, instr))
            return BL_targets
        else:
            print('  0x{:x}: {:08x}'.format(a, instr))
    return BL_targets

# Also search for ADRP+ADD+BLR sequences that load function addresses
def find_blr_to_target(target_addr):
    """Search for ADRP+ADD+BLR loading target_addr anywhere."""
    page = target_addr & ~0xFFF
    offset = target_addr & 0xFFF
    results = []
    
    for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 16, 4):
        instr = struct.unpack_from('<I', data, file_off)[0]
        addr = TEXT_ADDR + (file_off - TEXT_OFF)
        
        if (instr >> 24) == 0x90:  # ADRP
            Rd = instr & 0x1F
            immhi = (instr >> 5) & 0x7FFFF
            immlo = (instr >> 29) & 3
            if immhi >= 0x40000: immhi |= 0xFFF80000
            imm = (immhi << 2) | immlo
            target_page = (addr & ~0xFFF) + (imm << 12)
            
            if target_page == page:
                for j in range(1, 10):
                    ci = struct.unpack_from('<I', data, file_off + j*4)[0]
                    if (ci >> 24) == 0x91:  # ADD
                        add_Rd = ci & 0x1F
                        add_Rn = (ci >> 5) & 0x1F
                        add_imm12 = (ci >> 10) & 0xFFF
                        if add_Rn == Rd and add_Rd == Rd and add_imm12 == offset:
                            for k in range(j+1, 8):
                                ck = struct.unpack_from('<I', data, file_off + k*4)[0]
                                if (ck & 0xFFFFFC00) == 0xD63F0000 and (ck & 0x1F) == Rd:
                                    results.append(TEXT_ADDR + (file_off - TEXT_OFF) + k*4)
                                    break
                            break
    return results

# =================================================
# 1. Dump the consumer function at 0xC82944
# =================================================
print('=== 0xC82944 (consumer called after Lua check fails) ===')
targets1 = dump_func(0xC8293C, 50)

# 2. Dump nearby functions that form the consumer pipeline
print('\n=== 0xC828A0 (init struct) ===')
dump_func(0xC828A0, 10)

print('\n=== 0xC828B4 (helper 1) ===')
dump_func(0xC828B4, 30)

print('\n=== 0xC828D4 (helper 2) ===')
dump_func(0xC828D4, 30)

print('\n=== 0xC828DC (helper 3) ===')
dump_func(0xC828DC, 30)

print('\n=== 0xC828E4 (helper 4) ===')
dump_func(0xC828E4, 30)

print('\n=== 0xC828EC (helper 5) ===')
dump_func(0xC828EC, 30)

print('\n=== 0xC829A0 (helper 6) ===')
dump_func(0xC82998, 30)

print('\n=== 0xC82A30 (helper 7) ===')
dump_func(0xC82A18, 30)

# 3. Search for what calls 0xC82944 via BLR
print('\n=== BLR callers of 0xC82944 ===')
blr_callers = find_blr_to_target(0xC82944)
if blr_callers:
    for addr in blr_callers:
        print('  BLR at 0x{:x} calls 0xC82944'.format(addr))

# 4. Also check: does the pipeline function call 0xC82944 via BL?
print('\n=== BL callers of 0xC82944 ===')
for off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 4, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr >> 26) == 0x25:  # BL
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        addr = TEXT_ADDR + (off - TEXT_OFF)
        target = addr + (imm26 << 2)
        if target == 0xC82944 or target == 0xC8293C:
            print('  BL from 0x{:x}'.format(addr))
