"""
Trace the EXACT return path of the decompressed buffer.

Flow:
1. LMF decompressor (0x5B2400) called from 0x5B279C
2. The transform function at 0x5B2714 returns decompressed buffer
3. Where does it return TO?
4. What consumes it?

Also check luaLoadBuffer to see what it does with non-Lua output.
"""

import struct

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    data = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def ra(addr):
    """Read instruction at virtual address."""
    off = addr - TEXT_ADDR + TEXT_OFF
    return struct.unpack_from('<I', data, off)[0]

def find_func_start(addr):
    file_off = addr - TEXT_ADDR + TEXT_OFF
    for lookback in range(0, 1000):
        check_off = file_off - lookback * 4
        check_addr = addr - lookback * 4
        if check_off < TEXT_OFF:
            break
        instr = struct.unpack_from('<I', data, check_off)[0]
        # STP X29, X30, [SP, #imm]!
        if (instr & 0xFF000000) == 0xA8000000:
            rt = instr & 0x1F; rn = (instr >> 5) & 0x1F; rt2 = (instr >> 10) & 0x1F
            if rt == 29 and rt2 == 30 and rn == 31:
                return check_addr
        if (instr & 0xFF000000) == 0xA9000000:
            rt = instr & 0x1F; rn = (instr >> 5) & 0x1F; rt2 = (instr >> 10) & 0x1F
            if rt == 29 and rt2 == 30 and rn == 31:
                return check_addr
    return None

def show_block(addr, count=60):
    """Show instructions at addr, decoding BL and RET."""
    off = addr - TEXT_ADDR + TEXT_OFF
    for i in range(count):
        instr = struct.unpack_from('<I', data, off + i*4)[0]
        a = addr + i*4
        if (instr >> 26) == 0x25:  # BL
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000: imm26 -= 0x4000000
            target = a + (imm26 << 2)
            print('  0x{:x}: BL      0x{:x}'.format(a, target))
        elif (instr >> 26) == 0x05:  # B
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000: imm26 -= 0x4000000
            target = a + (imm26 << 2)
            print('  0x{:x}: B       0x{:x}'.format(a, target))
        elif instr == 0xD65F03C0:
            print('  0x{:x}: RET'.format(a))
            # Check if next is STP (new function)
            if i+1 < count:
                nxt = struct.unpack_from('<I', data, off + (i+1)*4)[0]
                if (nxt & 0xFF000000) == 0xA8000000 or (nxt & 0xFF000000) == 0xA9000000:
                    pass  # will be shown next iteration
            break
        elif instr == 0xAA0003E0:
            print('  0x{:x}: MOV     X0, X0'.format(a))
        elif (instr & 0xFFFFFC00) == 0xD63F0000:
            print('  0x{:x}: BLR     X{}'.format(a, instr & 0x1F))
        else:
            print('  0x{:x}: {:08x}'.format(a, instr))

# ==========================================
# 1. Show the transform function (0x5B2714) 
# ==========================================
print('=' * 70)
print('1. TRANSFORM FUNCTION at 0x5B2714 (called from luaLoadBuffer)')
print('=' * 70)

func_start = find_func_start(0x5B2714)
print('Function start: 0x{:x}'.format(func_start))
show_block(func_start, 80)

print()

# Find where the LMF decompressor output is used
# After BL to 0x5B2400 at 0x5B279C
# 0x5B27A0: MOV X19, X0 (save return value)
# 0x5B27A4: MOV X0, X23 (another arg?)
# 0x5B27A8: BL ??? (another call)
# 0x5B27AC: MOV X0, X19 (restore decompressed buffer to return)
# 0x5B27B0: LDP X19, X20, [SP, #...]
# ...
# 0x5B27B4: RET

# Let me check the instruction at 0x5B27A8 - what does it call?
print()
print('Context around LMF call at 0x5B279C:')
for addr in range(0x5B2780, 0x5B27C0, 4):
    instr = ra(addr)
    if (instr >> 26) == 0x25:
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        target = addr + (imm26 << 2)
        print('  0x{:x}: BL 0x{:x}'.format(addr, target))
    elif instr == 0xD65F03C0:
        print('  0x{:x}: RET'.format(addr))
    else:
        print('  0x{:x}: {:08x}'.format(addr, instr))

# ==========================================
# 2. Trace luaLoadBuffer (0x47249C)
# ==========================================
print()
print('=' * 70)
print('2. luaLoadBuffer at 0x47249C')
print('=' * 70)

func_start2 = find_func_start(0x47249C)
print('Function start: 0x{:x}'.format(func_start2))
print()
print('Call path:')
# Find what calls luaLoadBuffer
callers_of_luaload = []
for off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 4, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr >> 26) == 0x25:
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        addr = TEXT_ADDR + (off - TEXT_OFF)
        target = addr + (imm26 << 2)
        if target == 0x47249C or target == func_start2:
            print('  -> Called from: 0x{:x}'.format(addr))

# Also check for ADRP+BLR pattern
page_luaload = 0x47249C & ~0xFFF
for off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 16, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    addr = TEXT_ADDR + (off - TEXT_OFF)
    
    if (instr >> 24) == 0x90:  # ADRP
        Rd = instr & 0x1F
        immhi = (instr >> 5) & 0x7FFFF
        immlo = (instr >> 29) & 3
        if immhi >= 0x40000: immhi |= 0xFFF80000
        imm = (immhi << 2) | immlo
        target_page = (addr & ~0xFFF) + (imm << 12)
        if target_page == page_luaload:
            # Check ADD + BLR
            for j in range(1, 10):
                ci = struct.unpack_from('<I', data, off + j*4)[0]
                if (ci >> 24) == 0x91:  # ADD
                    add_Rd = ci & 0x1F
                    add_Rn = (ci >> 5) & 0x1F
                    add_imm12 = (ci >> 10) & 0xFFF
                    if add_Rn == Rd and add_Rd == Rd and add_imm12 == (0x47249C & 0xFFF):
                        # Found ADRP+ADD. Check for BLR
                        for k in range(j+1, j+8):
                            ck = struct.unpack_from('<I', data, off + k*4)[0]
                            if (ck & 0xFFFFFC00) == 0xD63F0000 and (ck & 0x1F) == Rd:
                                print('  -> Called from (ADRP+ADD+BLR): 0x{:x}'.format(
                                    TEXT_ADDR + (off - TEXT_OFF) + k*4))
                                break
                        break
