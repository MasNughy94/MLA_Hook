"""
Trace luaLoadBuffer's handling of the decompressed output.
Look specifically at what happens AFTER the transform function returns
and when luaL_loadbuffer succeeds/fails.
"""

import struct

with open(r'C:\Users\NGEONG\Videos\VSCODE\libagame.so', 'rb') as f:
    data = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def ra(addr):
    off = addr - TEXT_ADDR + TEXT_OFF
    match = struct.unpack_from('<I', data, off)
    return match[0]

# Show the full luaLoadBuffer function at 0x47249C
# First find its BL calls
print('=== luaLoadBuffer at 0x47249C ===')
print('Full disassembly (with BL targets):')
func_start = 0x47249C
off = func_start - TEXT_ADDR + TEXT_OFF

# Go until we hit multiple returns or 200 instructions
i = 0
while i < 200:
    instr = ra(func_start + i*4)
    a = func_start + i*4
    
    # Decode
    if (instr >> 26) == 0x25:  # BL
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        target = a + (imm26 << 2)
        # Check if target is in valid range
        if TEXT_ADDR <= target < TEXT_ADDR + TEXT_SIZE:
            print('  0x{:x}: BL      0x{:x}'.format(a, target))
        else:
            print('  0x{:x}: BL      (0x{:x})'.format(a, target))
    elif (instr >> 26) == 0x05:  # B
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        target = a + (imm26 << 2)
        if TEXT_ADDR <= target < TEXT_ADDR + TEXT_SIZE:
            print('  0x{:x}: B       0x{:x}'.format(a, target))
        else:
            print('  0x{:x}: B       (0x{:x})'.format(a, target))
    elif instr == 0xD65F03C0:
        print('  0x{:x}: RET'.format(a))
        i += 1
        break
    elif (instr >> 25) == 0x54 or (instr >> 25) == 0x55:  # B.cond
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        cond = instr & 0xF
        target = a + (imm19 << 2)
        print('  0x{:x}: B.{}    0x{:x}'.format(a, cond, target))
    elif (instr >> 24) == 0x34:  # CBZ
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        Rt = instr & 0x1F
        target = a + (imm19 << 2)
        print('  0x{:x}: CBZ    W{}, 0x{:x}'.format(a, Rt, target))
    elif (instr >> 24) == 0x35:  # CBNZ
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        Rt = instr & 0x1F
        target = a + (imm19 << 2)
        print('  0x{:x}: CBNZ   W{}, 0x{:x}'.format(a, Rt, target))
    elif (instr >> 24) == 0xB4:  # CBZ (64-bit)
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        Rt = instr & 0x1F
        target = a + (imm19 << 2)
        print('  0x{:x}: CBZ    X{}, 0x{:x}'.format(a, Rt, target))
    elif (instr >> 24) == 0xB5:  # CBNZ (64-bit)
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        Rt = instr & 0x1F
        target = a + (imm19 << 2)
        print('  0x{:x}: CBNZ   X{}, 0x{:x}'.format(a, Rt, target))
    elif instr == 0xD503201F:  # NOP
        print('  0x{:x}: NOP'.format(a))
    else:
        print('  0x{:x}: {:08x}'.format(a, instr))
    i += 1

# Now find callers of the transform function from luaLoadBuffer
print('\n=== Transform function 0x5B2714 callers ===')
for off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 4, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr >> 26) == 0x25:  # BL
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        addr = TEXT_ADDR + (off - TEXT_OFF)
        target = addr + (imm26 << 2)
        if target == 0x5B2714:
            print('  BL from 0x{:x} (offset from func start: 0x{:x})'.format(addr, addr - 0x47249C))

# Also trace what 0x474300 does (the lua_loader call to luaLoadBuffer)
print('\n=== Context of 0x474300 (caller of luaLoadBuffer in cocos2dx_lua_loader) ===')
for addr in range(0x4742E0, 0x474340, 4):
    instr = ra(addr)
    if (instr >> 26) == 0x25:
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        target = addr + (imm26 << 2)
        print('  0x{:x}: BL      0x{:x}'.format(addr, target))
    elif (instr >> 26) == 0x05:
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        target = addr + (imm26 << 2)
        print('  0x{:x}: B       0x{:x}'.format(addr, target))
    elif (instr >> 24) == 0x35:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        Rt = instr & 0x1F
        target = addr + (imm19 << 2)
        print('  0x{:x}: CBNZ   W{}, 0x{:x}'.format(addr, Rt, target))
    elif instr == 0xD65F03C0:
        print('  0x{:x}: RET'.format(addr))
    else:
        print('  0x{:x}: {:08x}'.format(addr, instr))
