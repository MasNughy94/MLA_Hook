"""
Trace 0xC82944 - the decompressed buffer consumer called from cocos2dx_lua_loader.
This is the FIRST function that reads the decompressed .mt format.
"""

import struct

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    data = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def ra(addr):
    off = addr - TEXT_ADDR + TEXT_OFF
    return struct.unpack_from('<I', data, off)[0]

# First find the function start of 0xC82944
# Search backwards for STP X29, X30 prologue
def find_func_start(addr):
    file_off = addr - TEXT_ADDR + TEXT_OFF
    for lookback in range(0, 500):
        check_off = file_off - lookback * 4
        check_addr = addr - lookback * 4
        if check_off < TEXT_OFF: break
        instr = struct.unpack_from('<I', data, check_off)[0]
        if (instr & 0xFF000000) in (0xA8000000, 0xA9000000):
            rt = instr & 0x1F; rn = (instr >> 5) & 0x1F; rt2 = (instr >> 10) & 0x1F
            if rt == 29 and rt2 == 30 and rn == 31:
                return check_addr
    return None

def show_func(addr, count=200):
    off = addr - TEXT_ADDR + TEXT_OFF
    for i in range(count):
        if off + i*4 >= TEXT_OFF + TEXT_SIZE: break
        instr = struct.unpack_from('<I', data, off + i*4)[0]
        a = addr + i*4
        
        if (instr >> 26) == 0x25:  # BL
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000: imm26 -= 0x4000000
            target = a + (imm26 << 2)
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
            i += 1; break
        elif (instr >> 25) in (0x54, 0x55) and (instr >> 24) not in (0x54, 0x55):
            # B.cond
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            print('  0x{:x}: B.{}    0x{:x}'.format(a, instr & 0xF, target))
        elif (instr >> 24) == 0x34:  # CBZ W
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            print('  0x{:x}: CBZ    W{}, 0x{:x}'.format(a, instr & 0x1F, target))
        elif (instr >> 24) == 0x35:  # CBNZ W
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            print('  0x{:x}: CBNZ   W{}, 0x{:x}'.format(a, instr & 0x1F, target))
        elif (instr >> 24) == 0xB4:  # CBZ X
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            print('  0x{:x}: CBZ    X{}, 0x{:x}'.format(a, instr & 0x1F, target))
        elif (instr >> 24) == 0xB5:  # CBNZ X
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            print('  0x{:x}: CBNZ   X{}, 0x{:x}'.format(a, instr & 0x1F, target))
        else:
            print('  0x{:x}: {:08x}'.format(a, instr))

print('=== Function 0xC82944 ===')
start = find_func_start(0xC82944)
print('Start: 0x{:x}'.format(start))
show_func(start, 200)

print()

# Also check 0xC829A0 and 0xC82A30 (called from Antm pipeline)
print('=== Function 0xC829A0 ===')
start2 = find_func_start(0xC829A0)
print('Start: 0x{:x}'.format(start2))
show_func(start2, 100)

print()
print('=== Function 0xC82A30 ===')
start3 = find_func_start(0xC82A30)
print('Start: 0x{:x}'.format(start3))
show_func(start3, 80)

print()
print('=== Function 0xC828EC (Antm reader?) ===')
start4 = find_func_start(0xC828EC)
print('Start: 0x{:x}'.format(start4))
show_func(start4, 80)
