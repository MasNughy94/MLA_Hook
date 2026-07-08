"""
Trace: find the 3 "Ro" (0x6F52) occurrences and the vtable dispatch function.
Also check the call hierarchy to understand how 200+ callers use the pipeline.
"""

import struct

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    data = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def show_func(addr, count=50):
    out = []
    off = addr - TEXT_ADDR + TEXT_OFF
    for i in range(count):
        if off + i*4 >= len(data): break
        a = addr + i*4
        instr = struct.unpack_from('<I', data, off + i*4)[0]
        if (instr >> 26) == 0x25:
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000: imm26 -= 0x4000000
            target = a + (imm26 << 2)
            info = '(->0x{:x})'.format(target) if TEXT_ADDR <= target < TEXT_ADDR + TEXT_SIZE else '(ext)'
            out.append('  BL {}'.format(info).format(a, target))
        elif instr == 0xD65F03C0:
            out.append('  RET')
            return '\n'.join(out)
        elif (instr >> 26) == 0x05:
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000: imm26 -= 0x4000000
            target = a + (imm26 << 2)
            out.append('  B -> 0x{:x}'.format(target))
        elif (instr >> 24) == 0x54:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            out.append('  B.{} -> 0x{:x}'.format('eq/ne/??' if (instr & 0xF) == 0 else '??', target))
        elif (instr >> 24) == 0x34:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            out.append('  CBZ W{}, -> 0x{:x}'.format(instr & 0x1F, target))
        elif (instr >> 24) == 0x35:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            out.append('  CBNZ W{}, -> 0x{:x}'.format(instr & 0x1F, target))
        elif (instr & 0xFF1FFFFF) == 0xD63F0000:
            out.append('  BLR X{}'.format((instr >> 5) & 0x1F))
        else:
            # decode LDR literal
            if (instr >> 24) == 0x18:
                imm19 = (instr >> 5) & 0x7FFFF
                if imm19 >= 0x40000: imm19 -= 0x80000
                target = a + (imm19 << 2)
                out.append('  LDR W{}(=0x{:x} at 0x{:x})'.format(instr & 0x1F, target, target))
            elif (instr >> 24) == 0x58:
                imm19 = (instr >> 5) & 0x7FFFF
                if imm19 >= 0x40000: imm19 -= 0x80000
                target = a + (imm19 << 2)
                out.append('  LDR X{}(=0x{:x})'.format(instr & 0x1F, target))
            else:
                out.append('  {:08x}'.format(instr))
    return '\n'.join(out)

# ============================================================
# 1. Check the 3 "Ro" 0x6F52 occurrences
# ============================================================
print('=' * 70)
print('1. Three "Ro" (0x6F52) constant occurrences:')
print('=' * 70)

for const_addr in [0xa33287, 0xd19f47, 0xd3a14b]:
    print('\nAt 0x{:x} (within TEXT):'.format(const_addr))
    # Show surrounding context as raw bytes
    off = const_addr - TEXT_ADDR + TEXT_OFF
    ctx = data[off-8:off+12]
    asc = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in ctx)
    print('  Context hex: {} | "{}"'.format(ctx.hex(), asc))
    
    # Check if this is part of a LDR literal
    # Search both forward and backward for LDR targeting this
    for delta in range(-0x1000, 0x1000, 4):
        ldr_addr = const_addr + delta
        if ldr_addr < TEXT_ADDR or ldr_addr + 4 > TEXT_ADDR + TEXT_SIZE:
            continue
        off_ldr = ldr_addr - TEXT_ADDR + TEXT_OFF
        instr = struct.unpack_from('<I', data, off_ldr)[0]
        
        if (instr >> 24) == 0x18:  # LDR Wt
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 -= 0x80000
            target = ldr_addr + (imm19 << 2)
            if target == const_addr:
                print('  REFERENCED FROM: 0x{:x}: LDR W{}'.format(ldr_addr, instr & 0x1F))
                # Show function containing this LDR
                func_start = ldr_addr
                while func_start > TEXT_ADDR:
                    off_fs = func_start - 4 - TEXT_ADDR + TEXT_OFF
                    prev_instr = struct.unpack_from('<I', data, off_fs)[0]
                    # Check for prologue (STP X29, X30 or similar)
                    if (prev_instr >> 22) == 0x3C5:  # STP
                        break
                    func_start -= 4
                print('  Function at ~0x{:x}:'.format(func_start))
                for line in show_func(func_start, 35).split('\n'):
                    print('    ' + line)

# ============================================================
# 2. Check function 0xC664F8 - vtable dispatch wrapper for X2=2
# ============================================================
print('\n' + '=' * 70)
print('2. Function 0xC664F8 (vtable dispatch wrapper)')
print('=' * 70)
print(show_func(0xC664F8, 40))

# ============================================================
# 3. Also check 0xC6630C - another wrapper near 0xC664F8
# ============================================================
print('\n' + '=' * 70)
print('3. Function 0xC6630C (near vtable dispatcher)')
print('=' * 70)
print(show_func(0xC6630C, 30))

# ============================================================
# 4. Check what 0xCDF0AC does (called after vtable dispatch in caller 0x414A1C)
# ============================================================
print('\n' + '=' * 70)
print('4. Function 0xCDF0AC (called with returned object)')
print('=' * 70)
print(show_func(0xCDF0AC, 30))

# ============================================================
# 5. Also check 0xCDC3A0 and 0xCDB008
# ============================================================
print('\n' + '=' * 70)
print('5. Function 0xCDC3A0 (repeat call)')
print('=' * 70)
print(show_func(0xCDC3A0, 20))
