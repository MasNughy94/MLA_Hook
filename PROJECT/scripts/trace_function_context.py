"""
The thunk 0x7D27E8 loads a function pointer from a context struct (X21).
Let me find WHO sets X21 and calls 0x7D27E8.
And trace the second pipeline at 0xC62F60 (different context setup).
"""

import struct

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    data = f.read()

def decode_adrp(at_vaddr):
    instr = struct.unpack_from('<I', data, at_vaddr)[0]
    if (instr >> 31) != 1: return None
    immhi = (instr >> 5) & 0x7FFFF
    immlo = (instr >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm >= 0x80000: imm -= 0x100000
    return (at_vaddr & ~0xFFF) + (imm << 12)

def show_func(addr, count=40):
    out = []
    off = addr
    for i in range(count):
        if off + i*4 >= len(data): break
        a = addr + i*4
        instr = struct.unpack_from('<I', data, off + i*4)[0]
        
        if (instr >> 26) == 0x25:
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000: imm26 -= 0x4000000
            target = a + (imm26 << 2)
            info = '(->0x{:x})'.format(target) if target < 0x1200000 else '(ext)'
            out.append('  BL {}'.format(info))
        elif instr == 0xD65F03C0:
            out.append('  RET')
            return '\n'.join(out)
        elif (instr >> 23) == 0x1F9 and (instr & 0x0C000000) == 0x00000000:
            match = True
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            out.append('  LDR X{}, [X{}, #0x{:x}]'.format(rt, rn, imm12 * 8))
            match = True
        elif (instr >> 23) == 0x1F9 and (instr >> 22) & 1:
            imm9 = (instr >> 12) & 0x1FF
            if imm9 >= 0x100: imm9 -= 0x200
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            # Check if post-index (bits[11:10] = 01)
            mode = (instr >> 10) & 3
            if mode == 1:
                out.append('  LDR X{}, [X{}], #0x{:x}'.format(rt, rn, imm9))
            elif mode == 2:
                out.append('  LDR X{}, [X{}, #0x{:x}]!'.format(rt, rn, imm9))
            elif mode == 0:
                out.append('  LDUR X{}, [X{}, #0x{:x}]'.format(rt, rn, imm9))
        elif (instr >> 26) == 0x05:
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000: imm26 -= 0x4000000
            target = a + (imm26 << 2)
            out.append('  B -> 0x{:x}'.format(target))
        elif (instr >> 24) == 0x54:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            out.append('  B.{} -> 0x{:x}'.format('EQ' if (instr & 0xF) == 0 else 'NE' if (instr & 0xF) == 1 else '??', target))
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
        elif (instr >> 24) == 0xB4:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            out.append('  CBZ X{}, -> 0x{:x}'.format(instr & 0x1F, target))
        elif (instr >> 24) == 0xB5:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            out.append('  CBNZ X{}, -> 0x{:x}'.format(instr & 0x1F, target))
        elif (instr & 0xFF1FFFFF) == 0xD63F0000:
            out.append('  BLR X{}'.format((instr >> 5) & 0x1F))
        elif (instr & 0x1F000000) == 0x90000000:
            page = decode_adrp(a)
            out.append('  ADRP X{}, -> 0x{:x}'.format(instr & 0x1F, page))
        elif (instr >> 22) == 0x3E5:
            imm12 = (instr >> 10) & 0xFFF
            rn = (instr >> 5) & 0x1F
            rt = instr & 0x1F
            out.append('  STR X{}, [X{}, #0x{:x}]'.format(rt, rn, imm12 * 8))
        else:
            out.append('  {:08x}'.format(instr))
    return '\n'.join(out)

# ============================================================
# 1. Show the full thunk function with correct disassembly
# ============================================================
print('=' * 70)
print('Thunk 0x7D27E8 (corrected)')
print('=' * 70)
print(show_func(0x7D27E8, 20))

# ============================================================
# 2. Find callers of 0x4149CC (the Roo parser candidate containing function)
# ============================================================
print('\n' + '=' * 70)
print('Callers of function at 0x4149CC:')
callers = []
off_start = 0x3FC000
off_end = 0x3FC000 + 0x9FA1EC
for off in range(off_start, off_end - 4, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr >> 26) == 0x25:  # BL
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        addr = off - off_start + 0x3FC000
        target = addr + (imm26 << 2)
        if target == 0x4149CC:
            callers.append(addr)
print('  {} callers found'.format(len(callers)))
for c in callers:
    print('    0x{:x}'.format(c))
    # Show first 12 lines of this caller
    print(show_func(c, 20))

# ============================================================
# 3. Show the second pipeline 0xC62F60 (also handles .mt)
# ============================================================
print('\n' + '=' * 70)
print('Second pipeline context function 0xC62F60:')
print('=' * 70)
print(show_func(0xC62F60, 20))

# Callers of 0xC62F60
print('\nCallers of 0xC62F60:')
callers2 = []
for off in range(off_start, off_end - 4, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr >> 26) == 0x25:
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        addr = off - off_start + 0x3FC000
        target = addr + (imm26 << 2)
        if target == 0xC62F60:
            callers2.append(addr)
print('  {} callers'.format(len(callers2)))
for c in callers2[:5]:
    print('    0x{:x}'.format(c))
    print(show_func(c, 15))
