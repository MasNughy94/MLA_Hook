"""
Disassemble the REAL .mt pipeline function at 0x910E30.
This is the function that the thunk 0x7D27E8 dispatches to.
It processes the .mt decryption and returns a C++ object.
"""

import struct

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    data = f.read()

# Function at vaddr 0x910E30, file offset 0x910E30
TEXT_BASE = 0  # first LOAD segment maps vaddr=0, file=0

def decode_instr(at_vaddr):
    """Check what kind of instruction this is."""
    off = at_vaddr - TEXT_BASE  # file offset = vaddr since vaddr starts at 0
    instr = struct.unpack_from('<I', data, off)[0]
    a = at_vaddr
    
    if (instr >> 26) == 0x25:  # BL
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        target = a + (imm26 << 2)
        return 'BL     -> 0x{:x}'.format(target)
    elif instr == 0xD65F03C0:
        return 'RET'
    elif (instr >> 26) == 0x05:  # B
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        target = a + (imm26 << 2)
        return 'B      -> 0x{:x}'.format(target)
    elif (instr & 0xFF1FFFFF) == 0xD63F0000:  # BLR Xn
        reg = (instr >> 5) & 0x1F
        return 'BLR    X{}'.format(reg)
    elif (instr & 0xFF1FFFFF) == 0xD61F0000:  # BR Xn
        reg = (instr >> 5) & 0x1F
        return 'BR     X{}'.format(reg)
    elif (instr >> 24) == 0x54:  # B.cond
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        target = a + (imm19 << 2)
        cond_codes = ['EQ', 'NE', 'CS/HS', 'CC/LO', 'MI', 'PL', 'VS', 'VC', 'HI', 'LS', 'GE', 'LT', 'GT', 'LE', 'AL', 'NV']
        cond = cond_codes[instr & 0xF]
        return 'B.{}   -> 0x{:x}'.format(cond, target)
    elif (instr >> 24) == 0x34:  # CBZ Wt
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        target = a + (imm19 << 2)
        return 'CBZ   W{}, -> 0x{:x}'.format(instr & 0x1F, target)
    elif (instr >> 24) == 0x35:  # CBNZ Wt
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        target = a + (imm19 << 2)
        return 'CBNZ  W{}, -> 0x{:x}'.format(instr & 0x1F, target)
    elif (instr >> 24) == 0xB4:  # CBZ Xt
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        target = a + (imm19 << 2)
        return 'CBZ   X{}, -> 0x{:x}'.format(instr & 0x1F, target)
    elif (instr >> 24) == 0xB5:  # CBNZ Xt
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        target = a + (imm19 << 2)
        return 'CBNZ  X{}, -> 0x{:x}'.format(instr & 0x1F, target)
    elif (instr & 0x1F000000) == 0x10000000:  # ADR
        immhi = (instr >> 5) & 0x7FFFF
        immlo = (instr >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm >= 0x80000: imm -= 0x100000
        target = a + imm
        return 'ADR    X{}, -> 0x{:x}'.format(instr & 0x1F, target)
    elif (instr & 0x1F000000) == 0x90000000:  # ADRP
        immhi = (instr >> 5) & 0x7FFFF
        immlo = (instr >> 29) & 0x3
        imm = (immhi << 2) | immlo
        if imm >= 0x80000: imm -= 0x100000
        target = (a & ~0xFFF) + (imm << 12)
        return 'ADRP   X{}, -> 0x{:x}'.format(instr & 0x1F, target)
    elif (instr >> 24) == 0x18:  # LDR Wt, literal
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 -= 0x80000
        target = a + (imm19 << 2)
        # Check if target is aligned constant pool
        off_t = target
        val = struct.unpack_from('<I', data, off_t)[0]
        return 'LDR    W{}, =0x{:x} (at 0x{:x})'.format(instr & 0x1F, val, target)
    elif (instr >> 24) == 0x58:  # LDR Xt, literal
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 -= 0x80000
        target = a + (imm19 << 2)
        val = struct.unpack_from('<Q', data, target)[0]
        return 'LDR    X{}, =0x{:x} (at 0x{:x})'.format(instr & 0x1F, val, target)
    else:
        return '{:08x}'.format(instr)

# Show the function
print('=' * 70)
print('REAL .mt PIPELINE function at 0x910E30:')
print('=' * 70)

func_addr = 0x910E30
for i in range(100):
    a = func_addr + i * 4
    decoded = decode_instr(a)
    print('  0x{:x}: {}'.format(a, decoded))
    if decoded == 'RET':
        break

# Also show: what BL targets does this function call?
print('\nBL targets from 0x910E30:')
for i in range(100):
    a = func_addr + i * 4
    decoded = decode_instr(a)
    if decoded.startswith('BL     ->'):
        target = int(decoded.split('0x')[1], 16)
        print('  0x{:x}: {}'.format(a, decoded))
        
        # Check what the target function does (show its first few instructions)
        print('    Target 0x{:x}:'.format(target))
        for j in range(8):
            t = target + j * 4
            td = decode_instr(t)
            print('      0x{:x}: {}'.format(t, td))
            if td == 'RET':
                break
    if decoded == 'RET':
        break
