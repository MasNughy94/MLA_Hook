"""
Find the Roo parser by searching for:
1. Decompressed data constants (magic 0x006D4C1B, type "Roo" 0x006F6F52)
2. LDR literal accesses near these constants
3. The class factory / constructor functions
"""

import struct

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    data = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def find_constant_refs(target_val, label):
    """Find a 32-bit constant value in the TEXT section and nearby LDR literals."""
    target_bytes = struct.pack('<I', target_val)
    
    # Search for the constant value
    results = []
    for off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 4, 1):
        if data[off:off+4] == target_bytes:
            addr = off - TEXT_OFF + TEXT_ADDR
            results.append(addr)
    
    return results

# ============================================================
# 1. Search for decompressed data constants in the TEXT section
# ============================================================
print('=' * 70)
print('1. Searching for decompressed data magic/type constants in TEXT section')
print('=' * 70)

# Magic: 1B 4C 6D 00 -> LE 32-bit: 0x006D4C1B
magic_val = 0x006D4C1B
matches = find_constant_refs(magic_val, 'magic')
print('  magic (0x006D4C1B = "\\x1bLm\\x00"): {} occurrences'.format(len(matches)))
for m in matches[:20]:
    print('    -> 0x{:x}'.format(m))

# Short magic: 1B 4C = 0x4C1B
matches = find_constant_refs(0x4C1B, 'short_magic')
print('\n  short magic (0x4C1B = "\\x1bL"): {} occurrences'.format(len(matches)))
for m in matches[:20]:
    print('    -> 0x{:x}'.format(m))

# "Roo" type: R=0x52, o=0x6F, o=0x6F -> LE 32-bit: 0x006F6F52
roo_val = 0x006F6F52
matches = find_constant_refs(roo_val, 'roo')
print('\n  "Roo" (0x006F6F52): {} occurrences'.format(len(matches)))
for m in matches[:20]:
    print('    -> 0x{:x}'.format(m))

# Short "Ro": 0x6F52
ro_short = 0x6F52
matches = find_constant_refs(ro_short, 'ro_short')
print('\n  "Ro" (0x6F52): {} occurrences'.format(len(matches)))
for m in matches[:20]:
    print('    -> 0x{:x}'.format(m))

# "Lua" type: L=0x4C, u=0x75, a=0x61 -> LE 32-bit: 0x0? Actually Lua header = 1B 4C 75 61
# Full magic: 1B 4C 75 61 = 0x61754C1B
lua_magic = 0x61754C1B
matches = find_constant_refs(lua_magic, 'lua_magic')
print('\n  Lua magic (0x61754C1B = "\\x1bLua"): {} occurrences'.format(len(matches)))
for m in matches[:20]:
    print('    -> 0x{:x}'.format(m))

# Try byte variant: \x1bL (0x1B 0x4C) as 16-bit
matches = find_constant_refs(0x006D4C, 'magic_3byte')
print('\n  magic 3-byte (0x006D4C): {} occurrences'.format(len(matches)))
for m in matches[:20]:
    print('    -> 0x{:x}'.format(m))

# ============================================================
# 2. For each found constant, check if there's an LDR literal nearby
# ============================================================
print('\n' + '=' * 70)
print('2. Checking for LDR literal references near magic constants')
print('=' * 70)

for const_addr in find_constant_refs(magic_val, 'magic')[:5]:
    # An LDR literal has format: 0x98000000 | imm19<<5 | Rt
    # The target PC-relative address = (LDR_addr & ~3) + imm19<<2
    # The constant should be at: const_addr = LDR_addr + imm<<2 (within ~1MB)
    
    # Search backward for LDR that could reference this constant
    # LDR literal encoding: 01 011 000 imm19[18:0] Rt[4:0]
    for delta in range(4, 0x1000, 4):  # search back up to 4KB
        ldr_addr = const_addr - delta
        if ldr_addr < TEXT_ADDR: break
        off = ldr_addr - TEXT_ADDR + TEXT_OFF
        instr = struct.unpack_from('<I', data, off)[0]
        
        # Check if LDR literal (bits 31:24 = 0x18 for W, 0x58 for Xt)
        if (instr >> 24) == 0x18:  # LDR Wt, label (32-bit)
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 -= 0x80000
            target = ldr_addr + (imm19 << 2)
            if target == const_addr:
                print('  0x{:x}: LDR W{}, -> 0x{:x} (constant at 0x{:x})'.format(
                    ldr_addr, instr & 0x1F, target, const_addr))
        elif (instr >> 24) == 0x58:  # LDR Xt, label (64-bit)
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 -= 0x80000
            target = ldr_addr + (imm19 << 2)
            if target == const_addr:
                print('  0x{:x}: LDR X{}, -> 0x{:x} (64-bit at 0x{:x})'.format(
                    ldr_addr, instr & 0x1F, target, const_addr))
    
    # Also check subsequent LDRs
    for delta in range(4, 0x1000, 4):
        ldr_addr = const_addr + delta
        if ldr_addr > TEXT_ADDR + TEXT_SIZE: break
        off = ldr_addr - TEXT_ADDR + TEXT_OFF
        instr = struct.unpack_from('<I', data, off)[0]
        
        if (instr >> 24) == 0x18:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 -= 0x80000
            target = ldr_addr + (imm19 << 2)
            if target == const_addr:
                print('  0x{:x}: LDR W{}, -> 0x{:x} (constant at 0x{:x})'.format(
                    ldr_addr, instr & 0x1F, target, const_addr))
        elif (instr >> 24) == 0x58:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 -= 0x80000
            target = ldr_addr + (imm19 << 2)
            if target == const_addr:
                print('  0x{:x}: LDR X{}, -> 0x{:x} (64-bit at 0x{:x})'.format(
                    ldr_addr, instr & 0x1F, target, const_addr))

# ============================================================
# 3. Also search for "Roo" as string data
# ============================================================
print('\n' + '=' * 70)
print('3. Searching for "Roo" as string data')
print('=' * 70)
# "Roo" or "Roo\0"
for s in [b'Roo\x00', b'\x00Roo', b'ROO', b'rOO']:
    idx = data.find(s)
    if idx != -1:
        ctx = data[max(0,idx-8):idx+12]
        asc = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in ctx)
        print('  "{}" at 0x{:x}: {} | {}'.format(s.decode(), idx, asc, ctx.hex()))

# ============================================================
# 4. Look at the constructor 0xCDE13C called at 0x414A14
# ============================================================
print('\n' + '=' * 70)
print('4. Constructor at 0xCDE13C')
print('=' * 70)
off = 0xCDE13C - TEXT_ADDR + TEXT_OFF
for i in range(50):
    if off + i*4 >= len(data): break
    a = 0xCDE13C + i*4
    instr = struct.unpack_from('<I', data, off + i*4)[0]
    
    if (instr >> 26) == 0x25:  # BL
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        target = a + (imm26 << 2)
        if TEXT_ADDR <= target < TEXT_ADDR + TEXT_SIZE:
            print('  0x{:x}: BL      0x{:x}'.format(a, target))
        else:
            print('  0x{:x}: BL      (0x{:x})'.format(a, target))
    elif instr == 0xD65F03C0:
        print('  0x{:x}: RET'.format(a))
        break
    elif (instr >> 24) == 0x54:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        target = a + (imm19 << 2)
        cond = instr & 0xF
        print('  0x{:x}: B.{}    0x{:x}'.format(a, cond, target))
    elif (instr >> 24) == 0x34:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        target = a + (imm19 << 2)
        print('  0x{:x}: CBZ    W{}, 0x{:x}'.format(a, instr & 0x1F, target))
    elif (instr >> 24) == 0x35:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        target = a + (imm19 << 2)
        print('  0x{:x}: CBNZ   W{}, 0x{:x}'.format(a, instr & 0x1F, target))
    elif (instr >> 26) == 0x05:  # B
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        target = a + (imm26 << 2)
        print('  0x{:x}: B       0x{:x}'.format(a, target))
    else:
        print('  0x{:x}: {:08x}'.format(a, instr))
