"""
Trace 0x7D27E8 - the UNIVERSAL .mt pipeline with 200+ callers.
Show its implementation, and also trace a few NON-Lua callers to find the Roo parser.
"""

import struct

with open(r'C:\Users\NGEONG\Videos\VSCODE\libagame.so', 'rb') as f:
    data = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def show_func(addr, count=100):
    off = addr - TEXT_ADDR + TEXT_OFF
    results = []
    for i in range(count):
        if off + i*4 >= TEXT_OFF + TEXT_SIZE: break
        instr = struct.unpack_from('<I', data, off + i*4)[0]
        a = addr + i*4
        
        if (instr >> 26) == 0x25:
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000: imm26 -= 0x4000000
            target = a + (imm26 << 2)
            if TEXT_ADDR <= target < TEXT_ADDR + TEXT_SIZE:
                results.append('  0x{:x}: BL      0x{:x}'.format(a, target))
            else:
                results.append('  0x{:x}: BL      (0x{:x})'.format(a, target))
        elif (instr >> 26) == 0x05:
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000: imm26 -= 0x4000000
            target = a + (imm26 << 2)
            if TEXT_ADDR <= target < TEXT_ADDR + TEXT_SIZE:
                results.append('  0x{:x}: B       0x{:x}'.format(a, target))
            else:
                results.append('  0x{:x}: B       (0x{:x})'.format(a, target))
        elif instr == 0xD65F03C0:
            results.append('  0x{:x}: RET'.format(a))
            return results
        elif (instr >> 24) == 0x54:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            cond = instr & 0xF
            results.append('  0x{:x}: B.{}    0x{:x}'.format(a, cond, target))
        elif (instr >> 24) == 0x34:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            results.append('  0x{:x}: CBZ    W{}, 0x{:x}'.format(a, instr & 0x1F, target))
        elif (instr >> 24) == 0x35:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            results.append('  0x{:x}: CBNZ   W{}, 0x{:x}'.format(a, instr & 0x1F, target))
        elif (instr >> 24) == 0xB4:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            results.append('  0x{:x}: CBZ    X{}, 0x{:x}'.format(a, instr & 0x1F, target))
        elif (instr >> 24) == 0xB5:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            results.append('  0x{:x}: CBNZ   X{}, 0x{:x}'.format(a, instr & 0x1F, target))
        else:
            results.append('  0x{:x}: {:08x}'.format(a, instr))
    return results

# ============================================================
# 1. The universal .mt pipeline at 0x7D27E8
# ============================================================
print('=' * 70)
print('1. UNIVERSAL .mt PIPELINE (0x7D27E8) - has 200+ callers')
print('=' * 70)
for line in show_func(0x7D27E8, 50):
    print(line)

# ============================================================
# 2. The Antm orchestrator at 0x7D2888
# ============================================================
print('\n' + '=' * 70)
print('2. Antm orchestrator (0x7D2888)')
print('=' * 70)
for line in show_func(0x7D2888, 60):
    print(line)

# Check: does 0x7D27E8 BL to 0x7D2888?

# ============================================================
# 3. Callers of 0x7D2888
# ============================================================
print('\n' + '=' * 70)
print('3. 0x7D2E68 (caller of 0x7D2888)')
print('=' * 70)
for line in show_func(0x7D2E68, 30):
    print(line)

print('\n--- 0x7D2F4C (caller of 0x7D2888) ---')
for line in show_func(0x7D2F4C, 20):
    print(line)

# ============================================================
# 4. Quick view of some non-Lua callers
# ============================================================
print('\n' + '=' * 70)
print('4. Sample non-Lua callers:')
print('=' * 70)
# Show first 5 non-Lua callers and their context
callers_to_show = [0x414a1c, 0x41748c, 0x425f64, 0x432d98, 0x602ea4]
for caller in callers_to_show:
    print('\n--- Caller at 0x{:x} (showing 24 instrs before and after BL) ---'.format(caller))
    for line in show_func(caller - 32, 48):
        print(line)
