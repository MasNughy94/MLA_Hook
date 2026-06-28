"""
FIXED: Correctly decode the thunk at 0x7D27E8 and trace the pipeline function.
"""

import struct

with open(r'C:\Users\NGEONG\Videos\VSCODE\libagame.so', 'rb') as f:
    data = f.read()

def decode_adrp(at_vaddr):
    """Decode ADRP instruction at a given vaddr (where vaddr=file_offset for first segment)."""
    instr = struct.unpack_from('<I', data, at_vaddr)[0]
    if (instr >> 31) != 1:
        return None
    immhi = (instr >> 5) & 0x7FFFF
    immlo = (instr >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm >= 0x80000:
        imm -= 0x100000
    return (at_vaddr & ~0xFFF) + (imm << 12)

def decode_ldr_imm(at_vaddr):
    """Decode LDR Xt, [Xn, #imm] (unsigned offset) to get imm12."""
    instr = struct.unpack_from('<I', data, at_vaddr)[0]
    if (instr >> 22) == 0x3E5 and (instr & 0xC0000000) == 0x40000000:  # LDR Xt unsigned offset
        imm12 = (instr >> 10) & 0xFFF
        rn = (instr >> 5) & 0x1F
        rt = instr & 0x1F
        return rt, rn, imm12 * 8, 'LDR'
    return None

# ============================================================
# 1. Decode the thunk at 0x7D27E8 correctly
# ============================================================
print('=' * 70)
print('1. Thunk at 0x7D27E8 - correct instruction decoding')
print('=' * 70)

# ADRP at 0x7D27F4
page = decode_adrp(0x7D27F4)
print('  ADRP at 0x7D27F4 -> page 0x{:x}'.format(page))

# LDR at 0x7D27FC: LDR X0, [X20, #imm]
result = decode_ldr_imm(0x7D27FC)
if result:
    rt, rn, offset, kind = result
    global_addr = page + offset
    print('  {} X{}, [X{}, #0x{:x}] -> global at 0x{:x}'.format(kind, rt, rn, offset, global_addr))
else:
    print('  Failed to decode LDR at 0x7D27FC')

# LDR at 0x7D2800
result2 = decode_ldr_imm(0x7D2800)
if result2:
    rt, rn, offset, kind = result2
    # This is LDR X19, [X0] - X0 is the value just loaded from the global
    print('  {} X{}, [X{}, #0x{:x}] -> loads pipeline func ptr from [global_value]'.format(kind, rt, rn, offset))

# ============================================================
# 2. Read the global and the pipeline function address
# ============================================================
print('\n' + '=' * 70)
print('2. Reading the function pointers')
print('=' * 70)

# The global at global_addr contains a pointer
# Read 8 bytes from file offset (which = vaddr since first LOAD segments use vaddr=0)
ptr_val = struct.unpack_from('<Q', data, global_addr)[0]
print('  Global at 0x{:x} -> value: 0x{:x}'.format(global_addr, ptr_val))

# Now check if this value points to another pointer (the actual function)
if ptr_val > 0:
    # Read 8 bytes at ptr_val (this is the function pointer that gets called)
    func_ptr = struct.unpack_from('<Q', data, ptr_val)[0]
    print('  [0x{:x}] -> 0x{:x} (actual pipeline function)'.format(ptr_val, func_ptr))
    
    # Show first 20 bytes as instructions
    print('\n  First 40 bytes at pipeline function (0x{:x}):'.format(func_ptr))
    for i in range(10):
        instr = struct.unpack_from('<I', data, func_ptr + i*4)[0]
        print('    0x{:x}: {:08x}'.format(func_ptr + i*4, instr))

# ============================================================
# 3. Read the SECOND thunk's function pointer too (0xC62F60)
# ============================================================
print('\n' + '=' * 70)
print('3. Second thunk 0xC62F60:')
print('=' * 70)
# First show the function
off = 0xC62F60
for i in range(12):
    instr = struct.unpack_from('<I', data, off + i*4)[0]
    a = 0xC62F60 + i*4
    print('  0x{:x}: {:08x}'.format(a, instr))
    
    # Check for ADRP
    if (instr >> 31) == 1 and (instr & 0x1F000000) == 0x90000000:
        page2 = decode_adrp(a)
        print('         -> ADRP page: 0x{:x}'.format(page2))
    
    # Check for LDR
    if (instr >> 22) == 0x3E5:
        result = decode_ldr_imm(a)
        if result:
            rt, rn, offset, kind = result
            # Need to find the previous ADRP that set rn
            print('         -> {}, X{}, [reg, #0x{:x}]'.format(kind, rt, offset))
