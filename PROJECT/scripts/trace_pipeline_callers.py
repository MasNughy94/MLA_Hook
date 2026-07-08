"""
0x7D27E8 is a THUNK to a function pointer.
It returns a C++ object with a vtable.
Trace: what happens after 0x7D27E8 returns? Find the constructor/callers.
Also: what is the function pointer that gets stored at the global?
"""

import struct

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    data = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC
DATA_ADDR = 0xDF9000  # rough start of writable data

def decode_adrp(data, addr):
    """Decode ADRP instruction to get target address."""
    off = addr - TEXT_ADDR + TEXT_OFF
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr >> 31) != 1:  # not ADRP
        return None
    immhi = (instr >> 5) & 0x7FFFF  # 19 bits
    immlo = (instr >> 29) & 0x3  # 2 bits
    imm = (immhi << 2) | immlo
    if imm >= 0x80000:  # sign extend 21-bit
        imm -= 0x100000
    page_addr = (addr & 0xFFFFFFFFFFFFF000) + (imm << 12)
    return page_addr

def follow_adrp_ldr(data, adrp_addr, ldr_offset, ldr_size=8):
    """Follow ADRP + LDR to get final address."""
    page = decode_adrp(data, adrp_addr)
    if page is None:
        return page
    return page + ldr_offset

# ============================================================
# 1. Where does the global function pointer point?
#    ADRP at 0x7D27F4, LDR at 0x7D27FC (offset 0x2A80 from page)
# ============================================================
print('=' * 70)
print('1. Function pointer target for 0x7D27E8 thunk')
page = decode_adrp(data, 0x7D27F4)
print('  ADRP target page: 0x{:x}'.format(page))
target_addr = page + 0x2A80
print('  Global ptr location: 0x{:x}'.format(target_addr))

# Read the pointer value
off = target_addr - DATA_ADDR + 0x176320  # approximate data section offset
# Actually let me calculate the correct data offset
DATA_FILE_OFF = 0xD7D040  # rough
print('  Value at that loc (8 bytes):', end=' ')
try:
    off_data = target_addr - DATA_ADDR + 0x176320
    ptr_val = struct.unpack_from('<Q', data, off_data)[0]
    print('0x{:x}'.format(ptr_val))
except:
    print('Not in data section range')

# ============================================================
# 2. Since ADRP + LDR is common, let me search for all functions 
#    that STORE to that global (STR Xn, [Xm, #offset])
# ============================================================
print('\n' + '=' * 70)
print('2. Searching for code that WRITES to global (0x{:x})'.format(target_addr))
# Search for STR instruction that targets this address
# STR Xt, [Xn, #imm] = 0xF9000000 + (imm12 << 10) + (Xn << 5) + Xt
# But finding by pattern matching is imprecise. Let me instead search for 
# ADRP + LDR patterns that match 0x7D27E8's global

# Better: search for "reference to target_addr" in the data section
# The target_addr might be in the GOT or BSS
# Search for the address value in the data section
addr_bytes = struct.pack('<Q', target_addr)
for off in range(0x176320, min(0x176320 + 0x20000, len(data)), 8):
    chunk = data[off:off+8]
    if chunk == addr_bytes:
        print('  Found address at file offset 0x{:x}'.format(off))

# ============================================================
# 3. Let's look at ONE caller in detail to understand the vtable dispatch
# ============================================================
print('\n' + '=' * 70)
print('3. Detailed trace of caller 0x414A1C (Roo parser?)')
# Show more of this function
off = 0x414A1C - TEXT_ADDR + TEXT_OFF
# Show the function containing this address
print('\nCaller function at 0x4149FC:')
func_start = 0x4149A0
for i in range(70):
    if off + i*4 >= TEXT_OFF + TEXT_SIZE: break
    a = func_start + i*4
    instr = struct.unpack_from('<I', data, func_start - TEXT_ADDR + TEXT_OFF + i*4)[0]
    
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
    elif (instr >> 24) == 0xB4:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        target = a + (imm19 << 2)
        print('  0x{:x}: CBZ    X{}, 0x{:x}'.format(a, instr & 0x1F, target))
    elif (instr >> 24) == 0xB5:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        target = a + (imm19 << 2)
        print('  0x{:x}: CBNZ   X{}, 0x{:x}'.format(a, instr & 0x1F, target))
    elif (instr >> 26) == 0x05:  # B
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        target = a + (imm26 << 2)
        print('  0x{:x}: B       0x{:x}'.format(a, target))
    elif (instr & 0xFC000000) == 0x94000000:  # BL with different format check
        pass
    else:
        print('  0x{:x}: {:08x}'.format(a, instr))

# ============================================================
# 4. Since the thunk dispatches to a global function pointer,
#    let me search for functions that SET this pointer
#    Common pattern: ADRP+X... + STR Xt, [Xaddr]
#    Search for BSS-init or plugin registration functions
# ============================================================
print('\n' + '=' * 70)
print('4. Looking at the Antm orchestrator 0x7D2888 - what does it call via BLR?')
off = 0x7D2888 - TEXT_ADDR + TEXT_OFF
for i in range(80):
    a = 0x7D2888 + i*4
    instr = struct.unpack_from('<I', data, off + i*4)[0]
    
    # Check if instruction is BLR (BLR Xn = 0xD63F0000 + n*0x100 + 0x20)
    if (instr & 0xFF1FFFFF) == 0xD63F0000:
        reg = (instr >> 5) & 0x1F
        print('  0x{:x}: BLR     X{}'.format(a, reg))
    elif instr == 0xD65F03C0:
        print('  0x{:x}: RET'.format(a))
        break
    elif (instr >> 26) == 0x25:
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        target = a + (imm26 << 2)
        if TEXT_ADDR <= target < TEXT_ADDR + TEXT_SIZE:
            print('  0x{:x}: BL      0x{:x}'.format(a, target))
        else:
            print('  0x{:x}: BL      (0x{:x})'.format(a, target))
    elif (instr >> 24) == 0x54:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        target = a + (imm19 << 2)
        cond = instr & 0xF
        print('  0x{:x}: B.{}    0x{:x}'.format(a, cond, target))
    elif (instr >> 24) == 0x35:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        target = a + (imm19 << 2)
        print('  0x{:x}: CBNZ   W{}, 0x{:x}'.format(a, instr & 0x1F, target))
    elif (instr >> 24) == 0x34:
        imm19 = (instr >> 5) & 0x7FFFF
        if imm19 >= 0x40000: imm19 |= 0xFFF80000
        target = a + (imm19 << 2)
        print('  0x{:x}: CBZ    W{}, 0x{:x}'.format(a, instr & 0x1F, target))
    elif (instr >> 26) == 0x05:
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        target = a + (imm26 << 2)
        print('  0x{:x}: B       0x{:x}'.format(a, target))
    else:
        print('  0x{:x}: {:08x}'.format(a, instr))
