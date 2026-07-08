"""
0x7D27E8 is a thunk dispatching through global pointer.
Focus on: what does caller 0x414A1C actually do with the returned C++ object?
Specifically, trace the vtable dispatch to find the real parser.
"""

import struct

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    data = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def show_func_raw(addr, count=60):
    """Show raw instructions for a function."""
    off = addr - TEXT_ADDR + TEXT_OFF
    for i in range(count):
        if off + i*4 >= TEXT_OFF + TEXT_SIZE: break
        a = addr + i*4
        instr = struct.unpack_from('<I', data, off + i*4)[0]
        
        if (instr >> 26) == 0x25:  # BL
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000: imm26 -= 0x4000000
            target = a + (imm26 << 2)
            print('  0x{:x}: BL      {:08x} (-> 0x{:x})'.format(a, target, target))
        elif instr == 0xD65F03C0:
            print('  0x{:x}: RET'.format(a))
            break
        elif (instr & 0xFF1FFFFF) == 0xD63F0000:  # BLR Xn
            reg = (instr >> 5) & 0x1F
            print('  0x{:x}: BLR     X{}'.format(a, reg))
        elif (instr >> 26) == 0x05:  # B
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000: imm26 -= 0x4000000
            target = a + (imm26 << 2)
            print('  0x{:x}: B       {:08x} (-> 0x{:x})'.format(a, target, target))
        elif (instr >> 24) == 0x54:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            cond = instr & 0xF
            print('  0x{:x}: B.{}    -> 0x{:x}'.format(a, cond, target))
        elif (instr >> 24) == 0x34:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            print('  0x{:x}: CBZ    W{}, -> 0x{:x}'.format(a, instr & 0x1F, target))
        elif (instr >> 24) == 0x35:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            print('  0x{:x}: CBNZ   W{}, -> 0x{:x}'.format(a, instr & 0x1F, target))
        elif (instr >> 24) == 0xB4:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            print('  0x{:x}: CBZ    X{}, -> 0x{:x}'.format(a, instr & 0x1F, target))
        elif (instr >> 24) == 0xB5:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            print('  0x{:x}: CBNZ   X{}, -> 0x{:x}'.format(a, instr & 0x1F, target))
        else:
            # Check for STR/LDR with comment
            op = '??'
            if (instr >> 22) == 0x3E4: op = 'LDR Xt, [Xn, #imm]'  # LDR imm
            elif (instr >> 22) == 0x3E5: op = 'LDP'
            elif (instr >> 22) == 0x3C4: op = 'STR Xt, [Xn, #imm]'
            elif (instr >> 22) == 0x3C5: op = 'STP'
            elif (instr & 0xFFC00000) == 0x90000000: op = 'ADRP'
            elif (instr & 0xFF000000) == 0x91000000: op = 'ADD Xd, Xn, #imm'
            elif (instr & 0xFF000000) == 0xD1000000: op = 'SUB Xd, Xn, #imm'
            elif (instr & 0xFF000000) == 0x11000000: op = 'ADD Wd, Wn, #imm'
            elif (instr & 0x7F000000) == 0x34000000: op = 'CBZ'
            elif instr == 0xD503201F: op = 'NOP'
            else: op = '{:08x}'.format(instr)
            print('  0x{:x}: {}'.format(a, op))

# ============================================================
# 1. Function containing 0x414A1C (shows the FULL function flow)
# ============================================================
print('=' * 70)
print('1. FULL function at 0x4149CC (caller of 0x7D27E8 via BL at 0x414A1C)')
print('=' * 70)
show_func_raw(0x4149CC, 80)

# The vtable dispatch at 0x414A2C-0x414A30:
# LDR X2, [X2, #0x10] - loads vtable[2]
# BLR X2 - calls vtable[2]
# X0 = object returned from 0x7D27E8
# X1 = X22 (some arg)
# X8 = stack pointer (return slot?)

# ============================================================
# 2. Find the constructor - what TYPE of object does 0x7D27E8 create?
# The vtable dispatch suggests a class hierarchy.
# Search for functions that create objects and store vtable pointers
# using the same vtable pattern LDR Xd, [Xn, #0x10] + BLR Xd
# ============================================================
print('\n' + '=' * 70)
print('2. Searching for functions that write vtables used in this dispatch')
print('   Looking for nearby vtable addresses...')
# The LDR X2, [X2, #0x10] loads from the vtable at offset 0x10
# This means vtable[2] is the processing function
# Let's find vtable tables near known addresses

# First, find vtable addresses by examining caller's data refs
# At 0x4149D8: ADRP + 0x6E55 -> page for string loading
page_addr_4149D8 = 0x4149D8 & 0xFFFFFFFFFFFFF000  # ADRP page
# This ADRP loads a page. Target = page + offset from LDR/ADD

# At 0x4149EC: LDR X1, [X21, #0x1F2] -> loading from known global
# 0x4149D8: d0006e55 -> ADRP X21, #some_page

# Let's decode ADRP at 0x4149D8
off = 0x4149D8 - TEXT_ADDR + TEXT_OFF
instr = struct.unpack_from('<I', data, off)[0]
immhi = (instr >> 5) & 0x7FFFF
immlo = (instr >> 29) & 0x3
imm = (immhi << 2) | immlo
if imm >= 0x80000: imm -= 0x100000
page = (0x4149D8 & ~0xFFF) + (imm << 12)
print('  ADRP at 0x4149D8 -> page 0x{:x}'.format(page))

# Now what does it load from? At 0x4149EC: f941f2a1
# = LDR X1, [X21, #0x3F0]
data_page = page + 0x3F0
print('  LDR target: 0x{:x}'.format(data_page))

# Let's see what's at 0x414A20:
# LDR X2, [X0] - this loads the vtable pointer from the returned object
# X0 is the return from 0x7D27E8
# vtable points to a structure where [2] (0x10 offset) is the processing function

# ============================================================
# 3. Search for functions that match the pattern of reading magic/type bytes
#    Use a different approach: search for code that reads decompressed data header
#    The header starts with: 1B 4C 6D 00 00 00 52 6F 6F
#    When code checks for "Roo" (52 6F 6F), it uses immediates like MOV{W|K}
# ============================================================
print('\n' + '=' * 70)
print('3. SEARCHING for functions that READ decompressed data header bytes')
print('   Looking for byte comparisons like LDRB + CMP #imm')
# These would appear as CMP Wd, #0x1B, CMP Wd, #0x4C, CMP Wd, #0x6D, etc.
# Search for these byte values as immediate comparisons in the TEXT section

# Search for 0x1B (Lua/Roo magic byte)
# Common pattern: AND Wd, Wd, 0xFF + CMP Wd, #0x1B
# or CMP Wd, #0x1BL (zero-extending compare)
import re

# Look for CMP Wd, #0x1B - this would be encoded as SUB Wd, Wd, #0x1B (with zero flag)
# CMP is just SUBS with WZR
# But the immediate encoding of SUB/SUBS is complex
# Let me search for LDRB patterns followed by comparisons

# Actually, let me search for the MOVZ/MOVK sequences for "Roo":
# 'R'=0x52, 'o'=0x6F, 'O'=0x4F
# MOVZ Wd, #0x6F52 (if bytes swapped) or similar

# Wait - earlier I found that BYTE comparison at 0xC82A80 uses:
# MOVZ Wd, #0x6E41 (immediate: 'A'=0x41, 'n'=0x6E -> "An")
# MOVK Wd, #0x6D74, LSL #16 (immediate: 't'=0x74, 'm'=0x6D -> "tm")

# So "Antm" = 0x6E41, 0x6D74 in two 16-bit halves (little-endian within halves)
# "Roo" would be stored as: 'R'=0x52, 'o'=0x6F in first half = 0x6F52
# But "Roo" has 3 bytes, so maybe stored with trailing null: 0x0052, 0x006F? Or 0x006F52?

# Let me search for MOVZ/MOVK patterns with these values
# MOVZ Wd, #0x6F52 (little-endian "Ro")
print('Searching for "Ro" (0x6F52) as MOVZ immediate...')
founds = []
for off in range(0, len(data) - 4, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    # MOVZ Wd, #imm16: 0x52800000 | (imm16 << 5) | Rd
    # SKIP: lower bits depend on shift amount and register
    # Just search for pattern 0x52XXXXXX where low bytes encode imm16
    if (instr & 0xFF000000) == 0x52000000:  # MOV/MOVK family
        imm16 = (instr >> 5) & 0xFFFF
        if imm16 in [0x6F52, 0x4C6D]:  # "Ro" or "Lm"
            hw = (instr >> 21) & 0x3
            print('  0x{:x}: MOVZ/MOVK imm16=0x{:04x} hw={} (encoded 0x{:08x})'.format(
                TEXT_ADDR + off - TEXT_OFF, imm16, hw, instr))

# Also search for "Lm" (0x4C6D) - the second word of magic \x1BLm
print('\nSearching for "Lm" (0x4C6D) as MOVZ immediate...')
for off in range(0, len(data) - 4, 4):
    instr = struct.unpack_from('<I', data, off)[0]
    if (instr & 0xFF000000) == 0x52000000:
        imm16 = (instr >> 5) & 0xFFFF
        if imm16 == 0x4C6D:
            hw = (instr >> 21) & 0x3
            print('  0x{:x}: MOVZ/MOVK imm16=0x{:04x} hw={} (encoded 0x{:08x})'.format(
                TEXT_ADDR + off - TEXT_OFF, imm16, hw, instr))
