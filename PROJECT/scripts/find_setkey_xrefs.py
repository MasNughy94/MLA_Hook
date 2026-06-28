"""
Find xrefs to setKey/setKey2 to understand where keys come from
"""
from capstone import *
import struct

with open(r'H:\PROJECTMOD\OriginalAPK\lib\arm64-v8a\libagame.so', 'rb') as f:
    data = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# setKey is at 0xceca74
# setKey2 is at 0xcecb5c
# These are called via BL instructions

# The BL instruction for ARM64:
# BL encodes a 26-bit signed offset << 2
# BL = 100101 + imm26

# Calculate the offset encoded in a BL instruction:
# instruction & 0x03FFFFFF gives the 26-bit value
# Sign extend from 26 to 32 bits, then shift left by 2

# Search for BL that targets 0xceca74 (setKey)
target = 0xceca74
text_start = 0x3fc000
text_end = 0x3fc000 + 10461676

print(f'Searching for calls to setKey (0x{target:x}) in .text section...')
print(f'.text: 0x{text_start:x} - 0x{text_end:x}')

# For each 4-byte aligned position in .text, check if it's a BL to our target
count = 0
for offset in range(text_start, text_end - 4, 4):
    inst_bytes = data[offset:offset+4]
    inst_val = struct.unpack('<I', inst_bytes)[0]
    
    # Check if it's a BL instruction (opcode 0b100101 = 0x25 at bits 26-31)
    opcode = (inst_val >> 26) & 0x3F
    if opcode == 0x25:  # BL
        # Calculate target address
        imm26 = inst_val & 0x03FFFFFF
        # Sign extend from 26 bits
        if imm26 & 0x02000000:
            imm26 |= 0xFC000000  # Sign extend
        target_offset = imm26 << 2
        bl_target = offset + target_offset
        
        if bl_target == target:
            # Show context around this call
            start = max(text_start, offset - 20)
            code = data[start:min(text_end, offset + 20)]
            print(f'\nCaller at 0x{offset:x}:')
            for i in md.disasm(code, start):
                marker = ' <--- CALL' if i.address == offset else ''
                print(f'  0x{i.address:x}: {i.mnemonic} {i.op_str}{marker}')
            count += 1

if count == 0:
    print('No direct BL calls found')
    
    # Maybe setKey is accessed through the GOT or virtual table
    # Let's search for addresses of setKey (0xceca74) in the data sections
    print('\nSearching for address 0xceca74 as data reference...')
    addr_bytes = struct.pack('<Q', target)
    idx = 0
    while True:
        idx = data.find(addr_bytes, idx)
        if idx < 0:
            break
        if idx >= 0x115db00:  # Only in data sections
            section = 'unknown'
            if 0x115db00 <= idx < 0x11d9db0:
                section = '.data.rel.ro'
            elif 0x11da030 <= idx < 0x11e8000:
                section = '.got'
            elif 0x11e8000 <= idx < 0x11fef30:
                section = '.data'
            print(f'  0x{idx:x} in {section}')
        idx += 8

# Same for setKey2 (0xcecb5c)
print(f'\nSearching for calls to setKey2 (0x{cecb5c:x})...')
target2 = 0xcecb5c
count2 = 0
for offset in range(text_start, text_end - 4, 4):
    inst_bytes = data[offset:offset+4]
    inst_val = struct.unpack('<I', inst_bytes)[0]
    opcode = (inst_val >> 26) & 0x3F
    if opcode == 0x25:  # BL
        imm26 = inst_val & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 |= 0xFC000000
        target_offset = imm26 << 2
        bl_target = offset + target_offset
        if bl_target == target2:
            print(f'  Caller at 0x{offset:x}')
            count2 += 1

print(f'Found {count} calls to setKey, {count2} calls to setKey2')

# Also look for calls to _getKeyv
print(f'\nSearching for calls to _getKeyv (0x{cebd20:x})...')
target3 = 0xcebd20
for offset in range(text_start, text_end - 4, 4):
    inst_bytes = data[offset:offset+4]
    inst_val = struct.unpack('<I', inst_bytes)[0]
    opcode = (inst_val >> 26) & 0x3F
    if opcode == 0x25:  # BL
        imm26 = inst_val & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 |= 0xFC000000
        target_offset = imm26 << 2
        bl_target = offset + target_offset
        if bl_target == target3:
            print(f'  Caller at 0x{offset:x}')
