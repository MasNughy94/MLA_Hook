import struct

BINARY = r'C:\Users\NGEONG\Videos\MLA\libagame.so'
with open(BINARY, 'rb') as f:
    data = f.read()
endian = '<'

e_phoff = struct.unpack_from(endian + 'Q', data, 0x20)[0]
e_phentsize = struct.unpack_from(endian + 'H', data, 0x36)[0]
e_phnum = struct.unpack_from(endian + 'H', data, 0x38)[0]

def virt_to_offset(va):
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        if p_type != 1: continue
        p_offset = struct.unpack_from('<Q', data, off + 8)[0]
        p_vaddr = struct.unpack_from('<Q', data, off + 0x10)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 0x20)[0]
        if p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr)
    return None

from capstone import *
from capstone.arm64 import *
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# Search for references to 0x11E4670 (the global pointer that holds key address)
# Pattern: adrp xN, #page(0x11E4670) + ldr xN, [xN, #offset]
target_page = 0x11E4000  # from adrp in getKey
target_offset = 0x670     # from ldr in getKey [x1, #0x670]

# 0x11E4670 = 0x11E4000 + 0x670
# ADRP encoding: 1:immlo:immhi
# ADRP x1, #0x11E4000 = adrp with immediate = page_delta
# The ADRP instruction's immediate encodes the page difference
# ADRP xN, #imm shifts imm by 12 and adds to PC

# Let me search for the ADRP pattern in .text
text_start = 0x3fc000
text_end = 0xdf61ec
text_off = virt_to_offset(text_start)

# Search for ADRP x1, #page targeting 0x11E4000
# ADRP x1, imm where imm >> 12 + (PC & ~0xFFF) == 0x11E4000
# imm = 0x11E4000 - (PC & ~0xFFF)
# But ADRP has limited reach (+-4GB so it's fine)

# Let me scan all of .text for the pattern:
# adrp x[0-9]+, #page_val followed by ldr x[0-9]+, [x[0-9]+, #offset]
# where page_val + offset = 0x11E4670

print(f"Searching for references to global at 0x11E4670 in .text...")
found_at = []

# Read .text
text_off = virt_to_offset(text_start)
text_code = data[text_off:text_off + (text_end - text_start)]

# Iterate looking for adrp+ldr patterns
# ADRP encoding: bits [24:29] = 100110, bits [23:5] = imm, bits [4:0] = Rd
# LDR (immediate, unsigned): bits [31:30] = 00, [29:27] = 111, [26:22] = 00101, [21:10] = imm12, [9:5] = Rn, [4:0] = Rt
from capstone.arm64 import *
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
md.skipdata = False

search_at = [0x11e4670, 0x124eb50]
for search_va in search_at:
    print(f"\nSearching for references to 0x{search_va:x}...")
    page_addr = search_va & ~0xFFF
    page_offset = search_va & 0xFFF
    
    for i in md.disasm(text_code[:0x100000], text_start):  # Scan first 1MB of .text
        if i.mnemonic == 'adrp':
            # Get the target page from adrp
            # ADRP: imm = (i.operands[1].imm) 
            # The target address = (PC & ~0xFFF) + imm
            pc_page = i.address & ~0xFFF
            target_page_val = pc_page + i.operands[1].imm
            if target_page_val == page_addr:
                # Check if next instruction is ldr from same register with matching offset
                next_addr = i.address + i.size
                # Read next instruction bytes
                next_off = virt_to_offset(next_addr)
                if next_off:
                    next_bytes = data[next_off:next_off+4]
                    next_i = list(md.disasm(next_bytes, next_addr))
                    if next_i and next_i[0].mnemonic == 'ldr':
                        ldr = next_i[0]
                        # ldr xD, [xN, #imm]
                        if len(ldr.operands) == 2 and ldr.operands[1].type == 3:
                            mem = ldr.operands[1]
                            if mem.index == 0 and mem.disp == page_offset:
                                print(f"  FOUND @ 0x{i.address:x}: {i.mnemonic} {i.op_str}")
                                print(f"         0x{next_addr:x}: {ldr.mnemonic} {ldr.op_str}")
                                found_at.append((i.address, search_va))

if not found_at:
    print("No ADRP+LDR references found in first 1MB. Key may be set differently (via BL, memcpy, etc.)")
    
    # Alternative: search for BL to functions that might set the key
    # The string at 0x124EB50 is a std::string. Let me check who writes to it
    # Search for reference in the form of: adrp xN, #0x124E000 + add xN, xN, #0xB50 (or str)
    print("\nSearching for ADRP+ADD/STR references to 0x124EB50...")
    for i in md.disasm(text_code[:0x100000], text_start):
        if i.mnemonic == 'adrp':
            pc_page = i.address & ~0xFFF
            target_page_val = pc_page + i.operands[1].imm
            if target_page_val == (0x124EB50 & ~0xFFF):
                next_addr = i.address + i.size
                next_off = virt_to_offset(next_addr)
                if next_off:
                    next_bytes = data[next_off:next_off+4]
                    next_i = list(md.disasm(next_bytes, next_addr))
                    if next_i:
                        print(f"  FOUND @ 0x{i.address:x}: {i.mnemonic} {i.op_str}")
                        print(f"         0x{next_addr:x}: {next_i[0].mnemonic} {next_i[0].op_str}")
