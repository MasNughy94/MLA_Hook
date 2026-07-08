"""
Find references to magic strings "Antm" and "lmF@" in libagame.so.
These 4-byte identifiers are compared against file headers to determine
the decryption/decompression pipeline.
"""

import struct

so = open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb').read()

# Search for the strings in the data
needles = [b'Antm', b'lmF@', b'LMF@', b'lmF', b'\x1bLm', b'\x1bLu', b'lua\x00', b'.mt\x00', b'.mt']

for needle in needles:
    matches = []
    offset = 0
    while True:
        idx = so.find(needle, offset)
        if idx == -1:
            break
        matches.append(idx)
        offset = idx + 1
    
    if matches:
        print('"{}" ({} bytes): {} occurrences'.format(needle.decode(errors='replace'), len(needle), len(matches)))
        for m in matches[:10]:
            ctx = so[max(0,m-4):m+len(needle)+16]
            print('  0x{:x}: {}'.format(m, ctx.hex()))
        
        # For each match, check if it's referenced by code
        # ARM64: code referencing data uses ADRP+ADD to load the address
        for m in matches[:5]:
            # If this is in the data section, find ADRP references to its page
            # Typically code does: ADRP Xn, page; ADD Xn, Xn, offset; (use Xn)
            data_page = m & ~0xFFF
            data_offset = m & 0xFFF
            
            page_refs = 0
            TEXT_ADDR = 0x3FC000
            TEXT_OFF = 0x3FC000
            TEXT_SIZE = 0x9FA1EC
            
            for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 4, 4):
                instr = struct.unpack_from('<I', so, file_off)[0]
                addr = TEXT_ADDR + (file_off - TEXT_OFF)
                
                if (instr >> 24) == 0x90:  # ADRP
                    Rd = instr & 0x1F
                    immhi = (instr >> 5) & 0x7FFFF
                    immlo = (instr >> 29) & 3
                    if immhi & 0x40000:
                        immhi |= 0xFFF80000
                    imm = (immhi << 2) | immlo
                    target_page = (addr & ~0xFFF) + (imm << 12)
                    
                    if target_page == data_page:
                        # Check subsequent instructions for ADD with matching offset
                        for j in range(1, 6):
                            if file_off + j*4 < TEXT_OFF + TEXT_SIZE:
                                next_instr = struct.unpack_from('<I', so, file_off + j*4)[0]
                                if (next_instr >> 24) == 0x91:  # ADD
                                    add_Rd = next_instr & 0x1F
                                    add_Rn = (next_instr >> 5) & 0x1F
                                    add_imm12 = (next_instr >> 10) & 0xFFF
                                    if add_Rn == Rd and add_Rd == Rd and add_imm12 == data_offset:
                                        page_refs += 1
                                        if page_refs <= 5:
                                            print('    Referenced by code at 0x{:x} (ADRP+ADD)'.format(addr))
                                        break
            if page_refs > 5:
                print('    ... and {} more references'.format(page_refs - 5))
            print('    Total references: {}'.format(page_refs))
    else:
        print('"{}": not found'.format(needle.decode(errors='replace')))
    print()
