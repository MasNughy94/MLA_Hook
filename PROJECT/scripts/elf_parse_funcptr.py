"""
Parse ELF headers to get proper file-to-virtual-address mapping.
Then read the global function pointer for 0x7D27E8's thunk.
Also search for all virtual functions that could be Roo parsers.
"""

import struct

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    data = f.read()

# ============================================================
# 1. Parse ELF program headers to find segment mappings
# ============================================================
print('=' * 70)
print('1. ELF Segment Mappings')
print('=' * 70)

# Parse ELF header
e_phoff = struct.unpack_from('<Q', data, 0x20)[0]  # Program header offset
e_phentsize = struct.unpack_from('<H', data, 0x36)[0]  # Program header entry size
e_phnum = struct.unpack_from('<H', data, 0x38)[0]  # Number of program headers

print('  ELF64: phoff=0x{:x}, phentsize={}, phnum={}'.format(e_phoff, e_phentsize, e_phnum))

for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack_from('<I', data, off)[0]
    p_flags = struct.unpack_from('<I', data, off + 4)[0]
    p_offset = struct.unpack_from('<Q', data, off + 8)[0]
    p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
    p_paddr = struct.unpack_from('<Q', data, off + 24)[0]
    p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
    p_memsz = struct.unpack_from('<Q', data, off + 40)[0]
    
    if p_type == 1:  # PT_LOAD
        p_flags_str = ''
        if p_flags & 1: p_flags_str += 'X'
        if p_flags & 2: p_flags_str += 'W'
        if p_flags & 4: p_flags_str += 'R'
        print('  LOAD: file=0x{:x}-0x{:x}, vaddr=0x{:x}-0x{:x}, flags={}, size=0x{:x}'.format(
            p_offset, p_offset + p_filesz, p_vaddr, p_vaddr + p_memsz, p_flags_str, p_filesz))
    elif p_type == 2:  # PT_DYNAMIC
        print('  DYNAMIC: vaddr=0x{:x}, size=0x{:x}'.format(p_vaddr, p_filesz))
    elif p_type == 0x6474e550:  # PT_GNU_EH_FRAME
        print('  EH_FRAME: vaddr=0x{:x}, size=0x{:x}'.format(p_vaddr, p_filesz))
    elif p_type == 0x6474e551:  # PT_GNU_STACK
        print('  STACK: flags={}'.format(p_flags))
    elif p_type == 0x6474e552:  # PT_GNU_RELRO
        print('  RELRO: vaddr=0x{:x}, memsz=0x{:x}'.format(p_vaddr, p_memsz))
    elif p_type == 4:  # PT_NOTE
        print('  NOTE: vaddr=0x{:x}'.format(p_vaddr))

# ============================================================
# 2. Now read the global function pointer correctly
#    ADRP at 0x7D27F4, page + 0x2A80
#    Find the correct file offset for virtual address (page + 0x2A80)
# ============================================================
print('\n' + '=' * 70)
print('2. Reading global function pointer for 0x7D27E8')
print('=' * 70)

# ADRP at 0x7D27F4: target page based on decoding
# Let me re-decode
off_instr = 0x7D27F4 - 0x3FC000 + 0x3FC000
instr = struct.unpack_from('<I', data, off_instr)[0]
immhi = (instr >> 5) & 0x7FFFF
immlo = (instr >> 29) & 0x3
imm = (immhi << 2) | immlo
if imm >= 0x80000:
    imm -= 0x100000
target_page = (0x7D27F4 & ~0xFFF) + (imm << 12)
func_ptr_addr = target_page + 0x2A80
print('  Function pointer at virtual address 0x{:x}'.format(func_ptr_addr))

# Now find which segment covers this address
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack_from('<I', data, off)[0]
    if p_type == 1:  # PT_LOAD
        p_offset = struct.unpack_from('<Q', data, off + 8)[0]
        p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
        
        if p_vaddr <= func_ptr_addr < p_vaddr + p_filesz:
            file_off = func_ptr_addr - p_vaddr + p_offset
            ptr_val = struct.unpack_from('<Q', data, file_off)[0]
            print('  Found in segment: file offset 0x{:x}'.format(file_off))
            print('  Value: 0x{:x}'.format(ptr_val))
            
            # Check if this points to the pipeline function
            for j in range(e_phnum):
                off2 = e_phoff + j * e_phentsize
                p_type2 = struct.unpack_from('<I', data, off2)[0]
                if p_type2 == 1:
                    p_offset2 = struct.unpack_from('<Q', data, off2 + 8)[0]
                    p_vaddr2 = struct.unpack_from('<Q', data, off2 + 16)[0]
                    p_filesz2 = struct.unpack_from('<Q', data, off2 + 32)[0]
                    
                    if p_vaddr2 <= ptr_val < p_vaddr2 + p_filesz2:
                        ptr_offset = ptr_val - p_vaddr2 + p_offset2
                        print('  Points to segment at file offset 0x{:x}'.format(ptr_offset))
                        # Show first 16 bytes
                        context = data[ptr_offset:ptr_offset+48]
                        print('  Context: {}'.format(context.hex()))
                        asc = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in context)
                        print('  ASCII: {}'.format(asc))
                    else:
                        print('  Points to unknown region: 0x{:x}'.format(ptr_val))
            break

# Also read around the global to see if it's in a GOT-like region
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack_from('<I', data, off)[0]
    if p_type == 1:
        p_offset = struct.unpack_from('<Q', data, off + 8)[0]
        p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
        
        if p_vaddr <= func_ptr_addr < p_vaddr + p_filesz:
            file_off = func_ptr_addr - p_vaddr + p_offset
            
            # Read 32 pointers around this location
            print('\n  Nearby pointers (relative to 0x{:x}):'.format(func_ptr_addr))
            for k in range(-5, 6):
                addr_cur = func_ptr_addr + k * 8
                if p_vaddr <= addr_cur < p_vaddr + p_filesz:
                    off_cur = addr_cur - p_vaddr + p_offset
                    val = struct.unpack_from('<Q', data, off_cur)[0]
                    marker = ' <--' if k == 0 else ''
                    print('    0x{:x} -> 0x{:x}{}'.format(addr_cur, val, marker))
