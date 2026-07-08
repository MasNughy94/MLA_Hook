import struct

BINARY = r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so'
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
md.skipdata = False

text_start = 0x3fc000
text_end = 0xdf61ec
text_off = virt_to_offset(text_start)
text_code = data[text_off:text_off + (text_end - text_start)]

# Search for ADRP instructions targeting pages that contain our globals
search_pages = {}
# getKey global pointer: [0x11E4670] -> points to key std::string at 0x124EB50
search_pages[0x11E4670 & ~0xFFF] = {0x11E4670: 'getKey_global_ptr'}
search_pages[0x124EB50 & ~0xFFF] = {0x124EB50: 'key_string'}
# getKey2 global pointer: [0x11E2418] -> ? 
search_pages[0x11E2418 & ~0xFFF] = {0x11E2418: 'getKey2_global_ptr'}

print(f"Scanning entire .text (0x{text_start:x} - 0x{text_end:x}, {len(text_code)} bytes)...")

results = []
for i in md.disasm(text_code, text_start):
    if i.mnemonic == 'adrp':
        pc_page = i.address & ~0xFFF
        target_page = pc_page + i.operands[1].imm
        
        if target_page in search_pages:
            # Read next instruction
            next_addr = i.address + i.size
            next_off = virt_to_offset(next_addr)
            if next_off:
                next_code = data[next_off:next_off+4]
                next_insns = list(md.disasm(next_code, next_addr))
                if next_insns:
                    next_i = next_insns[0]
                    rd = i.operands[0].reg
                    # Check various patterns
                    if next_i.mnemonic in ['ldr', 'add', 'str']:
                        for vaddr, label in search_pages[target_page].items():
                            offset_in_page = vaddr & 0xFFF
                            # Check for ldr xN, [xM, #offset] with matching offset
                            if next_i.operands[0].reg == rd or True:
                                try:
                                    mem = next_i.operands[1]
                                    if mem.type == 3:  # MEM
                                        if mem.index == 0 and mem.disp == offset_in_page:
                                            results.append((i.address, label, vaddr, i.op_str, next_i.op_str))
                                            break
                                except:
                                    pass

print(f"\nFound {len(results)} references:")
for addr, label, vaddr, adrp_op, next_op in results:
    print(f"  0x{addr:x}: adrp {adrp_op}")
    print(f"           : {next_op}  --> {label} @ 0x{vaddr:x}")

if not results:
    print("No ADRP+LDR/ADD references found in entire .text!")
    print("The key string initialization may use a different mechanism.")
    print("Checking if keys are hardcoded in .rodata or set via BL...")
    
    # Check what std::string::assign (0x9b14e0) does - maybe the key is from a literal
    # Let me look at where getKey is called from
    print()
    print("Searching for callers of getKey (0xcec678)...")
    text_off_local = virt_to_offset(text_start)
    for i in md.disasm(text_code, text_start):
        if i.mnemonic == 'bl' and i.operands[0].imm == 0xcec678:
            print(f"  CALLER @ 0x{i.address:x}")
        if i.mnemonic == 'bl' and i.operands[0].imm == 0xcec6a4:
            print(f"  CALLER (getKey2) @ 0x{i.address:x}")
