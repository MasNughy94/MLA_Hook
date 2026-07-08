"""
Comprehensive search for ALL .mt file loading pipelines.
Search for:
1. ".mt" string references
2. Asset directory paths ("assets/f", "assets/level", etc.)
3. File reading functions (getFileData, CCFileUtils, etc.)
4. Any JNI/Java bridge for file operations
"""

import struct

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    agame = f.read()
    
hades_path = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\lib\arm64-v8a\libhades.so'
with open(hades_path, 'rb') as f:
    hades = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def find_section(data, name):
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
    shstrtab_off = e_shoff + e_shstrndx * e_shentsize
    shstrtab_sh_offset = struct.unpack_from('<Q', data, shstrtab_off + 0x18)[0]
    
    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack_from('<I', data, sh_off)[0]
        sh_addr = struct.unpack_from('<Q', data, sh_off + 0x10)[0]
        sh_offset = struct.unpack_from('<Q', data, sh_off + 0x18)[0]
        sh_size = struct.unpack_from('<Q', data, sh_off + 0x20)[0]
        n = data[shstrtab_sh_offset + sh_name_idx:].split(b'\x00')[0].decode('ascii', errors='replace')
        if n == name:
            return sh_addr, sh_offset, sh_size
    return None, None, None

def find_data_refs(data, search_str, text_addr, text_off, text_size):
    """Find all code references to a string in the data section."""
    # First find ALL occurrences of the string
    occurrences = []
    offset = 0
    while True:
        idx = data.find(search_str, offset)
        if idx == -1:
            break
        occurrences.append(idx)
        offset = idx + 1
    
    if not occurrences:
        return []
    
    # For each occurrence, find ADRP+ADD references in the text section
    results = []
    for str_off in occurrences:
        str_page = str_off & ~0xFFF
        str_offset = str_off & 0xFFF
        
        for fo in range(text_off, text_off + text_size - 8, 4):
            instr = struct.unpack_from('<I', data, fo)[0]
            addr = text_addr + (fo - text_off)
            
            if (instr >> 24) == 0x90:  # ADRP
                Rd = instr & 0x1F
                immhi = (instr >> 5) & 0x7FFFF
                immlo = (instr >> 29) & 3
                if immhi >= 0x40000: immhi |= 0xFFF80000
                imm = (immhi << 2) | immlo
                target_page = (addr & ~0xFFF) + (imm << 12)
                
                if target_page == str_page:
                    for j in range(1, 8):
                        ci = struct.unpack_from('<I', data, fo + j*4)[0]
                        ci_addr = addr + j*4
                        if (ci >> 24) == 0x91:  # ADD
                            add_Rd = ci & 0x1F
                            add_Rn = (ci >> 5) & 0x1F
                            add_imm12 = (ci >> 10) & 0xFFF
                            if add_Rn == Rd and add_Rd == Rd and add_imm12 == str_offset:
                                results.append((str_off, search_str, addr, ci_addr))
                                break
                        elif (ci >> 24) == 0x90:  # another ADRP - skip
                            break
    
    return results

# =========== 1. Search libagame.so for all .mt references ===========
print('=' * 70)
print('1. STRING SEARCHES IN libagame.so')
print('=' * 70)

# Find references to ".mt"
print('\n--- .mt references ---')
for s, label in [(b'.mt', '.mt'), (b'.mt\x00', '.mt\\0')]:
    refs = find_data_refs(agame, s, TEXT_ADDR, TEXT_OFF, TEXT_SIZE)
    for str_off, pattern, adrp_addr, ref_addr in refs:
        print('  "{}" at data+0x{:x}: ADRP+ADD at 0x{:x} (ref addr 0x{:x})'.format(
            label, str_off, adrp_addr, ref_addr))

# Also search ALL data for .mt related strings
print('\n--- All".mt" data occurrences ---')
offset = 0
while True:
    idx = agame.find(b'.mt', offset)
    if idx == -1: break
    # Show context
    ctx = agame[max(0,idx-8):idx+16]
    ctx_str = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in ctx)
    print('  data+0x{:x}: ...{}...'.format(idx, ctx_str))
    offset = idx + 1

# Search for directory strings
dir_strings = [b'assets/f', b'assets/level', b'f/', b'/f/', b'level/', b'script/', b'lua/']
print('\n--- Directory/asset path strings ---')
for s in dir_strings:
    refs = find_data_refs(agame, s, TEXT_ADDR, TEXT_OFF, TEXT_SIZE)
    for str_off, pattern, adrp_addr, ref_addr in refs:
        ctx = agame[str_off-4:str_off+32]
        ctx_s = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in ctx)
        print('  "{}" at data+0x{:x}: ctx="{}"'.format(pattern.decode(), str_off, ctx_s))

# Search for loading-related strings
load_strings = [b'getFile', b'getString', b'loadString', b'fileData', b'openFile', b'CCFileUtils']
print('\n--- File loading function name strings ---')
for s in load_strings:
    refs = find_data_refs(agame, s, TEXT_ADDR, TEXT_OFF, TEXT_SIZE)
    for str_off, pattern, adrp_addr, ref_addr in refs[:5]:
        print('  "{}" at data+0x{:x}: referenced from 0x{:x}'.format(pattern.decode(), str_off, ref_addr))
    if len(refs) > 5:
        print('    ... and {} more'.format(len(refs)-5))

# =========== 2. Search libhades.so ===========
print('\n' + '=' * 70)
print('2. STRING SEARCHES IN libhades.so')
print('=' * 70)

# libhades.so executable section
# Need to find its text section
hades_text_addr, hades_text_off, hades_text_size = find_section(hades, '.text')
if not hades_text_addr:
    # Maybe it has different section name
    # Just scan all exec sections
    e_shoff = struct.unpack_from('<Q', hades, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', hades, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', hades, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', hades, 0x3E)[0]
    shstrtab_off = e_shoff + e_shstrndx * e_shentsize
    shstrtab_sh_offset = struct.unpack_from('<Q', hades, shstrtab_off + 0x18)[0]
    
    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh_flags = struct.unpack_from('<Q', hades, sh_off + 8)[0]
        sh_addr = struct.unpack_from('<Q', hades, sh_off + 0x10)[0]
        sh_offset = struct.unpack_from('<Q', hades, sh_off + 0x18)[0]
        sh_size = struct.unpack_from('<Q', hades, sh_off + 0x20)[0]
        sh_name_idx = struct.unpack_from('<I', hades, sh_off)[0]
        name = hades[shstrtab_sh_offset + sh_name_idx:].split(b'\x00')[0].decode('ascii', errors='replace')
        
        if sh_flags & 0x4:  # EXEC
            print('  Exec section: {} addr=0x{:x} off=0x{:x} size=0x{:x}'.format(name, sh_addr, sh_offset, sh_size))
            if not hades_text_addr or sh_size > hades_text_size:
                hades_text_addr = sh_addr
                hades_text_off = sh_offset
                hades_text_size = sh_size

print('  Using text: addr=0x{:x} off=0x{:x} size=0x{:x}'.format(hades_text_addr, hades_text_off, hades_text_size))

# Search for .mt in libhades
print('\n--- .mt references in libhades ---')
for s in [b'.mt', b'.mt\x00']:
    refs = find_data_refs(hades, s, hades_text_addr, hades_text_off, hades_text_size)
    for str_off, pattern, adrp_addr, ref_addr in refs:
        print('  "{}" at data+0x{:x}: referenced from 0x{:x}'.format(label, str_off, ref_addr))

# Search for loading-related strings in libhades
print('\n--- Loading-related strings in libhades ---')
for s in [b'getFile', b'open', b'file', b'load', b'cache', b'decode', b'decrypt']:
    refs = find_data_refs(hades, s, hades_text_addr, hades_text_off, hades_text_size)
    for str_off, pattern, adrp_addr, ref_addr in refs[:3]:
        ctx = hades[max(0,str_off-4):str_off+24]
        ctx_s = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in ctx)
        if len(refs) > 0:
            print('  "{}" at data+0x{:x}: ctx="{}" ({} refs)'.format(pattern.decode(), str_off, ctx_s, len(refs)))

# Also search for the magic and related strings in libhades
print('\n--- Game-specific strings in libhades ---')
for s in [b'Roo', b'lmF', b'LMF', b'magic', b'header', b'Hades', b'format']:
    offset = 0
    while True:
        idx = hades.find(s, offset)
        if idx == -1: break
        ctx = hades[max(0,idx-4):idx+16]
        ctx_s = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in ctx)
        print('  "{}" at data+0x{:x}: ctx="{}"'.format(s.decode(), idx, ctx_s))
        offset = idx + 1
        if offset - idx > 100:  # limit
            break
