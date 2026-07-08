import struct

so_path = r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so'
with open(so_path, 'rb') as f:
    data = f.read()

# Parse ELF
e_shoff = struct.unpack('<Q', data[0x28:0x30])[0]
e_shentsize = struct.unpack('<H', data[0x3A:0x3C])[0]
e_shnum = struct.unpack('<H', data[0x3C:0x3E])[0]
e_shstrndx = struct.unpack('<H', data[0x3E:0x40])[0]

shstrtab_off = e_shoff + e_shstrndx * e_shentsize
sh_off = struct.unpack('<Q', data[shstrtab_off+0x18:shstrtab_off+0x20])[0]
sh_size = struct.unpack('<Q', data[shstrtab_off+0x20:shstrtab_off+0x28])[0]
section_names = data[sh_off:sh_off+sh_size]

# Find .dynsym and .dynstr
dynsym_off = 0
dynsym_size = 0
dynstr_off = 0
dynstr_size = 0

for i in range(e_shnum):
    sh = data[e_shoff + i*e_shentsize : e_shoff + (i+1)*e_shentsize]
    sh_name_idx = struct.unpack('<I', sh[0:4])[0]
    sh_offset = struct.unpack('<Q', sh[0x18:0x20])[0]
    sh_size = struct.unpack('<Q', sh[0x20:0x28])[0]
    name = section_names[sh_name_idx:].split(b'\x00')[0].decode('utf-8', errors='replace')
    
    if name == '.dynsym':
        dynsym_off = sh_offset
        dynsym_size = sh_size
        print(f'.dynsym at 0x{dynsym_off:x}, size=0x{dynsym_size:x} ({dynsym_size//24} entries)')
    elif name == '.dynstr':
        dynstr_off = sh_offset
        dynstr_size = sh_size
        print(f'.dynstr at 0x{dynstr_off:x}, size=0x{dynstr_size:x}')

if dynstr_off:
    # Find xxtea_decrypt name offset in dynstr
    pos = data.find(b'xxtea_decrypt', dynstr_off, dynstr_off + dynstr_size)
    if pos >= 0:
        name_off = pos - dynstr_off
        print(f'\nxxtea_decrypt strtab offset: {name_off}')
        
        # Search for st_name == name_off in dynsym using memmem
        import re
        target_bytes = struct.pack('<I', name_off)
        # Search in dynsym
        found_offsets = []
        search_pos = dynsym_off
        while search_pos < dynsym_off + dynsym_size - 24:
            match_pos = data.find(target_bytes, search_pos, dynsym_off + dynsym_size - 24)
            if match_pos < 0:
                break
            # Check if the match is properly aligned (start of a 24-byte entry)
            if (match_pos - dynsym_off) % 24 == 0:
                entry = data[match_pos:match_pos+24]
                st_value = struct.unpack('<Q', entry[8:16])[0]
                st_size = struct.unpack('<Q', entry[16:24])[0]
                st_info = entry[4]
                st_shndx = struct.unpack('<H', entry[6:8])[0]
                type_ = st_info & 0xF
                print(f'  Found! st_value=0x{st_value:x}, st_size=0x{st_size:x}, type={type_}, shndx={st_shndx}')
                if type_ == 2:  # STT_FUNC
                    print(f'  ==> xxtea_decrypt is at 0x{st_value:x}, size 0x{st_size:x}')
            search_pos = match_pos + 4

# Also try finding it via searching for known xxtea-related strings
# Standard XXTEA uses specific constants - search for functions referencing them
# Also let me try searching the entire binary near known code regions
print('\n=== Searching for function that uses XXTEA delta near 0x11xxxx ===')
# Look at the region around 0x11c000 - 0x120000 for xxtea code
# Instead, let me check if there's an exported symbol table (.dynsym exports)
# Read .dynamic section to get DT_SYMTAB and DT_STRTAB

# Read program headers for PT_DYNAMIC
e_phoff_raw = struct.unpack('<Q', data[0x20:0x28])[0]
e_phentsize = struct.unpack('<H', data[0x36:0x38])[0]
e_phnum = struct.unpack('<H', data[0x38:0x3A])[0]

for i in range(e_phnum):
    ph = data[e_phoff_raw + i*e_phentsize : e_phoff_raw + (i+1)*e_phentsize]
    p_type = struct.unpack('<I', ph[0:4])[0]
    if p_type == 2:  # PT_DYNAMIC
        p_offset = struct.unpack('<Q', ph[8:16])[0]
        p_filesz = struct.unpack('<Q', ph[32:40])[0]
        print(f'\nDynamic section at 0x{p_offset:x}, size=0x{p_filesz:x}')
        
        # Parse .dynamic entries
        dyn = data[p_offset:p_offset+p_filesz]
        for j in range(0, len(dyn), 16):
            d_tag = struct.unpack('<Q', dyn[j:j+8])[0]
            d_val = struct.unpack('<Q', dyn[j+8:j+16])[0]
            if d_tag == 5:  # DT_STRTAB
                print(f'  DT_STRTAB = 0x{d_val:x}')
            elif d_tag == 6:  # DT_SYMTAB
                print(f'  DT_SYMTAB = 0x{d_val:x}')
            elif d_tag == 10:  # DT_STRSZ
                print(f'  DT_STRSZ = {d_val}')
            elif d_tag == 11:  # DT_GOTSZ (or similar)
                pass
            if d_tag == 0:
                break
