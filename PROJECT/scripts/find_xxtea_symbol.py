import struct

so_path = r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so'
with open(so_path, 'rb') as f:
    data = f.read()

# Parse ELF
e_shoff = struct.unpack('<Q', data[0x28:0x30])[0]
e_shentsize = struct.unpack('<H', data[0x3A:0x3C])[0]
e_shnum = struct.unpack('<H', data[0x3C:0x3E])[0]
e_shstrndx = struct.unpack('<H', data[0x3E:0x40])[0]

print(f'Section headers at 0x{e_shoff:x}, num={e_shnum}, strtab_idx={e_shstrndx}')

# Read section header string table
shstrtab_off = e_shoff + e_shstrndx * e_shentsize
sh_name = struct.unpack('<I', data[shstrtab_off:shstrtab_off+4])[0]
sh_type = struct.unpack('<I', data[shstrtab_off+4:shstrtab_off+8])[0]
sh_offset = struct.unpack('<Q', data[shstrtab_off+0x18:shstrtab_off+0x20])[0]
sh_size = struct.unpack('<Q', data[shstrtab_off+0x20:shstrtab_off+0x28])[0]
section_names = data[sh_offset:sh_offset+sh_size]

print(f'Section strtab at 0x{sh_offset:x}, size=0x{sh_size:x}')

# Find symtab and strtab sections
symtab_off = None
strtab_off = None
symtab_size = None
strtab_size = None

for i in range(e_shnum):
    sh = data[e_shoff + i*e_shentsize : e_shoff + (i+1)*e_shentsize]
    sh_name_idx = struct.unpack('<I', sh[0:4])[0]
    sh_type = struct.unpack('<I', sh[4:8])[0]
    sh_offset = struct.unpack('<Q', sh[0x18:0x20])[0]
    sh_size = struct.unpack('<Q', sh[0x20:0x28])[0]
    sh_entsize = struct.unpack('<Q', sh[0x38:0x40])[0]
    
    name = section_names[sh_name_idx:].split(b'\x00')[0].decode('utf-8', errors='replace')
    
    if sh_type == 2:  # SHT_SYMTAB
        symtab_off = sh_offset
        symtab_size = sh_size
        symtab_entsize = sh_entsize
        print(f'  SYMTAB at 0x{sh_offset:x}, size=0x{sh_size:x}, entsize={sh_entsize}, name={name}')
    elif sh_type == 3:  # SHT_STRTAB
        if i == e_shstrndx:
            pass  # Already have section name strtab
        elif name in ['.strtab', '.dynstr']:
            strtab_off = sh_offset
            strtab_size = sh_size
            print(f'  STRTAB at 0x{sh_offset:x}, size=0x{sh_size:x}, name={name}')

# Search for xxtea_decrypt in string table
if strtab_off:
    search = b'xxtea_decrypt'
    pos = data.find(search, strtab_off, strtab_off + strtab_size)
    if pos >= 0:
        name_offset = pos - strtab_off
        print(f'\nFound "xxtea_decrypt" at strtab offset {name_offset}')
        
        # Now search symtab for this name_offset
        if symtab_off:
            for entry_idx in range(symtab_size // symtab_entsize):
                entry = data[symtab_off + entry_idx*28 : symtab_off + (entry_idx+1)*28]
                st_name = struct.unpack('<I', entry[0:4])[0]
                if st_name == name_offset:
                    st_info = entry[4]
                    st_other = entry[5]
                    st_shndx = struct.unpack('<H', entry[6:8])[0]
                    st_value = struct.unpack('<Q', entry[8:16])[0]
                    st_size = struct.unpack('<Q', entry[16:24])[0]
                    bind = st_info >> 4
                    type_ = st_info & 0xF
                    print(f'  SYMBOL: st_value=0x{st_value:x}, st_size=0x{st_size:x}, bind={bind}, type={type_}')
                    break
        
        # Also search for related symbols
        for search_term in [b'xxtea', b'XXTEA', b'tea_key', b'getKey', b'getkey', b'get_key']:
            pos2 = data.find(search_term, strtab_off, strtab_off + strtab_size)
            if pos2 >= 0:
                name_off2 = pos2 - strtab_off
                # Find matching symbol
                if symtab_off:
                    for entry_idx in range(symtab_size // symtab_entsize):
                        entry = data[symtab_off + entry_idx*28 : symtab_off + (entry_idx+1)*28]
                        st_name = struct.unpack('<I', entry[0:4])[0]
                        if st_name == name_off2:
                            st_value = struct.unpack('<Q', entry[8:16])[0]
                            st_size = struct.unpack('<Q', entry[16:24])[0]
                            s_name = data[strtab_off + st_name:].split(b'\x00')[0].decode('utf-8', errors='replace')
                            print(f'  SYMBOL: {s_name} at 0x{st_value:x}, size=0x{st_size:x}')
                            break

# Also search for other interesting functions
print()
print('=== Related function symbols ===')
search_funcs = [b'decrypt', b'encrypt', b'tea', b'key_dec', b'KeyDec', b'getKey', b'Antm']
if strtab_off and symtab_off:
    for entry_idx in range(symtab_size // symtab_entsize):
        entry = data[symtab_off + entry_idx*28 : symtab_off + (entry_idx+1)*28]
        st_name = struct.unpack('<I', entry[0:4])[0]
        st_value = struct.unpack('<Q', entry[8:16])[0]
        st_size = struct.unpack('<Q', entry[16:24])[0]
        st_info = entry[4]
        type_ = st_info & 0xF
        if type_ == 2 and st_value > 0 and st_size > 0:  # STT_FUNC
            name = data[strtab_off + st_name:].split(b'\x00')[0].decode('utf-8', errors='replace')
            for sf in search_funcs:
                if sf in name.lower().encode():
                    print(f'  {name}')
                    print(f'    at 0x{st_value:x}, size=0x{st_size:x}')
                    break
