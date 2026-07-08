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

# Find .dynsym
dynsym_off = 0
dynsym_size = 0
dynsym_entsize = 24  # ELF64
dynstr_off = 0
dynstr_size = 0

for i in range(e_shnum):
    sh = data[e_shoff + i*e_shentsize : e_shoff + (i+1)*e_shentsize]
    sh_name_idx = struct.unpack('<I', sh[0:4])[0]
    sh_type = struct.unpack('<I', sh[4:8])[0]
    sh_offset = struct.unpack('<Q', sh[0x18:0x20])[0]
    sh_size = struct.unpack('<Q', sh[0x20:0x28])[0]
    name = section_names[sh_name_idx:].split(b'\x00')[0].decode('utf-8', errors='replace')
    
    if name == '.dynsym':
        dynsym_off = sh_offset
        dynsym_size = sh_size
        print(f'.dynsym at 0x{dynsym_off:x}, size=0x{dynsym_size:x}, num={dynsym_size//24}')
    elif name == '.dynstr':
        dynstr_off = sh_offset
        dynstr_size = sh_size
        print(f'.dynstr at 0x{dynstr_off:x}, size=0x{dynstr_size:x}')

# Only search for specific symbols by name
if dynstr_off:
    search_terms = {
        b'xxtea_decrypt': None,
        b'xxtea_encrypt': None,
        b'getKey\x00': None,
        b'getkey\x00': None,
        b'tea_decrypt': None,
        b'decrypt_mt': None,
        b'Antm': None,
    }
    
    for term in search_terms:
        pos = data.find(term, dynstr_off, dynstr_off + dynstr_size)
        if pos >= 0:
            name_offset = pos - dynstr_off
            search_terms[term] = name_offset
            name = data[pos:].split(b'\x00')[0].decode('utf-8', errors='replace')
            print(f'\nFound "{name}" at strtab idx {name_offset}')

    # Now scan dynsym for matching entries
    if dynsym_off and any(v is not None for v in search_terms.values()):
        offsets = set(v for v in search_terms.values() if v is not None)
        print(f'\nSearching dynsym for {len(offsets)} name offsets...')
        
        for entry_idx in range(dynsym_size // 24):
            entry = data[dynsym_off + entry_idx*24 : dynsym_off + (entry_idx+1)*24]
            st_name = struct.unpack('<I', entry[0:4])[0]
            
            if st_name in offsets:
                st_value = struct.unpack('<Q', entry[8:16])[0]
                st_size = struct.unpack('<Q', entry[16:24])[0]
                st_info = entry[4]
                bind = st_info >> 4
                type_ = st_info & 0xF
                
                name = data[dynstr_off + st_name:].split(b'\x00')[0].decode('utf-8', errors='replace')
                print(f'  {name}: addr=0x{st_value:x}, size=0x{st_size:x}, bind={bind}, type={type_}')
        
        # Also search for ANY symbol containing 'xxtea' in a single pass
        print('\n=== All xxtea/tea symbols (fast scan) ===')
        found = 0
        for entry_idx in range(dynsym_size // 24):
            entry = data[dynsym_off + entry_idx*24 : dynsym_off + (entry_idx+1)*24]
            st_name = struct.unpack('<I', entry[0:4])[0]
            st_info = entry[4]
            type_ = st_info & 0xF
            
            if st_name > 0 and type_ == 2:
                name = data[dynstr_off + st_name:].split(b'\x00')[0]
                lname = name.lower()
                if b'xxtea' in lname or b'tea_key' in lname or b'antm' in lname:
                    st_value = struct.unpack('<Q', entry[8:16])[0]
                    st_size = struct.unpack('<Q', entry[16:24])[0]
                    print(f'    {name.decode(errors="replace")}: addr=0x{st_value:x}, size=0x{st_size:x}')
                    found += 1
                    if found > 20:
                        print('    ... (too many, stopping)')
                        break
