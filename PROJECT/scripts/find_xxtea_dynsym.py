import struct

so_path = r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so'
with open(so_path, 'rb') as f:
    data = f.read()

# Parse ELF
e_shoff = struct.unpack('<Q', data[0x28:0x30])[0]
e_shentsize = struct.unpack('<H', data[0x3A:0x3C])[0]
e_shnum = struct.unpack('<H', data[0x3C:0x3E])[0]
e_shstrndx = struct.unpack('<H', data[0x3E:0x40])[0]

# Read section header string table
shstrtab_off = e_shoff + e_shstrndx * e_shentsize
sh_offset = struct.unpack('<Q', data[shstrtab_off+0x18:shstrtab_off+0x20])[0]
sh_size = struct.unpack('<Q', data[shstrtab_off+0x20:shstrtab_off+0x28])[0]
section_names = data[sh_offset:sh_offset+sh_size]

# Find .dynsym and .dynstr
dynsym_off = None
dynsym_size = None
dynsym_entsize = None
dynstr_off = None
dynstr_size = None

for i in range(e_shnum):
    sh = data[e_shoff + i*e_shentsize : e_shoff + (i+1)*e_shentsize]
    sh_name_idx = struct.unpack('<I', sh[0:4])[0]
    sh_type = struct.unpack('<I', sh[4:8])[0]
    sh_offset = struct.unpack('<Q', sh[0x18:0x20])[0]
    sh_size = struct.unpack('<Q', sh[0x20:0x28])[0]
    sh_entsize = struct.unpack('<Q', sh[0x38:0x40])[0]
    name = section_names[sh_name_idx:].split(b'\x00')[0].decode('utf-8', errors='replace')
    
    if name == '.dynsym':
        dynsym_off = sh_offset
        dynsym_size = sh_size
        dynsym_entsize = sh_entsize
        print(f'.dynsym at 0x{dynsym_off:x}, size=0x{dynsym_size:x}, entsize={dynsym_entsize}')
    elif name == '.dynstr':
        dynstr_off = sh_offset
        dynstr_size = sh_size
        print(f'.dynstr at 0x{dynstr_off:x}, size=0x{dynstr_size:x}')

if dynsym_off and dynstr_off:
    # Search in dynstr for xxtea symbols
    for search_term in [b'xxtea_decrypt', b'xxtea_encrypt', b'xxtea', b'getKey', b'getkey']:
        pos = data.find(search_term, dynstr_off, dynstr_off + dynstr_size)
        if pos >= 0:
            name_offset = pos - dynstr_off
            print(f'\nFound "{search_term.decode()}" at dynstr offset {name_offset}')
            
            # Search dynsym
            for entry_idx in range(dynsym_size // dynsym_entsize):
                entry = data[dynsym_off + entry_idx*24 : dynsym_off + (entry_idx+1)*24]
                st_name = struct.unpack('<I', entry[0:4])[0]
                if st_name == name_offset:
                    st_info = entry[4]
                    st_other = entry[5]
                    st_shndx = struct.unpack('<H', entry[6:8])[0]
                    st_value = struct.unpack('<Q', entry[8:16])[0]
                    st_size = struct.unpack('<Q', entry[16:24])[0]
                    bind = st_info >> 4
                    type_ = st_info & 0xF
                    s_name = data[dynstr_off + st_name:].split(b'\x00')[0].decode('utf-8', errors='replace')
                    print(f'  SYM: {s_name}')
                    print(f'    st_value=0x{st_value:x}, st_size=0x{st_size:x}, bind={bind}, type={type_}, shndx={st_shndx}')

    # List ALL xxtea/tea related symbols
    print('\n=== All xxtea/key-related dynamic symbols ===')
    for entry_idx in range(dynsym_size // dynsym_entsize):
        entry = data[dynsym_off + entry_idx*24 : dynsym_off + (entry_idx+1)*24]
        st_name = struct.unpack('<I', entry[0:4])[0]
        st_info = entry[4]
        type_ = st_info & 0xF
        
        if st_name > 0 and type_ == 2:  # STT_FUNC
            name = data[dynstr_off + st_name:].split(b'\x00')[0].decode('utf-8', errors='replace')
            if any(k in name.lower() for k in ['xxtea', 'tea', 'getkey', 'get_key', 'decrypt', 'encrypt', 'antm']):
                st_value = struct.unpack('<Q', entry[8:16])[0]
                st_size = struct.unpack('<Q', entry[16:24])[0]
                print(f'  {name}')
                print(f'    addr=0x{st_value:x}, size=0x{st_size:x}')
