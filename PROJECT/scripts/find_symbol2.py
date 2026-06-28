import struct

so = open(r'C:\Users\NGEONG\Videos\VSCODE\libagame.so', 'rb').read()

# Parse ELF headers
e_shoff = struct.unpack_from('<Q', so, 0x28)[0]
e_shentsize = struct.unpack_from('<H', so, 0x3A)[0]
e_shnum = struct.unpack_from('<H', so, 0x3C)[0]
e_shstrndx = struct.unpack_from('<H', so, 0x3E)[0]

# Find .dynsym
dynsym_off = 0
dynsym_size = 0
dynstr_off = 0

for i in range(e_shnum):
    sh_off = e_shoff + i * e_shentsize
    sh_type = struct.unpack_from('<I', so, sh_off + 4)[0]
    sh_offset = struct.unpack_from('<Q', so, sh_off + 0x18)[0]
    sh_size = struct.unpack_from('<Q', so, sh_off + 0x20)[0]
    sh_entsize = struct.unpack_from('<Q', so, sh_off + 0x38)[0]
    sh_name_o = struct.unpack_from('<I', so, sh_off + 0)[0]
    
    # Get section name
    shstrtab_off = e_shoff + e_shstrndx * e_shentsize
    shstrtab_offset = struct.unpack_from('<Q', so, shstrtab_off + 0x18)[0]
    secname = b''
    j = shstrtab_offset + sh_name_o
    while j < len(so) and so[j] != 0:
        secname += bytes([so[j]])
        j += 1
    secname = secname.decode('ascii', errors='replace')
    
    if sh_type == 11:  # SHT_DYNSYM
        dynsym_off = sh_offset
        dynsym_size = sh_size
        dynsym_entsize = sh_entsize
        print(f'.dynsym ({secname}) at {sh_offset:#x}, size={sh_size:#x}')
    if sh_type == 3 and 'dynstr' in secname:  # SHT_STRTAB
        dynstr_off = sh_offset
        print(f'.dynstr ({secname}) at {sh_offset:#x}, size={sh_size:#x}')

# Search for Lua-related function names in dynsym
search_terms = ['LoadFunction', 'LoadString', 'LoadCode', 'LoadConstants', 
                'LoadProtos', 'LoadDebug', 'LoadUpvalues', 'luaU_undump',
                'LoadByte', 'undump', 'lua_load', 'luaL_load',
                'luaLoadBuffer', 'LuaStack']

print(f'\nSearching {dynsym_size//dynsym_entsize} symbols...')
found = []

for i in range(dynsym_size // dynsym_entsize):
    sym_off = dynsym_off + i * dynsym_entsize
    st_name = struct.unpack_from('<I', so, sym_off)[0]
    st_value = struct.unpack_from('<Q', so, sym_off + 8)[0]
    st_size = struct.unpack_from('<Q', so, sym_off + 16)[0]
    
    name = b''
    j = dynstr_off + st_name
    while j < len(so) and so[j] != 0:
        name += bytes([so[j]])
        j += 1
    name = name.decode('ascii', errors='replace')
    
    for term in search_terms:
        if term.lower() in name.lower() and 'plt' not in name:
            found.append((name, st_value, st_size))
            break

for name, addr, sz in sorted(found, key=lambda x: x[1]):
    sym_type = 'FUNC' if 'F' in name else 'OBJ'
    print(f'  0x{addr:08x} ({sz:#x}B): {name}')
