import struct

so = open(r'C:\Users\NGEONG\Videos\VSCODE\libagame.so', 'rb').read()

# Search for ELF section headers to find symbol table
# ELF header is at offset 0
# For ARM64 (64-bit ELF):
# e_shoff (section header offset) at offset 0x28 (8 bytes, LE)
# e_shentsize at 0x3A (2 bytes)
# e_shnum at 0x3C (2 bytes)
# e_shstrndx at 0x3E (2 bytes)

e_shoff = struct.unpack_from('<Q', so, 0x28)[0]
e_shentsize = struct.unpack_from('<H', so, 0x3A)[0]
e_shnum = struct.unpack_from('<H', so, 0x3C)[0]
e_shstrndx = struct.unpack_from('<H', so, 0x3E)[0]

print(f'e_shoff={e_shoff:#x}, e_shentsize={e_shentsize}, e_shnum={e_shnum}, e_shstrndx={e_shstrndx}')

# Find .symtab and .strtab sections
# Section header entry structure (64-bit ELF):
# sh_name (4), sh_type (4), sh_flags (8), sh_addr (8), sh_offset (8)
# sh_size (8), sh_link (4), sh_info (4), sh_addralign (8), sh_entsize (8)
# Total: 64 bytes

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHN_UNDEF = 0

symtab_off = 0
symtab_size = 0
symtab_entsize = 0
strtab_off = 0
strtab_size = 0

for i in range(e_shnum):
    sh_off = e_shoff + i * e_shentsize
    sh_type = struct.unpack_from('<I', so, sh_off + 4)[0]
    sh_offset = struct.unpack_from('<Q', so, sh_off + 0x18)[0]
    sh_size = struct.unpack_from('<Q', so, sh_off + 0x20)[0]
    sh_entsize = struct.unpack_from('<Q', so, sh_off + 0x38)[0]
    if sh_type == SHT_SYMTAB:
        symtab_off = sh_offset
        symtab_size = sh_size
        symtab_entsize = sh_entsize
        print(f'.symtab at {symtab_off:#x}, size={symtab_size:#x}, entsize={symtab_entsize}')

# If no .symtab, try .dynsym (also uses SHT_DYNSYM = 11)
SHT_DYNSYM = 11
dynsym_off = 0
dynsym_size = 0
dynsym_entsize = 0
dynstr_off = 0

for i in range(e_shnum):
    sh_off = e_shoff + i * e_shentsize
    sh_type = struct.unpack_from('<I', so, sh_off + 4)[0]
    sh_offset = struct.unpack_from('<Q', so, sh_off + 0x18)[0]
    sh_size = struct.unpack_from('<Q', so, sh_off + 0x20)[0]
    sh_entsize = struct.unpack_from('<Q', so, sh_off + 0x38)[0]
    sh_name_o = struct.unpack_from('<I', so, sh_off + 0)[0]
    # Get section name from .shstrtab
    shstrtab_off = e_shoff + e_shstrndx * e_shentsize
    shstrtab_offset = struct.unpack_from('<Q', so, shstrtab_off + 0x18)[0]
    name = b''
    j = shstrtab_offset + sh_name_o
    while so[j] != 0:
        name += bytes([so[j]])
        j += 1
    name = name.decode('ascii', errors='replace')
    
    if sh_type == SHT_DYNSYM:
        dynsym_off = sh_offset
        dynsym_size = sh_size
        dynsym_entsize = sh_entsize
        print(f'.dynsym ({name}) at {sh_offset:#x}, size={sh_size:#x}, entsize={sh_entsize}')
    if sh_type == SHT_STRTAB and 'dynstr' in name:
        dynstr_off = sh_offset
        print(f'.dynstr ({name}) at {sh_offset:#x}, size={sh_size:#x}')

# Search dynsym for RunRootLua
print(f'\nSearching dynsym for RunRootLua:')
sym_size = 24  # ELF64 symbol entry
for i in range(dynsym_size // sym_size):
    sym_off = dynsym_off + i * sym_size
    st_name = struct.unpack_from('<I', so, sym_off)[0]  # offset in .dynstr
    st_info = so[sym_off + 4]
    st_other = so[sym_off + 5]
    st_shndx = struct.unpack_from('<H', so, sym_off + 6)[0]
    st_value = struct.unpack_from('<Q', so, sym_off + 8)[0]
    st_size = struct.unpack_from('<Q', so, sym_off + 16)[0]
    
    # Read the name
    name = b''
    j = dynstr_off + st_name
    while j < len(so) and so[j] != 0:
        name += bytes([so[j]])
        j += 1
    name = name.decode('ascii', errors='replace')
    
    if 'RunRootLua' in name or 'CheckIsLua' in name or 'RootLua' in name:
        bind = (st_info >> 4) & 0xF
        type_ = st_info & 0xF
        print(f'  {name}: value={st_value:#x}, size={st_size:#x}, bind={bind}, type={type_}')
