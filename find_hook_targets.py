"""Find exact addresses of Lua hook targets in libagame.so."""
import struct

path = r'C:\Users\NGEONG\Videos\MLA\libagame.so'
with open(path, 'rb') as f:
    data = f.read()

# Parse ELF64 header
shoff = struct.unpack_from('<Q', data, 0x28)[0]
shnum = struct.unpack_from('<H', data, 0x3C)[0]
shentsize = struct.unpack_from('<H', data, 0x3A)[0]
shstrndx = struct.unpack_from('<H', data, 0x3E)[0]

# Get section name string table
shstrtab_off = struct.unpack_from('<Q', data, shoff + shstrndx * shentsize + 0x18)[0]

def get_name(idx):
    if idx == 0: return ''
    end = data.find(b'\x00', shstrtab_off + idx)
    return data[shstrtab_off + idx:end].decode('ascii', errors='replace')

# Find .dynsym and .dynstr sections
sym_info = None
str_info = None
for i in range(shnum):
    sh_off = shoff + i * shentsize
    sh_type = struct.unpack_from('<I', data, sh_off + 4)[0]
    sh_flags = struct.unpack_from('<Q', data, sh_off + 8)[0]
    name = get_name(struct.unpack_from('<I', data, sh_off)[0])
    if sh_type == 11:  # SHT_DYNSYM
        sym_info = (
            struct.unpack_from('<Q', data, sh_off + 0x10)[0],  # addr
            struct.unpack_from('<Q', data, sh_off + 0x18)[0],  # offset
            struct.unpack_from('<Q', data, sh_off + 0x20)[0],  # size
        )
    elif name == '.dynstr':
        str_info = (
            struct.unpack_from('<Q', data, sh_off + 0x10)[0],  # addr
            struct.unpack_from('<Q', data, sh_off + 0x18)[0],  # offset
            struct.unpack_from('<Q', data, sh_off + 0x20)[0],  # size
        )

sym_addr, sym_off, sym_size = sym_info
str_addr, str_off, str_size = str_info
esize = 24
nsym = sym_size // esize

# Functions we want to hook
target_funcs = [
    'lua_rawgeti', 'lua_getfield', 'lua_setfield', 'lua_rawset',
    'lua_gettable', 'lua_settable', 'lua_rawget', 'lua_rawseti',
    'lua_pcall', 'lua_call', 'lua_load', 'luaL_loadbuffer',
    'lua_tointeger', 'lua_tointegerx', 'lua_pushinteger',
    'lua_gettop', 'lua_settop', 'lua_pushvalue',
]

found = {}
for i in range(nsym):
    off = sym_off + i * esize
    st_name = struct.unpack_from('<I', data, off)[0]
    st_value = struct.unpack_from('<Q', data, off + 8)[0]
    st_size = struct.unpack_from('<Q', data, off + 16)[0]
    st_type = data[off + 4] & 0xF
    
    if st_name == 0 or st_name >= str_size:
        continue
    
    name_bytes = data[str_off + st_name:str_off + st_name + 64]
    name = name_bytes.split(b'\x00')[0].decode('ascii', errors='replace')
    
    for t in target_funcs:
        if name == t:
            tname = 'FUNC' if st_type == 2 else 'OBJECT'
            found[name] = (st_value, st_size, tname)
            break

print("Target Function Addresses in libagame.so:")
print("=" * 65)
print("{:<25s} {:<15s} {:<10s} {}".format('Function', 'Address', 'Type', 'Size'))
print("-" * 65)
for name in target_funcs:
    if name in found:
        addr, size, tname = found[name]
        offset_from_text = addr - 0x3fc000
        print("{:<25s} 0x{:08x} ({:>+6d} from .text) {:<6s} {} bytes".format(
            name, addr, offset_from_text, tname, size))
    else:
        print("{:<25s} NOT FOUND in .dynsym".format(name))

# Also look for lua_rawgeti by searching for function names ending with it
print("\n\nSearching for lua_rawget variants in all 34,426 symbols...")
for i in range(nsym):
    off = sym_off + i * esize
    st_name = struct.unpack_from('<I', data, off)[0]
    st_value = struct.unpack_from('<Q', data, off + 8)[0]
    
    if st_name == 0 or st_name >= str_size:
        continue
    name_bytes = data[str_off + st_name:str_off + st_name + 64]
    name = name_bytes.split(b'\x00')[0].decode('ascii', errors='replace')
    
    if 'rawgeti' in name or 'rawseti' in name or 'getfield' in name:
        print("  0x{:08x} {}".format(st_value, name))
