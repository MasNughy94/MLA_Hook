"""Find all hook-related function addresses in libagame.so."""
import struct

path = r'C:\Users\NGEONG\Videos\MLA\libagame.so'
with open(path, 'rb') as f:
    data = f.read()

# Parse ELF64
shoff = struct.unpack_from('<Q', data, 0x28)[0]
shnum = struct.unpack_from('<H', data, 0x3C)[0]
shentsize = struct.unpack_from('<H', data, 0x3A)[0]
shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
shstrtab_off = struct.unpack_from('<Q', data, shoff + shstrndx * shentsize + 0x18)[0]

def get_name(idx):
    if idx == 0: return ''
    end = data.find(b'\x00', shstrtab_off + idx)
    return data[shstrtab_off + idx:end].decode('ascii', errors='replace')

# Find sections
sym_info = str_info = None
for i in range(shnum):
    sh_off = shoff + i * shentsize
    sh_type = struct.unpack_from('<I', data, sh_off + 4)[0]
    name = get_name(struct.unpack_from('<I', data, sh_off)[0])
    saddr = struct.unpack_from('<Q', data, sh_off + 0x10)[0]
    soff = struct.unpack_from('<Q', data, sh_off + 0x18)[0]
    ssize = struct.unpack_from('<Q', data, sh_off + 0x20)[0]
    if sh_type == 11:
        sym_info = (saddr, soff, ssize)
    elif name == '.dynstr':
        str_info = (saddr, soff, ssize)

sym_addr, sym_off, sym_size = sym_info
str_addr, str_off, str_size = str_info

# Additional Lua functions needed
extra_funcs = [
    # Core Lua API
    'lua_type', 'lua_typename', 'lua_rawequal', 'lua_toboolean',
    'lua_tolstring', 'lua_touserdata', 'lua_tothread', 'lua_topointer',
    'lua_pushnil', 'lua_pushnumber', 'lua_pushstring', 'lua_pushlstring',
    'lua_pushcclosure', 'lua_pushboolean', 'lua_pushlightuserdata',
    'lua_createtable', 'lua_newuserdata', 'lua_newtable',
    'lua_next', 'lua_concat', 'lua_len',
    'lua_getmetatable', 'lua_setmetatable',
    'lua_lessthan', 'lua_equal', 'lua_compare',
    'lua_error', 'lua_isnumber', 'lua_isstring', 'lua_iscfunction',
    'lua_isuserdata', 'lua_isfunction', 'lua_isnil', 'lua_istable',
    # tolua++
    'tolua_typename', 'tolua_tofield', 'tolua_pushfield',
    'tolua_getfieldboolean',
    # Game-specific (from earlier analysis)
    'luaopen_base', 'luaopen_table', 'luaopen_string',
]

# Also search for all lua_push*, lua_to*, lua_is* functions systematically
prefixes = ['lua_push', 'lua_to', 'lua_is', 'luaL_']

print("=== Lua API Functions in libagame.so ===\n")

# First pass: exact matches for extra_funcs
found = {}
for i in range(sym_size // 24):
    off = sym_off + i * 24
    st_name = struct.unpack_from('<I', data, off)[0]
    st_value = struct.unpack_from('<Q', data, off + 8)[0]
    if st_name == 0 or st_name >= str_size:
        continue
    name = data[str_off + st_name:str_off + st_name + 64].split(b'\x00')[0].decode('ascii', errors='replace')
    
    for f in extra_funcs:
        if name == f:
            found[name] = st_value

for name in extra_funcs:
    if name in found:
        print("  0x{:08x}  {}".format(found[name], name))
    else:
        print("  ----------  {}  NOT FOUND".format(name))

# Second pass: systematic search for all lua_push*, lua_to*, lua_is*, luaL_*
print("\n\n=== All lua_push* functions ===")
for i in range(sym_size // 24):
    off = sym_off + i * 24
    st_name = struct.unpack_from('<I', data, off)[0]
    st_value = struct.unpack_from('<Q', data, off + 8)[0]
    st_size = struct.unpack_from('<Q', data, off + 16)[0]
    if st_name == 0 or st_name >= str_size:
        continue
    name = data[str_off + st_name:str_off + st_name + 80].split(b'\x00')[0].decode('ascii', errors='replace')
    if name.startswith('lua_push'):
        print("  0x{:08x}  {} ({})".format(st_value, name, st_size))

print("\n\n=== All lua_to* and luaL_check* functions ===")
for i in range(sym_size // 24):
    off = sym_off + i * 24
    st_name = struct.unpack_from('<I', data, off)[0]
    st_value = struct.unpack_from('<Q', data, off + 8)[0]
    st_size = struct.unpack_from('<Q', data, off + 16)[0]
    if st_name == 0 or st_name >= str_size:
        continue
    name = data[str_off + st_name:str_off + st_name + 80].split(b'\x00')[0].decode('ascii', errors='replace')
    if name.startswith('lua_to') or name.startswith('luaL_check'):
        print("  0x{:08x}  {} ({})".format(st_value, name, st_size))

# Write all found addresses to a config file
print("\n\n=== Address map for hook config ===")
all_addrs = {}
for i in range(sym_size // 24):
    off = sym_off + i * 24
    st_name = struct.unpack_from('<I', data, off)[0]
    st_value = struct.unpack_from('<Q', data, off + 8)[0]
    if st_name == 0 or st_name >= str_size:
        continue
    name = data[str_off + st_name:str_off + st_name + 80].split(b'\x00')[0].decode('ascii', errors='replace')
    if name.startswith('lua_') or name.startswith('tolua_'):
        all_addrs[name] = st_value

# Save as C header
with open(r'C:\Users\NGEONG\Videos\MLA\lua_offsets.h', 'w') as f:
    f.write('// Auto-generated Lua function offsets for libagame.so\n')
    f.write('// Static base = 0, runtime = base + offset\n\n')
    f.write('#ifndef LUA_OFFSETS_H\n#define LUA_OFFSETS_H\n\n')
    for name in sorted(all_addrs.keys()):
        f.write('#define {:<35s} 0x{:08x}\n'.format('OFF_' + name.upper(), all_addrs[name]))
    f.write('\n#endif\n')

print("  Written {} offsets to lua_offsets.h".format(len(all_addrs)))
