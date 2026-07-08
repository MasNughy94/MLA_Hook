so = open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb').read()

# Find the "RunRootLua" string reference and trace its XREFs
print("String references near RunRootLua:")
idx = so.find(b'RunRootLua')
# The mangled name is: _Z10RunRootLuav
# Let's also search for the full mangled name
mangled = b'_Z10RunRootLuav'
idx2 = so.find(mangled)
if idx2 >= 0:
    ctx = so[max(0,idx2-16):idx2+len(mangled)+32]
    print(f'  Mangied name at {idx2:#x}')
    for i in range(0, len(ctx), 16):
        chunk = ctx[i:i+16]
        hexstr = ' '.join(f'{b:02x}' for b in chunk)
        asciistr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'    {idx2-16+i:#x}: {hexstr:<48s} {asciistr}')

# Search for related Lua loading function names
print('\nCocos2d-x Lua loader symbols:')
import re
# Look for mangled names near "lua_loader" and "xxtea"
loaders = []
for marker in [b'lua_loader', b'xxtea_decrypt', b'luaL_loadbuffer']:
    idx = 0
    while True:
        idx = so.find(marker, idx)
        if idx == -1:
            break
        # Get surrounding context (typically mangled C++ name)
        ctx_start = max(0, idx - 40)
        ctx = so[ctx_start:min(len(so), idx + 80)]
        # Extract strings (null-terminated)
        mystr = b''
        for c in ctx:
            if 32 <= c < 127 or c == 0:
                if c == 0:
                    if len(mystr) > 3:
                        loaders.append(mystr.decode('ascii', errors='replace'))
                    mystr = b''
                else:
                    mystr += bytes([c])
        idx += 1

# Print unique symbols
seen = set()
for s in loaders:
    if s.startswith('_Z'):
        if s not in seen:
            seen.add(s)
            print(f'  {s}')
