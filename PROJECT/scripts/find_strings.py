so = open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb').read()

# Search for Lua-related strings that indicate the parser
patterns = [
    b'RunRootLua',
    b'loadbuffer',
    b'lua_load',
    b'luaL_loadbuffer',
    b'luaU_undump',
    b'Loader',
    b'reader',
    b'chunk',
    b'header',
    b'function',
    b'constant',
    b'prototype',
    b'string table',
    b'RootLua',
]

for pat in patterns:
    off = 0
    first = None
    count = 0
    while True:
        idx = so.find(pat, off)
        if idx == -1:
            break
        if first is None:
            first = idx
        count += 1
        off = idx + 1
    if count > 0:
        ctx_start = max(0, first - 8)
        ctx_end = min(len(so), first + len(pat) + 16)
        ctx = so[ctx_start:ctx_end]
        hexstr = ' '.join(f'{b:02x}' for b in ctx)
        asciistr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f'{pat.decode(errors="replace"):20s}: {count:3d} hits  first@ {first:#x}  ctx={hexstr}  "{asciistr}"')
