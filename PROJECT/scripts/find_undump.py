so = open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb').read()

# Look for all Lua undump error messages
patterns = [
    b'bad header',
    b'bad instruction',
    b'bad constant',
    b'invalid string table',
    b'bad description',
    b'read error',
    b'truncated',
    b'premature end',
    b'unknown type',
    b'number expected',
    b'integer expected',
    b'luaU_undump',
    b'LoadFunction',
    b'LoadString',
    b'LoadCode',
    b'LoadConstants',
    b'LoadDebug',
    b'LoadUpvalues',
    b'LoadProtos',
    b'Undump',
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
        ctx_end = min(len(so), first + len(pat) + 24)
        ctx = so[ctx_start:ctx_end]
        hexstr = ' '.join(f'{b:02x}' for b in ctx)
        asciistr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f'{pat.decode(errors="replace"):25s}: {count:3d} first@ {first:#x} ctx={hexstr}  "{asciistr}"')
