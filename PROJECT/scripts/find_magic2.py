import struct

so = open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb').read()
print(f'libagame.so size: {len(so)} bytes')

patterns = [
    (b'\x1b\x4c\x6d', '1B 4C 6D (custom magic)'),
    (b'\x1bL', '1B 4C (escape+L)'),
    (b'Roo', 'Roo string'),
    (b'\x1bLua\x00\x19\x93', 'standard Lua 5.3 magic'),
    (b'\x1bLua', 'standard Lua magic prefix'),
]

for pat, desc in patterns:
    off = 0
    count = 0
    first_offsets = []
    while True:
        idx = so.find(pat, off)
        if idx == -1:
            break
        if count < 5:
            first_offsets.append(idx)
        count += 1
        off = idx + 1
    print(f'{desc}: {count} hits', end='')
    if first_offsets:
        contexts = []
        for o in first_offsets[:3]:
            ctx = so[max(0,o-4):o+len(pat)+12]
            contexts.append(' '.join(f'{b:02x}' for b in ctx))
        print(f'  @ {[hex(o) for o in first_offsets[:3]]}', end='')
        if first_offsets:
            print(f'  ctx: ...{contexts[0]}...')
        else:
            print()
    else:
        print()

# Also look for references in specific sections
# Search in .text section roughly
print()
print('Searching near LMF decompressor (0xcf2b2c):')
# Read around that offset
for off in range(0xcf2b2c - 0x40, 0xcf2b2c + 0x200):
    try:
        if so[off:off+4] == b'\x1b\x4c\x6d\x00' or so[off:off+2] == b'\x1bL':
            ctx = so[max(0,off-8):off+16]
            hexstr = ' '.join(f'{b:02x}' for b in ctx)
            print(f'  Found at {off:#x}: ...{hexstr}...')
    except: pass
