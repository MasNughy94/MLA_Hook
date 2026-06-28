import struct

so = open(r'C:\Users\NGEONG\Videos\VSCODE\mt_dump\libagame.so', 'rb').read()
print(f'libagame.so size: {len(so)} bytes')

patterns = [
    b'\x1b\x4c\x6d',       # 1B 4C 6D - our magic (esc L m)
    b'\x1bL',              # 1B 4C - just escape+L
    b'Roo',                # Root/"Roo" string
    b'\x1bLua',            # standard Lua magic
]

for pat in patterns:
    off = 0
    count = 0
    first_offsets = []
    while True:
        idx = so.find(pat, off)
        if idx == -1:
            break
        if count < 3:
            first_offsets.append(idx)
        count += 1
        off = idx + 1
    print(f'  pattern {pat.hex()!r}: {count} occurrences', end='')
    if first_offsets:
        print(f'  first at: {[hex(o) for o in first_offsets]}')
    else:
        print()
