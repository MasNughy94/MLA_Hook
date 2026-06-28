import struct

so = open(r'C:\Users\NGEONG\Videos\VSCODE\libagame.so', 'rb').read()

# Search for 'Roo' as a string
print('Searching for "Roo" string references:')
for off in range(0, len(so)-4):
    if so[off:off+3] == b'Roo' and so[off+3] == 0:
        if off > 0x100000:
            ctx = so[max(0,off-16):off+16]
            s = '' if off+3 >= len(so) else ''
            print('  Found at 0x{:x}'.format(off))
            print('    ctx: {}'.format(ctx.hex()))

# Also search for 'Root' 
print()
print('Searching for "Root" string:')
for off in range(0, len(so)-5):
    if so[off:off+4] == b'Root' and so[off+4] == 0:
        if off > 0x100000:
            end = so.find(b'\x00', off)
            s = so[off:end].decode(errors='replace')
            print('  Found at 0x{:x}: "{}"'.format(off, s))
            ctx = so[max(0,off-16):off+16]
            print('    ctx: {}'.format(ctx.hex()))

# Search for magic bytes sequences in .rodata
# Check if our magic (1B 4C 6D 00) exists anywhere
magic = b'\x1b\x4c\x6d\x00'
print()
print('Searching for magic bytes 1B 4C 6D 00:')
off = 0
while True:
    off = so.find(magic, off)
    if off == -1:
        break
    print('  Found at 0x{:x}'.format(off))
    # Context
    if off >= 0xe00000:  # rodata
        ctx = so[max(0,off-8):off+16]
        print('    ctx: {}'.format(ctx.hex()))
    off += 1

# Also check if the magic appears as part of a compressed/encoded data table
# in .rodata or .data sections
print()
print('Searching for "Lm" (partial magic) in .rodata:')
for off in range(0xe00000, min(0xf00000, len(so))):
    if so[off:off+2] == b'Lm':
        print('  Found at 0x{:x}'.format(off))
        ctx = so[max(0,off-4):off+12]
        print('    ctx: {} ASCII: {}'.format(ctx.hex(), ctx))
        break
