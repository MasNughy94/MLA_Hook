import struct
from collections import Counter

data = open(r'C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump\intermediate\01_aes_output.bin.decompressed', 'rb').read()
size = len(data)

print(f'Total size: {size} bytes')
print(f'=== Full hex dump (first 512 bytes) ===')
for row in range(32):
    offset = row * 16
    hexb = ' '.join(f'{data[offset+i]:02x}' for i in range(16))
    ascii_str = ''.join(chr(data[offset+i]) if 0x20 <= data[offset+i] < 0x7f else '.' for i in range(16))
    print(f'{offset:04x}: {hexb}  {ascii_str}')

# --- Analyze as potential records of varying sizes ---
print('\n=== Alignment/Record Structure Analysis ===')

# Check if the buffer size is divisible by various powers of 2
for align in [2, 4, 8, 16, 32]:
    if size % align == 0:
        # Check non-zero byte density per alignment block
        blocks = size // align
        nonzero_blocks = 0
        for b in range(blocks):
            blk = data[b*align:(b+1)*align]
            if any(x != 0 for x in blk):
                nonzero_blocks += 1
        print(f'  Aligned to {align}: {size//align} blocks, {nonzero_blocks} non-zero ({nonzero_blocks*100//max(1,blocks)}%)')

# --- Check for potential pointer/offset values (little-endian 32-bit) ---
print('\n=== Potential 32-bit values (that could be offsets) ===')
max_offset = size
potential_offsets = []
for i in range(0, size - 3, 1):
    val = struct.unpack_from('<I', data, i)[0]
    if 0 < val < max_offset:
        potential_offsets.append((i, val))

# Show the first 50 potential offset values
count = 0
for offset, val in potential_offsets[:50]:
    # Check if the offset points to a non-zero byte
    points_to_nonzero = data[val] != 0 if val < size else False
    print(f'  offset {offset} (0x{offset:04x}): value {val} (0x{val:04x}) points_to_nonzero={points_to_nonzero}')
    count += 1
print(f'  ... and {len(potential_offsets)-count} more')

# --- Check for potential 16-bit values ---
print('\n=== Potential 16-bit values ===')
nonzero_16bit = []
for i in range(0, size - 1, 2):
    val = struct.unpack_from('<H', data, i)[0]
    if val != 0:
        nonzero_16bit.append((i, val))
print(f'  Total non-zero 16-bit values: {len(nonzero_16bit)}')
# Show first 30
for i, val in nonzero_16bit[:30]:
    print(f'  offset {i} (0x{i:04x}): {val} (0x{val:04x})')

# --- String detection ---
print('\n=== Potential null-terminated strings (min 3 chars) ===')
strings = []
i = 0
while i < size:
    # Check if we have a printable string
    if 0x20 <= data[i] < 0x7f:
        start = i
        while i < size and 0x20 <= data[i] < 0x7f:
            i += 1
        if i - start >= 3:
            s = data[start:i].decode('ascii')
            strings.append((start, s))
    else:
        i += 1

for offset, s in strings[:40]:
    print(f'  offset {offset} (0x{offset:04x}): "{s}"')
print(f'  ... {len(strings)-40} more strings found' if len(strings) > 40 else '')

# --- Byte histogram ---
print('\n=== Byte value histogram (non-zero only) ===')
hist = Counter(data[b] for b in range(size) if data[b] != 0)
for byte_val, count in hist.most_common(30):
    ch = chr(byte_val) if 0x20 <= byte_val < 0x7f else '.'
    print(f'  0x{byte_val:02x} ({byte_val:3d}) \'{ch}\': {count:5d} occurrences')
