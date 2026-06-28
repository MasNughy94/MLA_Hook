import struct

f1 = open(r'C:\Users\NGEONG\AppData\Local\Temp\opencode\0000488d2f64199aca0cc7d54e7d11c0.mt.dec', 'rb').read()
f2 = open(r'C:\Users\NGEONG\AppData\Local\Temp\opencode\00378c64fbd63011a81dccef6bf6e2bd.mt.dec', 'rb').read()

print(f'f1 size: {len(f1)}')
print(f'f2 size: {len(f2)}')
min_len = min(len(f1), len(f2))

# Find regions of change
print('\n=== Regions where bytes differ (starts > 10 diff bytes apart) ===')
in_diff = False
diff_start = 0
diff_len = 0
regions = []
for i in range(min_len):
    if f1[i] != f2[i]:
        if not in_diff:
            diff_start = i
            in_diff = True
            diff_len = 1
        else:
            diff_len += 1
    else:
        if in_diff:
            regions.append((diff_start, diff_len))
            in_diff = False

if in_diff:
    regions.append((diff_start, diff_len))

print(f'Total differing regions: {len(regions)}')
# Show first 50 regions
for offset, length in regions[:50]:
    # Show context: 4 bytes before, differing bytes, 4 bytes after
    ctx_start = max(0, offset - 4)
    ctx_end = min(min_len, offset + length + 4)
    prefix = f1[ctx_start:offset]
    diff1 = f1[offset:offset+length]
    diff2 = f2[offset:offset+length]
    suffix = f1[offset+length:ctx_end]
    
    print(f'  [{offset:5d}-{offset+length-1:5d}] len={length:3d}: ', end='')
    if length <= 16:
        print(f'f1={diff1.hex()} f2={diff2.hex()}', end='')
    else:
        print(f'f1=({length} bytes) f2=({length} bytes)', end='')
    print()

# Also show the common structure percentage by region
print('\n=== Structure density analysis ===')
# Divide file into 256-byte blocks and show % identical per block
print('Block-level identity (256-byte blocks):')
for block_start in range(0, min_len, 256):
    block_end = min(min_len, block_start + 256)
    identical = sum(1 for i in range(block_start, block_end) if f1[i] == f2[i])
    block_size = block_end - block_start
    pct = identical * 100 // block_size
    if pct < 90:  # Show only blocks with significant differences
        print(f'  {block_start:5d}-{block_end-1:5d}: {pct}% identical')

# Find longest common substring regions
print('\n=== Potential string table area ===')
# Search for longer printable runs that are IDENTICAL between files
i = 0
while i < min_len:
    if 0x20 <= f1[i] < 0x7f and f1[i] == f2[i]:
        start = i
        while i < min_len and 0x20 <= f1[i] < 0x7f and f1[i] == f2[i]:
            i += 1
        if i - start > 5:
            s = f1[start:i].decode('ascii')
            print(f'  Common string at {start} (0x{start:04x}): "{s}" ({i-start} chars)')
    else:
        i += 1

# Check if zeros separate records (divide by zero runs)
print('\n=== Zero-run analysis (potential record separators) ===')
z1 = [0]
z2 = [0]
for i in range(min_len):
    if f1[i] == 0 and f2[i] == 0:
        z1[-1] = z1[-1] + 1 if len(z1) > 0 else 1
    else:
        if z1[-1] > 0:
            z1.append(0)
zero_run_counts = {}
for run in [z1]:
    for r in run:
        if r > 0:
            zero_run_counts[r] = zero_run_counts.get(r, 0) + 1
print('Zero-run length histogram (where both files have zeros):')
for length, count in sorted(zero_run_counts.items()):
    print(f'  {length} zeros: {count} occurrences')
