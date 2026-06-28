import struct
from collections import Counter

f1 = open(r'C:\Users\NGEONG\AppData\Local\Temp\opencode\0000488d2f64199aca0cc7d54e7d11c0.mt.dec', 'rb').read()

# Start at offset 69 (after the common header)
body = f1[69:]

print('Body starts at offset 69, {} bytes remaining'.format(len(body)))
print('Body first 128 bytes:')
for i in range(0, min(128, len(body)), 16):
    chunk = body[i:i+16]
    hexb = ' '.join('{:02x}'.format(b) for b in chunk)
    ascii_str = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
    print('  {:04x}: {:<48s} {}'.format(69+i, hexb, ascii_str))

# Find all non-zero runs in the body
print('\n=== All non-zero runs in body (first 100) ===')
i = 0
runs = []
while i < len(body) and len(runs) < 200:
    if body[i] != 0:
        start = i
        run = []
        while i < len(body) and body[i] != 0:
            run.append(body[i])
            i += 1
        runs.append((start + 69, run))
    else:
        i += 1

for offset, run in runs[:100]:
    hexb = ' '.join('{:02x}'.format(b) for b in run)
    ascii_str = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in run)
    print('  {} (0x{:04x}): len={:2d} {}  {}'.format(offset, offset, len(run), hexb, ascii_str))

# Analyze first bytes of each non-zero run as potential TYPE TAGS
print('\n=== First byte of each non-zero run (potential type tags) ===')
first_bytes = [run[0] for _, run in runs]
tag_counts = Counter(first_bytes)
for tag, count in tag_counts.most_common(30):
    ch = chr(tag) if 0x20 <= tag < 0x7f else '.'
    print('  0x{:02x} ({:3d}) \'{}\': {:4d} occurrences'.format(tag, tag, ch, count))

# Analyze run lengths
print('\n=== Run length histogram ===')
run_lengths = [len(run) for _, run in runs]
len_counts = Counter(run_lengths)
for length, count in sorted(len_counts.items()):
    print('  len={}: {} runs'.format(length, count))

# For runs of length 2, check if they might be tag+value pairs
len2_runs = [run for _, run in runs if len(run) == 2]
if len2_runs:
    print('\n=== Length-2 runs (potential tag+value pairs) ===')
    for run in len2_runs[:30]:
        print('  0x{:02x} 0x{:02x} (tag={}, value={})'.format(run[0], run[1], run[0], run[1]))

# For runs of length 3, check patterns
len3_runs = [run for _, run in runs if len(run) == 3]
if len3_runs:
    print('\n=== Length-3 runs (first 30) ===')
    for run in len3_runs[:30]:
        print('  0x{:02x} 0x{:02x} 0x{:02x}'.format(run[0], run[1], run[2]))
