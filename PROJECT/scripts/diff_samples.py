"""
Diff analysis of two .mt.dec files.
"""
import os, struct

samples_dir = r'C:\Users\NGEONG\AppData\Local\Temp\opencode'
fn1 = '0000488d2f64199aca0cc7d54e7d11c0.mt.dec'
fn2 = '008fea3143557d628ac845a13a254e8a.mt.dec'

d1 = open(os.path.join(samples_dir, fn1), 'rb').read()
d2 = open(os.path.join(samples_dir, fn2), 'rb').read()

HDR = 69
b1 = d1[HDR:]
b2 = d2[HDR:]

print('File 1 body size:', len(b1))
print('File 2 body size:', len(b2))

# Find differing regions
diff_regions = []
for o in range(max(len(b1), len(b2))):
    if o >= len(b1) or o >= len(b2) or b1[o] != b2[o]:
        if not diff_regions or o > diff_regions[-1][1] + 1:
            diff_regions.append([o, o])
        else:
            diff_regions[-1][1] = o

print(f'\nTotal differing regions: {len(diff_regions)}')

overlap = min(len(b1), len(b2))
diff_in_overlap = [r for r in diff_regions if r[0] < overlap]
same_count = overlap - sum(r[1]-r[0]+1 for r in diff_in_overlap)
print(f'Overlap region size: {overlap} bytes')
print(f'Identical bytes in overlap: {same_count} ({same_count/overlap*100:.1f}%)')
print(f'Diff regions in overlap: {len(diff_in_overlap)}')

print(f'\nFirst 50 diff regions (offset, len, values):')
for i, (start, end) in enumerate(diff_in_overlap[:50]):
    length = end - start + 1
    v1 = b1[start:end+1].hex()
    v2 = b2[start:end+1].hex()
    print(f'  body+0x{start:04x} ({length:2d} bytes):')
    print(f'    f1: {v1}')
    print(f'    f2: {v2}')

# Find all runs of printable ASCII
for name, body_data in [('File1', b1), ('File2', b2)]:
    print(f'\n--- {name}: runs of printable ASCII (>=3 chars) ---')
    i = 0
    while i < len(body_data):
        if 32 <= body_data[i] < 127:
            start = i
            chars = []
            while i < len(body_data) and 32 <= body_data[i] < 127:
                chars.append(chr(body_data[i]))
                i += 1
            if len(chars) >= 3:
                print(f'  body+0x{start:04x}: {"".join(chars)}')
        else:
            i += 1

# Also check: are there any string-like patterns (length-prefixed)?
print('\n--- Length-prefixed string candidates (leading byte = string len) ---')
for name, body_data in [('File1', b1), ('File2', b2)]:
    for o in range(len(body_data) - 3):
        l = body_data[o]
        if 1 <= l <= 40:  # reasonable string length
            cand = body_data[o+1:o+1+l]
            if all(32 <= b < 127 for b in cand):
                print(f'  {name} body+0x{o:04x}: len={l}, str="{cand.decode("ascii", errors="replace")}"')
