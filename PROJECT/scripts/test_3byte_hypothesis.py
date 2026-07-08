"""
Test the 3-byte record hypothesis for the Roo binary format.

Theory: The body is a sequence of 3-byte records [tag, val1, val2].
0x00 bytes are valid zero values, NOT separators.
Records for the same tag can appear consecutively (array/list encoding).
The 3-byte structure repeats continuously through the body.

Let's test: read body as consecutive 3-byte groups, analyze the patterns.
"""
import os, struct
from collections import defaultdict

samples_dir = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode'
fn = '0000488d2f64199aca0cc7d54e7d11c0.mt.dec'
with open(os.path.join(samples_dir, fn), 'rb') as f:
    data = f.read()

HDR = 69
body = data[HDR:]
print(f'Body size: {len(body)} bytes')
print(f'Body size mod 3: {len(body) % 3}')

# Read as 3-byte records
records = []
for i in range(0, len(body) - 2, 3):
    tag, v1, v2 = body[i], body[i+1], body[i+2]
    records.append((i, tag, v1, v2))

print(f'\nNumber of 3-byte records: {len(records)}')

# Count unique (tag, v1, v2) patterns
pattern_counts = defaultdict(int)
for _, t, v1, v2 in records:
    pattern_counts[(t, v1, v2)] += 1

print(f'\nUnique 3-byte patterns: {len(pattern_counts)}')

# Top patterns
print(f'\nTop 30 most common 3-byte patterns:')
for (t, v1, v2), cnt in sorted(pattern_counts.items(), key=lambda x: -x[1])[:30]:
    ch_t = chr(t) if 32 <= t < 127 else '.'
    ch_v1 = chr(v1) if 32 <= v1 < 127 else '.'
    ch_v2 = chr(v2) if 32 <= v2 < 127 else '.'
    print(f'  [{t:02x} {v1:02x} {v2:02x}] ({ch_t} {ch_v1} {ch_v2}) : {cnt:5d} occurrences')

# Analyze runs of records with the same tag
print(f'\n--- Tag run analysis (consecutive records with same tag) ---')
tag_runs = []
current_tag = None
current_run = []
run_count = 0
for offset, tag, v1, v2 in records:
    if tag == current_tag:
        current_run.append((offset, tag, v1, v2))
        run_count += 1
    else:
        if current_tag is not None:
            tag_runs.append((current_tag, run_count, current_run[:3]))
        current_tag = tag
        current_run = [(offset, tag, v1, v2)]
        run_count = 1
if current_tag is not None:
    tag_runs.append((current_tag, run_count, current_run[:3]))

# Sort by run length (descending)
tag_runs.sort(key=lambda x: -x[1])

print(f'Total runs: {len(tag_runs)}')
print(f'Top 30 longest runs:')
for tag, length, sample in tag_runs[:30]:
    ch = chr(tag) if 32 <= tag < 127 else '.'
    if sample:
        off, t, v1, v2 = sample[0]
        print(f'  tag=0x{tag:02x} ({ch}), run_len={length:4d}, sample=({v1:02x} {v2:02x})')

# Distribution of tags
print(f'\n--- Tag distribution (all tags with >= 10 occurrences) ---')
tag_counts = defaultdict(int)
for _, t, v1, v2 in records:
    tag_counts[t] += 1
for tag, cnt in sorted(tag_counts.items(), key=lambda x: -x[1]):
    if cnt >= 10:
        ch = chr(tag) if 32 <= tag < 127 else '.'
        print(f'  0x{tag:02x} ({ch}): {cnt:4d} occurrences')

# Value distribution: what do V1 and V2 look like?
print(f'\n--- V1 value distribution (non-zero) ---')
v1_counts = defaultdict(int)
count_nonzero_v1 = 0
for _, t, v1, v2 in records:
    if v1 != 0:
        v1_counts[v1] += 1
        count_nonzero_v1 += 1
print(f'Total non-zero V1: {count_nonzero_v1}')
print(f'Unique non-zero V1 values: {len(v1_counts)}')
print(f'Top 20 non-zero V1 values:')
for val, cnt in sorted(v1_counts.items(), key=lambda x: -x[1])[:20]:
    ch = chr(val) if 32 <= val < 127 else '.'
    print(f'  V1=0x{val:02x} ({ch}): {cnt:4d} occurrences')

print(f'\n--- V2 value distribution (non-zero) ---')
v2_counts = defaultdict(int)
count_nonzero_v2 = 0
for _, t, v1, v2 in records:
    if v2 != 0:
        v2_counts[v2] += 1
        count_nonzero_v2 += 1
print(f'Total non-zero V2: {count_nonzero_v2}')
print(f'Unique non-zero V2 values: {len(v2_counts)}')
print(f'Top 20 non-zero V2 values:')
for val, cnt in sorted(v2_counts.items(), key=lambda x: -x[1])[:20]:
    ch = chr(val) if 32 <= val < 127 else '.'
    print(f'  V2=0x{val:02x} ({ch}): {cnt:4d} occurrences')

# Check most common tag combinations
print(f'\n--- Tag+value correlation ---')
# For each tag, what are most common V1,V2 values?
for tag in sorted(tag_counts.keys(), key=lambda x: -tag_counts[x])[:10]:
    patterns = defaultdict(int)
    for _, t, v1, v2 in records:
        if t == tag:
            patterns[(v1, v2)] += 1
    total = tag_counts[tag]
    ch = chr(tag) if 32 <= tag < 127 else '.'
    print(f'\nTag 0x{tag:02x} ({ch}) - {total} occurrences:')
    for (v1, v2), cnt in sorted(patterns.items(), key=lambda x: -x[1])[:10]:
        pct = cnt / total * 100
        print(f'  V1=0x{v1:02x} V2=0x{v2:02x}: {cnt:3d} ({pct:.0f}%)')

# Try interpreting as u16 pairs (2-byte records)
print(f'\n\n--- 2-byte record hypothesis ---')
body_even = len(body) // 2
pairs = []
for i in range(0, body_even * 2, 2):
    t, v = body[i], body[i+1]
    pairs.append((i, t, v))

pair_tag_counts = defaultdict(int)
for off, t, v in pairs:
    if t != 0:
        pair_tag_counts[t] += 1

print(f'Total 2-byte pairs: {len(pairs)}')
print(f'Non-zero tags in pairs: {sum(pair_tag_counts.values())}')
print(f'Top 20 tags (2-byte mode):')
for tag, cnt in sorted(pair_tag_counts.items(), key=lambda x: -x[1])[:20]:
    ch = chr(tag) if 32 <= tag < 127 else '.'
    print(f'  0x{tag:02x} ({ch}): {cnt:4d} occurrences')
