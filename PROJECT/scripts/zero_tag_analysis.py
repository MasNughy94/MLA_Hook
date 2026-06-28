"""
Analyze zero-tag records which dominate Roo files.
Hypothesis: tag=0x00 records are structural references (entry_index, field_index)
while non-zero records are actual data values.
"""
import os
from collections import defaultdict, Counter

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\dec_batch'

def parse_file(fpath):
    with open(fpath, 'rb') as f:
        data = f.read()
    body = data[HDR_SIZE:]
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        val = v1 | (v2 << 8)
        records.append({'off': i, 'tag': tag, 'v1': v1, 'v2': v2, 'val': val})
    return os.path.basename(fpath), records, body

# Analyze the main file
fpath = os.path.join(DEC_BATCH, '0217cbdae530696836de83aa3c162e1a.mt.dec')
name, records, body = parse_file(fpath)

zeros = [r for r in records if r['tag'] == 0x00]
nonzeros = [r for r in records if r['tag'] != 0x00]

print(f"File: {name}")
print(f"Total records: {len(records)}")
print(f"  Zero-tag:    {len(zeros)} ({100*len(zeros)/len(records):.1f}%)")
print(f"  Non-zero:    {len(nonzeros)} ({100*len(nonzeros)/len(records):.1f}%)")

# Hypothesis: 0x00 records are structural (entry_idx, field_idx)
v1_vals = [r['v1'] for r in zeros]
v2_vals = [r['v2'] for r in zeros]

print(f"\n--- Zero-tag v1 distribution ---")
print(f"Range: {min(v1_vals)}-{max(v1_vals)}")
print(f"Unique: {len(set(v1_vals))}")
v1_counter = Counter(v1_vals)
print(f"Top v1 values: {v1_counter.most_common(30)}")

print(f"\n--- Zero-tag v2 distribution ---")
print(f"Range: {min(v2_vals)}-{max(v2_vals)}")
print(f"Unique: {len(set(v2_vals))}")
v2_counter = Counter(v2_vals)
print(f"Top v2 values: {v2_counter.most_common(30)}")

# Check: do v1 values correspond to entry indices?
# Group zero records by (v1, v2) pairs
pair_counts = Counter()
for r in zeros:
    pair_counts[(r['v1'], r['v2'])] += 1

print(f"\n--- Zero-tag (v1, v2) pair count ---")
print(f"Unique pairs: {len(pair_counts)}")
print(f"Most common pairs: {pair_counts.most_common(30)}")

# If v1 is entry index, group zero records by v1
by_v1 = defaultdict(list)
for r in zeros:
    by_v1[r['v1']].append(r)

print(f"\n--- Zero-tag grouping by v1 (entry index?) ---")
v1_sizes = Counter(len(v) for v in by_v1.values())
print(f"Entries (unique v1 values): {len(by_v1)}")
print(f"Zero records per v1: {v1_sizes.most_common(30)}")

# Check the relationship between zero records and non-zero records
# Look at sequences of records
print(f"\n--- SEQUENCE ANALYSIS ---")
print(f"First 200 records as (tag, v1, v2):")
for i in range(min(200, len(records))):
    r = records[i]
    s = "    " if i % 5 != 0 else f"\n{i:>4}:"
    if r['tag'] == 0x00:
        print(f"{s}(00,{r['v1']:>3},{r['v2']:>3})", end="")
    else:
        tc = chr(r['tag']) if 32 <= r['tag'] < 127 else '.'
        print(f"{s}[{r['tag']:02x}('{tc}'),{r['val']:>5}]", end="")
print()

# Now check: gap between non-zero records
print(f"\n--- Non-zero record positions ---")
nz_offsets = [r['off'] for r in nonzeros]
print(f"First 50 non-zero offsets: {nz_offsets[:50]}")
if len(nz_offsets) > 1:
    gaps = [nz_offsets[i+1] - nz_offsets[i] - 3 for i in range(len(nz_offsets)-1)]
    gap_counter = Counter(gaps)
    print(f"Gap distribution (bytes between consecutive non-zero records):")
    for g, cnt in sorted(gap_counter.most_common(30)):
        print(f"  {g:>4} bytes ({g//3:>3} records): {cnt}x")

# Let me also check if the file header contains entry count info
header = body[:HDR_SIZE]
print(f"\n--- Header analysis ---")
print(f"Header bytes ({HDR_SIZE}): {header.hex()}")

# Check for entry_count at various positions
for pos in [0, 1, 2, 4, 8, 16, 32, 64, 68]:
    if pos < len(header) - 3:
        val = header[pos] | (header[pos+1] << 8) | (header[pos+2] << 16) | (header[pos+3] << 24)
        if val == len(by_v1):  # matches number of entries by v1
            print(f"  Header[{pos}:{pos+3}] = {val} matches entry count!")
        val16 = header[pos] | (header[pos+1] << 8)
        if val16 == len(by_v1):
            print(f"  Header[{pos}:{pos+1}] (16-bit) = {val16} matches entry count!")
