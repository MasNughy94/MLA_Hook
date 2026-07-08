"""
Crack the 3-byte record encoding by correlating zero-tag records with data records.
Key finding: 7749 non-(0,0) zero records = 7749 template defaults.
"""
import os
from collections import defaultdict

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\dec_batch'

def parse_records(body):
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        val = v1 | (v2 << 8)
        records.append({'off': i, 'tag': tag, 'v1': v1, 'v2': v2, 'val': val})
    return records

fpath = os.path.join(DEC_BATCH, '0217cbdae530696836de83aa3c162e1a.mt.dec')
with open(fpath, 'rb') as f:
    data = f.read()
body = data[HDR_SIZE:]
records = parse_records(body)

# Separate zero and non-zero records
zeros_w_pos = [(i, r) for i, r in enumerate(records) if r['tag'] == 0x00 and (r['v1'] != 0 or r['v2'] != 0)]
zeros_pad = [(i, r) for i, r in enumerate(records) if r['tag'] == 0x00 and r['v1'] == 0 and r['v2'] == 0]
nonzeros = [(i, r) for i, r in enumerate(records) if r['tag'] != 0x00]

print(f"Zero-tag (non-00): {len(zeros_w_pos)}")
print(f"Zero-tag (00-00):  {len(zeros_pad)}")
print(f"Non-zero:          {len(nonzeros)}")

# Group non-(0,0) zero records by the data records (non-zero) that follow them
# Within a certain window
print(f"\n--- Position correlation ---")
print(f"First 50 non-(0,0) zero records and their context:")
for idx, (ri, r) in enumerate(zeros_w_pos[:50]):
    # Find next non-zero record after this zero record
    next_nz = None
    for j in range(ri+1, min(ri+50, len(records))):
        if records[j]['tag'] != 0x00:
            next_nz = j
            break
    
    # Find previous non-zero record before this zero record
    prev_nz = None
    for j in range(ri-1, max(0, ri-50), -1):
        if records[j]['tag'] != 0x00:
            prev_nz = j
            break
    
    context = f"prev_nz=idx({prev_nz})" if prev_nz is not None else "prev_nz=None"
    context += f" next_nz=idx({next_nz})" if next_nz is not None else " next_nz=None"
    
    print(f"  zero[{ri:>6}] (v1={r['v1']:>3}, v2={r['v2']:>3}) mid={r['val']:>6} {context}")

# Hypothesis: each entry has a fixed maximum field count (say N fields per row)
# The template defaults are at specific offsets within each entry's record block
# Try different field counts per row
print(f"\n--- Template field count analysis ---")
# Count distinct v2 values, grouped by common ranges
from collections import Counter
v2_counts = Counter(r['v2'] for _, r in zeros_w_pos)
print(f"Distinct v2 values: {len(v2_counts)}")
print(f"Top 50 v2 values: {v2_counts.most_common(50)}")

v1_counts = Counter(r['v1'] for _, r in zeros_w_pos)
print(f"\nDistinct v1 values: {len(v1_counts)}")
print(f"Top 50 v1 values: {v1_counts.most_common(50)}")

# What if we treat v1 as field position and v2 as value?
# Then entries with v1>0 and v2>0 would be (pos=X, default=Y)
# For (0, X) patterns, v1=0, v2=X -> position=0, default=X
# For (X, 0) patterns, v1=X, v2=0 -> position=X, default=0

# Let's see: are all zero records with v1=0 followed by specific non-zero records?
# This would mean (0, X) pair encodes: "position 0 has default X"
# And the following non-zero records encode: "override values for other positions"
print(f"\n--- Testing: v1=field_pos, v2=default_value ---")
v1_positions = {}
for _, r in zeros_w_pos:
    pos = r['v1']
    val = r['v2']
    if pos not in v1_positions:
        v1_positions[pos] = []
    v1_positions[pos].append(val)

# Check how many distinct default values each position has
for pos in sorted(v1_positions.keys())[:30]:
    defaults = set(v1_positions[pos])
    cnt = len(v1_positions[pos])
    print(f"  position {pos:>3}: {len(defaults):>3} unique defaults (total {cnt:>4} occurrences): {sorted(defaults)[:10]}")

# Alternative: maybe v1 and v2 together are the 12-bit position?
# Or maybe a different encoding entirely
print(f"\n--- Time to look at actual non-zero data values ---")
nz_tag_counts = Counter()
nz_val_ranges = {}
for _, r in nonzeros:
    nz_tag_counts[r['tag']] += 1
    if r['tag'] not in nz_val_ranges:
        nz_val_ranges[r['tag']] = [r['val'], r['val'], set()]
    nz_val_ranges[r['tag']][0] = min(nz_val_ranges[r['tag']][0], r['val'])
    nz_val_ranges[r['tag']][1] = max(nz_val_ranges[r['tag']][1], r['val'])
    nz_val_ranges[r['tag']][2].add(r['val'])

print(f"Non-zero tags: {len(nz_tag_counts)}")
for tag, cnt in nz_tag_counts.most_common(30):
    mn, mx, svals = nz_val_ranges[tag]
    tc = chr(tag) if 32 <= tag < 127 else '.'
    print(f"  0x{tag:02x}('{tc}'): {cnt:>5} records [{mn:>6}-{mx:>6}] uniq={len(svals):>3}")

# Check if any non-zero records have values that match known game IDs
print(f"\n--- Looking for known game IDs in non-zero records ---")
hero_range = set(range(2111, 5971))
skill_range = set(range(1301, 73381))
item_range = set(range(60000, 180001))

for _, r in nonzeros:
    v = r['val']
    notes = []
    if v in hero_range:
        notes.append("HERO_ID")
    if v in skill_range:
        notes.append("SKILL_ID")
    if 60000 <= v < 180000:
        notes.append("ITEM_ID")
    if 0 <= v <= 1:
        notes.append("FLAG")
    if 1 <= v <= 5:
        notes.append("ENUM(1-5)")
    if 1 <= v <= 8:
        notes.append("ENUM(1-8)")
    
    if notes:
        tc = chr(r['tag']) if 32 <= r['tag'] < 127 else '.'
        print(f"  tag=0x{r['tag']:02x}('{tc}') val={v:>6} {' '.join(notes)}")
