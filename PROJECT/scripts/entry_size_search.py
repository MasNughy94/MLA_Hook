"""
Find the entry size via autocorrelation of override record positions.
If entries have fixed size, override positions relative to entry start should be consistent.
"""
import os
from collections import defaultdict, Counter
import struct

samples_dir = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode'
fn1 = '0000488d2f64199aca0cc7d54e7d11c0.mt.dec'

with open(os.path.join(samples_dir, fn1), 'rb') as f:
    data = f.read()

HDR = 69
body = data[HDR:]

# Parse records
records = []
for i in range(0, len(body) - 2, 3):
    tag, v1, v2 = body[i], body[i+1], body[i+2]
    records.append((i, tag, v1, v2))

# Get positions of override (non-zero-tag) records as record indices
override_record_indices = [i // 3 for i, t, v1, v2 in records if t != 0]
print(f"Override records: {len(override_record_indices)}")
print(f"First 20 override record indices: {override_record_indices[:20]}")

# Try to find entry size by looking for autocorrelation
# For each candidate entry size (in records), check how many override records
# align at the same relative positions

total_records = len(body) // 3
print(f"\nTotal records: {total_records}")

# Build a bitmap of override positions
override_bitmap = [0] * total_records
for idx in override_record_indices:
    if idx < total_records:
        override_bitmap[idx] = 1

# For each candidate entry size, compute the autocorrelation
best_sizes = []
for entry_size in range(3, 200):
    if entry_size > total_records:
        break
    
    # Place entries at 0, entry_size, 2*entry_size, ...
    # Count override records at each relative position
    position_counts = Counter()
    total_entries = 0
    for entry_start in range(0, total_records - entry_size, entry_size):
        total_entries += 1
        for rel_pos in range(min(entry_size, total_records - entry_start)):
            abs_pos = entry_start + rel_pos
            if override_bitmap[abs_pos]:
                position_counts[rel_pos] += 1
    
    if total_entries < 5:
        continue
    
    # How many distinct relative positions have overrides?
    num_positions = len(position_counts)
    
    # How well do the positions match across entries?
    # For each position, what fraction of entries has an override there?
    consistency = []
    for pos, count in position_counts.most_common():
        frac = count / total_entries
        consistency.append((pos, frac))
    
    # Good entry size = many positions have high consistency
    high_consistency = sum(1 for _, f in consistency if f > 0.5)
    
    # Also check: do all override records fall at these positions?
    override_matches = sum(count for _, count in position_counts.items())
    override_coverage = override_matches / len(override_record_indices) * 100 if override_record_indices else 0
    
    if high_consistency >= 3 or override_coverage > 70:
        best_sizes.append((entry_size, entry_size * 3, num_positions, high_consistency, override_coverage))
        print(f"  Entry size {entry_size:3d} records ({entry_size*3:3d} bytes): {num_positions:3d} positions, {high_consistency:2d} >50% consistent, {override_coverage:5.1f}% coverage")

# Show top candidate entry sizes
print(f"\n\nTop 20 candidate entry sizes:")
for entry_size, byte_size, positions, high_consistency, coverage in sorted(best_sizes, key=lambda x: -x[-1])[:20]:
    print(f"  {entry_size:3d} records ({byte_size:3d} bytes): {positions:2d} unique positions, {high_consistency:2d} highly consistent, {coverage:5.1f}% coverage")

# Also check: what's the step from first to last override in each entry
# if we use the best entry size?
candidate = 36  # try 36 records per entry
print(f"\n\n--- Analysis with entry_size = {candidate} records ---")
n_entries = total_records // candidate
print(f"Number of entries: {n_entries}")

entry_templates = []
for e in range(n_entries):
    start = e * candidate
    end = start + candidate
    entry_records = [(t, v1, v2) for i, t, v1, v2 in records[start*3:end*3:3]]
    override_positions = [(pos, t, v1, v2) for pos, (t, v1, v2) in enumerate(entry_records) if t != 0]
    entry_templates.append(override_positions)

# Show the tag patterns for first 10 entries
print(f"First 10 entries (relative record positions of non-zero tags):")
for e in range(min(10, n_entries)):
    tags = [(pos, f'0x{t:02x}') for pos, t, v1, v2 in entry_templates[e]]
    print(f"  Entry {e:3d}: {tags}")

# Also check: does the 'version' field at body start (0xA9) correlate with anything?
print(f"\n--- Entry start analysis ---")
# The first record is [00 A9 A9] which is a template with value 0xA9 in both v1 and v2
# This might be a file-level default
# Let's check what override records look like in the FIRST entry
first_entry_start = 0
first_entry_end = candidate
print(f"First entry records {first_entry_start} to {first_entry_end}:")
for i in range(first_entry_start, min(first_entry_end, total_records)):
    if i * 3 < len(body) - 2:
        t, v1, v2 = body[i*3], body[i*3+1], body[i*3+2]
        if t != 0 or v1 != 0 or v2 != 0:
            marker = 'OVERRIDE' if t != 0 else 'TEMPLATE'
            print(f"  Record {i:4d} body+0x{i*3:04x}: [{t:02x} {v1:02x} {v2:02x}] {marker}")
