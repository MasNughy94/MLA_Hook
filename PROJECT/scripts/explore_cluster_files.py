"""Analyze all 55 files in the hero/skill cluster."""
import os, json
from collections import defaultdict

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\decrypted\dec_batch'
TARGET = '0217cbdae530696836de83aa3c162e1a.mt.dec'

# Load cluster info
with open('analysis/cluster_report.json') as f:
    clusters = json.load(f)

# Find our target cluster
target_cluster = None
for c in clusters:
    if c['num_members'] == 55 and c['num_tags'] == 255:
        target_cluster = c
        break

all_samples = target_cluster['sample_members']
print(f"Cluster: {target_cluster['num_members']} files, {target_cluster['num_tags']} tags")
print(f"Samples available: {len(all_samples)}\n")

def file_stats(path):
    """Return basic stats for a decrypted file."""
    with open(path, 'rb') as f:
        data = f.read()
    body = data[HDR_SIZE:]
    records = []
    tags = set()
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        if tag != 0:
            val = v1 | (v2 << 8)
            records.append(val)
            tags.add(tag)
    # Cluster entries
    gaps = []
    prev_offset = -31
    entry_count = 0
    for i in range(0, len(body) - 2, 3):
        tag = body[i]
        if tag != 0:
            if i - prev_offset > 30:
                entry_count += 1
            prev_offset = i
    return {
        'size': len(data),
        'rec_count': len(records),
        'tag_count': len(tags),
        'tags_sorted': sorted(tags),
        'entry_est': entry_count,
        'min_val': min(records) if records else 0,
        'max_val': max(records) if records else 0,
    }

# Analyze each sample file
results = []
for fname in all_samples:
    path = os.path.join(DEC_BATCH, fname)
    if not os.path.exists(path):
        results.append({'file': fname, 'status': 'MISSING'})
        continue
    try:
        s = file_stats(path)
        results.append({'file': fname, **s})
    except Exception as e:
        results.append({'file': fname, 'status': f'ERROR: {e}'})

# Sort by entry count descending
results.sort(key=lambda x: x.get('entry_est', 0), reverse=True)

print(f"{'File':<40} {'Entries':<8} {'Tags':<6} {'Size':<8} {'Min':<6} {'Max':<8}")
print("-"*80)
for r in results:
    if r.get('status', 'OK') != 'OK':
        print(f"{r['file']:<40} {r['status']}")
        continue
    tag_str = f"{r['tag_count']}"
    print(f"{r['file']:<40} {r['entry_est']:<8} {tag_str:<6} {r['size']:<8} {r['min_val']:<6} {r['max_val']:<8}")

# Group by tag count patterns
print("\n=== GROUPED BY TAG COUNT ===")
tag_groups = defaultdict(list)
for r in results:
    if r.get('status', 'OK') == 'OK':
        tag_groups[r['tag_count']].append(r)

for tc in sorted(tag_groups.keys()):
    files = tag_groups[tc]
    avg_entries = sum(f['entry_est'] for f in files) / len(files)
    print(f"  {tc:3d} tags: {len(files):2d} files, avg entries={avg_entries:.0f}")

# Show the most important files (high entry count, many tags)
print("\n=== TOP FILES BY ENTRY COUNT ===")
top = [r for r in results if r.get('status', 'OK') == 'OK' and r['entry_est'] >= 100]
top.sort(key=lambda x: -x['entry_est'])
for r in top[:15]:
    print(f"  {r['file']:<42} entries={r['entry_est']:<6} tags={r['tag_count']:<4} size={r['size']:<7} range=[{r['min_val']},{r['max_val']}]")
