"""Get all 55 members of the 55f_255t cluster and analyze each."""
import json
from collections import defaultdict

DEC_BATCH = r'C:\Users\NGEONG\Videos\MLA\PROJECT\decrypted\dec_batch'

# Load catalog
with open('analysis/roo_file_catalog.json') as f:
    catalog = json.load(f)

# Load corpus summary for entry counts
with open('analysis/corpus_summary.json') as f:
    corpus = json.load(f)

corpus_by_file = {e['file']: e for e in corpus}

# Find files in the 55-member cluster
cluster_files = []
for fhash, info in catalog.items():
    if info.get('cluster_size') == 55:
        # The filename from catalog is: hash.mt (not .mt.dec)
        fname = f"{fhash}.mt.dec"
        cluster_files.append((fhash, fname, info))

print(f"Files in 55-member cluster: {len(cluster_files)}")

# Analyze each file's basic stats
print(f"\n=== ALL 55 MEMBER FILES ===")
print(f"{'File Hash (first 16)':<18} {'Entries':<8} {'Tags':<6} {'SizeKB':<8} {'Density':<10} {'Schema':<20}")
print("="*70)

for fhash, fname, info in sorted(cluster_files, key=lambda x: x[2].get('num_entries', 0), reverse=True):
    entries = info.get('num_entries', 0)
    tags = info.get('tag_count', 0)
    size_kb = info.get('size_kb', 0)
    density = info.get('density', '')
    schema = info.get('schema', '')[:20]
    print(f"{fhash[:16]:<18} {entries:<8} {tags:<6} {size_kb:<8} {density:<10} {schema:<20}")

# Also show the tag distribution for this cluster
print(f"\n=== TAG USAGE ACROSS ALL 55 FILES ===")
tag_file_count = defaultdict(int)
for fhash, fname, info in cluster_files:
    tags = set(info.get('cluster_tags', []))
    for t in tags:
        tag_file_count[t] += 1

print(f"Tags shared by all 55 files: {sum(1 for t, c in tag_file_count.items() if c == 55)}")
print(f"Tags shared by >50 files: {sum(1 for t, c in tag_file_count.items() if c >= 50)}")
print(f"Tags shared by >1 file: {sum(1 for t, c in tag_file_count.items() if c > 1)}")

# Show the most commonly shared tags
common_tags = sorted(tag_file_count.items(), key=lambda x: -x[1])[:20]
for tag, count in common_tags:
    print(f"  tag=0x{tag:02x}: present in {count} files")

# Categorize files by entry count ranges
print(f"\n=== FILE CATEGORIZATION ===")
ranges = [(0, 100), (100, 500), (500, 2000), (2000, 5000), (5000, 10000), (10000, 20000), (20000, 50000)]
for lo, hi in ranges:
    count = sum(1 for _, _, info in cluster_files if lo <= info.get('num_entries', 0) < hi)
    if count > 0:
        print(f"  {lo:5d} - {hi:<5d} entries: {count:2d} files")
