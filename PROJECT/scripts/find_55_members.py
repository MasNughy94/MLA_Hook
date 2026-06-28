"""Find all 55 members of the 55f_255t cluster and analyze each file."""
import os, json
from collections import defaultdict

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\NGEONG\Videos\MLA\PROJECT\decrypted\dec_batch'

# Load cluster report
with open('analysis/cluster_report.json') as f:
    clusters = json.load(f)

# Get the 55f_255t cluster tag set
target_cluster = None
for c in clusters:
    if c['num_members'] == 55 and c['num_tags'] == 255:
        target_cluster = c
        break

cluster_tags = set(target_cluster['tags'])
print(f"Cluster tag count: {len(cluster_tags)}")
print(f"Tag range: {target_cluster['tag_range']}")

# Load file catalog to find all members
with open('analysis/roo_file_catalog.json') as f:
    catalog = json.load(f)

# If catalog has tag info per file, use it to find cluster members
# Otherwise, scan decrypted files to match tags

# First check if catalog entries have tag info
sample_val = next(iter(catalog.values()))
has_tags = 'tags' in sample_val or 'tag_count' in sample_val
has_entries = 'entry_count' in sample_val or 'entries' in sample_val
print(f"\nCatalog has tags: {has_tags}")
print(f"Catalog has entries: {has_entries}")
print(f"Sample entry keys: {list(sample_val.keys())}")

# Check if final_classification.json has cluster info
with open('analysis/final_classification.json') as f:
    final = json.load(f)

print(f"\nfinal_classification type: {type(final).__name__}")
if isinstance(final, dict):
    print(f"  Keys: {list(final.keys())[:5]}")
    sv = next(iter(final.values()))
    print(f"  Sample keys: {list(sv.keys())[:10] if isinstance(sv, dict) else 'not dict'}")
