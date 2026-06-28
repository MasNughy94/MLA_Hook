"""
Final comprehensive identity mapping for all 7,258 Roo files.
Produces per-file semantic classification and a summary report.
"""
import json, os
from collections import Counter, defaultdict

analysis_dir = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\analysis'

with open(os.path.join(analysis_dir, 'roo_file_catalog.json')) as f:
    catalog = json.load(f)

with open(os.path.join(analysis_dir, 'corpus_summary.json')) as f:
    corpus = json.load(f)

# Build per-file lookup
file_metrics = {}
for fi in corpus:
    fname = fi['file'].replace('.mt.dec', '')
    file_metrics[fname] = fi

# Classify every file into a semantic group
def classify_file(fhash, info):
    tags = info['tag_count']
    entries = info['num_entries']
    schema = info['schema']
    size = info['size_class']
    density = info['density']
    cluster_size = info.get('cluster_size', 0)
    
    # HEAVY DATABASES (255 tags, 10K+ entries)
    if entries >= 10000 and tags >= 200:
        return 'MASTER_HERO_DB'  # 33K entries with hero/skill/item IDs
    
    # LARGE DB (255 tags, 3K-10K entries)
    if entries >= 3000 and tags >= 200:
        return 'MASTER_GAME_DB'  # Large game database
    
    # MEDIUM DB (200+ tags, 1K-3K entries)
    if entries >= 1000 and tags >= 200:
        return 'GAME_SYSTEM_DB'  # Equipment/Artifact/Skill DB
    
    # 310 ENTRIES CLUSTER (174 tags, exactly 310 entries)
    if entries == 310 and tags >= 160:
        return 'STAGE_MISSION_DB'  # Campaign stages
    
    # 250ish entries, 255 tags 
    if 200 <= entries <= 500 and tags >= 200:
        return 'LEVEL_DIFFICULTY_DB'
    
    # 100-200 entries, 100+ tags
    if 100 <= entries <= 500 and 100 <= tags <= 199:
        return 'MEDIUM_CONFIG_DB'
    
    # 50-99 entries, 40+ tags
    if entries >= 50 and tags >= 40:
        return 'SMALL_CONFIG_DB'
    
    # 10-49 entries, 15+ tags
    if entries >= 10 and tags >= 15:
        return 'TABLE_CONFIG'
    
    # FEW ENTRIES, MANY TAGS - could be special
    if entries <= 10 and tags >= 40:
        return 'COMPLEX_SINGLETON'
    
    # 1-9 entries, 5-15 tags
    if entries <= 10 and 5 <= tags <= 15:
        return 'SIMPLE_CONFIG'
    
    # 1-4 tags, 1-10 entries
    if tags <= 5 and entries <= 10:
        return 'MINIMAL_CONFIG'
    
    # 0 tags
    if tags == 0:
        return 'EMPTY_DB'
    
    # Catch-all for remaining
    if entries == 0 and tags == 0:
        return 'EMPTY_DB'
    if tags >= 100:
        return 'COMPLEX_CONFIG'
    return 'UNKNOWN_CONFIG'

# Classify
classification_counts = Counter()
per_cluster = defaultdict(list)
catalog_with_class = {}

for fhash, info in catalog.items():
    cls = classify_file(fhash, info)
    info['classification'] = cls
    catalog_with_class[fhash] = info
    classification_counts[cls] += 1
    per_cluster[cls].append(fhash)

print("=== FINAL FILE CLASSIFICATION ===\n")
for cls, cnt in sorted(classification_counts.items(), key=lambda x: -x[1]):
    print(f"  {cls:>25s}: {cnt:>5d} files ({100*cnt/len(catalog):>5.1f}%)")

# Detailed breakdown for each major class
print("\n\n=== DETAILED BREAKDOWN ===\n")

for cls in ['MASTER_HERO_DB', 'MASTER_GAME_DB', 'GAME_SYSTEM_DB', 'STAGE_MISSION_DB',
            'LEVEL_DIFFICULTY_DB', 'MEDIUM_CONFIG_DB', 'SMALL_CONFIG_DB',
            'TABLE_CONFIG', 'COMPLEX_SINGLETON', 'COMPLEX_CONFIG',
            'SIMPLE_CONFIG', 'MINIMAL_CONFIG', 'EMPTY_DB']:
    files = per_cluster[cls]
    if not files:
        continue
    # Show stats for this class
    entry_counts = [catalog[f]['num_entries'] for f in files]
    tag_counts = [catalog[f]['tag_count'] for f in files]
    
    print(f"\n  {cls} ({len(files)} files):")
    print(f"    Entries: min={min(entry_counts)}, max={max(entry_counts)}, avg={sum(entry_counts)//len(entry_counts)}")
    print(f"    Tags:    min={min(tag_counts)}, max={max(tag_counts)}, avg={sum(tag_counts)//len(tag_counts)}")
    
    # Show sample paths
    if len(files) <= 5:
        for f in files:
            print(f"    {catalog[f]['path']}")
    else:
        for f in files[:3]:
            print(f"    {catalog[f]['path']}")
        print(f"    ... ({len(files) - 3} more)")

# Export final catalog
output_path = os.path.join(analysis_dir, 'final_classification.json')
with open(output_path, 'w') as f:
    json.dump(catalog_with_class, f, indent=2)
print(f"\n\nExported to: {output_path}")

# Summary statistics
print("\n\n=== SUMMARY STATISTICS ===")
total_entries = sum(info['num_entries'] for info in catalog.values())
total_overrides = sum(info['num_override'] for info in catalog.values() 
                     if 'num_override' in info)
print(f"Total files: {len(catalog)}")
print(f"Total entries across all files: {total_entries}")
print(f"Total override records: {total_overrides}")
print(f"Unique tag signatures: {len(set(info['tag_count'] for info in catalog.values()))}")

# Entry count bins
entry_bins = Counter()
for info in catalog.values():
    e = info['num_entries']
    if e == 0: b = '0'
    elif e == 1: b = '1'
    elif e <= 5: b = '2-5'
    elif e <= 10: b = '6-10'
    elif e <= 50: b = '11-50'
    elif e <= 100: b = '51-100'
    elif e <= 200: b = '101-200'
    elif e <= 300: b = '201-300'
    elif e <= 500: b = '301-500'
    elif e <= 1000: b = '501-1K'
    elif e <= 3000: b = '1K-3K'
    elif e <= 10000: b = '3K-10K'
    else: b = '10K+'
    entry_bins[b] += 1

print("\nEntry count distribution:")
for b in ['0', '1', '2-5', '6-10', '11-50', '51-100', '101-200', '201-300', '301-500', '501-1K', '1K-3K', '3K-10K', '10K+']:
    print(f"  {b:>8s}: {entry_bins.get(b, 0):>5d}")
