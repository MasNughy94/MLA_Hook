"""
Final classification of all 7,258 Roo files.
Classifies each file by structural properties into logical game asset groups.
"""
import os, json, re
from collections import Counter, defaultdict

base = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\decoded_apk\assets'
analysis_dir = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\analysis'

# 1. Load corpus summary (per-file metrics)
with open(os.path.join(analysis_dir, 'corpus_summary.json')) as f:
    corpus = json.load(f)
print(f"Corpus entries: {len(corpus)}")

# 2. Load cluster report
with open(os.path.join(analysis_dir, 'cluster_report.json')) as f:
    raw = json.load(f)
if isinstance(raw, dict):
    clusters = raw
else:
    clusters = {str(i): c for i, c in enumerate(raw)}
print(f"Cluster entries: {len(clusters)}")

# 3. Load cluster tag profile (if exists)
tag_profile_path = os.path.join(analysis_dir, 'cluster_tag_profile.json')
tag_profiles = {}
if os.path.exists(tag_profile_path):
    with open(tag_profile_path) as f:
        tag_profiles = json.load(f)
    print(f"Tag profiles loaded: {len(tag_profiles)}")

# 4. Build manifest lookup
with open(os.path.join(base, 'resList.lua'), 'r', encoding='utf-8') as f:
    reslist_text = f.read()
start = reslist_text.find('fileList = {')
end = reslist_text.rfind('}')
data_section = reslist_text[start+12:end]
pat = re.compile(r'\["([^"]+)"\]=\{md5="([^"]+)"(,bDown=true)?\}')
manifest = {}
for path, md5, bdown in pat.findall(data_section):
    fname = path.split('/')[-1].replace('.mt', '')
    if fname not in manifest:  # first wins
        manifest[fname] = {
            'path': path,
            'dir': path.split('/')[0],
            'md5': md5,
            'bDown': bool(bdown)
        }

# 5. Build file-to-cluster index
file_to_cluster = {}
if isinstance(clusters, dict):
    cluster_items = clusters.items()
else:
    cluster_items = enumerate(clusters)
for cid, cdata in cluster_items:
    if isinstance(cdata, dict):
        cfiles = cdata.get('sample_members', cdata.get('files', cdata.get('filenames', [])))
        for cf in cfiles:
            fbase = cf.replace('.mt.dec', '').replace('.mt', '')
            if fbase not in file_to_cluster:
                file_to_cluster[fbase] = {
                    'cluster_id': str(cid),
                    'cluster_size': cdata.get('num_members', len(cfiles)),
                    'cluster_tags': cdata.get('num_tags', 0),
                }

# 6. Build complete catalog for roo files (directories 0-f)
roo_catalog = {}
for finfo in corpus:
    fname = finfo['file'].replace('.mt.dec', '')
    if fname not in manifest:
        continue
    minfo = manifest[fname]
    if minfo['dir'] not in '0123456789abcdef':
        continue
    
    entry = {
        'hash': fname,
        'path': minfo['path'],
        'dir': minfo['dir'],
        'size_kb': minfo.get('size_kb', 0.0),
        'bDown': minfo.get('bDown', False),
        'md5': minfo.get('md5', ''),
        'body_size': finfo.get('body_size', 0),
        'num_records': finfo.get('num_records', 0),
        'num_override': finfo.get('num_override', 0),
        'num_template': finfo.get('num_template', 0),
        'num_entries': finfo.get('entries', 0),
        'tag_count': finfo.get('num_unique_tags', 0),
    }
    
    if fname in file_to_cluster:
        entry.update(file_to_cluster[fname])
    else:
        entry['cluster_id'] = 'singleton'
        entry['cluster_size'] = 1
        entry['cluster_tags'] = entry['tag_count']
    
    tags = entry['tag_count']
    entries = entry['num_entries']
    overrides = entry['num_override']
    body = entry['body_size']
    
    entry['override_density'] = overrides / max(body, 1) * 100
    
    # Schema groups based on tag count + entry structure
    if tags >= 200:
        schema = 'MASTER_DB'
    elif tags >= 100:
        schema = 'LARGE_SCHEMA'
    elif tags >= 40:
        schema = 'MEDIUM_SCHEMA'
    elif tags >= 15:
        schema = 'SMALL_SCHEMA'
    elif tags >= 5:
        schema = 'TINY_SCHEMA'
    else:
        schema = 'MINIMAL'
    
    if entries == 0:
        size = 'EMPTY'
    elif entries == 1:
        size = 'SINGLE'
    elif entries <= 10:
        size = 'SMALL'
    elif entries <= 100:
        size = 'MEDIUM'
    elif entries <= 1000:
        size = 'LARGE'
    else:
        size = 'VERY_LARGE'
    
    # Override density
    if overrides == 0:
        density = 'NO_DATA'
    elif entry['override_density'] < 0.1:
        density = 'SPARSE'
    elif entry['override_density'] < 1.0:
        density = 'MODERATE'
    else:
        density = 'DENSE'
    
    entry['schema'] = schema
    entry['size_class'] = size
    entry['density'] = density
    
    roo_catalog[fname] = entry

print(f"\nRoo file catalog: {len(roo_catalog)} entries")

# 7. Classification summary
class_counts = Counter()
schema_counts = Counter()
size_counts = Counter()
density_counts = Counter()

for info in roo_catalog.values():
    class_counts[(info['schema'], info['size_class'], info['density'])] += 1
    schema_counts[info['schema']] += 1
    size_counts[info['size_class']] += 1
    density_counts[info['density']] += 1

print(f"\nSCHEMA GROUPS:")
for s, cnt in sorted(schema_counts.items(), key=lambda x: -x[1]):
    print(f"  {s:15s}: {cnt:>5d} ({100*cnt/len(roo_catalog):>5.1f}%)")

print(f"\nSIZE CLASSES:")
for s, cnt in sorted(size_counts.items(), key=lambda x: -x[1]):
    print(f"  {s:15s}: {cnt:>5d} ({100*cnt/len(roo_catalog):>5.1f}%)")

print(f"\nDENSITY CLASSES:")
for s, cnt in sorted(density_counts.items(), key=lambda x: -x[1]):
    print(f"  {s:15s}: {cnt:>5d} ({100*cnt/len(roo_catalog):>5.1f}%)")

# 8. MASTER_DB files - these are the complex ones
print(f"\n\nMASTER DB FILES (200+ tags):")
master_db = [(f, info) for f, info in roo_catalog.items() if info['schema'] == 'MASTER_DB']
master_db.sort(key=lambda x: -x[1]['num_entries'])

for f, info in master_db:
    print(f"  {f}")
    print(f"    Path: {info['path']} | {info['size_kb']:>6.1f} KB | "
          f"Tags: {info['tag_count']} | Entries: {info['num_entries']} | "
          f"Overrides: {info['num_override']} | Cluster #{info['cluster_id']} ({info['cluster_size']} files)")

# 9. LARGE_SCHEMA files
print(f"\n\nLARGE SCHEMA FILES (100-199 tags, by entry count):")
large_schema = [(f, info) for f, info in roo_catalog.items() if info['schema'] == 'LARGE_SCHEMA']
large_schema.sort(key=lambda x: -x[1]['num_entries'])
for f, info in large_schema[:20]:
    print(f"  {f}  {info['path']:>30s}  {info['size_kb']:>6.1f} KB  Tags:{info['tag_count']:>3d}  Entry:{info['num_entries']:>5d}")

# 10. FINAL CATEGORIZATION by structural patterns
print(f"\n\nFINAL CATEGORIZATION:")

# Use the known APK info: hero IDs, skill IDs, item IDs
# We'll categorize by file properties:
# - VERY_LARGE + MASTER_DB: game-wide databases (hero_db, skill_db, item_db)
# - LARGE + MASTER_DB: major game systems
# - MEDIUM + LARGE_SCHEMA: medium game systems  
# - SMALL: configuration/settings

# Count files by their tag count
tag_buckets = Counter()
for info in roo_catalog.values():
    t = info['tag_count']
    if t == 0: bucket = '0 tags'
    elif t <= 5: bucket = '1-5'
    elif t <= 15: bucket = '6-15'
    elif t <= 40: bucket = '16-40'
    elif t <= 100: bucket = '41-100'
    elif t <= 200: bucket = '101-200'
    else: bucket = '200+'
    tag_buckets[bucket] += 1

print(f"\nTag count distribution:")
for b in ['0 tags', '1-5', '6-15', '16-40', '41-100', '101-200', '200+']:
    print(f"  {b:>8s}: {tag_buckets.get(b, 0):>5d} files")

# 11. Export the final catalog
export_keys = ['hash', 'path', 'dir', 'size_kb', 'bDown', 'md5',
               'num_entries', 'tag_count', 'schema', 'size_class', 'density',
               'cluster_id', 'cluster_size', 'cluster_tags']

export_catalog = {}
for fname, info in roo_catalog.items():
    export_catalog[fname] = {k: info.get(k) for k in export_keys}

output_path = os.path.join(analysis_dir, 'roo_file_catalog.json')
with open(output_path, 'w') as f:
    json.dump(export_catalog, f, indent=2)
print(f"\n\nCatalog exported: {output_path}")
print(f"Total Roo files classified: {len(roo_catalog)}")
