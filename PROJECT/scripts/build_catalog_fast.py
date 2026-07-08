"""Build file catalog - optimized version."""
import re, os, json
from collections import defaultdict

base = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\decoded_apk\assets'
dec_batch = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\dec_batch'
analysis_dir = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\analysis'

# 1. Parse resList.lua - use line-by-line to avoid regex backtracking
with open(os.path.join(base, 'resList.lua'), 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Skip first 3 lines (resInfo = {, version, fileList = {)
data_lines = lines[3:-1]  # skip last closing }

# Build manifest
manifest = {}
print(f"Parsing {len(data_lines)} resList.lua entries...")
for line in data_lines:
    line = line.strip()
    if not line or line == '}':
        continue
    # Format: ["path"]={md5="hash",bDown=true},
    # Or: ["path"]={md5="hash"},
    line = line.rstrip(',').strip()
    # Extract path
    m = line[1:].split('"')[0] if line.startswith('[') else None
    if not m:
        continue
    path = m.split('"')[0] if '"' in m else m
    
    # Extract md5
    md5_start = line.find('md5="') + 5
    md5_end = line.find('"', md5_start)
    md5 = line[md5_start:md5_end] if md5_start >= 5 else ''
    
    bdown = 'bDown=true' in line
    
    fname = path.split('/')[-1].replace('.mt', '')
    manifest[fname] = {
        'path': path,
        'orig_dir': path.split('/')[0],
        'md5': md5,
        'bDown': bdown,
        'size_kb': 0.0
    }

# 2. Parse resSizeList.lua
with open(os.path.join(base, 'resSizeList.lua'), 'r', encoding='utf-8') as f:
    size_lines = f.readlines()

size_data = size_lines[3:-1]
print(f"Parsing {len(size_data)} resSizeList.lua entries...")
for line in size_data:
    line = line.strip().rstrip(',').strip()
    if not line or line == '}':
        continue
    # ["path"]="size",
    if not line.startswith('['):
        continue
    path = line[2:].split('"')[0]
    size_str = line.split('"')[3] if line.count('"') >= 4 else '0'
    try:
        size = float(size_str)
    except ValueError:
        size = 0.0
    
    for fname, info in manifest.items():
        if info['path'] == path:
            info['size_kb'] = size
            break

print(f"Manifest entries: {len(manifest)}")

# 3. Load corpus and cluster data
corpus = {}
cluster_path = os.path.join(analysis_dir, 'cluster_report.json')
if os.path.exists(cluster_path):
    with open(cluster_path) as f:
        raw = json.load(f)
    if isinstance(raw, dict):
        clusters = raw
    elif isinstance(raw, list):
        clusters = {str(i): c for i, c in enumerate(raw)}
    else:
        clusters = {}
    print(f"Cluster entries: {len(clusters)}")
    
    # Build file -> cluster lookup
    file_to_cluster = {}
    for cid, cdata in clusters.items():
        cfiles = []
        if isinstance(cdata, dict):
            cfiles = cdata.get('files', cdata.get('filenames', []))
        for cf in cfiles:
            fbase = cf.replace('.mt.dec', '').replace('.mt', '')
            file_to_cluster[fbase] = {
                'cluster_id': cid,
                'cluster_size': cdata.get('count', len(cfiles)) if isinstance(cdata, dict) else len(cfiles),
                'cluster_tags': cdata.get('tags', 0) if isinstance(cdata, dict) else 0
            }
    print(f"File-to-cluster mappings: {len(file_to_cluster)}")
else:
    clusters = {}
    file_to_cluster = {}

corpus_path = os.path.join(analysis_dir, 'corpus_summary.json')
if os.path.exists(corpus_path):
    with open(corpus_path) as f:
        corpus = json.load(f)
    print(f"Corpus entries: {len(corpus)}")

# 4. Build catalog
catalog = {}
for fname, info in manifest.items():
    entry = info.copy()
    
    # Add corpus info
    if fname in corpus:
        c = corpus[fname]
        entry['body_size'] = c.get('body_size', 0)
        entry['num_records'] = c.get('num_records', 0)
        entry['num_override'] = c.get('num_override', 0)
        entry['num_template'] = c.get('num_template', 0)
        entry['num_entries'] = c.get('num_entries', 0)
        entry['tag_count'] = c.get('tag_count', 0)
    else:
        entry['body_size'] = entry['num_records'] = entry['num_override'] = 0
        entry['num_template'] = entry['num_entries'] = entry['tag_count'] = 0
    
    # Add cluster info
    if fname in file_to_cluster:
        entry.update(file_to_cluster[fname])
    else:
        entry['cluster_id'] = None
        entry['cluster_size'] = 0
        entry['cluster_tags'] = 0
    
    # Compute classification
    tags = entry['tag_count'] or entry['cluster_tags'] or 0
    entries = entry.get('num_entries', 0)
    
    if tags >= 200:
        schema_group = 'master_db'
    elif tags >= 100:
        schema_group = 'large_schema'
    elif tags >= 50:
        schema_group = 'medium_schema'
    elif tags >= 20:
        schema_group = 'small_schema'
    elif tags >= 5:
        schema_group = 'tiny_schema'
    else:
        schema_group = 'minimal'
    
    if entries > 1000:
        size_group = 'very_large'
    elif entries > 100:
        size_group = 'large'
    elif entries > 10:
        size_group = 'medium'
    elif entries > 0:
        size_group = 'small'
    else:
        size_group = 'empty'
    
    entry['schema_group'] = schema_group
    entry['size_group'] = size_group
    entry['combined_group'] = f"{schema_group}_{size_group}"
    
    catalog[fname] = entry

print(f"Catalog built: {len(catalog)} files")

# 5. Classification summary
from collections import Counter
group_counts = Counter(info['combined_group'] for info in catalog.values())
print(f"\nClassification groups:")
for group, cnt in sorted(group_counts.items(), key=lambda x: -x[1]):
    print(f"  {group:30s}: {cnt:>5d}")

# 6. Master DB files
print(f"\n\nMASTER DB FILES (255 tags, very large):")
master_db = [f for f, info in catalog.items() 
             if info.get('cluster_tags', 0) >= 200 or info.get('tag_count', 0) >= 200]
master_db.sort(key=lambda f: catalog[f].get('num_entries', 0), reverse=True)
for f in master_db:
    info = catalog[f]
    print(f"  {f}")
    print(f"    Path: {info['path']}  Size: {info['size_kb']:>6.1f} KB  MD5: {info['md5']}")
    print(f"    Tags: {info.get('tag_count', info.get('cluster_tags', '?'))}  "
          f"Entries: {info.get('num_entries', '?')}  "
          f"Overrides: {info.get('num_override', '?')}")

# 7. Duplicate MD5s
md5_groups = defaultdict(list)
for fname, info in catalog.items():
    md5_groups[info['md5']].append(fname)

dups = {k: v for k, v in md5_groups.items() if len(v) > 1}
print(f"\n\nDUPLICATE CONTENT (same MD5): {len(dups)} groups")
for md5, fnames in sorted(dups.items(), key=lambda x: -len(x[1]))[:10]:
    paths = [catalog[f]['path'] for f in fnames]
    print(f"  [{len(fnames)} copies] md5={md5[:16]}...")
    for p in paths:
        print(f"    {p}")

# 8. Export catalog
output_path = os.path.join(analysis_dir, 'file_catalog.json')
with open(output_path, 'w') as f:
    json.dump(catalog, f, indent=2)
print(f"\nCatalog exported to {output_path}")
print(f"Done! Total files cataloged: {len(catalog)}")
