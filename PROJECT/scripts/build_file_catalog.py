"""Build complete file identity catalog for all 7,258 Roo files."""
import re, os, json
from collections import Counter, defaultdict

base = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\decoded_apk\assets'
dec_batch = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\dec_batch'
analysis_dir = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\analysis'

# 1. Parse resList.lua
with open(os.path.join(base, 'resList.lua'), 'r', encoding='utf-8') as f:
    full_text = f.read()

pat_path_md5 = re.compile(
    r'\["([^"]+)"\]=\{md5="([^"]+)"(,bDown=true)?\}'
)
reslist_entries = pat_path_md5.findall(full_text)
print(f"resList.lua entries: {len(reslist_entries)}")

# Build: filename -> metadata
manifest = {}
for path, md5, bdown in reslist_entries:
    fname = path.split('/')[-1].replace('.mt', '')
    manifest[fname] = {
        'path': path,
        'orig_dir': path.split('/')[0],
        'md5': md5,
        'bDown': bool(bdown)
    }

# 2. Parse resSizeList.lua  
with open(os.path.join(base, 'resSizeList.lua'), 'r', encoding='utf-8') as f:
    size_text = f.read()

pat_size = re.compile(r'\["([^"]+)"\]="([\d.]+)"')
size_entries = pat_size.findall(size_text)
print(f"resSizeList.lua entries: {len(size_entries)}")

path_to_size = {p: float(s) for p, s in size_entries}

# Add size info to manifest
for fname in manifest:
    path = manifest[fname]['path']
    manifest[fname]['size_kb'] = path_to_size.get(path, 0)

# 3. Load corpus summary (per-file metrics)
corpus_path = os.path.join(analysis_dir, 'corpus_summary.json')
if os.path.exists(corpus_path):
    with open(corpus_path) as f:
        corpus = json.load(f)
    print(f"Corpus summary entries: {len(corpus)}")
else:
    corpus = {}
    print("No corpus summary found")

# 4. Load cluster report
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
    print(f"Cluster report entries: {len(clusters)}")
else:
    clusters = {}
    print("No cluster report found")

# 5. Build the complete catalog
catalog = {}
for fname in sorted(manifest.keys()):
    info = manifest[fname].copy()
    info['filename'] = fname
    
    # Add corpus info if available
    if corpus and fname in corpus:
        c = corpus[fname]
        info['body_size'] = c.get('body_size', 0)
        info['num_records'] = c.get('num_records', 0)
        info['num_override'] = c.get('num_override', 0)
        info['num_template'] = c.get('num_template', 0)
        info['num_entries'] = c.get('num_entries', 0)
        info['tag_count'] = c.get('tag_count', 0)
    
    # Add cluster info
    info['cluster_id'] = None
    info['cluster_size'] = 0
    info['cluster_tags'] = 0
    
    for cid, cluster_data in clusters.items():
        if isinstance(cluster_data, dict):
            cfiles = cluster_data.get('files', cluster_data.get('filenames', []))
            if fname + '.mt.dec' in cfiles or fname in cfiles:
                info['cluster_id'] = cid
                info['cluster_size'] = cluster_data.get('count', len(cfiles))
                info['cluster_tags'] = cluster_data.get('tags', 0)
                break
    
    catalog[fname] = info

print(f"\nCatalog built: {len(catalog)} files")

# 6. Classification by cluster tags and entry count
# Groups based on internal structure
classification = defaultdict(list)

for fname, info in catalog.items():
    tags = info.get('tag_count', 0) or info.get('cluster_tags', 0)
    entries = info.get('num_entries', 0)
    body_size = info.get('body_size', 0)
    
    if tags >= 200:
        group = 'master_db'
    elif tags >= 100:
        group = 'large_schema'
    elif tags >= 50:
        group = 'medium_schema'
    elif tags >= 20:
        group = 'small_schema'
    elif tags >= 5:
        group = 'tiny_schema'
    else:
        group = 'minimal_schema'
    
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
    
    info['schema_group'] = group
    info['size_group'] = size_group
    info['combined_group'] = f"{group}_{size_group}"
    classification[(group, size_group)].append(fname)

print(f"\nClassification groups:")
for (g, s), files in sorted(classification.items(), key=lambda x: -len(x[1])):
    print(f"  {g:20s} {s:15s}: {len(files):>5d} files")
    if len(files) <= 5:
        for f in files:
            print(f"      {f}")

# 7. List the 55f_255t cluster specifically
print(f"\n\n55F/255T CLUSTER FILES (master_db_very_large):")
master_files = classification.get(('master_db', 'very_large'), [])
for f in sorted(master_files):
    info = catalog[f]
    print(f"  {f}")
    print(f"    Path: {info['path']}")
    print(f"    MD5:  {info['md5']}")
    print(f"    Size: {info['size_kb']} KB")
    print(f"    Tags: {info.get('tag_count', info.get('cluster_tags', '?'))}")
    print(f"    Entries: {info.get('num_entries', '?')}")

# 8. Group files with the same MD5 (duplicates)
md5_groups = defaultdict(list)
for fname, info in catalog.items():
    md5_groups[info['md5']].append(fname)

dups = {k: v for k, v in md5_groups.items() if len(v) > 1}
print(f"\n\nDUPLICATE FILES (same MD5 content):")
for md5, fnames in sorted(dups.items(), key=lambda x: -len(x[1]))[:20]:
    paths = [catalog[f]['path'] for f in fnames]
    print(f"  md5={md5[:16]}... ({len(fnames)} copies):")
    for p in paths[:5]:
        print(f"    {p}")

# 9. Export catalog
output_path = os.path.join(analysis_dir, 'file_catalog.json')
with open(output_path, 'w') as f:
    json.dump(catalog, f, indent=2)
print(f"\nCatalog exported to {output_path}")

# 10. Summary statistics
print(f"\n\nSUMMARY:")
print(f"Total files: {len(catalog)}")
print(f"Directories used: {sorted(set(info['orig_dir'] for info in catalog.values()))}")
print(f"File size range: {min(info['size_kb'] for info in catalog.values()):.1f} - {max(info['size_kb'] for info in catalog.values()):.1f} KB")
print(f"Average file size: {sum(info['size_kb'] for info in catalog.values())/len(catalog):.1f} KB")
bdown_count = sum(1 for info in catalog.values() if info.get('bDown'))
print(f"bDown=true files: {bdown_count}")
