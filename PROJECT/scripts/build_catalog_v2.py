"""Build file catalog - using robust regex search per line."""
import re, os, json
from collections import defaultdict

base = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\decoded_apk\assets'
analysis_dir = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\analysis'

# 1. Parse resList.lua - use simple find all approach on each data line
with open(os.path.join(base, 'resList.lua'), 'r', encoding='utf-8') as f:
    content = f.read()

# Extract start of fileList
start = content.find('fileList = {')
end = content.rfind('}')
data_section = content[start+12:end]  # after 'fileList = {'

# Pattern for each entry: ["path"]={md5="hash"[,bDown=true]}
pat = re.compile(r'\["([^"]+)"\]=\{md5="([^"]+)"(,bDown=true)?\}')
matches = pat.findall(data_section)
print(f"resList.lua entries: {len(matches)}")

manifest = {}
for path, md5, bdown in matches:
    fname = path.split('/')[-1].replace('.mt', '')
    manifest[fname] = {
        'path': path,
        'orig_dir': path.split('/')[0],
        'md5': md5,
        'bDown': bool(bdown),
        'size_kb': 0.0
    }
print(f"Manifest entries: {len(manifest)}")

# 2. Parse resSizeList.lua
with open(os.path.join(base, 'resSizeList.lua'), 'r', encoding='utf-8') as f:
    size_content = f.read()

start = size_content.find('fileList = {')
end = size_content.rfind('}')
size_section = size_content[start+12:end]

pat_size = re.compile(r'\["([^"]+)"\]="([\d.]+)"')
size_matches = pat_size.findall(size_section)
print(f"resSizeList.lua entries: {len(size_matches)}")

path_to_size = {}
for path, size_str in size_matches:
    path_to_size[path] = float(size_str)

# Add size to manifest
for fname, info in manifest.items():
    info['size_kb'] = path_to_size.get(info['path'], 0.0)

# 3. Load corpus summary
corpus = {}
corpus_path = os.path.join(analysis_dir, 'corpus_summary.json')
if os.path.exists(corpus_path):
    with open(corpus_path) as f:
        corpus = json.load(f)
    print(f"Corpus entries: {len(corpus)}")

# 4. Load cluster report
file_to_cluster = {}
cluster_path = os.path.join(analysis_dir, 'cluster_report.json')
if os.path.exists(cluster_path):
    with open(cluster_path) as f:
        raw = json.load(f)
    if isinstance(raw, dict):
        clist = [(cid, cdata) for cid, cdata in raw.items()]
    elif isinstance(raw, list):
        clist = [(str(i), c) for i, c in enumerate(raw)]
    else:
        clist = []
    print(f"Cluster entries: {len(clist)}")
    
    for cid, cdata in clist:
        cfiles = cdata.get('files', cdata.get('filenames', [])) if isinstance(cdata, dict) else []
        for cf in cfiles:
            for ext in ['.mt.dec', '.mt', '']:
                fbase = cf.replace(ext, '')
                if fbase and fbase != cf:
                    break
            if fbase:
                file_to_cluster[fbase] = {
                    'cluster_id': cid,
                    'cluster_size': cdata.get('count', len(cfiles)) if isinstance(cdata, dict) else len(cfiles),
                    'cluster_tags': cdata.get('tags', 0) if isinstance(cdata, dict) else 0
                }
    print(f"File-to-cluster mappings: {len(file_to_cluster)}")

# 5. Build catalog
catalog = {}
for fname, info in manifest.items():
    entry = info.copy()
    
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
    
    if fname in file_to_cluster:
        entry.update(file_to_cluster[fname])
    else:
        entry['cluster_id'] = None
        entry['cluster_size'] = 0
        entry['cluster_tags'] = 0
    
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

# 6. Summary
from collections import Counter
group_counts = Counter(info['combined_group'] for info in catalog.values())
print(f"\nClassification groups:")
for group, cnt in sorted(group_counts.items(), key=lambda x: -x[1]):
    print(f"  {group:30s}: {cnt:>5d}")

# 7. Master DB files
print(f"\nMASTER DB FILES:")
master_db = [(f, info) for f, info in catalog.items() 
             if info.get('cluster_tags', 0) >= 200 or info.get('tag_count', 0) >= 200]
master_db.sort(key=lambda x: -x[1].get('num_entries', 0))
print(f"  Count: {len(master_db)}")
for f, info in master_db[:55]:
    print(f"  {f}")
    print(f"    Path: {info['path']}  Size: {info['size_kb']:>6.1f} KB  "
          f"Tags: {info.get('tag_count', info.get('cluster_tags', '?'))}  "
          f"Entries: {info.get('num_entries', '?')}")

# 8. Export catalog
output_path = os.path.join(analysis_dir, 'file_catalog.json')
with open(output_path, 'w') as f:
    json.dump(catalog, f, indent=2)
print(f"\nCatalog exported: {output_path}")

# 9. Print directories used
dirs = set(info['orig_dir'] for info in catalog.values())
print(f"\nDirectories: {sorted(dirs)}")
size_range = (min(info['size_kb'] for info in catalog.values()),
              max(info['size_kb'] for info in catalog.values()))
print(f"Size range: {size_range[0]:.1f} - {size_range[1]:.1f} KB")
bdown_count = sum(1 for info in catalog.values() if info.get('bDown'))
print(f"bDown=true: {bdown_count}")
print(f"Total DEC files in batch: {len([f for f in os.listdir(r'C:\\Users\\NGEONG\\AppData\\Local\\Temp\\opencode\\dec_batch') if f.endswith('.mt.dec')])}")
