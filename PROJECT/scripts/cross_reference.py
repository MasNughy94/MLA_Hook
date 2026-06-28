#!/usr/bin/env python3
"""
Cross-reference decompressed files with game manifest data.
Match file MD5 hashes from resSizeList.lua to identify data types.
"""
import os, sys, re, json
from collections import defaultdict

dec_dir = os.path.join(os.path.dirname(__file__), 'dec_batch')
assets_dir = os.path.join(os.path.dirname(__file__), 'decoded_apk', 'assets')

# Load manifests
res_size_path = os.path.join(assets_dir, 'resSizeList.lua')
res_list_path = os.path.join(assets_dir, 'resList.lua')

def parse_resSizeList(path):
    """Parse resSizeList.lua: { [\"0/hash.mt\"] = \"size_kb\" }"""
    with open(path, 'rb') as f:
        content = f.read().decode('utf-8', errors='replace')
    entries = {}
    for m in re.finditer(r'\["([^"]+)"\]\s*=\s*"([^"]*)"', content):
        key_path = m.group(1)
        val = m.group(2)
        mt_match = re.match(r'(?:[0-9a-f]/)?([0-9a-f]{32})\.mt', key_path)
        if mt_match:
            entries[mt_match.group(1)] = float(val)  # size in KB
    return entries

def parse_resList(path):
    """Parse resList.lua: { [\"0/hash.mt\"] = { md5=\"content_hash\" } }"""
    with open(path, 'rb') as f:
        content = f.read().decode('utf-8', errors='replace')
    entries = {}
    for m in re.finditer(r'\["([^"]+)"\]\s*=\s*\{[^}]*md5="([^"]*)"', content):
        key_path = m.group(1)
        content_hash = m.group(2)
        mt_match = re.match(r'(?:[0-9a-f]/)?([0-9a-f]{32})\.mt', key_path)
        if mt_match:
            entries[mt_match.group(1)] = content_hash
    return entries

res_sizes = parse_resSizeList(res_size_path)
res_map = parse_resList(res_list_path)

# Parse manifests
print("Loading manifests...")
res_sizes = parse_resSizeList(res_size_path)
res_map = parse_resList(res_list_path)
print(f"resSizeList: {len(res_sizes)} entries")
print(f"resList: {len(res_map)} entries")

# For each decompressed file, find its metadata
# The .mt file name is an MD5 hash of the encrypted content
# resList maps: .mt filename -> content hash (md5 field)
# resSizeList maps: .mt filename -> size in KB
#
# Our decompressed .dec files are named by their .mt filename
# So we can look up: .mt filename -> content hash (what the decompressed data represents)
# and: .mt filename -> size (KB)

dec_files = sorted([f.replace('.mt.dec', '') for f in os.listdir(dec_dir) if f.endswith('.dec')])
print(f"\nDecompressed files: {len(dec_files)}")

# Match by .mt filename hash
matched = []
unmatched = []
for fname_hash in dec_files:
    content_hash = res_map.get(fname_hash, None)
    mt_size_kb = res_sizes.get(fname_hash, None)
    matched.append({
        'mt_hash': fname_hash,
        'content_hash': content_hash,
        'mt_size_kb': mt_size_kb,
    })

with_content = [m for m in matched if m['content_hash']]
with_size = [m for m in matched if m['mt_size_kb']]
print(f"Matched with content hash: {len(with_content)}")
print(f"Matched with size info: {len(with_size)}")
print(f"Unmatched (no content OR size): {len([m for m in matched if not m['content_hash'] and not m['mt_size_kb']])}")

# Show sample matched files with structure info
print(f"\n=== Sample matched files ===")
HDR_SIZE = 69
count = 0
for meta in sorted(with_content, key=lambda x: x['mt_size_kb'] or 0)[:40]:
    fname_hash = meta['mt_hash']
    dec_path = os.path.join(dec_dir, fname_hash + '.mt.dec')
    actual_size = os.path.getsize(dec_path)
    
    with open(dec_path, 'rb') as f:
        data = f.read()
    body = data[HDR_SIZE:]
    trailing = len(body) % 3
    if trailing:
        body = body[:-trailing]
    num_records = len(body) // 3 if len(body) >= 3 else 0
    
    tag_set = set()
    override_count = 0
    for i in range(0, len(body), 3):
        if i+2 < len(body):
            tag, v1, v2 = body[i], body[i+1], body[i+2]
            if tag != 0:
                tag_set.add(tag)
                override_count += 1
    
    # Cluster entries
    sorted_offsets = sorted([i for i in range(0, len(body), 3) if body[i] != 0])
    entries = 0
    if sorted_offsets:
        entries = 1
        last = sorted_offsets[0]
        for off in sorted_offsets[1:]:
            if off - last > 30:
                entries += 1
            last = off
    
    tags_ascii = ''.join(chr(t) if 32 <= t < 127 else '.' for t in sorted(tag_set))
    print(f"  {meta['content_hash'][:12]}... <- {fname_hash[:12]}... | "
          f"sz={actual_size/1024:.1f}KB mt={meta['mt_size_kb']}KB | "
          f"rec={num_records} ovr={override_count} ent={entries} "
          f"tags[{len(tag_set)}]={tags_ascii[:30]}")
    count += 1
