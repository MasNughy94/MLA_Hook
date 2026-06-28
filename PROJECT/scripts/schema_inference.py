#!/usr/bin/env python3
"""
Deep Schema Inference for Roo Format
====================================
Analyzes the override record structure to infer field schemas
across different data types in the corpus.
"""
import os, sys, json, struct
from collections import defaultdict, Counter

HDR_SIZE = 69
MAX_TAGS_TO_PREVIEW = 8
MAX_ENTRIES_PREVIEW = 50

dec_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), 'dec_batch')
out_dir = os.path.join(os.path.dirname(__file__), 'analysis')
os.makedirs(out_dir, exist_ok=True)

def parse_file(fpath):
    with open(fpath, 'rb') as f:
        data = f.read()
    if len(data) < HDR_SIZE:
        return None
    header = data[:HDR_SIZE]
    body = data[HDR_SIZE:]
    trailing = len(body) % 3
    if trailing:
        body = body[:-trailing]
    if len(body) < 3:
        return None
    variant = '0x{:02x}'.format(header[-1])
    
    records = []
    for i in range(0, len(body), 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        if tag != 0:
            records.append({'offset': i, 'tag': tag, 'v1': v1, 'v2': v2, 'u16': v1 | (v2 << 8)})
    
    # Cluster entries by gap
    sorted_recs = sorted(records, key=lambda x: x['offset'])
    entries = []
    current = []
    for r in sorted_recs:
        if current and r['offset'] - current[-1]['offset'] > 30:
            entries.append(current)
            current = [r]
        else:
            current.append(r)
    if current:
        entries.append(current)
    
    return {'variant': variant, 'header': header, 'records': records, 'entries': entries}

def field_position_analysis(files_by_variant):
    """For each file group, map which body positions have which tags."""
    for variant, file_list in sorted(files_by_variant.items(), key=lambda x: -len(x[1])):
        if len(file_list) < 3:
            continue
        
        print(f"\n{'='*60}")
        print(f"Variant {variant} — {len(file_list)} files")
        print(f"{'='*60}")
        
        # Group files by tag set (same data type)
        tag_sets = defaultdict(list)
        for fname in file_list:
            fpath = os.path.join(dec_dir, fname)
            parsed = parse_file(fpath)
            if parsed and parsed['records']:
                tag_set = frozenset(r['tag'] for r in parsed['records'])
                tag_sets[tag_set].append(fname)
        
        # For each data type cluster (with at least 2 files), analyze field positions
        for tag_set, members in sorted(tag_sets.items(), key=lambda x: -len(x[1])):
            if len(members) < 2:
                continue
            tags_sorted = sorted(tag_set)
            n_tags = len(tags_sorted)
            
            print(f"\n  Cluster: {len(members)} files, {n_tags} tags")
            tag_chars = ''.join(chr(t) if 32 <= t < 127 else '.' for t in tags_sorted)
            print(f"  Tags: {tag_chars}")
            print(f"  Tag hex: {' '.join(f'0x{t:02x}' for t in tags_sorted)}")
            
            # Parse the first file in detail
            first = parse_file(os.path.join(dec_dir, members[0]))
            entries = first['entries']
            records = first['records']
            
            print(f"  Entries: {len(entries)}")
            print(f"  Records: {len(records)}")
            
            # For each entry, show which tags appear and the positions
            # This helps infer the field structure
            if len(entries) <= MAX_ENTRIES_PREVIEW and len(entries) >= 2:
                print(f"\n  Entry record breakdown (first {min(MAX_ENTRIES_PREVIEW, len(entries))} entries):")
                
                # Track which tags appear at which positions in each entry
                entry_patterns = {}
                for e_idx, entry in enumerate(entries[:MAX_ENTRIES_PREVIEW]):
                    # Normalize offsets to entry-relative
                    base = entry[0]['offset']
                    pattern = tuple((r['tag'], r['offset'] - base) for r in entry)
                    key = str(sorted(pattern))
                    if key not in entry_patterns:
                        entry_patterns[key] = {'count': 0, 'entry_indices': []}
                    entry_patterns[key]['count'] += 1
                    entry_patterns[key]['entry_indices'].append(e_idx)
                
                # Show the most common patterns
                print(f"    Unique entry patterns: {len(entry_patterns)}")
                for pat_str, info in sorted(entry_patterns.items(), key=lambda x: -x[1]['count'])[:5]:
                    print(f"    -> {info['count']} entries ({info['entry_indices']}):")
                    # Reconstruct from string
                    import ast
                    pat = ast.literal_eval(pat_str)
                    for tag, rel_pos in pat[:n_tags]:  # show first few
                        ch = chr(tag) if 32 <= tag < 127 else '.'
                        print(f"        tag=0x{tag:02x}('{ch}') @ +{rel_pos}B")
            
            # Template record analysis: which positions have tag=0 default values?
            body_all = []
            for fname in members:
                fpath = os.path.join(dec_dir, fname)
                with open(fpath, 'rb') as f:
                    data = f.read()
                body = data[HDR_SIZE:]
                trailing = len(body) % 3
                if trailing:
                    body = body[:-trailing]
                body_all.append(body)
            
            # Find template positions shared across files
            if len(body_all) >= 3:
                template_agreement = []
                for i in range(0, len(body_all[0]), 3):
                    tag0 = body_all[0][i]
                    if tag0 != 0:
                        continue
                    v1s = set()
                    v2s = set()
                    for b in body_all:
                        if i+2 < len(b):
                            v1s.add(b[i+1])
                            v2s.add(b[i+2])
                    if len(v1s) == 1 and len(v2s) == 1:
                        v1, v2 = v1s.pop(), v2s.pop()
                        if v1 != 0 or v2 != 0:
                            template_agreement.append((i, v1, v2))
                
                if template_agreement:
                    print(f"\n    Shared template defaults: {len(template_agreement)} positions")
                    for pos, v1, v2 in template_agreement[:10]:
                        print(f"      @{pos}: V1=0x{v1:02x} V2=0x{v2:02x} (u16={v1|(v2<<8)})")


# ─── Main: load corpus ───
files = sorted([f for f in os.listdir(dec_dir) if f.endswith('.dec')])
print(f"Loading {len(files)} files...")

# Group by variant
files_by_variant = defaultdict(list)
for fname in files:
    fpath = os.path.join(dec_dir, fname)
    with open(fpath, 'rb') as f:
        hdr = f.read(HDR_SIZE)
    if len(hdr) >= HDR_SIZE:
        variant = '0x{:02x}'.format(hdr[-1])
        files_by_variant[variant].append(fname)

field_position_analysis(files_by_variant)

print("\n\n=== DATA TYPE ANALYSIS ===")
# Now let's look specifically at the largest clusters
# Re-load and analyze top data type clusters
from ast import literal_eval

dec_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), 'dec_batch')

# Index all files by tag set
tag_set_index = defaultdict(list)
for fname in files:
    fpath = os.path.join(dec_dir, fname)
    parsed = parse_file(fpath)
    if parsed and parsed['records']:
        tag_set = frozenset(r['tag'] for r in parsed['records'])
        tag_set_index[tag_set].append(fname)

# Sort clusters by size
clusters = sorted(tag_set_index.items(), key=lambda x: -len(x[1]))

# Group clusters by tag characteristics
print("\nClusters by tag characteristics:")
tag_usage = Counter()
for tag_set, members in clusters:
    for tag in tag_set:
        tag_usage[tag] += len(members)

# For each cluster, identify the "primary key" tag (appears once per entry, small value range)
print("\n=== PRIMARY KEY / ID FIELD INFERENCE ===")
for tag_set, members in clusters[:50]:
    if len(members) < 2:
        continue
    fname = members[0]
    fpath = os.path.join(dec_dir, fname)
    parsed = parse_file(fpath)
    if not parsed or len(parsed['entries']) < 3:
        continue
    
    entries = parsed['entries']
    tag_counts = Counter(r['tag'] for r in parsed['records'])
    
    # Tags that appear once per entry are likely ID fields
    once_per_entry_tags = {tag for tag, cnt in tag_counts.items() 
                           if cnt == len(entries)}
    
    tags_sorted = sorted(tag_set)
    tag_chars = ''.join(chr(t) if 32 <= t < 127 else '.' for t in tags_sorted)
    
    if once_per_entry_tags:
        print(f"\n  Cluster {len(members)} files, {len(tag_set)} tags: {tag_chars}")
        print(f"  Potential ID tags (once/entry): ", end='')
        for tag in sorted(once_per_entry_tags):
            ch = chr(tag) if 32 <= tag < 127 else '.'
            vals = Counter(r['u16'] for r in parsed['records'] if r['tag'] == tag)
            v1_vals = Counter(r['v1'] for r in parsed['records'] if r['tag'] == tag)
            v2_vals = Counter(r['v2'] for r in parsed['records'] if r['tag'] == tag)
            print(f"0x{tag:02x}('{ch}'):unique_u16={len(vals)},u16_range=[{min(vals.keys())}..{max(vals.keys())}],v1_vals={len(v1_vals)},v2_vals={len(v2_vals)}", end=' | ')

# Look at a specific interesting cluster: hero data
print("\n\n=== HERO DATA CLUSTER (lowercase tags, from earlier analysis) ===")
# The hero file we analyzed earlier used tags: a-g-i-k-m (lowercase)
for tag_set, members in clusters:
    tags_sorted = sorted(tag_set)
    # Check if all tags are lowercase letters
    if all(ord('a') <= t <= ord('z') for t in tags_sorted if 32 <= t < 127):
        # Check if it's mostly lowercase
        lowercase_ratio = sum(1 for t in tags_sorted if ord('a') <= t <= ord('z')) / len(tags_sorted)
        if lowercase_ratio > 0.8:
            print(f"\n  Likely hero data: {len(members)} files, {len(tag_set)} tags")
            print(f"  Tags: {' '.join(chr(t) for t in tags_sorted)}")
            fname = members[0]
            fpath = os.path.join(dec_dir, fname)
            parsed = parse_file(fpath)
            if parsed:
                print(f"  Entries: {len(parsed['entries'])}, Records: {len(parsed['records'])}")
                # Show first entry in detail
                if parsed['entries']:
                    entry = parsed['entries'][0]
                    print(f"\n  First entry ({len(entry)} records):")
                    for r in entry[:20]:
                        ch = chr(r['tag']) if 32 <= r['tag'] < 127 else '.'
                        print(f"    tag=0x{r['tag']:02x}('{ch}') V1=0x{r['v1']:02x}({r['v1']}) V2=0x{r['v2']:02x}({r['v2']}) u16={r['u16']}")
