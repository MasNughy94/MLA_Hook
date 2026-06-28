#!/usr/bin/env python3
"""
Semantic Reconstruction Engine — Phase 1 & 2
=============================================
1. Merge exact-match clusters into similarity-based groups
2. Deep value-pattern analysis per merged cluster
3. Candidate field-type inference
"""
import os, sys, json, struct, time
from collections import defaultdict, Counter
from itertools import combinations

HDR_SIZE = 69
dec_dir = os.path.join(os.path.dirname(__file__), 'dec_batch')
analysis_dir = os.path.join(os.path.dirname(__file__), 'analysis')
out_dir = os.path.join(os.path.dirname(__file__), 'semantic')
os.makedirs(out_dir, exist_ok=True)

# ─── Load cached analysis ───
print("Loading corpus summary...")
with open(os.path.join(analysis_dir, 'corpus_summary.json')) as f:
    corpus = json.load(f)

print("Loading tag database...")
with open(os.path.join(analysis_dir, 'tag_database.json')) as f:
    tag_db = json.load(f)

# Index by filename
file_index = {}
for entry in corpus:
    file_index[entry['file']] = entry

# ─── Phase 1: Merge clusters by tag similarity ───
print("\n=== Phase 1: Similarity-based Cluster Merging ===")

# Build tag-set index (hashable frozenset per file)
# For files with valid tag data
valid_files = {f['file']: frozenset(f.get('tag_list', [])) for f in corpus 
               if f.get('valid') and f.get('tag_list')}

print(f"Valid files with tag data: {len(valid_files)}")

# Build inverted index: tag -> [files with that tag]
tag_to_files = defaultdict(set)
for fname, tags in valid_files.items():
    for t in tags:
        tag_to_files[t].add(fname)

# Assign numeric IDs to files for faster bit operations
file_ids = {f: i for i, f in enumerate(sorted(valid_files.keys()))}
id_to_file = {i: f for f, i in file_ids.items()}
n_files = len(file_ids)

# Build bitset for each file (as Python integer)
file_bitset = {}
for fname, tags in valid_files.items():
    bs = 0
    for t in tags:
        # Parse tag like '0x61' -> byte value
        tag_val = int(t, 16)
        if 1 <= tag_val <= 255:
            bs |= (1 << tag_val)
    file_bitset[fname] = bs

def jaccard(bs1, bs2):
    inter = (bs1 & bs2).bit_count()
    union = (bs1 | bs2).bit_count()
    return inter / union if union else 0

def containment(bs1, bs2):
    """How much of bs1 is contained in bs2."""
    inter = (bs1 & bs2).bit_count()
    return inter / bs1.bit_count() if bs1.bit_count() else 0

# Build similarity graph: edge between files with Jaccard > 0.5 or strong containment
print("Computing file similarities...")
t0 = time.time()

# Group files by tag count for efficient candidate selection
files_by_count = defaultdict(list)
for fname in valid_files:
    cnt = len(valid_files[fname])
    files_by_count[cnt].append(fname)

# For each file, find similar files
# Strategy: files with similar tag counts are most likely to match
merged_groups = {}  # fname -> group_id
next_group = 0
edge_count = 0

# Process files in order of decreasing tag count (larger sets first)
sorted_files = sorted(valid_files.keys(), key=lambda f: -len(valid_files[f]))
processed = set()

for fname in sorted_files:
    if fname in processed:
        continue
    bs1 = file_bitset[fname]
    tags1 = valid_files[fname]
    cnt1 = len(tags1)
    
    # Find candidate files: similar count (±40%) or sharing tags
    candidates = set()
    for cnt2 in range(max(1, cnt1 - 10), min(cnt1 + 10, 256)):
        for cf in files_by_count.get(cnt2, []):
            if cf not in processed and cf != fname:
                candidates.add(cf)
    
    # Limit candidates for large groups
    if len(candidates) > 5000:
        # Use tag intersection instead
        candidates = set()
        for t in list(tags1)[:5]:  # first 5 tags
            candidates.update(tag_to_files[t])
        candidates.discard(fname)
    
    if not candidates:
        merged_groups[fname] = next_group
        next_group += 1
        processed.add(fname)
        continue
    
    # Compute Jaccard with candidates
    group_members = {fname}
    group_tags = set(tags1)
    
    for cf in candidates:
        if cf in processed:
            continue
        bs2 = file_bitset[cf]
        j = jaccard(bs1, bs2)
        c12 = containment(bs1, bs2)
        c21 = containment(bs2, bs1)
        
        # Merge if: Jaccard > 0.5 OR strong containment in either direction
        if j > 0.5 or c12 > 0.8 or c21 > 0.8:
            group_members.add(cf)
            group_tags.update(valid_files[cf])
            edge_count += 1
    
    gid = next_group
    for m in group_members:
        merged_groups[m] = gid
        processed.add(m)
    next_group += 1
    
    if next_group % 200 == 0:
        dt = time.time() - t0
        print(f"  {next_group} groups formed from {len(processed)} files in {dt:.0f}s")

total_time = time.time() - t0
print(f"Formed {next_group} merged groups ({edge_count} edges) in {total_time:.0f}s")

# Group files by merged group
groups = defaultdict(list)
for fname, gid in merged_groups.items():
    groups[gid].append(fname)

# Sort groups by size descending
sorted_groups = sorted(groups.values(), key=lambda g: -len(g))
print(f"\nMerged group sizes:")
size_dist = Counter(len(g) for g in sorted_groups)
for sz in sorted(size_dist.keys(), reverse=True)[:15]:
    cnt = size_dist[sz]
    print(f"  {sz} files: {cnt} groups")

print(f"\nTop 30 merged groups:")
for i, members in enumerate(sorted_groups[:30]):
    # Determine the unified tag set
    all_tags = set()
    for m in members:
        all_tags.update(valid_files.get(m, []))
    sorted_tags = sorted(all_tags)
    tag_chars = ''.join(chr(int(t,16)) if 32 <= int(t,16) < 127 else '.' for t in sorted_tags)
    print(f"  [{i+1:2d}] {len(members):3d} files, {len(sorted_tags):3d} tags: {tag_chars[:60]}")

# ─── Phase 2: Deep Field Analysis ───
print("\n\n=== Phase 2: Deep Field Analysis ===")

def parse_file_body(fpath):
    """Parse Roo body from a decompressed file."""
    with open(fpath, 'rb') as f:
        data = f.read()
    if len(data) < HDR_SIZE:
        return None
    body = data[HDR_SIZE:]
    trailing = len(body) % 3
    if trailing:
        body = body[:-trailing]
    return body

def extract_entry_fields(body):
    """Extract fields grouped by entry from body."""
    records = []
    for i in range(0, len(body), 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        if tag != 0:
            records.append({'offset': i, 'rec_idx': i//3, 'tag': tag, 'v1': v1, 'v2': v2, 'u16': v1 | (v2<<8)})
    
    # Cluster into entries
    sorted_recs = sorted(records, key=lambda r: r['offset'])
    entries = []
    cur = []
    for r in sorted_recs:
        if cur and r['offset'] - cur[-1]['offset'] > 30:
            entries.append(cur)
            cur = [r]
        else:
            cur.append(r)
    if cur:
        entries.append(cur)
    return entries, records

def classify_field(tag, field_data):
    """
    Given a tag and its observed values across entries & files,
    propose candidate field types with confidence scores.
    field_data = {'u16_vals': set, 'v1_vals': set, 'v2_vals': set,
                  'per_entry': bool, 'per_file_stable': bool,
                  'entry_count': int, 'value_count': int, ...}
    """
    clues = []
    score = 0.0
    candidates = []
    
    v1 = field_data['v1_vals']
    v2 = field_data['v2_vals']
    u16 = field_data['u16_vals']
    n_entries = field_data['entry_count']
    n_vals = len(u16)
    all_v1_single = len(v1) == 1
    all_v2_single = len(v2) == 1
    
    # CLUE: appears once per entry, values are sequential-ish → likely an ID
    if field_data.get('per_entry') and n_vals == n_entries:
        sorted_vals = sorted(u16)
        if sorted_vals and max(sorted_vals) - min(sorted_vals) < n_entries * 3:
            # Sequential or near-sequential values
            clues.append(("sequential_values", 0.8))
            candidates.append(("primary_id", 0.8))
        else:
            clues.append(("one_per_entry_wide_range", 0.6))
            candidates.append(("foreign_key", 0.5))
    
    # CLUE: small value range (2-16 values) → likely an enum
    if n_vals <= 16 and n_vals >= 2 and n_entries > n_vals * 2:
        clues.append(("enum_range", 0.9))
        candidates.append(("enumeration", 0.7))
    
    # CLUE: single value across all entries → type/class identifier
    if n_vals == 1:
        clues.append(("constant_value", 0.95))
        candidates.append(("type_id", 0.6))
    
    # CLUE: values 0 or 1 only → flag
    if n_vals <= 2 and max(u16) <= 1:
        clues.append(("boolean_flag", 0.9))
        candidates.append(("flag", 0.8))
    
    # CLUE: values in 0..100 → percentage or level
    if all(0 <= v <= 100 for v in u16) and n_vals > 3:
        clues.append(("bounded_0_100", 0.7))
        candidates.append(("level_or_percent", 0.5))
    
    # CLUE: V1 and V2 both have many unique values → two separate IDs packed
    if len(v1) > 5 and len(v2) > 5 and len(v1) * len(v2) > len(u16) * 2:
        clues.append(("packed_ids", 0.6))
        candidates.append(("composite_key", 0.5))
    
    # CLUE: V1 is constant, V2 varies → V1 is category/subtype, V2 is value
    if all_v1_single and len(v2) > 3:
        clues.append(("v1_constant_v2_varies", 0.7))
        candidates.append(("categorized_value", 0.6))
    
    # CLUE: V2 constant, V1 varies → simple u8 value
    if all_v2_single and len(v1) > 3:
        clues.append(("v2_constant_v1_varies", 0.5))
        candidates.append(("single_byte_value", 0.4))
    
    # CLUE: values are all < 200 → small ID range (hero IDs, item IDs)
    if all(v <= 200 for v in u16) and n_vals == n_entries and n_entries > 10:
        clues.append(("small_id_range", 0.7))
        candidates.append(("small_entity_id", 0.6))
    
    return clues, candidates

# Analyze top merged groups
print("Analyzing top file groups...")
for g_idx, members in enumerate(sorted_groups[:30]):
    print(f"\n--- Group {g_idx+1}: {len(members)} files ---")
    
    # Get unified tag set
    all_tags = set()
    for m in members:
        all_tags.update(valid_files.get(m, []))
    sorted_tags = sorted(all_tags, key=lambda t: int(t,16))
    tag_chars = ''.join(chr(int(t,16)) if 32 <= int(t,16) < 127 else '.' for t in sorted_tags)
    print(f"  Tags ({len(sorted_tags)}): {tag_chars[:80]}")
    
    # Parse first few files
    analyzed = 0
    tag_aggregate = defaultdict(lambda: {
        'u16_vals': set(), 'v1_vals': set(), 'v2_vals': set(),
        'per_entry_counts': [], 'entry_count': 0, 'files_seen': 0,
        'entries_with_field': 0,
    })
    
    for fname in members[:10]:  # analyze up to 10 files per group
        fpath = os.path.join(dec_dir, fname)
        body = parse_file_body(fpath)
        if body is None:
            continue
        entries, records = extract_entry_fields(body)
        
        if not entries:
            continue
        
        analyzed += 1
        n_entries = len(entries)
        
        # Count per-entry tag occurrences
        tag_in_entries = defaultdict(int)
        for entry in entries:
            seen_in_entry = set()
            for r in entry:
                key = f'0x{r["tag"]:02x}'
                tag_aggregate[key]['u16_vals'].add(r['u16'])
                tag_aggregate[key]['v1_vals'].add(r['v1'])
                tag_aggregate[key]['v2_vals'].add(r['v2'])
                tag_aggregate[key]['entries_with_field'] += 1
                seen_in_entry.add(key)
            for k in seen_in_entry:
                tag_in_entries[k] += 1
        
        for key in tag_aggregate:
            tag_aggregate[key]['per_entry_counts'].append(tag_in_entries.get(key, 0))
            tag_aggregate[key]['entry_count'] += n_entries
            tag_aggregate[key]['files_seen'] += 1
    
    if analyzed == 0:
        print("  (no parseable files)")
        continue
    
    print(f"  Analyzed {analyzed}/{len(members)} files")
    
    # For each tag, classify
    tag_classifications = {}
    for tag_key in sorted_tags:
        td = tag_aggregate[tag_key]
        if td['files_seen'] == 0 or td['entry_count'] == 0:
            continue
        
        # Only take tags that appear in the majority of entries
        per_entry_ratio = td['entries_with_field'] / max(td['entry_count'], 1)
        per_file_ratio = td['files_seen'] / analyzed
        
        avg_per_entry = sum(td['per_entry_counts']) / max(len(td['per_entry_counts']), 1)
        appears_once_per_entry = per_entry_ratio < 1.1 and avg_per_entry <= 1.1 and avg_per_entry >= 0.8
        
        field_data = {
            'u16_vals': td['u16_vals'],
            'v1_vals': td['v1_vals'],
            'v2_vals': td['v2_vals'],
            'entry_count': td['entry_count'],
            'value_count': len(td['u16_vals']),
            'per_entry': appears_once_per_entry,
            'per_file_ratio': per_file_ratio,
        }
        
        clues, candidates = classify_field(tag_key, field_data)
        tag_classifications[tag_key] = {
            'char': chr(int(tag_key,16)) if 32 <= int(tag_key,16) < 127 else '.',
            'v1_vals': len(td['v1_vals']),
            'v2_vals': len(td['v2_vals']),
            'u16_vals': len(td['u16_vals']),
            'u16_min': min(td['u16_vals']) if td['u16_vals'] else 0,
            'u16_max': max(td['u16_vals']) if td['u16_vals'] else 0,
            'per_entry_ratio': round(per_entry_ratio, 2),
            'once_per_entry': appears_once_per_entry,
            'clues': clues,
            'candidates': candidates,
        }
    
    # Print field classifications
    for tag_key in sorted_tags:
        tc = tag_classifications.get(tag_key)
        if not tc:
            continue
        best = tc['candidates'][:2] if tc['candidates'] else [("unknown", 0.0)]
        clue_str = ', '.join(f"{c[0]}({c[1]:.0%})" for c in tc['clues'][:3])
        cand_str = '|'.join(f"{c[0]}:{c[1]:.0%}" for c in best)
        
        print(f"    {tag_key}({tc['char']}): "
              f"u16=[{tc['u16_min']}..{tc['u16_max']}]({tc['u16_vals']}vals) "
              f"v1={tc['v1_vals']}v2={tc['v2_vals']} "
              f"once={tc['once_per_entry']} "
              f"-> {cand_str}")
    
    # Print summary tag characteristics
    id_tags = [k for k, v in tag_classifications.items() 
               if any(c[0] == 'primary_id' for c in v['candidates'])]
    enum_tags = [k for k, v in tag_classifications.items() 
                 if any(c[0] == 'enumeration' for c in v['candidates'])]
    flag_tags = [k for k, v in tag_classifications.items() 
                 if any(c[0] == 'flag' for c in v['candidates'])]
    
    if id_tags:
        id_chars = ', '.join(f"{t}({chr(int(t,16))})" for t in id_tags if 32<=int(t,16)<127)
        print(f"  → ID candidates: {id_chars}")
    if enum_tags:
        enum_chars = ', '.join(f"{t}({chr(int(t,16))})" for t in enum_tags if 32<=int(t,16)<127)
        print(f"  → Enum candidates: {enum_chars}")

# ─── Phase 3: Output clustered data for Phase 4 ───
print("\n\n=== Phase 3: Saving Cluster Data ===")
cluster_output = []
for g_idx, members in enumerate(sorted_groups[:100]):
    all_tags = set()
    for m in members:
        all_tags.update(valid_files.get(m, []))
    cluster_output.append({
        'group_id': g_idx,
        'size': len(members),
        'num_tags': len(all_tags),
        'tags': sorted(all_tags),
        'members': members[:50],
        'sample_entry_counts': [],
    })

with open(os.path.join(out_dir, 'merged_clusters.json'), 'w') as f:
    json.dump(cluster_output, f, indent=1)
print(f"Saved {len(cluster_output)} merged clusters to merged_clusters.json")

# Save tag classification database
print("\nBuilding tag classification database...")
# Aggregate tag classifications across all groups
semantic_db = {}
for g_idx, members in enumerate(sorted_groups[:50]):
    all_tags = set()
    for m in members:
        all_tags.update(valid_files.get(m, []))
    
    for tag_key in sorted(all_tags):
        if tag_key not in semantic_db:
            semantic_db[tag_key] = {
                'char': chr(int(tag_key,16)) if 32 <= int(tag_key,16) < 127 else '.',
                'groups_observed': 0,
                'classifications': [],
            }
        semantic_db[tag_key]['groups_observed'] += 1

tag_db_output = []
for tag_key, tdata in sorted(semantic_db.items()):
    tag_db_output.append({
        'tag': tag_key,
        'char': tdata['char'],
        'groups_observed': tdata['groups_observed'],
    })

with open(os.path.join(out_dir, 'tag_semantics.json'), 'w') as f:
    json.dump(tag_db_output, f, indent=1)
print(f"Saved {len(tag_db_output)} tag entries to tag_semantics.json")

print(f"\nDone. Output in {out_dir}/")
