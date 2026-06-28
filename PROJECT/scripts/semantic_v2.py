#!/usr/bin/env python3
"""
Semantic Reconstruction Engine v2
==================================
Two-stage clustering:
  Stage 1: Tag-set Jaccard similarity (already done — 2861 groups)
  Stage 2: For 255-tag supergroups, sub-cluster by active-field profile

Then: deep value-pattern analysis per cluster, field classification.
"""
import os, sys, json, struct, time
from collections import defaultdict, Counter

HDR_SIZE = 69
dec_dir = os.path.join(os.path.dirname(__file__), 'dec_batch')
analysis_dir = os.path.join(os.path.dirname(__file__), 'analysis')
out_dir = os.path.join(os.path.dirname(__file__), 'semantic')
os.makedirs(out_dir, exist_ok=True)

# ─── Load data ───
print("Loading corpus summary...")
with open(os.path.join(analysis_dir, 'corpus_summary.json')) as f:
    corpus = json.load(f)
file_index = {e['file']: e for e in corpus}

# ─── Stage 1: Tag-set Jaccard clustering ───
print("Building tag-set clusters...")
valid = {f['file']: frozenset(f.get('tag_list', [])) for f in corpus 
         if f.get('valid') and f.get('tag_list')}

# Build bitsets
file_bs = {}
for fname, tags in valid.items():
    bs = 0
    for t in tags:
        tv = int(t, 16)
        if 1 <= tv <= 255:
            bs |= (1 << tv)
    file_bs[fname] = bs

def jaccard(b1, b2):
    i = (b1 & b2).bit_count()
    u = (b1 | b2).bit_count()
    return i / u if u else 0

# Group by tag count first
by_count = defaultdict(list)
for fname, tags in valid.items():
    by_count[len(tags)].append(fname)

processed = set()
groups = []
t0 = time.time()

# Sort files: process those with few tags first (more specific types)
sorted_global = sorted(valid.keys(), key=lambda f: len(valid[f]))

for fname in sorted_global:
    if fname in processed:
        continue
    bs1 = file_bs[fname]
    t1 = valid[fname]
    n1 = len(t1)
    
    # Candidates: similar count +/- some range or tag-sharing
    cand = set()
    for n2 in range(max(1, n1-15), min(n1+15, 256)):
        cand.update(by_count.get(n2, []))
    cand.discard(fname)
    cand -= processed
    
    if len(cand) > 5000:
        cand = set()
        for t in list(t1)[:3]:
            cand.update(by_count.get(int(t,16), []))
        cand.discard(fname)
        cand -= processed
    
    members = {fname}
    for cf in cand:
        j = jaccard(bs1, file_bs[cf])
        c12 = (bs1 & file_bs[cf]).bit_count() / max(n1, 1)
        c21 = (bs1 & file_bs[cf]).bit_count() / max(len(valid[cf]), 1)
        if j > 0.5 or c12 > 0.8 or c21 > 0.8:
            members.add(cf)
    
    for m in members:
        processed.add(m)
    groups.append(sorted(members, key=lambda f: -len(valid[f])))

print(f"Stage 1: {len(groups)} groups from {len(processed)} files in {time.time()-t0:.0f}s")

# ─── Stage 2: Sub-cluster 255-tag supergroups ───
print("\nStage 2: Sub-clustering 255-tag supergroups...")
sub_clusters = []
for members in groups:
    # Check if ALL files in the group have 255 tags
    has_255 = sum(1 for m in members if len(valid[m]) >= 254)
    if has_255 < 2:
        sub_clusters.append(members)
        continue
    
    # Sub-cluster by entry count and override density
    # Use (entries, num_override) as fingerprint
    fingerprint_groups = defaultdict(list)
    for m in members:
        fi = file_index.get(m, {})
        entries = fi.get('entries', 0)
        overrides = fi.get('num_override', 0)
        # Round to nearest range for grouping
        e_bucket = entries // 10 * 10 if entries >= 10 else entries
        o_bucket = overrides // 50 * 50 if overrides >= 50 else overrides
        fp = (e_bucket, o_bucket)
        fingerprint_groups[fp].append(m)
    
    for fp_members in fingerprint_groups.values():
        if fp_members:
            sub_clusters.append(fp_members)

print(f"Stage 2: {len(sub_clusters)} final groups")

# Sort by size
sub_clusters.sort(key=lambda g: -len(g))

# Report
print(f"\nTop 40 final groups:")
for i, members in enumerate(sub_clusters[:40]):
    all_tags = set()
    for m in members:
        all_tags.update(valid.get(m, []))
    st = sorted(all_tags)
    chars = ''.join(chr(int(t,16)) if 32<=int(t,16)<127 else '.' for t in st)
    e = file_index.get(members[0], {})
    print(f"  [{i+1:2d}] {len(members):3d} files, {len(st):3d} tags, "
          f"~{e.get('entries',0):4d} entries, ~{e.get('num_override',0):4d} overrides: {chars[:50]}")

# ─── Phase 2: Deep Field Analysis ───
print("\n\n=== Phase 2: Deep Field Analysis ===")

def parse_body(fpath):
    with open(fpath, 'rb') as f:
        data = f.read()
    if len(data) < HDR_SIZE:
        return None, None
    body = data[HDR_SIZE:]
    trailing = len(body) % 3
    if trailing:
        body = body[:-trailing]
    
    records = []
    for i in range(0, len(body), 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        if tag != 0:
            records.append({'off': i, 'idx': i//3, 't': tag, 'v1': v1, 'v2': v2, 'u16': v1|(v2<<8)})
    
    # Cluster entries
    sr = sorted(records, key=lambda r: r['off'])
    entries = []
    cur = []
    for r in sr:
        if cur and r['off'] - cur[-1]['off'] > 30:
            entries.append(cur)
            cur = [r]
        else:
            cur.append(r)
    if cur:
        entries.append(cur)
    return entries, records

def analyze_field(vals_by_entry, n_entries):
    """
    vals_by_entry: list of (u16, v1, v2) for a tag across entries
    Returns semantic clues.
    """
    u16s = set(v[0] for v in vals_by_entry)
    v1s = set(v[1] for v in vals_by_entry)
    v2s = set(v[2] for v in vals_by_entry)
    n = len(vals_by_entry)
    
    clues = {}
    
    # Once per entry ⇒ potential ID or required field
    if n == n_entries:
        clues['per_entry'] = 'always'
        clues['id_likelihood'] = 0.0
        sv = sorted(u16s)
        if sv and len(sv) == n_entries:
            if max(sv) - min(sv) < n_entries * 2:
                clues['sequential'] = True
                clues['id_likelihood'] = 0.85
            elif len(sv) > n_entries * 0.5:
                clues['id_likelihood'] = 0.65
    elif n > 0:
        clues['per_entry'] = f'{n}/{n_entries}'
    
    # Value range analysis
    clues['u16_count'] = len(u16s)
    clues['v1_count'] = len(v1s)
    clues['v2_count'] = len(v2s)
    if u16s:
        clues['u16_min'] = min(u16s)
        clues['u16_max'] = max(u16s)
    
    # Flag detection
    if u16s <= {0, 1}:
        clues['type'] = 'flag'
        clues['confidence'] = 0.9
    elif u16s <= {0, 1} | set(range(2, 256)) and len(u16s) <= 8:
        clues['type'] = 'small_enum'
        clues['confidence'] = 0.75
    elif len(u16s) <= 16 and n > len(u16s) * 3:
        clues['type'] = 'enum'
        clues['confidence'] = 0.7
    elif all(1 <= v <= 200 for v in u16s) and len(u16s) == n_entries:
        clues['type'] = 'id_range_1_200'
        clues['confidence'] = 0.6
    elif all(0 <= v <= 100 for v in u16s) and len(u16s) > 5:
        clues['type'] = 'level_or_pct'
        clues['confidence'] = 0.4
    elif len(v1s) == 1 and len(v2s) > 5:
        clues['type'] = 'categorized_u8'
        clues['confidence'] = 0.55
    elif len(v2s) == 1 and len(v1s) > 5:
        clues['type'] = 'plain_u8'
        clues['confidence'] = 0.4
    else:
        clues['type'] = 'generic_u16'
        clues['confidence'] = 0.15
    
    return clues

# Analyze top groups
print("Analyzing top groups...")
semantic_db = {}  # tag_key -> {meanings}

for g_idx, members in enumerate(sub_clusters[:40]):
    print(f"\n--- Group {g_idx+1}: {len(members)} files ---")
    
    all_tags = set()
    for m in members:
        all_tags.update(valid.get(m, []))
    st = sorted(all_tags, key=lambda t: int(t,16))
    chars = ''.join(chr(int(t,16)) if 32<=int(t,16)<127 else '.' for t in st)
    print(f"  Tags ({len(st)}): {chars[:80]}")
    
    # Parse files
    tag_data = defaultdict(list)  # tag -> [(u16, v1, v2) per entry]
    n_entries_total = 0
    parsed_ok = 0
    
    for m in members[:10]:
        fp = os.path.join(dec_dir, m)
        entries, records = parse_body(fp)
        if entries is None or not entries:
            continue
        parsed_ok += 1
        n_entries_total += len(entries)
        
        # Collect per-tag values across entries
        for entry in entries:
            seen = set()
            for r in entry:
                key = f'0x{r["t"]:02x}'
                tag_data[key].append((r['u16'], r['v1'], r['v2']))
                seen.add(key)
    
    avg_entries = n_entries_total // max(parsed_ok, 1)
    if parsed_ok == 0:
        continue
    print(f"  Parsed {parsed_ok} files, avg {avg_entries} entries")
    
    # Classify each tag
    for tag_key in st:
        vals = tag_data.get(tag_key, [])
        if not vals:
            continue
        clues = analyze_field(vals, avg_entries)
        ch = chr(int(tag_key,16)) if 32<=int(tag_key,16)<127 else '.'
        
        # Print interesting ones
        if clues.get('id_likelihood', 0) > 0.6 or clues.get('confidence', 0) > 0.6:
            print(f"    {tag_key}('{ch}'): {clues.get('type','?')} "
                  f"u16=[{clues.get('u16_min','?')}..{clues.get('u16_max','?')}] "
                  f"n={clues['u16_count']} once={clues.get('per_entry')} "
                  f"conf={clues.get('confidence',clues.get('id_likelihood',0)):.0%}")
        
        # Build cross-file semantic DB
        if tag_key not in semantic_db:
            semantic_db[tag_key] = {
                'char': ch,
                'groups_seen': 0,
                'total_observations': 0,
                'proposed_meanings': defaultdict(float),
            }
        sd = semantic_db[tag_key]
        sd['groups_seen'] += 1
        sd['total_observations'] += len(vals)
        
        # Accumulate meaning proposals
        typ = clues.get('type')
        conf = clues.get('confidence', clues.get('id_likelihood', 0))
        if typ and conf:
            sd['proposed_meanings'][typ] = max(sd['proposed_meanings'].get(typ, 0), conf)

# ─── Output semantic database ───
print("\n\n=== Semantic Database ===")
print("\nAggregated field meanings (tags observed in 2+ groups, confidence > 40%):")
db_out = []
for tag_key in sorted(semantic_db.keys(), key=lambda t: int(t,16)):
    sd = semantic_db[tag_key]
    if sd['groups_seen'] < 2:
        continue
    best_meanings = sorted(sd['proposed_meanings'].items(), key=lambda x: -x[1])[:3]
    best_fmt = ' | '.join(f'{m}({c:.0%})' for m, c in best_meanings)
    if best_meanings and best_meanings[0][1] >= 0.4:
        print(f"  {tag_key}('{sd['char']}'): seen={sd['groups_seen']} obs={sd['total_observations']} -> {best_fmt}")
        db_out.append({
            'tag': tag_key,
            'char': sd['char'],
            'groups_seen': sd['groups_seen'],
            'observations': sd['total_observations'],
            'meanings': [{'type': m, 'confidence': c} for m, c in best_meanings],
        })

with open(os.path.join(out_dir, 'semantic_db.json'), 'w') as f:
    json.dump(db_out, f, indent=1)
print(f"\nSaved {len(db_out)} semantic entries to semantic_db.json")
