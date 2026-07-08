"""Deep analysis of multi-tag entry structures in the hero roster file."""
import os, json
from collections import defaultdict

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\decrypted\dec_batch'
TARGET = '07b5cc5ea4a8d86273be8170720a4587.mt.dec'

def parse_entries(path):
    with open(path, 'rb') as f:
        data = f.read()
    body = data[HDR_SIZE:]
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        if tag != 0:
            val = v1 | (v2 << 8)
            records.append({'offset': i, 'tag': tag, 'val': val})
    entries = []
    if records:
        gap = 30
        cur = [records[0]]
        for r in records[1:]:
            if r['offset'] - cur[-1]['offset'] > gap:
                entries.append(cur)
                cur = [r]
            else:
                cur.append(r)
        if cur:
            entries.append(cur)
    return entries

entries = parse_entries(os.path.join(DEC_BATCH, TARGET))

# Focus on multi-tag signatures with 5+ tags (complex entity definitions)
sig_groups = defaultdict(list)
for eidx, entry in enumerate(entries):
    sig = tuple(sorted(set(r['tag'] for r in entry)))
    sig_groups[sig].append(eidx)

print("=== MULTI-TAG SIGNATURES (5+ tags) ===")
multi = [(sig, eidxs) for sig, eidxs in sig_groups.items() if len(sig) >= 5]
multi.sort(key=lambda x: -(len(x[1]) * len(x[0])))  # sort by total fields impact

for sig, eidxs in multi[:20]:
    tag_list = sorted(sig)
    total_fields = len(eidxs) * len(tag_list)
    tag_hex = ' '.join(f"0x{t:02x}" for t in tag_list)
    print(f"\n  [{len(eidxs):3d} entries] ({len(tag_list):2d} tags) {tag_hex}")
    
    # Show value analysis for each position
    max_show = min(len(eidxs), 20)
    sample_ents = [entries[e] for e in eidxs[:max_show]]
    
    pos_data = defaultdict(list)
    for ent in sample_ents:
        for pi, r in enumerate(ent):
            pos_data[pi].append(r['val'])
    
    for pi in sorted(pos_data.keys())[:6]:  # Show first 6 fields
        vals = pos_data[pi]
        uv = len(set(vals))
        tag = sample_ents[0][pi]['tag'] if pi < len(sample_ents[0]) else 0
        tc = chr(tag) if 32 <= tag < 127 else '.'
        mn, mx = min(vals), max(vals)
        unique_vals = sorted(set(vals))[:10]
        
        note = ''
        class_vals = [v for v in set(vals) if 1 <= v <= 5]
        star_vals = [v for v in set(vals) if 1 <= v <= 8]
        id_vals = [v for v in set(vals) if 1000 <= v <= 9999]
        zero_count = sum(1 for v in vals if v == 0)
        
        if len(class_vals) >= 4 and mx <= 5:
            note = f' [CLASS:{class_vals}]'
        elif len(star_vals) >= 5 and mx <= 8:
            note = f' [STAR:{star_vals}]'
        elif len(id_vals) >= 3:
            note = f' [IDS:{id_vals[:6]}]'
        elif zero_count / len(vals) > 0.8:
            note = ' [MOSTLY_ZERO]'
        elif uv >= 10:
            note = f' [REF:{unique_vals[:5]}]'
        
        print(f"    pos={pi:2d} tag=0x{tag:02x}('{tc}'): {uv:3d} unique [{mn:5d},{mx:5d}]{note}")

# Now specifically look at tag 0x09 usage (which carried HeroID 2111)
print("\n\n=== TAG 0x09 ANALYSIS ===")
tag09_entries = []
for eidx, entry in enumerate(entries):
    for r in entry:
        if r['tag'] == 0x09:
            tag09_entries.append((eidx, entry))
            break

print(f"Entries with tag 0x09: {len(tag09_entries)}")
tag09_vals = defaultdict(list)
for eidx, entry in tag09_entries:
    for pi, r in enumerate(entry):
        if r['tag'] == 0x09:
            tag09_vals[len(entry)].append((eidx, pi, r['val']))

for num_fields, hits in sorted(tag09_vals.items()):
    vals = [h[2] for h in hits]
    uv = len(set(vals))
    id_vals = [v for v in set(vals) if 1000 <= v <= 9999]
    print(f"  {len(hits):4d} entries with {num_fields:2d} fields: {uv} unique values, ID-range: {id_vals[:10]}")
