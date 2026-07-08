"""
Deep analysis: Find entity DBs among 20-60 tag files.
Entity DBs = homogeneous entries with shared tag-signature.
"""
import os, sys, json
from collections import Counter
sys.path.insert(0, r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode')
from roo_parser_final import RooBinaryFormat

BATCH_DIR = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\dec_batch'
ANALYSIS_DIR = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\analysis'

with open(os.path.join(ANALYSIS_DIR, 'corpus_summary.json')) as f:
    corpus = json.load(f)

# Phase 1: Find files with 20-60 tags, sorted by entry count
candidates = []
for fi in corpus:
    t = fi.get('num_unique_tags', 0)
    e = fi.get('entries', 0)
    fname = fi['file'].replace('.mt.dec', '')
    fpath = os.path.join(BATCH_DIR, fname + '.mt.dec')
    if not os.path.exists(fpath):
        continue
    if 20 <= t <= 60 and e >= 10:
        candidates.append((e, t, fname, fpath))
    # Also check 5-19 tag files
    if 5 <= t <= 19 and e >= 10:
        candidates.append((e, t, fname, fpath))

candidates.sort(key=lambda x: -x[0])

print(f"Total mid-size files to scan: {len(candidates)}")
print(f"Scanning top 40...\n")

results = []
for entries, tags, fname, fpath in candidates[:40]:
    with open(fpath, 'rb') as f:
        data = f.read()
    
    parser = RooBinaryFormat(data)
    parser.cluster_entries(gap_threshold=30)
    
    total = len(parser.entries)
    if total < 5:
        continue
    
    sig_counts = Counter()
    for entry in parser.entries:
        sig = tuple(sorted(set(f'0x{rec[1]:02x}' for rec in entry)))
        sig_counts[sig] += 1
    
    unique_sigs = len(sig_counts)
    if unique_sigs == 0:
        continue
    
    top_sig, top_cnt = sig_counts.most_common(1)[0]
    top_pct = 100 * top_cnt / total
    homogeneity = top_pct
    
    # Check for hero-ID fields
    hero_fields = set()
    for entry in parser.entries:
        for _, tag, v1, v2 in entry:
            u16 = v1 | (v2 << 8)
            if 2000 <= u16 <= 9999:
                hero_fields.add(tag)
    
    results.append({
        'fname': fname,
        'entries': total,
        'tags': tags,
        'unique_sigs': unique_sigs,
        'homogeneity': round(homogeneity, 1),
        'top_sig_len': len(top_sig),
        'top_sig': list(top_sig),
        'hero_field_count': len(hero_fields),
        'override_count': len(parser.override_records),
        'template_count': len(parser.template_records),
    })

# Sort by homogeneity (desc)
results.sort(key=lambda x: -x['homogeneity'])

print(f"{'HASH':>32s} {'ENTRIES':>6s} {'TAGS':>4s} {'SIGS':>5s} {'HOMOG':>6s} {'SIGLEN':>6s} {'HERO':>4s} {'OVERRIDE':>8s}")
print('-'*80)
for r in results:
    short = r['fname'][:32]
    print(f"{short:>32s} {r['entries']:>6d} {r['tags']:>4d} {r['unique_sigs']:>5d} {r['homogeneity']:>5.1f}% {r['top_sig_len']:>6d} {r['hero_field_count']:>4d} {r['override_count']:>8d}")

# Show top 5 in detail
print(f"\n\n{'='*70}")
print("TOP 5 HOMOGENEOUS FILES:")
print("(These are likely entity-specific databases)")
print(f"{'='*70}")

for r in results[:5]:
    print(f"\nFILE: {r['fname']}")
    print(f"  Entries: {r['entries']}, Tags: {r['tags']}, [{r['homogeneity']}% homogeneous]")
    print(f"  Top signature ({r['top_sig_len']} fields): {r['top_sig']}")
    print(f"  Hero-ID fields: {r['hero_field_count']}")
    
    fpath = os.path.join(BATCH_DIR, r['fname'] + '.mt.dec')
    with open(fpath, 'rb') as f:
        data = f.read()
    parser = RooBinaryFormat(data)
    parser.cluster_entries(gap_threshold=30)
    
    top_sig_set = set(int(s, 16) for s in r['top_sig'])
    
    # Collect values for the homogeneous group
    tag_vals = {}
    for entry in parser.entries:
        entry_tags = set(rec[1] for rec in entry)
        if entry_tags == top_sig_set:
            for _, tag, v1, v2 in entry:
                u16 = v1 | (v2 << 8)
                if tag not in tag_vals:
                    tag_vals[tag] = []
                tag_vals[tag].append(u16)
    
    print(f"  Field values (homogeneous group):")
    for tag in sorted(tag_vals.keys()):
        vals = tag_vals[tag]
        uniq = len(set(vals))
        mn, mx = min(vals), max(vals)
        ch = chr(tag) if 32 <= tag < 127 else '.'
        
        # ID range detection
        id_hint = ""
        if any(2000 <= v <= 9999 for v in vals):
            id_hint = " [HERO-ID range]"
        elif any(1301 <= v <= 73380 for v in vals):
            id_hint = " [SKILL-ID range]"
        elif any(60000 <= v <= 180000 for v in vals):
            id_hint = " [ITEM-ID range]"
        if max(vals) <= 5:
            id_hint += " [0-5 enum]"
        elif max(vals) <= 10:
            id_hint += " [0-10 enum]"
        elif max(vals) <= 20:
            id_hint += " [0-20 enum]"
        
        print(f"    0x{tag:02x}('{ch}'): uniq={uniq}/{len(vals)}, range={mn}-{mx}{id_hint}")
        if uniq <= 20:
            print(f"      values: {sorted(set(vals))}")
