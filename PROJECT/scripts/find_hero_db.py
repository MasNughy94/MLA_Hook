"""
Find the actual Hero DB by looking for files where entries have homogeneous structure
AND contain hero-ID values (2000-9999 range) in a repeatable field position.
"""
import os, sys, json
from collections import Counter, defaultdict
sys.path.insert(0, r'C:\Users\NGEONG\AppData\Local\Temp\opencode')
from roo_parser_final import RooBinaryFormat

BATCH_DIR = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\dec_batch'
ANALYSIS_DIR = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\analysis'

with open(os.path.join(ANALYSIS_DIR, 'corpus_summary.json')) as f:
    corpus = json.load(f)

# Heuristic 1: Find files where a SPECIFIC TAG always carries 2000-9999 values
# This would mean that tag is a HeroID field
print("Phase 1: Scanning for files with Hero-ID fields...\n")

candidates = []
for fi in corpus:
    e = fi.get('entries', 0)
    t = fi.get('num_unique_tags', 0)
    if e < 50 or e > 100000:
        continue
    if t < 10:
        continue
    if 'tag_list' not in fi:
        continue
    candidates.append((e, t, fi['file'].replace('.mt.dec', '')))

# Sort by entry count, take top 20
candidates.sort(key=lambda x: -x[0])
print(f"Total candidates: {len(candidates)}")
print(f"Scanning top 30...")

results = []
for entries, tags, fname in candidates[:30]:
    fpath = os.path.join(BATCH_DIR, fname + '.mt.dec')
    if not os.path.exists(fpath):
        continue
    
    with open(fpath, 'rb') as f:
        data = f.read()
    
    parser = RooBinaryFormat(data, fname + '.mt.dec')
    parser.cluster_entries(gap_threshold=30)
    
    total = len(parser.entries)
    if total < 10:
        continue
    
    # Extract all override records (tag, u16)
    records = []
    for ei, entry in enumerate(parser.entries):
        for offset, tag, v1, v2 in entry:
            u16 = v1 | (v2 << 8)
            records.append((ei, tag, u16))
    
    # For each tag, check if values are in hero-ID range
    tag_hero_ids = defaultdict(list)
    hero_id_entries = set()
    
    for ei, tag, u16 in records:
        if 2000 <= u16 <= 9999:
            tag_hero_ids[tag].append(u16)
            hero_id_entries.add(ei)
    
    if not tag_hero_ids:
        continue
    
    # Find the best hero-ID tag
    best_tag = max(tag_hero_ids.keys(), key=lambda t: len(set(tag_hero_ids[t])))
    hero_vals = tag_hero_ids[best_tag]
    unique_heroes = len(set(hero_vals))
    
    # Count how many entries share the same tag-signature as hero-ID entries
    hero_entry_sigs = Counter()
    for ei in hero_id_entries:
        if ei < len(parser.entries):
            tags_in_entry = tuple(sorted(set(rec[1] for rec in parser.entries[ei])))
            hero_entry_sigs[tags_in_entry] += 1
    
    homogeneity = 0
    top_sig = None
    if hero_entry_sigs:
        top_sig, top_cnt = hero_entry_sigs.most_common(1)[0]
        homogeneity = 100 * top_cnt / len(hero_id_entries) if hero_id_entries else 0
    
    # Check if the hero-ID tag is consistently present and unique
    hero_id_tag_usage = sum(1 for ei, tag, u16 in records if tag == best_tag)
    
    results.append({
        'fname': fname,
        'entries': total,
        'tags': tags,
        'hero_id_tag': f'0x{best_tag:02x}',
        'unique_hero_ids': unique_heroes,
        'hero_id_occurrences': len(hero_vals),
        'entries_with_hero': len(hero_id_entries),
        'entries_with_hero_pct': round(100*len(hero_id_entries)/total, 1),
        'homogeneity_pct': round(homogeneity, 1),
        'top_sig_tags': len(top_sig) if top_sig else 0,
    })

# Sort by homogeneity * entries_with_hero (best hero DB candidates)
results.sort(key=lambda x: -x['homogeneity_pct'] * x['entries_with_hero'])

print(f"\n{'HASH':>32s} {'ENTRIES':>6s} {'TAGS':>4s} {'HERO_TAG':>8s} {'UNIQ_ID':>7s} {'E_W_HERO':>8s} {'%HERO':>6s} {'HOMOG%':>7s} {'SIGLEN':>6s}")
print('-'*90)
for r in results[:20]:
    print(f"{r['fname'][:32]:>32s} {r['entries']:>6d} {r['tags']:>4d} {r['hero_id_tag']:>8s} {r['unique_hero_ids']:>7d} {r['entries_with_hero']:>8d} {r['entries_with_hero_pct']:>5.1f}% {r['homogeneity_pct']:>6.1f}% {r['top_sig_tags']:>6d}")

# Phase 2: Deep analysis of best candidate
print(f"\n{'='*70}")
if results:
    best = results[0]
    print(f"BEST CANDIDATE: {best['fname']}")
    print(f"  Entries: {best['entries']}, Tags: {best['tags']}")
    print(f"  Hero-ID Tag: {best['hero_id_tag']} ({best['unique_hero_ids']} unique IDs)")
    print(f"  Entries with hero IDs: {best['entries_with_hero']}/{best['entries']} ({best['entries_with_hero_pct']}%)")
    print(f"  Homogeneity of hero entries: {best['homogeneity_pct']}%")
    
    fpath = os.path.join(BATCH_DIR, best['fname'] + '.mt.dec')
    with open(fpath, 'rb') as f:
        data = f.read()
    parser = RooBinaryFormat(data, best['fname'] + '.mt.dec')
    parser.cluster_entries(gap_threshold=30)
    
    best_tag = int(best['hero_id_tag'], 16)
    
    # Collect ALL entries that have this hero-ID tag
    hero_entries_info = []
    for ei, entry in enumerate(parser.entries):
        for offset, tag, v1, v2 in entry:
            if tag == best_tag:
                u16 = v1 | (v2 << 8)
                if 2000 <= u16 <= 9999:
                    hero_entries_info.append((ei, u16, entry))
                    break
    
    print(f"\n  Analyzing {len(hero_entries_info)} hero entries...")
    
    # What other fields appear with hero ID?
    co_tags = Counter()
    sig_counter = Counter()
    for ei, hero_id, entry in hero_entries_info:
        tags_in_entry = tuple(sorted(set(rec[1] for rec in entry)))
        sig_counter[tags_in_entry] += 1
        for rec in entry:
            if rec[1] != best_tag:
                co_tags[rec[1]] += 1
    
    print(f"\n  Fields that co-occur with HeroID:")
    for tag, cnt in co_tags.most_common(30):
        if cnt < 2:
            break
        ch = chr(tag) if 32 <= tag < 127 else '.'
        print(f"    0x{tag:02x}('{ch}'): present in {cnt}/{len(hero_entries_info)} hero entries ({100*cnt/len(hero_entries_info):.0f}%)")
    
    print(f"\n  Hero entry signatures ({len(sig_counter)} unique):")
    for sig, cnt in sig_counter.most_common(15):
        sig_hex = [f'0x{t:02x}' for t in sig]
        print(f"    {cnt:>4d} entries: {sig_hex}")
    
    # Show values for the most common hero-entry signature
    if sig_counter:
        top_sig = sig_counter.most_common(1)[0][0]
        print(f"\n  Values for top signature ({len(top_sig)} fields, {sig_counter.most_common(1)[0][1]} entries):")
        tag_positions = {tag: i for i, tag in enumerate(sorted(top_sig))}
        entry_values = defaultdict(list)
        for ei, hero_id, entry in hero_entries_info:
            tags_in_entry = tuple(sorted(set(rec[1] for rec in entry)))
            if tags_in_entry == top_sig:
                for rec in entry:
                    tag, v1, v2 = rec[1], rec[2], rec[3]
                    u16 = v1 | (v2 << 8)
                    entry_values[tag].append(u16)
        
        for tag in sorted(entry_values.keys()):
            vals = entry_values[tag]
            uniq = len(set(vals))
            mn, mx = min(vals), max(vals)
            ch = chr(tag) if 32 <= tag < 127 else '.'
            id_hint = ""
            if tag == best_tag:
                id_hint = " [HERO PRIMARY KEY]"
            elif any(2000 <= v <= 9999 for v in vals):
                id_hint = " [hero-IDs]"
            elif any(1301 <= v <= 73380 for v in vals):
                id_hint = " [skill-IDs]"
            elif any(60000 <= v <= 180000 for v in vals):
                id_hint = " [item-IDs]"
            if max(vals) <= 10:
                id_hint = " [enum 1-10]"
            elif max(vals) <= 20:
                id_hint = " [enum 1-20]"
            
            print(f"    0x{tag:02x}('{ch}'): uniq={uniq}/{len(vals)}, range={mn}-{mx}{id_hint}")
            if uniq <= 10:
                print(f"      values: {sorted(set(vals))}")
            elif uniq <= 30:
                print(f"      samples (first 20): {sorted(set(vals))[:20]}")
