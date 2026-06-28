"""
Deep value analysis: search for known game entity IDs in cluster field values.
Cross-references parsed records against known Hero IDs, Skill IDs, Item IDs, etc.
"""
import os, sys, json, struct
from collections import defaultdict

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\dec_batch'
OUTPUT = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\value_analysis.json'

# Known game IDs from APK exploration
HERO_IDS = {2111, 2112, 2113, 5970} | set(range(16110110, 16119999, 10))
SKILL_IDS = set(range(1301, 1305)) | set(range(1601, 1605)) | set(range(1801, 1805)) | \
            set(range(53201, 53206)) | {61861} | set(range(73301, 73381))
ITEM_IDS = {61200, 61383, 61492, 61514, 178274}
STORY_CHARACTER_IDS = set()  # To be filled from spine data

# Read cluster report for target files
with open(r'C:\Users\NGEONG\AppData\Local\Temp\opencode\analysis\cluster_report.json') as f:
    clusters = json.load(f)

# Read corpus for entry counts
with open(r'C:\Users\NGEONG\AppData\Local\Temp\opencode\analysis\corpus_summary.json') as f:
    corpus = {e['file']: e for e in json.load(f)}

def parse_file(path):
    with open(path, 'rb') as f:
        data = f.read()
    body = data[HDR_SIZE:]
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        if tag != 0:
            val = v1 | (v2 << 8)
            records.append({'offset': i, 'tag': tag, 'v1': v1, 'v2': v2, 'val': val})
    # Cluster by gap
    gap = 30
    entries = []
    if records:
        cur = [records[0]]
        for r in records[1:]:
            if r['offset'] - cur[-1]['offset'] > gap:
                entries.append(cur)
                cur = [r]
            else:
                cur.append(r)
        if cur:
            entries.append(cur)
    return records, entries

def get_field_values(entries):
    """Build position -> [values] across all entries."""
    pv = defaultdict(list)
    for entry in entries:
        for idx, r in enumerate(entry):
            pv[idx].append(r['val'])
    return dict(pv)

# Analyze clusters of interest
results = {}
cluster_groups = defaultdict(list)
for c in clusters:
    if c['num_members'] > 1:
        cluster_groups[(c['num_members'], c['num_tags'])].append(c)

for key, cgroup in sorted(cluster_groups.items(), key=lambda x: -x[0][0]):
    nm, nt = key
    c = cgroup[0]
    tags = c['tags']
    samples = c['sample_members'][:3]
    
    all_field_values = defaultdict(list)
    all_entry_counts = []
    
    for fname in samples:
        path = os.path.join(DEC_BATCH, fname)
        if not os.path.exists(path):
            continue
        recs, entries = parse_file(path)
        fv = get_field_values(entries)
        all_entry_counts.append(len(entries))
        for pos, vals in fv.items():
            all_field_values[pos].extend(vals)
    
    if not all_field_values:
        continue
    
    avg_entries = sum(all_entry_counts) / len(all_entry_counts)
    
    # For each position, search for known game IDs
    field_hits = {}
    for pos, vals in all_field_values.items():
        svals = set(vals)
        
        # Check hero ID matches
        hero_matches = svals & HERO_IDS
        skill_matches = svals & SKILL_IDS
        item_matches = svals & ITEM_IDS
        
        # Check class range (1-5)
        class_vals = [v for v in svals if 1 <= v <= 5]
        
        # Check faction range
        faction_vals = [v for v in svals if 1 <= v <= 5]
        
        # Check star quality (1-8)
        star_vals = [v for v in svals if 1 <= v <= 8]
        
        # Check equipment tier (1-4)
        equip_tier_vals = [v for v in svals if 1 <= v <= 4]
        
        # Boolean/flag
        is_flag = svals <= {0, 1}
        
        # Level/percents
        level_vals = [v for v in svals if 0 <= v <= 100]
        
        # Sequential ID if all unique
        is_unique = len(svals) == len(vals) and len(vals) > 2
        is_sequential = is_unique and svals == set(range(min(svals), min(svals) + len(svals)))
        
        field_hits[pos] = {
            'min': min(vals), 'max': max(vals),
            'unique': len(svals), 'total': len(vals),
            'hero_matches': list(hero_matches)[:10],
            'skill_matches': list(skill_matches)[:10],
            'item_matches': list(item_matches)[:10],
            'class_range_count': len(class_vals),
            'star_range_count': len(star_vals),
            'is_flag': is_flag,
            'is_unique': is_unique,
            'is_sequential': is_sequential,
            'level_range_count': len(level_vals),
            'equip_tier_count': len(equip_tier_vals),
        }
    
    results[f'{nm}f_{nt}t'] = {
        'num_members': nm,
        'num_tags': nt,
        'tags_preview': tags[:10],
        'avg_entry_count': round(avg_entries, 1),
        'entry_counts': all_entry_counts,
        'num_fields_with_data': len(all_field_values),
        'fields': field_hits,
    }

# Print report
print("=" * 100)
print("DEEP VALUE CROSS-REFERENCE ANALYSIS")
print("=" * 100)

for key, r in sorted(results.items(), key=lambda x: -x[1]['num_members']):
    print(f"\n--- {key} ---")
    print(f"  Members: {r['num_members']}, Tags: {r['num_tags']}, Entries: {r['avg_entry_count']}")
    
    # Check for hero IDs
    hero_positions = [p for p, f in r['fields'].items() if f['hero_matches']]
    skill_positions = [p for p, f in r['fields'].items() if f['skill_matches']]
    item_positions = [p for p, f in r['fields'].items() if f['item_matches']]
    flag_positions = [p for p, f in r['fields'].items() if f['is_flag']]
    class_positions = [p for p, f in r['fields'].items() if f['class_range_count'] >= 4]
    star_positions = [p for p, f in r['fields'].items() if f['star_range_count'] >= 5]
    seq_positions = [p for p, f in r['fields'].items() if f['is_sequential']]
    unique_positions = [p for p, f in r['fields'].items() if f['is_unique']]
    
    if hero_positions:
        print(f"  HERO ID fields: pos {hero_positions}")
        for p in hero_positions[:3]:
            print(f"    pos {p}: {r['fields'][p]['hero_matches']}")
    if skill_positions:
        print(f"  SKILL ID fields: pos {skill_positions}")
        for p in skill_positions[:3]:
            print(f"    pos {p}: {r['fields'][p]['skill_matches']}")
    if item_positions:
        print(f"  ITEM ID fields: pos {item_positions}")
    if class_positions:
        print(f"  CLASS enum (1-5): pos {class_positions}")
    if star_positions:
        print(f"  STAR quality (1-8): pos {star_positions}")
    if seq_positions:
        print(f"  SEQUENTIAL ID: pos {seq_positions}")
    if flag_positions:
        print(f"  FLAGS: pos {flag_positions}")
    
    # Entity type inference
    if hero_positions and r['avg_entry_count'] >= 200:
        print(f"  => LIKELY: Hero/skill database ({r['avg_entry_count']} entries)")
    elif r['avg_entry_count'] >= 200 and r['avg_entry_count'] <= 500:
        print(f"  => LIKELY: Stage/mission database ({r['avg_entry_count']} entries)")
    elif r['avg_entry_count'] >= 500 and r['avg_entry_count'] <= 5000:
        print(f"  => LIKELY: Language/localization database ({r['avg_entry_count']} entries)")
    elif r['avg_entry_count'] >= 5000:
        print(f"  => LIKELY: Resource manifest ({r['avg_entry_count']} entries)")
    elif r['avg_entry_count'] <= 10:
        print(f"  => LIKELY: Config/team data ({r['avg_entry_count']} entries)")
    elif item_positions:
        print(f"  => LIKELY: Shop/item database ({r['avg_entry_count']} entries)")
    else:
        print(f"  => LIKELY: Generic game data ({r['avg_entry_count']} entries)")

# Save
with open(OUTPUT, 'w') as f:
    json.dump(results, f, indent=2, default=str)
print(f"\nSaved to {OUTPUT}")
