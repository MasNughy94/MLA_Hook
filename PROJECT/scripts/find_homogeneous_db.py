"""
Find homogeneous entity databases: files where entries share the same tag-signature.
This identifies true entity-type databases (Hero, Item, Skill, etc.).
"""
import os, sys, json
from collections import Counter
sys.path.insert(0, r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode')
from roo_parser_final import RooBinaryFormat

BATCH_DIR = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\dec_batch'
ANALYSIS_DIR = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\analysis'

# Load catalog to find files by classification
with open(os.path.join(ANALYSIS_DIR, 'roo_file_catalog.json')) as f:
    catalog = json.load(f)

# Find MASTER_HERO_DB and MASTER_GAME_DB files
target_files = [f for f, info in catalog.items() 
                if info.get('classification') in ('MASTER_HERO_DB', 'MASTER_GAME_DB', 'GAME_SYSTEM_DB') 
                and info['num_entries'] < 10000][:3]

# Also check some LARGE_SCHEMA files with homogeneous entries
# And the 33K file
large_file = [f for f, info in catalog.items() if info['num_entries'] > 30000][:1]

for h in large_file + target_files:
    fname = h + '.mt.dec'
    fpath = os.path.join(BATCH_DIR, fname)
    if not os.path.exists(fpath):
        print(f"\nMISSING: {h}")
        continue
    
    with open(fpath, 'rb') as f:
        data = f.read()
    
    parser = RooBinaryFormat(data, fname)
    parser.cluster_entries(gap_threshold=30)
    
    print(f"\n{'='*70}")
    print(f"FILE: {h}")
    print(f"  Catalog: entries={catalog[h]['num_entries']} tags={catalog[h]['tag_count']} class={catalog[h].get('classification','?')}")
    print(f"  Body: {len(parser.body)} bytes, {len(parser.records)} records")
    print(f"  Overrides: {len(parser.override_records)}, Templates: {len(parser.template_records)}, Empty: {len(parser.empty_records)}")
    print(f"  Parsed entries: {len(parser.entries)}")
    
    # Build tag-signature distribution
    sig_counts = Counter()
    for entry in parser.entries:
        tags = tuple(sorted(set(f'0x{rec[1]:02x}' for rec in entry)))
        sig_counts[tags] += 1
    
    total = len(parser.entries)
    unique_sigs = len(sig_counts)
    
    print(f"  Unique signatures: {unique_sigs} ({100*unique_sigs/total:.1f}% of entries)")
    
    # Find HOMOGENEITY: what % of entries share the top signature?
    top_sig, top_cnt = sig_counts.most_common(1)[0]
    top_pct = 100 * top_cnt / total
    print(f"  Top signature: {top_cnt}/{total} entries ({top_pct:.1f}%)")
    print(f"    Tags in top sig: {len(top_sig)} fields -> {list(top_sig)}")
    
    # Top 5 signatures
    print(f"  Top 5 signatures:")
    for sig, cnt in sig_counts.most_common(5):
        print(f"    {cnt:>5d} entries: {list(sig)}")
    
    # Check homogeneity class
    if top_pct > 80:
        print(f"  >>> HOMOGENEOUS DB ({top_pct:.1f}% share same schema)")
    elif top_pct > 50:
        print(f"  >>> SEMI-HOMOGENEOUS DB ({top_pct:.1f}% share top schema)")
    elif top_pct > 10:
        print(f"  >>> DIVERSE DB (top schema only {top_pct:.1f}%)")
    else:
        print(f"  >>> HETEROGENEOUS STORE")
    
    # Analyze the top signature group: are these "hero-like"?
    if top_pct > 50:
        print(f"\n  DETAILED ANALYSIS OF TOP HOMOGENEOUS GROUP:")
        # Collect values for each tag in the top group
        top_tag_values = {}
        for entry in parser.entries:
            tags = tuple(sorted(set(f'0x{rec[1]:02x}' for rec in entry)))
            if tags != top_sig:
                continue
            for offset, tag, v1, v2 in entry:
                u16 = v1 | (v2 << 8)
                tag_hex = f'0x{tag:02x}'
                if tag_hex not in top_tag_values:
                    top_tag_values[tag_hex] = []
                top_tag_values[tag_hex].append(u16)
        
        for tag_hex in sorted(top_tag_values.keys()):
            vals = top_tag_values[tag_hex]
            unique_vals = len(set(vals))
            min_v, max_v = min(vals), max(vals)
            range_desc = ""
            if any(2000 <= v <= 9999 for v in vals):
                range_desc = " [HERO-ID range]"
            elif any(1301 <= v <= 73380 for v in vals):
                range_desc = " [SKILL-ID range]"
            elif any(60000 <= v <= 180000 for v in vals):
                range_desc = " [ITEM-ID range]"
            ch = chr(int(tag_hex, 16)) if 32 <= int(tag_hex, 16) < 127 else '.'
            print(f"    {tag_hex}('{ch}'): unique={unique_vals}, range={min_v}-{max_v}{range_desc}")
            if unique_vals <= 20:
                print(f"      values: {sorted(set(vals))}")
