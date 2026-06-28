"""
Read full records from the master database cluster (55f_255t).
Extracts detailed per-field values with known ID matches for semantic naming.
"""
import os, json, struct
from collections import defaultdict

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\dec_batch'

# Known game enums
HERO_CLASSES = {1: 'Mage', 2: 'Support', 3: 'Archer', 4: 'Tank', 5: 'Warrior'}
HERO_FACTIONS = {1: 'Light', 2: 'Technology', 3: 'Elemental', 4: 'Monster', 5: 'Dark'}
STAR_QUALITY = {i: f'{i}★' for i in range(1, 9)}
EQUIP_TIER = {1: 'Tier1_Bronze', 2: 'Tier2_Silver', 3: 'Tier3_Gold', 4: 'Tier4_Red'}

# Sample filenames from the 55f cluster
SAMPLE_FILES = [
    '0217cbdae530696836de83aa3c162e1a.mt.dec',
    '07b5cc5ea4a8d86273be8170720a4587.mt.dec',
    '0e3bbac67f12505f7dfe45d4e6aba1ea.mt.dec',
]

def parse_file(path):
    with open(path, 'rb') as f:
        data = f.read()
    body = data[HDR_SIZE:]
    
    # Get records as 3-byte sequences
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        if tag != 0:
            val = v1 | (v2 << 8)
            records.append({'offset': i, 'tag': tag, 'v1': v1, 'v2': v2, 'val': val})
    
    # Cluster into entries by gap
    entries = []
    if records:
        cur = [records[0]]
        for r in records[1:]:
            if r['offset'] - cur[-1]['offset'] > 30:
                entries.append(cur)
                cur = [r]
            else:
                cur.append(r)
        if cur:
            entries.append(cur)
    
    return records, entries, len(records), len(entries), os.path.basename(path)

# Read and analyze each sample file
all_tag_values = defaultdict(lambda: defaultdict(list))  # tag -> {entry_idx: [vals]}
all_position_values = defaultdict(list)  # position -> [values across all entries+files]

for fname in SAMPLE_FILES:
    path = os.path.join(DEC_BATCH, fname)
    records, entries, nrecs, nentries, name = parse_file(path)
    
    print(f"\n{'='*70}")
    print(f"FILE: {name}")
    print(f"Records: {nrecs}, Entries: {nentries}")
    print(f"{'='*70}")
    
    # Collect values per position within each entry
    for eidx, entry in enumerate(entries[:5]):
        print(f"\n  Entry {eidx}:")
        for ridx, r in enumerate(entry):
            tag_char = chr(r['tag']) if 32 <= r['tag'] < 127 else '.'
            # Classify the value
            notes = []
            if 1 <= r['val'] <= 5:
                if r['val'] in HERO_CLASSES:
                    notes.append(f'CLASS:{HERO_CLASSES[r["val"]]}')
                if r['val'] in HERO_FACTIONS:
                    notes.append(f'FACTION:{HERO_FACTIONS[r["val"]]}')
            if 1 <= r['val'] <= 8:
                notes.append(f'STAR:{r["val"]}★')
            if r['val'] in {0, 1}:
                notes.append('FLAG')
            if 2111 <= r['val'] <= 2113 or r['val'] == 5970 or (16100000 <= r['val'] <= 16199999):
                notes.append('HERO_ID')
            if (1301 <= r['val'] <= 1304) or (1601 <= r['val'] <= 1604) or (1801 <= r['val'] <= 1804):
                notes.append('SKILL_ID')
            if (53201 <= r['val'] <= 53205) or (73301 <= r['val'] <= 73380):
                notes.append('SKILL_ID')
            if r['val'] in {61200, 61383, 61492, 61514, 178274}:
                notes.append('ITEM_ID')
            
            note_str = f" [{', '.join(notes)}]" if notes else ''
            print(f"    pos={ridx:2d} tag=0x{r['tag']:02x}('{tag_char}') val={r['val']:>6}{note_str}")
        
        if len(entry) > 15:
            print(f"    ... +{len(entry)-15} more fields")
    
    # Collect all values by position
    for entry in entries:
        for ridx, r in enumerate(entry):
            all_position_values[ridx].append(r['val'])
            all_tag_values[r['tag']][fname].append(r['val'])
    
    print(f"\n  Total entries in file: {nentries}")

# Build position-level summary
print(f"\n{'='*70}")
print("POSITION-LEVEL SUMMARY (across all sample files)")
print(f"{'='*70}")

for pos in sorted(all_position_values.keys()):
    vals = all_position_values[pos]
    svals = sorted(set(vals))
    
    # Detect meaning
    meanings = []
    
    # Check hero ID
    hero_ids = [v for v in svals if 2111 <= v <= 2113 or v == 5970 or (16100000 <= v <= 16199999)]
    if hero_ids:
        meanings.append(f"HeroID({hero_ids[:5]})")
    
    # Check skill IDs
    skill_ids = [v for v in svals if (1301 <= v <= 1304) or (1601 <= v <= 1604) or 
                 (1801 <= v <= 1804) or (53201 <= v <= 53205) or (73301 <= v <= 73380)]
    if skill_ids:
        meanings.append(f"SkillID({skill_ids[:5]})")
    
    # Check item IDs
    item_ids = [v for v in svals if 60000 <= v <= 180000]
    if item_ids:
        meanings.append(f"ItemID({item_ids[:3]})")
    
    # Check class/faction (1-5)
    class_vals = [v for v in svals if 1 <= v <= 5]
    if len(class_vals) >= 4:
        mapped = {v: HERO_CLASSES.get(v, '?') for v in class_vals}
        meanings.append(f"Class({mapped})")
    
    # Check star quality (1-8)
    star_vals = [v for v in svals if 1 <= v <= 8]
    if len(star_vals) >= 5:
        meanings.append(f"Star({min(star_vals)}-{max(star_vals)})")
    
    # Check flag (0/1)
    if set(vals) <= {0, 1} and len(vals) > 3:
        meanings.append("Flag")
    
    # Check constant across entries
    if len(svals) == 1 and len(vals) > 10:
        meanings.append(f"Constant({svals[0]})")
    
    # Check sequential
    if len(svals) == len(vals) and len(vals) > 5:
        if svals == list(range(min(svals), min(svals) + len(svals))):
            meanings.append("SeqID")
    
    # Check unique values vs count
    if len(svals) <= 8 and len(vals) > len(svals) * 2:
        meanings.append(f"Enum({len(svals)}vals)")
    
    # Check level-like
    if max(vals) <= 100 and len(svals) >= 5:
        meanings.append("Level%")
    
    meaning_str = f"  [{'; '.join(meanings)}]" if meanings else ""
    tag_of_pos = None
    for entry in [parse_file(os.path.join(DEC_BATCH, f))[1] for f in SAMPLE_FILES]:
        if entry and len(entry[0]) > pos:
            tag_of_pos = entry[0][pos]['tag']
            break
    
    tag_char = chr(tag_of_pos) if tag_of_pos and 32 <= tag_of_pos < 127 else '.'
    tag_str = f"0x{tag_of_pos:02x}('{tag_char}')" if tag_of_pos else '?'
    
    print(f"  pos={pos:2d} tag={tag_str:12s} range=[{min(vals):6d}-{max(vals):6d}] "
          f"unique={len(svals):4d}/{len(vals):<6d}{meaning_str}")

# Build tag-level summary
print(f"\n{'='*70}")
print("TAG-LEVEL SUMMARY (across all sample files)")
print(f"{'='*70}")

for tag in sorted(all_tag_values.keys()):
    all_vals_f = all_tag_values[tag]
    combined = []
    for fname, vals in all_vals_f.items():
        combined.extend(vals)
    svals = sorted(set(combined))
    
    tag_char = chr(tag) if 32 <= tag < 127 else '.'
    print(f"  tag=0x{tag:02x}('{tag_char}'): range=[{min(combined):6d}-{max(combined):6d}] "
          f"unique={len(svals):4d}/{len(combined):<6d} "
          f"in {len(all_vals_f)} files")
