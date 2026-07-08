"""Find entries with known HeroIDs and analyze their structure."""
import os, json
from collections import defaultdict

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\dec_batch'
TARGET = '0217cbdae530696836de83aa3c162e1a.mt.dec'

# Known game IDs
HERO_IDS = {2111, 2112, 2113, 5970}
SKILL_IDS = {53201, 53202, 53203, 53204, 53205, 73301, 73302, 73303, 73304, 73305}
ITEM_IDS = {61200, 61383, 61492, 61514, 178274}

def parse_entries(path):
    with open(path, 'rb') as f:
        data = f.read()
    body = data[HDR_SIZE:]
    
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        if tag != 0:
            val = v1 | (v2 << 8)
            records.append({'offset': i, 'tag': tag, 'v1': v1, 'v2': v2, 'val': val})
    
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
    return entries, body

entries, body = parse_entries(os.path.join(DEC_BATCH, TARGET))

# For each entry, build a tag->value map
tag_entry_maps = []
for eidx, entry in enumerate(entries):
    tag_map = {}
    val_map = {}
    for r in entry:
        tag_map[r['tag']] = r
        val_map[r['tag']] = r['val']
    tag_entry_maps.append((eidx, tag_map, val_map, entry))

# Search for entries with known HeroIDs/SkillIDs
print("=== ENTRIES WITH KNOWN HERO IDs ===")
found_hero = 0
for eidx, tag_map, val_map, entry in tag_entry_maps:
    for tag, val in val_map.items():
        if val in HERO_IDS:
            print(f"\nEntry {eidx} ({len(entry)} fields): has HeroID={val} at tag=0x{tag:02x}")
            for r in sorted(entry, key=lambda x: x['offset']):
                tc = chr(r['tag']) if 32 <= r['tag'] < 127 else '.'
                tag_name = ''
                if r['val'] in HERO_IDS:
                    tag_name = ' [HERO_ID]'
                elif r['val'] in SKILL_IDS:
                    tag_name = f' [SKILL_ID]'
                elif r['val'] in ITEM_IDS:
                    tag_name = ' [ITEM_ID]'
                print(f"  tag=0x{r['tag']:02x}('{tc}'): val={r['val']:>6}{tag_name}")
            found_hero += 1
            if found_hero >= 3:
                break
    if found_hero >= 3:
        break

print(f"\n\n=== ALL TAGS WITH KNOWN HERO/SKILL/ITEM VALUES ===")
tag_values = defaultdict(list)
for eidx, tag_map, val_map, entry in tag_entry_maps:
    for tag, val in val_map.items():
        tag_values[tag].append(val)

# For each tag, check if it contains hero/skill/item IDs
for tag in sorted(tag_values.keys()):
    vals = set(tag_values[tag])
    hero_match = vals & HERO_IDS
    skill_match = vals & SKILL_IDS
    item_match = vals & ITEM_IDS
    ch = chr(tag) if 32 <= tag < 127 else '.'
    parts = []
    if hero_match:
        parts.append(f"HERO({hero_match})")
    if skill_match:
        parts.append(f"SKILL({skill_match})")
    if item_match:
        parts.append(f"ITEM({item_match})")
    if parts:
        n = len(tag_values[tag])
        u = len(vals)
        print(f"  0x{tag:02x}('{ch}'): [{min(vals)}-{max(vals)}] {u}/{n} {'; '.join(parts)}")

# Identify the most common tags across all entries
print(f"\n\n=== TOP 30 MOST COMMON TAGS ===")
tag_freq = [(tag, len(tag_values[tag])) for tag in tag_values]
for tag, cnt in sorted(tag_freq, key=lambda x: -x[1])[:30]:
    ch = chr(tag) if 32 <= tag < 127 else '.'
    vals = set(tag_values[tag])
    u = len(vals)
    print(f"  0x{tag:02x}('{ch}'): {cnt:>5d} entries, {u:>3d} unique vals [{min(vals)}-{max(vals)}]")
