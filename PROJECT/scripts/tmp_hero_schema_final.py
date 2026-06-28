"""Final hero schema: find the specific tags for each field position in hero entries."""
import os
from collections import defaultdict

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\dec_batch'
TARGET = '0217cbdae530696836de83aa3c162e1a.mt.dec'

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

# Key positions and their TAGs from deep_value_analysis:
# pos 17 = HeroID (2111)
# pos 0, 1, 9 = SkillIDs
# pos 0-14 = Class (1-5) and Star (1-8)

# For each position in hero entries, find the specific tag used
# "Hero entries" = entries that have the HeroID pattern

# First, find which tag corresponds to HeroID at position 17
print("=== POSITION 17 TAG ANALYSIS (HeroID location) ===")
pos17_info = []
for eidx, entry in enumerate(entries):
    if len(entry) > 17:
        r = entry[17]  # The 18th field in the entry
        pos17_info.append((eidx, r['tag'], r['val']))

# Show unique (tag, val) pairs at position 17
tag_vals_at_17 = defaultdict(list)
for eidx, tag, val in pos17_info:
    tag_vals_at_17[tag].append(val)
    
for tag, vals in sorted(tag_vals_at_17.items()):
    ch = chr(tag) if 32 <= tag < 127 else '.'
    print(f"  tag=0x{tag:02x}('{ch}'): {len(vals)} occurrences, vals={sorted(set(vals))[:20]}")

# Find all entries that use tag=0xCE (skill 53203) - likely skill entries
print("\n=== TAG 0xCE ANALYSIS (SkillID 53203) ===")
ce_entries = []
for eidx, entry in enumerate(entries):
    for r in entry:
        if r['tag'] == 0xCE:
            ce_entries.append((eidx, entry))
            break
            
print(f"Entries with tag 0xCE: {len(ce_entries)}")
# Show first few
for eidx, entry in ce_entries[:3]:
    print(f"  Entry {eidx} ({len(entry)} fields):")
    for r in sorted(entry, key=lambda x: x['offset']):
        tc = chr(r['tag']) if 32 <= r['tag'] < 127 else '.'
        print(f"    tag=0x{r['tag']:02x}('{tc}'): val={r['val']}")

# Find all entries that use lowercase 'a' tag (0x61) - hero-related
print("\n=== TAG 0x61 'a' ANALYSIS ===")
tag61_entries = []
for eidx, entry in enumerate(entries):
    for r in entry:
        if r['tag'] == 0x61:
            tag61_entries.append((eidx, entry))
            break
print(f"Entries with tag 0x61: {len(tag61_entries)}")
for eidx, entry in tag61_entries[:3]:
    print(f"  Entry {eidx} ({len(entry)} fields):")
    for r in sorted(entry, key=lambda x: x['offset']):
        tc = chr(r['tag']) if 32 <= r['tag'] < 127 else '.'
        print(f"    tag=0x{r['tag']:02x}('{tc}'): val={r['val']}")

# Find the specific tag at each position
# For entries with 10+ fields (complex entities), look at position 0-14 tags
print("\n=== TAG MAPPING FOR COMPLEX ENTRIES (15+ fields) ===")
for eidx, entry in enumerate(entries):
    if len(entry) < 15:
        continue
    print(f"\nEntry {eidx} ({len(entry)} fields):")
    for pi, r in enumerate(sorted(entry, key=lambda x: x['offset'])):
        tc = chr(r['tag']) if 32 <= r['tag'] < 127 else '.'
        # Flag interesting values
        note = ''
        if 1 <= r['val'] <= 5:
            note = ' [CLASS/FACTION]'
        elif 1000 <= r['val'] <= 9999:
            note = ' [4DIGIT-ID]'
        elif 53200 <= r['val'] <= 53206:
            note = ' [SKILL]'
        elif 60000 <= r['val'] <= 180000:
            note = ' [ITEM/REF]'
        elif r['val'] > 40000:
            note = ' [LARGE]'
        print(f"  pos={pi:2d} tag=0x{r['tag']:02x}('{tc}'): val={r['val']}{note}")
    if eidx >= 3:
        break
