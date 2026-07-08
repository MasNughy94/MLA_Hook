import os

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\dec_batch'
TARGET = '0217cbdae530696836de83aa3c162e1a.mt.dec'

with open(os.path.join(DEC_BATCH, TARGET), 'rb') as f:
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

# Find entry where pos 17 has val 2111
for eidx, entry in enumerate(entries):
    if len(entry) > 17 and entry[17]['val'] == 2111:
        print(f'Found HeroID 2111 at Entry {eidx}, pos 17, tag=0x{entry[17]["tag"]:02x}')
        print(f'  Entry has {len(entry)} fields:')
        for pi, r in enumerate(entry):
            tc = chr(r['tag']) if 32 <= r['tag'] < 127 else '.'
            # Check if this tag value maps to a known field
            note = ''
            if 1 <= r['val'] <= 5: note = ' [CLASS/FAC]'
            elif r['val'] == 2111: note = ' [HERO_ID]'
            elif 53200 <= r['val'] <= 53206: note = ' [SKILL]'
            elif 1000 <= r['val'] <= 9999: note = ' [ID]'
            elif 60000 <= r['val']: note = ' [REF]'
            print(f'  pos={pi:2d} tag=0x{r["tag"]:02x}("{tc}"): val={r["val"]}{note}')
        break

# Also find all entries with pos 17 and same tag as hero entry
print()
print('=== ALL ENTRIES WITH SAME TAG AT POS 17 AS HERO ENTRY ===')
hero_tag = None
for eidx, entry in enumerate(entries):
    if len(entry) > 17 and entry[17]['val'] == 2111:
        hero_tag = entry[17]['tag']
        print(f'Hero entry {eidx}: tag=0x{hero_tag:02x}')
        break

if hero_tag is not None:
    matches = []
    for eidx, entry in enumerate(entries):
        if len(entry) > 17 and entry[17]['tag'] == hero_tag:
            matches.append(eidx)
    print(f'Entries with tag 0x{hero_tag:02x} at pos 17: {len(matches)} entries: {matches}')
    # Show values at pos 17 for these entries
    for eidx in matches:
        entry = entries[eidx]
        val = entry[17]['val']
        print(f'  Entry {eidx}: val={val}')
    
    # Now compare what other positions these entries have
    print()
    print('=== COMPARING ALL HERO-LIKE ENTRIES ===')
    # Find common positions
    pos_tags = {}
    for eidx in matches:
        entry = entries[eidx]
        for pi, r in enumerate(entry):
            if pi not in pos_tags:
                pos_tags[pi] = set()
            pos_tags[pi].add(r['tag'])
    
    print('Position-to-tag mappings across hero entries:')
    for pi in sorted(pos_tags.keys()):
        tags = pos_tags[pi]
        print(f'  pos={pi}: {len(tags)} different tags: {["0x%02x" % t for t in sorted(tags)]}')
