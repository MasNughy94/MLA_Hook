"""Cluster entries in the Master DB by tag signature and identify hero entries."""
import os, json
from collections import defaultdict

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\dec_batch'
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
print(f"Total entries: {len(entries)}")

# Group by tag signature (comma-separated sorted tag list)
sig_groups = defaultdict(list)
for eidx, entry in enumerate(entries):
    tags = tuple(sorted(set(r['tag'] for r in entry)))
    sig_groups[tags].append(eidx)

# Show most common signatures
print(f"\n=== MOST COMMON TAG SIGNATURES ===")
sig_counts = [(tags, len(entries)) for tags, entries in sorted(sig_groups.items(), key=lambda x: -len(x[1]))]
for tags, count in sig_counts[:30]:
    tag_str = ', '.join(f"0x{t:02x}" for t in tags[:5])
    if len(tags) > 5:
        tag_str += f"... (+{len(tags)-5} more)"
    print(f"  [{count:3d} entries] ({len(tags):2d} tags): {tag_str}")

# Now find entry signatures that look like hero entries:
# Hero entries should have: an ID field (4-digit), skill fields, stat fields, class/faction field
# Let's look at multi-tag signatures (5+ tags) that include common tags
print(f"\n=== MULTI-TAG SIGNATURES (5+ tags, potential hero entries) ===")
multi = [(tags, es) for tags, es in sig_groups.items() if len(tags) >= 5]
multi.sort(key=lambda x: -len(x[1]))
for tags, entries_list in multi[:15]:
    print(f"  [{len(entries_list):3d} entries] ({len(tags):2d} tags): {', '.join(f'0x{t:02x}' for t in sorted(tags))}")
    # Show one example entry
    eidx = entries_list[0]
    entry = entries[eidx]
    print(f"    Example Entry {eidx}:")
    for pi, r in enumerate(entry):
        tc = chr(r['tag']) if 32 <= r['tag'] < 127 else '.'
        note = ''
        if 1000 <= r['val'] <= 9999: note = f' [ID]'
        elif 50000 <= r['val']: note = ' [REF]'
        elif r['val'] == 0: note = ' [ZERO]'
        print(f"      pos={pi:2d} tag=0x{r['tag']:02x}('{tc}'): val={r['val']}{note}")
    print()

# Look specifically for signatures that have tag 0xCE (skill) and 0xCF (skill) together with other tags
print("\n=== SIGNATURES WITH BOTH 0xCE AND 0xCF (dual-skill hero entries) ===")
for tags, entries_list in sig_groups.items():
    if 0xCE in tags and 0xCF in tags and len(tags) >= 8:
        print(f"  [{len(entries_list)} entries] ({len(tags)} tags): {', '.join(f'0x{t:02x}' for t in sorted(tags))}")
        eidx = entries_list[0]
        entry = entries[eidx]
        print(f"    Example Entry {eidx}:")
        for pi, r in enumerate(entry):
            tc = chr(r['tag']) if 32 <= r['tag'] < 127 else '.'
            note = ''
            if 1000 <= r['val'] <= 9999: note = ' [ID]'
            elif 50000 <= r['val']: note = ' [REF]'
            print(f"      pos={pi:2d} tag=0x{r['tag']:02x}('{tc}'): val={r['val']}{note}")
        print()

# Find the single entry with HeroID 2111
print("\n=== SEARCH FOR HEROID 2111 ===")
for eidx, entry in enumerate(entries):
    for r in entry:
        if r['val'] == 2111:
            tc = chr(r['tag']) if 32 <= r['tag'] < 127 else '.'
            print(f"  Entry {eidx}: tag=0x{r['tag']:02x}('{tc}') at position {[pi for pi, r2 in enumerate(entry) if r2['offset']==r['offset']][0]}, val=2111")
            # Show full entry
            print(f"  Full entry ({len(entry)} fields):")
            for pi, r2 in enumerate(entry):
                note = ''
                if 1000 <= r2['val'] <= 9999: note = ' [ID]'
                elif 53200 <= r2['val'] <= 53206: note = ' [SKILL]'
                elif r2['val'] == 2111: note = ' [HERO_ID]'
                elif 50000 <= r2['val']: note = ' [REF]'
                print(f"    pos={pi:2d} tag=0x{r2['tag']:02x}('{tc2}'): val={r2['val']}{note}")
            break
