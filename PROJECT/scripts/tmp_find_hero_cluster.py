"""Identify hero entries in the Master DB by looking for entries with class+faction+skill patterns."""
import os
from collections import defaultdict, Counter

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
print(f"Total entries: {len(entries)}")

# Analyze each entry's tag set and values
entry_profiles = []
for eidx, entry in enumerate(entries):
    tags_set = set()
    tag_vals = {}
    for r in entry:
        tags_set.add(r['tag'])
        tag_vals[r['tag']] = r['val']
    entry_profiles.append((eidx, tags_set, tag_vals, len(entry)))

# Build tag co-occurrence matrix
tag_occurrence = Counter()
tag_pairs = Counter()
for eidx, tags_set, tag_vals, _ in entry_profiles:
    for t in tags_set:
        tag_occurrence[t] += 1

# Find entries with potential hero indicators:
# 1-5 values (class/faction), skill ID ranges, etc.
print("\n=== ENTRIES WITH CLASS-LIKE VALUES (1-5) ===")
for eidx, tags_set, tag_vals, nf in entry_profiles:
    class_tags = [(t, v) for t, v in tag_vals.items() if 1 <= v <= 5]
    if class_tags and len(class_tags) >= 2:
        print(f"  Entry {eidx} ({nf} fields): class_tags={class_tags}")
        if eidx > 5:
            break

print("\n=== ENTRIES WITH 4-DIGIT IDS (hero range 1000-9999) ===")
hero_entries = []
for eidx, tags_set, tag_vals, nf in entry_profiles:
    id_vals = [(t, v) for t, v in tag_vals.items() if 1000 <= v <= 9999]
    if id_vals:
        print(f"  Entry {eidx} ({nf} fields): ids={id_vals}")
        hero_entries.append((eidx, tags_set, tag_vals, nf))
        if len(hero_entries) >= 10:
            break

print(f"\n=== TOP 10 ENTRIES BY FIELD COUNT (likely complex entities) ===")
for eidx, tags_set, tag_vals, nf in sorted(entry_profiles, key=lambda x: -x[3])[:10]:
    kv = [(chr(t) if 32 <= t < 127 else f'0x{t:02x}', v) for t, v in sorted(tag_vals.items())]
    print(f"  Entry {eidx}: {nf} fields")
    for tc, v in kv[:15]:
        print(f"    tag={tc}: val={v}")
    if len(kv) > 15:
        print(f"    ... ({len(kv)-15} more fields)")

# Tag signature distribution
print(f"\n=== TAG SIGNATURE DISTRIBUTION ===")
sig_counts = Counter()
for eidx, tags_set, tag_vals, nf in entry_profiles:
    sig = tuple(sorted(tags_set))
    sig_counts[sig] += 1

print(f"Unique signatures: {len(sig_counts)} out of {len(entries)} entries")
for sig, cnt in sig_counts.most_common(20):
    tag_names = [f'0x{t:02x}' for t in sig[:10]]
    print(f"  {cnt:>5d} entries: tags={tag_names}{'...' if len(sig) > 10 else ''} (total {len(sig)} tags)")

# Find the most "hero-like" entry: one with many diverse tags including lowercase letters
print(f"\n=== ENTRIES USING LOWERCASE TAGS (a-z = 0x61-0x7A, hero-related) ===")
for eidx, tags_set, tag_vals, nf in entry_profiles:
    lc_tags = [t for t in tags_set if 0x61 <= t <= 0x7A]
    if len(lc_tags) >= 3:
        print(f"  Entry {eidx}: {nf} fields, lowercase tags: {[f'0x{t:02x}(\'{chr(t)}\')' for t in lc_tags]}")
        tag_list = [(f'0x{t:02x}(\'{chr(t) if 32<=t<127 else "."}\')', tag_vals[t]) for t in sorted(tags_set)]
        print(f"    All tags: {tag_list}")
        break
