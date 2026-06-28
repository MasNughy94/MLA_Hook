"""Extract and document the most complete hero record from the 55-file cluster."""
import os, json
from collections import defaultdict

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\NGEONG\Videos\MLA\PROJECT\decrypted\dec_batch'

files_of_interest = [
    '07b5cc5ea4a8d86273be8170720a4587.mt.dec',  # HeroID 2111
    '12eb65e862c413254ae49d2eba76eea2.mt.dec',  # HeroID 2112
    '1c7efa501c5305fb7062cdcbf148c4a9.mt.dec',  # HeroID 5970
    '0217cbdae530696836de83aa3c162e1a.mt.dec',  # Master DB
]

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

print("=== FINDING THE MOST COMPLEX ENTRIES WITH HERO IDs ===")

for fname in files_of_interest:
    path = os.path.join(DEC_BATCH, fname)
    entries = parse_entries(path)
    
    # Find entries with both high field count and 4-digit IDs
    candidates = []
    for eidx, entry in enumerate(entries):
        tags = set(r['tag'] for r in entry)
        id_vals = [r['val'] for r in entry if 2000 <= r['val'] <= 9999]
        has_ce = 0xCE in tags
        has_cf = 0xCF in tags
        
        if len(entry) >= 15 and (has_ce or has_cf):
            candidates.append((eidx, len(entry), id_vals))
    
    candidates.sort(key=lambda x: -x[1])
    
    print(f"\n--- {fname} ---")
    if candidates:
        print(f"  Top candidates: {candidates[:5]}")
        
        # Show the best candidate in detail
        best_idx, best_len, best_ids = candidates[0]
        entry = entries[best_idx]
        tc = chr(0xCE) if 0xCE < 127 else '.'
        
        print(f"\n  === BEST CANDIDATE Entry {best_idx} ({best_len} fields, IDs={best_ids}) ===")
        for pi, r in enumerate(entry):
            tc = chr(r['tag']) if 32 <= r['tag'] < 127 else '.'
            note = ''
            if r['val'] in {2111, 2112, 2113, 5970}: note = ' [HERO_ID]'
            elif 2000 <= r['val'] <= 9999: note = ' [4D-ID]'
            elif r['val'] >= 50000: note = ' [LARGE_REF]'
            elif r['tag'] in (0xCE, 0xCF): note = ' [SKILL_TAG]'
            print(f"    pos={pi:3d} tag=0x{r['tag']:02x}('{tc}'): val={r['val']}{note}")
    else:
        print("  No candidates found")

# Now let's find entries that share the same tag signature across different files
# (same tag at same position = same semantic meaning)
print("\n\n=== CROSS-FILE TAG POSITION ANALYSIS ===")
print("Checking if position 17 consistently has HeroID across all files...")

for fname in files_of_interest:
    path = os.path.join(DEC_BATCH, fname)
    entries = parse_entries(path)
    
    # Count which tags carry 4-digit IDs at which positions
    pos_id_counts = defaultdict(lambda: defaultdict(int))
    for entry in entries:
        for pi, r in enumerate(entry):
            if 2000 <= r['val'] <= 9999:
                pos_id_counts[pi][r['tag']] += 1
    
    print(f"\n--- {fname[:20]}... ---")
    # Show positions where 4-digit IDs commonly appear
    for pi in sorted(pos_id_counts.keys())[:5]:
        tag_counts = pos_id_counts[pi]
        total = sum(tag_counts.values())
        print(f"  pos={pi}: {total} ID values across {len(tag_counts)} different tags: {dict(sorted(tag_counts.items(), key=lambda x: -x[1])[:5])}")
