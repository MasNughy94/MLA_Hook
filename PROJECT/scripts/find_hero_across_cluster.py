"""Search for known HeroIDs across all files in the 55-file cluster."""
import os, json
from collections import defaultdict

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\NGEONG\Videos\MLA\PROJECT\decrypted\dec_batch'

KNOWN_HERO_IDS = {2111, 2112, 2113, 5970}
EXPANDED_IDS = set(range(2000, 5999))  # Full hero ID range to check

with open('analysis/cluster_report.json') as f:
    clusters = json.load(f)

target_cluster = None
for c in clusters:
    if c['num_members'] == 55 and c['num_tags'] == 255:
        target_cluster = c
        break

all_samples = target_cluster['sample_members']

def scan_file(path):
    """Find known HeroIDs and their entry context."""
    with open(path, 'rb') as f:
        data = f.read()
    body = data[HDR_SIZE:]
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        if tag != 0:
            val = v1 | (v2 << 8)
            records.append({'offset': i, 'tag': tag, 'val': val})
    # Cluster entries
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

# For each file, find entries containing any known HeroID
print("=== SEARCHING FOR KNOWN HERO IDs ACROSS CLUSTER ===\n")
results = {}

for fname in all_samples:
    path = os.path.join(DEC_BATCH, fname)
    if not os.path.exists(path):
        continue
    
    entries = scan_file(path)
    found = []
    
    for eidx, entry in enumerate(entries):
        for r in entry:
            if r['val'] in KNOWN_HERO_IDS:
                found.append({
                    'entry': eidx,
                    'tag': r['tag'],
                    'val': r['val'],
                    'num_fields': len(entry)
                })
    
    if found:
        results[fname] = found
        print(f"\n--- {fname} ({len(entries)} entries) ---")
        for hit in found[:10]:
            print(f"  Entry {hit['entry']:5d} ({hit['num_fields']:3d} fields): tag=0x{hit['tag']:02x} val={hit['val']}")
    else:
        print(f"  {fname}: no HeroIDs found")

# Now look for hero-like entries (entries with 20+ fields that include skill tag 0xCE)
print("\n\n=== ENTRIES WITH 20+ FIELDS INCLUDING TAG 0xCE (complex hero candidates) ===")
for fname in all_samples:
    path = os.path.join(DEC_BATCH, fname)
    if not os.path.exists(path):
        continue
    
    entries = scan_file(path)
    complex_entries = []
    
    for eidx, entry in enumerate(entries):
        tags = set(r['tag'] for r in entry)
        if len(entry) >= 20 and 0xCE in tags:
            complex_entries.append(eidx)
            if len(complex_entries) >= 3:
                break
    
    if complex_entries:
        print(f"  {fname}: {len(complex_entries)} complex hero-like entries (first: {complex_entries[0]})")
        # Show first complex entry
        eidx = complex_entries[0]
        entry = entries[eidx]
        print(f"    Entry {eidx} ({len(entry)} fields):")
        for pi, r in enumerate(entry):
            note = ''
            if r['val'] in KNOWN_HERO_IDS: note = ' [HERO_ID]'
            elif 1000 <= r['val'] <= 9999: note = ' [4D-ID]'
            elif 50000 <= r['val']: note = ' [REF]'
            print(f"      pos={pi:2d} tag=0x{r['tag']:02x} val={r['val']}{note}")
