"""Cross-file signature analysis: categorize each file in the 55-file cluster."""
import os, json
from collections import defaultdict

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\decrypted\dec_batch'

with open('analysis/cluster_report.json') as f:
    clusters = json.load(f)

target_cluster = None
for c in clusters:
    if c['num_members'] == 55 and c['num_tags'] == 255:
        target_cluster = c
        break

all_samples = target_cluster['sample_members']

def analyze_file(path):
    """Return entry signatures and counts."""
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
    
    # Signature analysis
    sig_counts = defaultdict(int)
    for ent in entries:
        sig = tuple(sorted(set(r['tag'] for r in ent)))
        sig_counts[sig] += 1
    
    return entries, dict(sig_counts)

# Analyze each file
all_analyses = {}
for fname in all_samples:
    path = os.path.join(DEC_BATCH, fname)
    if not os.path.exists(path):
        continue
    entries, sig_counts = analyze_file(path)
    
    # Top signatures
    top_sigs = sorted(sig_counts.items(), key=lambda x: -x[1])[:10]
    
    # Count single-tag vs multi-tag entries
    single_tag = sum(c for sig, c in sig_counts.items() if len(sig) == 1)
    multi_tag = sum(c for sig, c in sig_counts.items() if len(sig) > 1)
    
    # Most common single tag
    common_single = 'N/A'
    for sig, c in top_sigs:
        if len(sig) == 1:
            common_single = f"0x{sig[0]:02x}"
            break
    
    # Entry size stats
    sizes = [len(e) for e in entries]
    avg_size = sum(sizes) / len(sizes) if sizes else 0
    
    all_analyses[fname] = {
        'total_entries': len(entries),
        'single_tag_entries': single_tag,
        'multi_tag_entries': multi_tag,
        'common_single_tag': common_single,
        'avg_fields': round(avg_size, 1),
        'unique_signatures': len(sig_counts),
        'top_signatures': [(f"{' '.join(f'0x{t:02x}' for t in sig)}", c) for sig, c in top_sigs],
    }

# Print summary table
print(f"{'File':<42} {'Total':<7} {'Single':<7} {'Multi':<6} {'AvgFld':<7} {'UniqSig':<8} {'TopTag':<8}")
print("="*85)
for fname, a in sorted(all_analyses.items(), key=lambda x: -x[1]['total_entries']):
    print(f"{fname:<42} {a['total_entries']:<7} {a['single_tag_entries']:<7} {a['multi_tag_entries']:<6} {a['avg_fields']:<7} {a['unique_signatures']:<8} {a['common_single_tag']:<8}")

# Show detailed signatures for top 3 files
print("\n=== DETAILED SIGNATURE BREAKDOWN ===")
for fname, a in sorted(all_analyses.items(), key=lambda x: -x[1]['total_entries'])[:3]:
    print(f"\n--- {fname} ({a['total_entries']} entries) ---")
    for sig_str, count in a['top_signatures'][:15]:
        print(f"  [{count:5d}] {sig_str}")
