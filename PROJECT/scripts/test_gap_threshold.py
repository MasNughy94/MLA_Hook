"""
Test multiple gap thresholds to find the true entity boundaries.
If Roo files are document stores, large entries should emerge at the right threshold.
"""
import os, sys, json
from collections import Counter, defaultdict
sys.path.insert(0, r'C:\Users\NGEONG\AppData\Local\Temp\opencode')
from roo_parser_final import RooBinaryFormat

BATCH_DIR = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\dec_batch'

# Pick a 255-tag file with ~3000 entries
fname = '0217cbdae530696836de83aa3c162e1a'
fpath = os.path.join(BATCH_DIR, fname + '.mt.dec')

with open(fpath, 'rb') as f:
    data = f.read()

for gap_threshold in [30, 90, 150, 300, 600, 1500, 3000, 6000, 15000]:
    parser = RooBinaryFormat(data)
    parser.cluster_entries(gap_threshold=gap_threshold)
    
    sig_counts = Counter()
    for entry in parser.entries:
        sig = tuple(sorted(set(rec[1] for rec in entry)))
        sig_counts[sig] += 1
    
    total = len(parser.entries)
    unique_sigs = len(sig_counts)
    top_sig, top_cnt = sig_counts.most_common(1)[0]
    top_pct = 100 * top_cnt / total
    avg_fields = sum(len(e) for e in parser.entries) / max(total, 1)
    max_fields = max(len(e) for e in parser.entries) if total > 0 else 0
    min_fields = min(len(e) for e in parser.entries) if total > 0 else 0
    
    print(f"Gap={gap_threshold:>5d}: entries={total:>5d} sigs={unique_sigs:>5d} "
          f"top_sig={top_cnt:>4d}({top_pct:>4.1f}%) "
          f"fields=[{min_fields}-{max_fields}, avg={avg_fields:.1f}]")

# Also show template structure
parser = RooBinaryFormat(data)
print(f"\n\nTemplate positions: {len(parser.template_records)}")
print(f"Override positions: {len(parser.override_records)}")
print(f"Empty slots:        {len(parser.empty_records)}")
print(f"Total body records: {len(parser.records)}")

# Wait, check: template records should define ALL field defaults
# Let me look at template positions
temp_positions = [rec[0] // 3 for rec in parser.template_records]
over_positions = [rec[0] // 3 for rec in parser.override_records]
empty_positions = [rec[0] // 3 for rec in parser.empty_records]

print(f"\nRecord index ranges:")
print(f"  Body slots: 0-{len(parser.records)-1}")
print(f"  Template slots: min={min(temp_positions)}, max={max(temp_positions)}" if temp_positions else "  Template slots: none")
print(f"  Override slots: min={min(over_positions)}, max={max(over_positions)}" if over_positions else "  Override slots: none")

# Are template positions contiguous or scattered?
temp_positions.sort()
if temp_positions:
    gaps = [temp_positions[i+1] - temp_positions[i] for i in range(len(temp_positions)-1)]
    max_t_gap = max(gaps)
    avg_t_gap = sum(gaps) / len(gaps) if gaps else 0
    print(f"  Template gaps: max={max_t_gap}, avg={avg_t_gap:.1f}")
    print(f"  Template span: {temp_positions[-1] - temp_positions[0] + 1} slots")
    print(f"  Template density: {len(temp_positions)}/{len(parser.records)} = {100*len(temp_positions)/len(parser.records):.1f}%")

# Also check: do template positions form a PHASED pattern?
phases = defaultdict(list)
for p in temp_positions:
    phases[p % 3].append(p)
for phase, positions in sorted(phases.items()):
    print(f"  Template positions at index %3 == {phase}: {len(positions)} positions")
