"""
Analyze heterogeneous files where each entry can be a different entity type.
Groups entries by tag pattern to discover embedded entity types.
"""
import os, json
from collections import defaultdict

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\dec_batch'

# Files from the 55f_255t and 2f_254t clusters
SAMPLES = [
    '0217cbdae530696836de83aa3c162e1a.mt.dec',  # 2980 entries
    '07b5cc5ea4a8d86273be8170720a4587.mt.dec',  # 13133 entries
    '0e3bbac67f12505f7dfe45d4e6aba1ea.mt.dec',  # 1035 entries
]

def parse_file(path):
    with open(path, 'rb') as f:
        data = f.read()
    body = data[HDR_SIZE:]
    
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        if tag != 0:
            val = v1 | (v2 << 8)
            records.append({'offset': i, 'tag': tag, 'val': val, 'v1': v1, 'v2': v2})
    
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
    
    return os.path.basename(path), records, entries

def entry_signature(entry):
    """Create a signature for an entry based on tags and their position pattern."""
    # Tag signature: ordered list of (tag, v1_byte, v2_byte)
    # Use V1/V2 bytes to differentiate sub-types
    sig_parts = []
    for ridx, r in enumerate(entry):
        sig_parts.append(f"{r['tag']:02x}")
    return '+'.join(sig_parts)

def analyze_heterogeneous_file(fpath):
    """Analyze a heterogeneous file by grouping entries by their signature."""
    name, records, entries = parse_file(fpath)
    
    print(f"\n{'='*70}")
    print(f"FILE: {name}")
    print(f"Total entries: {len(entries)}")
    print(f"{'='*70}")
    
    # Group entries by tag signature
    sig_groups = defaultdict(list)
    for eidx, entry in enumerate(entries):
        sig = entry_signature(entry)
        sig_groups[sig].append(eidx)
    
    # Sort groups by size (descending)
    sorted_groups = sorted(sig_groups.items(), key=lambda x: -len(x[1]))
    
    print(f"\nDistinct entry types (tag patterns): {len(sorted_groups)}")
    print(f"\nTop 30 entry type groups:")
    print(f"{'Rank':<5} {'Count':<8} {'Fields':<8} {'Tag Signature':<60} {'Sample Tags+Values'}")
    print("-" * 120)
    
    for rank, (sig, indices) in enumerate(sorted_groups[:30]):
        entry0 = entries[indices[0]]
        pct = len(indices) / len(entries) * 100
        
        # Show sample field values from first entry of this type
        sample_vals = []
        for r in entry0[:5]:
            tc = chr(r['tag']) if 32 <= r['tag'] < 127 else '.'
            sample_vals.append(f"0x{r['tag']:02x}('{tc}')={r['val']}")
        sample_str = ', '.join(sample_vals)
        if len(entry0) > 5:
            sample_str += f" ... +{len(entry0)-5}"
        
        print(f"  {rank:<4} {len(indices):<8} {len(entry0):<8} {sig[:55]:<60} {sample_str[:60]}")
    
    # Now analyze each group separately
    print(f"\n\n{'='*70}")
    print("DETAILED ANALYSIS OF EACH ENTRY TYPE GROUP")
    print(f"{'='*70}")
    
    for rank, (sig, indices) in enumerate(sorted_groups[:20]):
        entry0 = entries[indices[0]]
        
        # Collect field values across all entries of this type
        field_values = defaultdict(list)
        field_tags = {}
        
        for idx in indices:
            entry = entries[idx]
            for ridx, r in enumerate(entry):
                field_values[ridx].append(r['val'])
                if ridx not in field_tags:
                    field_tags[ridx] = r['tag']
        
        print(f"\n--- Type {rank}: {len(indices)} entries, {len(entry0)} fields ---")
        print(f"  Sample indices: {indices[:5]}")
        
        for pos in range(len(entry0)):
            if pos not in field_values:
                continue
            vals = field_values[pos]
            svals = sorted(set(vals))
            tag = field_tags[pos]
            tc = chr(tag) if 32 <= tag < 127 else '.'
            
            notes = []
            # Check if constant
            if len(svals) == 1:
                notes.append(f"CONST({svals[0]})")
            # Check flag
            elif set(vals) <= {0, 1}:
                notes.append("FLAG")
            # Check enum
            elif len(svals) <= 8 and len(vals) > len(svals) * 2:
                notes.append(f"ENUM({len(svals)})")
            # Check sequential ID
            elif len(svals) == len(vals) and len(vals) > 3:
                notes.append(f"UNIQUE_ID")
                if svals == list(range(min(svals), min(svals) + len(svals))):
                    notes.append("SEQ")
            # Check range
            if max(vals) <= 100:
                notes.append("PCT")
            elif max(vals) <= 1000:
                notes.append("SMALL")
            elif max(vals) >= 50000:
                notes.append("LARGE")
            
            note_str = f" [{'; '.join(notes)}]" if notes else ""
            print(f"    pos={pos:2d} tag=0x{tag:02x}('{tc}') "
                  f"[{min(vals):>6}-{max(vals):>6}] uniq={len(svals):>3}/{len(vals):<4}{note_str}")
    
    return sorted_groups

# Analyze the main file
groups = analyze_heterogeneous_file(os.path.join(DEC_BATCH, SAMPLES[0]))

# Summary
print(f"\n\n{'='*70}")
print("SUMMARY: ENTITY TYPES FOUND")
print(f"{'='*70}")

for rank, (sig, indices) in enumerate(groups[:20]):
    entry0 = parse_file(os.path.join(DEC_BATCH, SAMPLES[0]))[2][indices[0]]
    field_types = []
    for r in entry0:
        if r['val'] <= 1:
            field_types.append('FLAG')
        elif r['val'] <= 5:
            field_types.append('ENUM(1-5)')
        elif r['val'] <= 8:
            field_types.append(f'ENUM(1-8)')
        elif r['val'] <= 100:
            field_types.append('PCT')
        elif r['val'] <= 1000:
            field_types.append('SMALL')
        else:
            field_types.append('LARGE')
    print(f"  Type {rank}: {len(indices)} entries, {len(entry0)} fields")
    print(f"    Field categories: {field_types[:10]}...")
