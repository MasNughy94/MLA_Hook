"""
Fundamentally re-examine the Roo record stream. Instead of gap-based entry
clustering, look at the raw record stream to understand the actual structure.
"""
import os, struct
from collections import defaultdict, Counter

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\dec_batch'

def parse_raw_records(path):
    """Parse file into raw 3-byte records without any grouping."""
    with open(path, 'rb') as f:
        data = f.read()
    body = data[HDR_SIZE:]
    
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        val = v1 | (v2 << 8)
        records.append({'offset': i, 'tag': tag, 'val': val, 'v1': v1, 'v2': v2})
    return os.path.basename(path), records, body

def tag_value_distribution(records):
    """Show what values each tag takes."""
    tag_vals = defaultdict(list)
    for r in records:
        tag_vals[r['tag']].append(r['val'])
    
    print(f"\n{'='*70}")
    print("TAG DISTRIBUTION (tags with >50 occurrences)")
    print(f"{'='*70}")
    print(f"{'Tag':<8} {'Char':<6} {'Count':<8} {'Range':<18} {'Unique':<8} {'Typical Values'}")
    print("-" * 90)
    
    for tag in sorted(tag_vals.keys()):
        vals = tag_vals[tag]
        if len(vals) <= 50:
            continue
        svals = sorted(set(vals))
        tc = chr(tag) if 32 <= tag < 127 else '.'
        
        # Show representative values
        if len(svals) <= 10:
            typ = str(svals)
        else:
            typ = f"[{min(svals)}..{max(svals)}]"
        
        # Check for known ID ranges
        notes = []
        if max(vals) >= 20000:
            notes.append("LARGE")
        if min(vals) >= 2000 and max(vals) <= 6000:
            notes.append("HERO_ID?")
        if min(vals) >= 1300 and max(vals) <= 74000:
            notes.append("SKILL_ID?")
        if min(vals) >= 60000 and max(vals) <= 180000:
            notes.append("ITEM_ID?")
        if len(svals) <= 5 and len(vals) > 50:
            notes.append(f"ENUM({len(svals)})")
        if set(vals) <= {0, 1}:
            notes.append("FLAG")
        
        print(f"  0x{tag:02x}   '{tc}'   {len(vals):<8} [{min(vals):>6}-{max(vals):>6}] {len(svals):<8} {' '.join(notes)}")

def detect_entry_sentinels(records):
    """Look for tag=0x00 records which might be entry separators."""
    zeros = [r for r in records if r['tag'] == 0x00]
    nonzeros = [r for r in records if r['tag'] != 0x00]
    print(f"\n{'='*70}")
    print(f"ZERO-TAG RECORDS (possible entry separators): {len(zeros)}")
    print(f"NON-ZERO RECORDS: {len(nonzeros)}")
    print(f"{'='*70}")
    
    if zeros:
        ranges = []
        zero_offsets = [r['offset'] for r in zeros]
        for i, off in enumerate(zero_offsets[:30]):
            v1, v2 = records[off // 3]['v1'] if off // 3 < len(records) else (0,0)
            print(f"  zero[{i}] offset={off:>6} v1={v1:>3} v2={v2:>3} val={v1|(v2<<8):>6}")
        
        # Check interval between zero tags
        if len(zero_offsets) > 1:
            intervals = [zero_offsets[i+1] - zero_offsets[i] for i in range(len(zero_offsets)-1)]
            print(f"  Zero-tag intervals: min={min(intervals)}, max={max(intervals)}, avg={sum(intervals)//len(intervals)}")
            # Show gap distribution
            gap_counter = Counter(intervals)
            print(f"  Top interval sizes: {gap_counter.most_common(20)}")

def find_template_records(records):
    """Identify template records: records at specific offsets that define defaults."""
    # In our earlier analysis, position 0-4 were always present
    # Let's find all records and see if there's an offset-based structure
    tag_seq = [(i, r['tag'], r['val']) for i, r in enumerate(records[:200])]
    
    print(f"\n{'='*70}")
    print("FIRST 100 RECORDS IN SEQUENCE")
    print(f"{'='*70}")
    print(f"{'Idx':<6} {'Off':<8} {'Tag':<8} {'Val':<8} {'V1':<6} {'V2':<6}")
    print("-" * 50)
    for idx, tag, val in tag_seq[:100]:
        tc = chr(tag) if 32 <= tag < 127 else '.'
        off = idx * 3
        v1 = val & 0xFF
        v2 = (val >> 8) & 0xFF
        print(f"{idx:<6} {off:<8} 0x{tag:02x}('{tc}') {val:<8} {v1:<6} {v2:<6}")

def analyze_by_object_type(records):
    """
    Analyze the record stream by looking at repeated sequences.
    If the game serializes Lua objects, each object might have a set of keys.
    """
    # Count all unique (tag, v1, v2) triples
    triple_counts = Counter()
    for r in records:
        triple_counts[(r['tag'], r['v1'], r['v2'])] += 1
    
    print(f"\n{'='*70}")
    print(f"UNIQUE (tag, v1, v2) triples: {len(triple_counts)}")
    print(f"MOST COMMON TRIPLES:")
    print(f"{'='*70}")
    
    for (tag, v1, v2), cnt in triple_counts.most_common(30):
        tc = chr(tag) if 32 <= tag < 127 else '.'
        val = v1 | (v2 << 8)
        print(f"  0x{tag:02x}('{tc}') v1={v1:>3} v2={v2:>3} val={val:>6} x {cnt}")
    
    # Check if tag=0xFF or similar is used as a delimiter
    ff_records = [r for r in records if r['tag'] == 0xFF]
    print(f"\nTag=0xFF records: {len(ff_records)}")
    if ff_records:
        ff_vals = Counter(r['val'] for r in ff_records)
        print(f"  Values: {ff_vals.most_common(20)}")

# Run on the main file
fpath = os.path.join(DEC_BATCH, '0217cbdae530696836de83aa3c162e1a.mt.dec')
name, records, body = parse_raw_records(fpath)

print(f"File: {name}")
print(f"Body size: {len(body)} bytes = {len(body)/3:.0f} records")
print(f"Total records: {len(records)}")

tag_value_distribution(records)
detect_entry_sentinels(records)
find_template_records(records)
analyze_by_object_type(records)

# Now also look at adjacent record pairs to find patterns
print(f"\n{'='*70}")
print("ADJACENT RECORD TAG PATTERNS (first 300 records)")
print(f"{'='*70}")
pairs = ""
for i in range(min(300, len(records))):
    tc = chr(records[i]['tag']) if 32 <= records[i]['tag'] < 127 else '.'
    pairs += tc
print(pairs)

# Show as hex
hex_pairs = ""
for i in range(min(300, len(records))):
    hex_pairs += f"{records[i]['tag']:02x} "
print(hex_pairs)
