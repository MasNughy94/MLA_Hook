"""
Now that the 3-byte record structure is confirmed, analyze the ENTRY STRUCTURE.
Find repeating patterns in tag sequences to determine entry boundaries.
"""
import os, struct
from collections import defaultdict, Counter

def analyze_tags(body):
    """Parse body as 3-byte records, return list of (offset, tag, v1, v2)."""
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        records.append((i, tag, v1, v2))
    return records

def find_entry_pattern(records):
    """
    Find the entry structure by looking for repeating tag patterns.
    Return tags that are frequently seen together.
    """
    # Filter to non-zero-tag records only
    nz_tags = [(offset, tag, v1, v2) for offset, tag, v1, v2 in records if tag != 0]
    
    # Find positions of each unique tag
    tag_positions = defaultdict(list)
    for offset, tag, v1, v2 in nz_tags:
        tag_positions[tag].append(offset)
    
    # For each tag, find the gap between consecutive occurrences
    print("Gap analysis (offset deltas between consecutive occurrences of the same tag):")
    tag_gaps = {}
    for tag, positions in sorted(tag_positions.items(), key=lambda x: -len(x[1])):
        if len(positions) >= 3:
            gaps = [positions[i+1] - positions[i] for i in range(len(positions)-1)]
            min_gap = min(gaps)
            max_gap = max(gaps)
            avg_gap = sum(gaps) / len(gaps)
            common_gap = Counter(gaps).most_common(1)[0]
            ch = chr(tag) if 32 <= tag < 127 else '.'
            print(f"  0x{tag:02x} ({ch}): {len(positions):3d} occurrences, gap min={min_gap:4d} avg={avg_gap:6.1f} max={max_gap:4d} mode={common_gap[0]} (x{common_gap[1]})")
            tag_gaps[tag] = (avg_gap, common_gap[0])
    
    return nz_tags, tag_positions, tag_gaps

def detect_entries_by_tag_set(nz_tags, tag_positions):
    """
    Detect entry boundaries by looking at which tags appear together.
    If entries are separate, each entry would have its own set of tags.
    """
    # Sort all non-zero-tag records by offset
    sorted_records = sorted(nz_tags, key=lambda x: x[0])
    
    # Look for "START OF ENTRY" markers
    # An entry might start with a specific tag pattern
    print("\n\n--- Entry boundary detection ---")
    
    # Check: do tags appear in a FIXED ORDER within each entry?
    # If yes, we'd see tag sequences like: a, b, c, d, a, b, c, d, ...
    
    # Get just the tag sequence
    tag_seq = [tag for _, tag, _, _ in sorted_records]
    
    # Look for repetitions of the first few tags
    if len(tag_seq) > 10:
        first_few = tag_seq[:10]
        print(f"First 10 non-zero tags in sequence: {[f'0x{t:02x}' for t in first_few]}")
    
    # Check if the sequence is periodic (same tags repeating in order)
    # Try to find the period
    for period in range(5, 100):
        if period * 5 > len(tag_seq):
            break
        # Check if tags at positions 0..period-1 repeat at positions period..2*period-1
        match = True
        for i in range(period):
            if len(tag_seq) <= i + period:
                match = False
                break
            if tag_seq[i] != tag_seq[i + period]:
                match = False
                break
        if match:
            first_period_tags = tag_seq[:period]
            non_zero_period = sum(1 for t in first_period_tags if t != 0)
            if non_zero_period >= 5:  # at least 5 non-zero tags
                print(f"\n*** FOUND PERIODIC TAG SEQUENCE: period={period} ***")
                print(f"  Tags: {[f'0x{t:02x}' for t in first_period_tags]}")
                break

def analyze_entry_layout_from_file(filepath):
    """Analyze a single file for entry structure."""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    HDR = 69
    body = data[HDR:]
    
    print(f"File: {os.path.basename(filepath)}")
    print(f"Body size: {len(body)} bytes ({len(body)//3} records)")
    
    records = analyze_tags(body)
    nz_tags, tag_positions, tag_gaps = find_entry_pattern(records)
    
    # Try to detect entry structure
    detect_entries_by_tag_set(nz_tags, tag_positions)
    
    return records, nz_tags, tag_positions, tag_gaps

def compare_entry_structures(file1_path, file2_path):
    """Compare the tag structures of two files to find common entry boundaries."""
    _, nz1, pos1, gaps1 = analyze_entry_layout_from_file(file1_path)
    print("\n" + "="*60)
    _, nz2, pos2, gaps2 = analyze_entry_layout_from_file(file2_path)
    
    # Compare tags used in both files
    tags1 = set(t for _, t, _, _ in nz1)
    tags2 = set(t for _, t, _, _ in nz2)
    common = tags1 & tags2
    only1 = tags1 - tags2
    only2 = tags2 - tags1
    
    print(f"\n=== Tag comparison ===")
    print(f"Tags in file 1: {len(tags1)}")
    print(f"Tags in file 2: {len(tags2)}")
    print(f"Common tags: {len(common)}")
    print(f"Tags only in file 1 ({len(only1)}): {[f'0x{t:02x}' for t in sorted(only1)[:20]]}")
    print(f"Tags only in file 2 ({len(only2)}): {[f'0x{t:02x}' for t in sorted(only2)[:20]]}")
    
    # Check if file 2 tags are ALL uppercase/symbols and file 1 has lowercase
    f1_lower = sum(1 for t in tags1 if ord('a') <= t <= ord('z'))
    f1_upper = sum(1 for t in tags1 if ord('A') <= t <= ord('Z'))
    f2_lower = sum(1 for t in tags2 if ord('a') <= t <= ord('z'))
    f2_upper = sum(1 for t in tags2 if ord('A') <= t <= ord('Z'))
    
    print(f"\nFile 1: lowercase tags={f1_lower}, uppercase tags={f1_upper}")
    print(f"File 2: lowercase tags={f2_lower}, uppercase tags={f2_upper}")

if __name__ == '__main__':
    samples_dir = r'C:\Users\NGEONG\AppData\Local\Temp\opencode'
    fn1 = '0000488d2f64199aca0cc7d54e7d11c0.mt.dec'
    fn2 = '008fea3143557d628ac845a13a254e8a.mt.dec'
    fn3 = '00378c64fbd63011a81dccef6bf6e2bd.mt.dec'
    
    f1 = os.path.join(samples_dir, fn1)
    f2 = os.path.join(samples_dir, fn2)
    f3 = os.path.join(samples_dir, fn3)
    
    print("=" * 60)
    print("FILE 1 ANALYSIS")
    print("=" * 60)
    records1, nz1, pos1, gaps1 = analyze_entry_layout_from_file(f1)
    
    print("\n" + "=" * 60)
    print("FILE 2 ANALYSIS") 
    print("=" * 60)
    records2, nz2, pos2, gaps2 = analyze_entry_layout_from_file(f2)
    
    print("\n" + "=" * 60)
    print("FILE 3 ANALYSIS (LARGE FILE)")
    print("=" * 60)
    records3, nz3, pos3, gaps3 = analyze_entry_layout_from_file(f3)
    
    print("\n" + "=" * 60)
    print("CROSS-FILE COMPARISON")
    print("=" * 60)
    compare_entry_structures(f1, f2)
