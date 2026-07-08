"""
Find the entry/section size by autocorrelation analysis.
Also try to group records into entries.
"""
import os, struct
from collections import defaultdict, Counter

samples_dir = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode'

for fname in [
    '0000488d2f64199aca0cc7d54e7d11c0.mt.dec',
    '008fea3143557d628ac845a13a254e8a.mt.dec',
]:
    with open(os.path.join(samples_dir, fname), 'rb') as f:
        data = f.read()
    
    HDR = 69
    body = data[HDR:]
    
    print(f"\n{'='*60}")
    print(f"File: {fname}")
    print(f"{'='*60}")
    
    # Find positions of all non-zero bytes
    nz_positions = [i for i, b in enumerate(body) if b != 0]
    
    # Compute autocorrelation: for each possible period, count how many
    # non-zero bytes are at the same relative position
    print("\nAutocorrelation of non-zero byte positions:")
    print("(looking for the period that aligns most non-zero bytes)")
    
    # For each 3-byte position (0,1,2 within each 3-byte group),
    # check if non-zero bytes repeat at that position
    for phase in range(3):
        phase_positions = [i for i in nz_positions if i % 3 == phase]
        print(f"  Phase {phase} (byte position in record): {len(phase_positions)} non-zero bytes")
        
        if len(phase_positions) > 10:
            # Find gaps between consecutive phase-aligned non-zero bytes
            gaps = [phase_positions[j+1] - phase_positions[j] for j in range(len(phase_positions)-1)]
            gap_counter = Counter(gaps)
            common_gaps = gap_counter.most_common(10)
            print(f"  Common byte-gaps at this phase:")
            for gap, count in common_gaps:
                rec_count = gap / 3 if gap % 3 == 0 else gap
                print(f"    {gap:4d} bytes ({gap/3:6.1f} records): {count}x")
    
    # Look for the 3-byte record structure around each non-zero byte
    # If the format is [tag, v1, v2], then:
    # Phase 0 positions = tag bytes
    # Phase 1 positions = v1 bytes
    # Phase 2 positions = v2 bytes
    
    tag_positions = [i for i in nz_positions if i % 3 == 0]
    v1_positions = [i for i in nz_positions if i % 3 == 1]
    v2_positions = [i for i in nz_positions if i % 3 == 2]
    
    print(f"\n  3-byte aligned positions:")
    print(f"    Tags (offset%3==0): {len(tag_positions)}")
    print(f"    V1    (offset%3==1): {len(v1_positions)}")
    print(f"    V2    (offset%3==2): {len(v2_positions)}")
    total = len(tag_positions) + len(v1_positions) + len(v2_positions)
    print(f"    Total: {total} (body has {len(nz_positions)} non-zero bytes)")
    
    # If the 3-byte alignment is correct, ALL non-zero bytes should be captured
    # AND we can analyze the distribution
    print(f"\n  Tag-value correlation for non-zero records:")
    
    # Parse as 3-byte records
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        records.append((i, tag, v1, v2))
    
    # Count records that have tag=0 but non-zero v1/v2
    tag0_nz = [(off, t, v1, v2) for off, t, v1, v2 in records if t == 0 and (v1 != 0 or v2 != 0)]
    print(f"  Records with tag=0 but non-zero v1/v2: {len(tag0_nz)}")
    if tag0_nz:
        tag0_v2_counts = Counter(v2 for _, _, _, v2 in tag0_nz)
        print(f"  Top V2 values for tag=0 records: {tag0_v2_counts.most_common(10)}")
    
    # Count records with non-zero tag
    nz_records = [(off, t, v1, v2) for off, t, v1, v2 in records if t != 0]
    print(f"\n  Non-zero tag records: {len(nz_records)}")
    
    # For each tag, what are the most common (v1, v2) patterns?
    # Focus on tags with both V1 and V2 non-zero (these are likely the "data" records)
    data_records = [(off, t, v1, v2) for off, t, v1, v2 in nz_records if v1 != 0 and v2 != 0]
    print(f"  Records with all 3 bytes non-zero: {len(data_records)}")
    
    # Try to identify "field groups" â€” sets of tags that appear together within a short span
    # This would reveal the entry structure
    print(f"\n  --- Co-occurring tag groups ---")
    
    # Look at windows of consecutive non-zero-tag records
    # If entries are contiguous blocks of non-zero-tag records, find block boundaries
    
    # For each record, what's its index in the list of non-zero-tag records?
    nz_indices = sorted([off for off, t, v1, v2 in nz_records])
    
    # Find blocks where consecutive non-zero-tag records are close together
    # A gap > some threshold indicates a block boundary
    blocks = []
    if nz_indices:
        current_block = [nz_indices[0]]
        for i in range(1, len(nz_indices)):
            gap = nz_indices[i] - nz_indices[i-1]
            if gap > 30:  # threshold: 30 bytes = 10 records gap means new block
                blocks.append(current_block)
                current_block = [nz_indices[i]]
            else:
                current_block.append(nz_indices[i])
        blocks.append(current_block)
    
    print(f"  Blocks (gap threshold 30 bytes): {len(blocks)}")
    block_sizes = [len(b) for b in blocks]
    print(f"  Block sizes: min={min(block_sizes)} max={max(block_sizes)} avg={sum(block_sizes)/len(block_sizes):.1f}")
    
    size_counter = Counter(block_sizes)
    print(f"  Most common block sizes:")
    for sz, cnt in size_counter.most_common(10):
        print(f"    {sz:4d} records: {cnt}x")
    
    # Show the tag sets of a few blocks
    print(f"\n  First 5 blocks (tags in each):")
    for b_idx, block in enumerate(blocks[:5]):
        block_tags = []
        for off in block:
            # Find the record at this offset
            match = [t for o, t, v1, v2 in nz_records if o == off]
            if match:
                block_tags.append(f'0x{match[0]:02x}')
        print(f"    Block {b_idx}: {', '.join(block_tags[:20])}..." if len(block_tags) > 20 else f"    Block {b_idx}: {', '.join(block_tags)}")
    
    # Check number of blocks against the first body value
    first_nz = body[body.find(next(b for b in body if b != 0))] if any(b != 0 for b in body) else 0
    print(f"\n  First non-zero body byte: 0x{first_nz:02x} = {first_nz}")
    print(f"  Number of blocks: {len(blocks)}")
    if first_nz == len(blocks):
        print(f"  *** MATCH: First byte = number of blocks! ({first_nz}) ***")
    elif first_nz > 0:
        print(f"  Ratio blocks/first_byte: {len(blocks)/first_nz:.2f}")
