#!/usr/bin/env python3
"""Investigate why so many files fail 3-byte alignment."""
import os, sys
from collections import defaultdict, Counter

dec_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), 'dec_batch')

# Find files with main header (0x6FA9) that fail 3-byte alignment
target_hdr = bytes.fromhex("1b4c6d000000526f6f000000000000000000000000d1d10000000000000000000000000000000000000000000000000000000000000000d100000000000000000000006fa9")

failing = []
passing = []
for fname in sorted(os.listdir(dec_dir)):
    if not fname.endswith('.dec'):
        continue
    path = os.path.join(dec_dir, fname)
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) < 69:
        continue
    if data[:69] != target_hdr:
        continue
    body = data[69:]
    if len(body) % 3 != 0:
        failing.append((fname, len(data), len(body), len(body) % 3, body[:32].hex()))
    else:
        passing.append((fname, len(data), len(body)))

print(f"Files with 0x6FA9 header: {len(failing) + len(passing)}")
print(f"  Passing (3-aligned): {len(passing)}")
print(f"  Failing (not 3-aligned): {len(failing)}")

# Analyze failing files
body_mod_counts = Counter()
for fname, sz, bsz, mod, first32 in failing[:50]:
    body_mod_counts[mod] += 1

print(f"\nBody mod values: {dict(body_mod_counts)}")

# Try different header offsets
for offset_try in [0, 69, 72, 68, 96, 64, 80, 48]:
    aligned = 0
    not_aligned = 0
    for fname, sz, bsz, mod, first32 in failing[:100]:
        with open(os.path.join(dec_dir, fname), 'rb') as f:
            data = f.read()
        if len(data) > offset_try:
            body = data[offset_try:]
            if len(body) % 3 == 0:
                aligned += 1
            else:
                not_aligned += 1
    print(f"  Offset {offset_try}: {aligned} aligned, {not_aligned} not aligned")

# Check: maybe the body has a trailing byte that's the 0x6F variant?
print("\n\nChecking last bytes of failing files:")
for fname, sz, bsz, mod, first32 in failing[:5]:
    path = os.path.join(dec_dir, fname)
    with open(path, 'rb') as f:
        data = f.read()
    body = data[69:]
    print(f"\n{fname}: body={len(body)}, mod3={len(body)%3}")
    print(f"  Last 8 bytes: {body[-8:].hex()}")
    # Check if removing last byte makes it align
    if (len(body) - 1) % 3 == 0:
        print(f"  Removing last byte makes 3-aligned!")
    if (len(body) - 2) % 3 == 0:
        print(f"  Removing last 2 bytes makes 3-aligned!")
    # What if offset is 68?
    if len(data) > 68:
        body68 = data[68:]
        print(f"  Offset 68 body: {len(body68)}, mod3={len(body68)%3}")
    # What about offset 70?
    if len(data) > 70:
        body70 = data[70:]
        print(f"  Offset 70 body: {len(body70)}, mod3={len(body70)%3}")

# Show first few records of a failing file
print("\n\nSample failing files structure:")
for fname, sz, bsz, mod, first32 in failing[:3]:
    path = os.path.join(dec_dir, fname)
    with open(path, 'rb') as f:
        data = f.read()
    body = data[69:]
    print(f"\n{fname}:")
    print(f"  Body length: {len(body)}, mod {len(body)%3}")
    # Try to find where the 3-byte alignment breaks
    # Look for non-zero patterns
    for start in range(3):
        body_try = body[start:]
        if len(body_try) >= 12:
            recs = [body_try[i:i+3].hex() for i in range(0, min(30, len(body_try)), 3)]
            print(f"  Start offset {start} records: {recs[:10]}")
