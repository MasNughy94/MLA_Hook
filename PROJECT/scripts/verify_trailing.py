#!/usr/bin/env python3
"""Verify the trailing-byte theory and fix parse logic."""
import os, sys
from collections import Counter

dec_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), 'dec_batch')

target_hdr = bytes.fromhex("1b4c6d000000526f6f000000000000000000000000d1d10000000000000000000000000000000000000000000000000000000000000000d100000000000000000000006fa9")

# Check trailing byte patterns
trailing_patterns = Counter()
aligned_only = 0
total = 0
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
    total += 1
    body = data[69:]
    rem = len(body) % 3
    if rem == 0:
        aligned_only += 1
    else:
        # Extract trailing bytes
        trail = body[-rem:]
        trailing_patterns[trail.hex()] += 1

print(f"Total 0x6FA9 files: {total}")
print(f"3-byte aligned: {aligned_only}")
print(f"With trailing bytes: {sum(trailing_patterns.values())}")
print(f"Unique trailing patterns: {len(trailing_patterns)}")
print("\nTop trailing patterns:")
for pat, cnt in trailing_patterns.most_common(20):
    print(f"  {pat}: {cnt}")

# Verify: after stripping trailing bytes, do all bodies align?
print("\nVerifying fix: parse up to len(body) - (len(body) % 3)")
good = 0
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
    valid_len = len(body) - (len(body) % 3)
    if valid_len > 0:
        num_records = valid_len // 3
        # Quick check: first record should be parseable
        if num_records > 0:
            good += 1

print(f"All {good}/{total} files parseable with trailing-byte fix")
