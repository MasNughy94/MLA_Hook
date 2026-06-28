"""
Deep binary format analysis.
Look for section tables, record patterns, repeated structures.
Focus on detecting the underlying binary serialization format.
"""

import struct, os

samples_dir = r'C:\Users\NGEONG\AppData\Local\Temp\opencode'
fn = '0000488d2f64199aca0cc7d54e7d11c0.mt.dec'
with open(os.path.join(samples_dir, fn), 'rb') as f:
    data = f.read()

HDR_SZ = 69
body = data[HDR_SZ:]

print('File: {} ({} bytes, body: {} bytes)'.format(fn, len(data), len(body)))

# ============================================================
# 1. Look for RECORD STRUCTURES - scan for repeating byte patterns
# ============================================================
print('\n' + '=' * 70)
print('1. SEARCH FOR REPEATING RECORD PATTERNS')
print('=' * 70)

# Look for records of fixed size by checking alignment
for rec_size in [4, 8, 12, 16, 20, 24, 32, 48, 64]:
    # Check if body size is divisible by this record size (roughly)
    # and look for patterns every rec_size bytes
    count = 0
    sample_vals = []
    for off in range(0, min(1024, len(body) - rec_size), rec_size):
        chunk = body[off:off+rec_size]
        # Skip all-zeros
        if all(b == 0 for b in chunk):
            continue
        count += 1
        if len(sample_vals) < 3:
            sample_vals.append(chunk.hex())
    
    if count > 10:
        print('  Rec size {:2d}: {:4d} non-zero records in first 1K | samples: {}'.format(
            rec_size, count, ', '.join(sample_vals)))

# ============================================================
# 2. Find ALL non-zero u32 values and check if they're offsets
# ============================================================
print('\n' + '=' * 70)
print('2. ALL NON-ZERO U32 VALUES THAT COULD BE OFFSETS (relative to body)')
print('=' * 70)
for off in range(0, min(4096, len(body)-4), 4):
    val = struct.unpack_from('<I', body, off)[0]
    if 0 < val < len(body):
        # Check if val aligns to u32 boundary
        alignment = '4' if val % 4 == 0 else '2' if val % 2 == 0 else '1'
        print('  [{:04x}] u32={:>8d} (0x{:04x}) aligns:{}'.format(off + HDR_SZ, val, val, alignment))

# ============================================================
# 3. Check for U16 offsets/counts
# ============================================================
print('\n' + '=' * 70)
print('3. ALL NON-ZERO U16 VALUES (possible section markers)')
print('=' * 70)
for off in range(0, min(1024, len(body)-2), 2):
    val = struct.unpack_from('<H', body, off)[0]
    if val > 0 and val < 2000:
        print('  [{:04x}] u16={}'.format(off + HDR_SZ, val))

# ============================================================
# 4. Try to interpret body as a list of VARIABLE-LENGTH records
#    Look for length-prefixed structures
# ============================================================
print('\n' + '=' * 70)
print('4. LEN-PREFIXED STRUCTURES (varint/length byte)')
print('=' * 70)
# Scan for structures where first byte is a length and next N bytes follow
for start in range(0, min(2048, len(body)-1)):
    length = body[start]
    if 1 <= length <= 200 and start + 1 + length <= len(body):
        chunk = body[start:start+1+length]
        # Check if the payload starts with specific marker
        if length >= 4:
            print('  [{:04x}] len={}: {}'.format(start + HDR_SZ, length, chunk[1:].hex()[:40]))

# ============================================================
# 5. Check for INDEX TABLE - consecutive non-zero ints
# ============================================================
print('\n' + '=' * 70)
print('5. INDEX TABLE CANDIDATES (consecutive u32 values)')
print('=' * 70)
# Look for a region where u32 values are small consecutive integers
# This would indicate an index table (0, 1, 2, 3, ... or 1, 2, 3, ...)
for off in range(0, min(2048, len(body)-16), 4):
    vals = [struct.unpack_from('<I', body, off + i*4)[0] for i in range(4)]
    if all(0 <= v <= 10000 for v in vals):
        # Check if consecutive or sequential
        diff = [vals[i+1] - vals[i] for i in range(len(vals)-1)]
        if all(0 < d <= 10 for d in diff):
            print('  [{:04x}] consecutive: {} -> diffs: {}'.format(off + HDR_SZ, vals, diff))

# ============================================================
# 6. Look for U32 arrays (potential offset tables)
# ============================================================
print('\n' + '=' * 70)
print('6. POTENTIAL POINTER TABLES (>20 consecutive valid offsets)')
print('=' * 70)
# Scan for runs of u32 values that are valid body offsets
for off in range(0, len(body)-80, 4):
    valid = 0
    for i in range(20):
        val = struct.unpack_from('<I', body, off + i*4)[0]
        if 0 < val <= len(body):
            valid += 1
    if valid >= 18:
        vals = [struct.unpack_from('<I', body, off + i*4)[0] for i in range(20)]
        print('  [{:04x}] {} valid ptrs: {}...'.format(off + HDR_SZ, valid, vals[:8]))

# ============================================================
# 7. Byte distribution analysis
# ============================================================
print('\n' + '=' * 70)
print('7. BYTE DISTRIBUTION')
print('=' * 70)
from collections import Counter
c = Counter(body)
print('  Total bytes: {}'.format(len(body)))
print('  Zero bytes: {} ({:.1f}%)'.format(c[0], c[0]/len(body)*100))
# Most common non-zero bytes
for byte_val, count in c.most_common(20):
    if byte_val > 0:
        print('    0x{:02x}: {:6d}'.format(byte_val, count))

# ============================================================
# 8. LOOK FOR SECTION HEADER MARKERS
# ============================================================
print('\n' + '=' * 70)
print('8. CHECK FOR SUB-HEADERS: first 32 bytes of body interpreted')
print('=' * 70)
sub = body[:32]
for off in range(0, 32, 4):
    val32 = struct.unpack_from('<I', sub, off)[0]
    val16 = struct.unpack_from('<H', sub, off)[0]
    print('  [{:04x}] u32={:10d} (0x{:08x}) u16={}'.format(HDR_SZ+off, val32, val32, val16))

# ============================================================
# 9. RAW HEX with section analysis numbering
# ============================================================
print('\n' + '=' * 70)
print('9. BODY FULL HEX (first 512 bytes), annotated')
print('=' * 70)
for i in range(0, min(512, len(body)), 16):
    chunk = body[i:i+16]
    hex_str = ' '.join('{:02x}'.format(b) for b in chunk)
    # Mark non-zero positions
    markers = ''
    for j, b in enumerate(chunk):
        if b == 0:
            markers += '.. '
        elif i+j < 32:
            markers += '## '  # header fields
        else:
            # Try to show pattern based on context
            markers += '{:02x} '.format(b)
    print('  {:04x}: {}'.format(HDR_SZ + i, hex_str))
