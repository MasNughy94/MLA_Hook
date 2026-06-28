"""
Deeper analysis: 
1. Check if the format is Protobuf / FlatBuffers / custom binary table
2. Look for root pointer, section tables, string table
3. Compare all 3 samples looking for structure patterns
"""

import struct, os

samples_dir = r'C:\Users\NGEONG\AppData\Local\Temp\opencode'
files = [
    '0000488d2f64199aca0cc7d54e7d11c0.mt.dec',  # 32K
    '00378c64fbd63011a81dccef6bf6e2bd.mt.dec',  # 96K  
    '008fea3143557d628ac845a13a254e8a.mt.dec',  # 23K
]

def load(fn):
    with open(os.path.join(samples_dir, fn), 'rb') as f:
        return f.read()

samples = {fn: load(fn) for fn in files}
HDR_SZ = 69

# ============================================================
# 1. Compare body sizes and structure
# ============================================================
print('=' * 70)
print('1. FILE SIZES AND DIFFERENCES')
print('=' * 70)
for fn in files:
    d = samples[fn]
    body = d[HDR_SZ:]
    print('  {:40s}: total={}, body={} ({:.1f}% header)'.format(
        fn[:40], len(d), len(body), HDR_SZ/len(d)*100))

# ============================================================
# 2. Body: is the first uint32 a section count or root pointer?
# ============================================================
print('\n' + '=' * 70)
print('2. BODY ROOT STRUCTURE INTERPRETATION')
print('=' * 70)
for fn in files:
    d = samples[fn][HDR_SZ:]  # body only
    print('\n--- {} body ({}) ---'.format(fn, len(d)))
    # Try to interpret as a table of contents
    # First u32: count of TOC entries?
    count = struct.unpack_from('<I', d, 0)[0]
    print('  [0x00] u32 toc_count={} (0x{:08x})'.format(count, count))
    
    # Read next 4 u32 to check if they're plausible section offsets
    for i in range(1, min(8, len(d)//4 - 1)):
        val = struct.unpack_from('<I', d, i*4)[0]
        if 0 < val < len(d):
            print('  [{:04x}] u32 offset->0x{:04x} ({})'.format(i*4, val, val))
    
    # Maybe the data starts with 2 u16 values
    u16_0 = struct.unpack_from('<H', d, 0)[0]
    u16_2 = struct.unpack_from('<H', d, 2)[0]
    u16_4 = struct.unpack_from('<H', d, 4)[0]
    print('  [0x00] u16={}, u16_2={}, u16_4={}'.format(u16_0, u16_2, u16_4))
    
    # Maybe it's a count of things
    if count < 200:
        print('  (small count - maybe section count)')
        # If it's a count, expect count*4 offset table next
        expected_table_size = count * 4
        if 4 + expected_table_size <= len(d):
            offsets = []
            for i in range(count):
                off = struct.unpack_from('<I', d, 4 + i*4)[0]
                offsets.append(off)
            print('  Read {} offsets: {}'.format(count, offsets[:min(10, count)]))

# ============================================================
# 3. Look at the 96K file's EXTRA data (beyond 32K)
# ============================================================
print('\n' + '=' * 70)
print('3. 96K FILE extra data (what makes it 3x larger)')
print('=' * 70)
d0 = samples[files[0]][HDR_SZ:]  # 32K
d1 = samples[files[1]][HDR_SZ:]  # 96K

# Show where d1 has data beyond d0's size
print('  File 0 ends at {}'.format(len(d0)))
print('  File 1 extends to {}'.format(len(d1)))
print('  Extra region ({}..{}):'.format(len(d0), len(d0)+512))
extra = d1[len(d0):min(len(d0)+1024, len(d1))]
for i in range(0, len(extra), 32):
    chunk = extra[i:i+32]
    hex_str = ' '.join('{:02x}'.format(b) for b in chunk)
    non_zero = sum(1 for b in chunk if b != 0)
    if non_zero > 0:
        print('  [{:06x}] {} ({} non-zero)'.format(
            len(d0) + i + HDR_SZ, hex_str, non_zero))

# ============================================================
# 4. TEST: Is this a TRIE data structure?
# ============================================================
print('\n' + '=' * 70)
print('4. TESTING FOR TRIE / PREFIX TREE ENCODING')
print('=' * 70)

# In a trie, each node would have: children pointer, end-of-word flag, value
# Looking at the 3-byte records: key value1 value2
# If it's a trie: key=byte, value1=first_child, value2=sibling

for fn in files:
    d = samples[fn][HDR_SZ:]
    # Scan for 3-byte records within non-zero regions
    trie_candidates = []
    for off in range(0, min(4096, len(d)-3)):
        if d[off] != 0 and d[off+1] != 0:  # non-zero key and first value
            trie_candidates.append((off, d[off], d[off+1], d[off+2]))
    
    # Find consecutive records with same key
    print('\n--- {} (first 100 non-zero records) ---'.format(fn))
    for off, k, v1, v2 in trie_candidates[:100]:
        print('    [{:04x}] key=0x{:02x}, v1=0x{:02x}, v2=0x{:02x}'.format(off + HDR_SZ, k, v1, v2))

# ============================================================
# 5. Check if it's a BINARY JSON (BSON-like) format
# ============================================================
print('\n' + '=' * 70)
print('5. CHECK FOR BSON/PROTOBUF ELEMENT TYPES')
print('=' * 70)

# In protobuf, the first byte would be a tag: (field_number << 3) | wire_type
# Wire types: 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit

for fn in files:
    d = samples[fn]
    print('\n--- {} ---'.format(fn))
    for off in range(HDR_SZ, min(HDR_SZ + 128, len(d))):
        b = d[off]
        if b == 0:
            continue
        # Check if this looks like a protobuf tag
        field_num = b >> 3
        wire_type = b & 7
        if field_num > 0 and wire_type <= 5:
            # Valid protobuf tag
            if off + 1 < len(d):
                next_b = d[off+1]
                print('  [0x{:04x}] tag=0x{:02x}: field={}, wire_type={} | next=0x{:02x}'.format(
                    off, b, field_num, wire_type, next_b))
