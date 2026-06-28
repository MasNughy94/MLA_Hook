import struct

with open(r'C:\Users\NGEONG\Videos\MLA\libagame.so', 'rb') as f:
    data = f.read()

# The decompression function uses lookup tables at:
# T1: 0xf63000 (x6 base, base+0x400, base+0x800, base+0xc00)
T1_BASE = 0xf63000
# T2: 0xf64000 + 0x1c0 - 0x100 = 0xf640c0
T2_BASE = 0xf640c0

# Table 1: 4 sub-tables of 256 u32 entries each
print("=== Table 1 at 0xf63000 (4 * 256 u32) ===")
for ti in range(4):
    offset = T1_BASE + ti * 0x400
    vals = struct.unpack_from('<256I', data, offset)
    print(f"  Sub-table {ti} at 0x{offset:08x}:")
    print(f"    First 8: {vals[:8]}")
    print(f"    Last 8: {vals[-8:]}")
    # Check for patterns
    unique = len(set(vals))
    print(f"    Unique values: {unique}/256")
    # Check if it's a permutation of 0-255
    is_perm = all(v < 256 for v in vals)
    print(f"    All values < 256: {is_perm}")

# Table 2: byte lookup table (256 entries, 1 byte each)
print("\n=== Table 2 at 0xf640c0 (256 bytes) ===")
vals2 = list(data[T2_BASE:T2_BASE+256])
print(f"  First 16: {vals2[:16]}")
print(f"  Unique values: {len(set(vals2))}/256")
is_perm2 = all(v < 256 for v in vals2)
print(f"  All values < 256: {is_perm2}")
if is_perm2:
    # Check if it's a permutation (0-255 each once)
    sorted_vals = sorted(vals2)
    is_full_perm = sorted_vals == list(range(256))
    print(f"  Full permutation: {is_full_perm}")

# Check nearby memory for additional tables
print("\n=== Checking areas referenced by the function ===")
for addr in [0xf63000, 0xf63400, 0xf63800, 0xf63c00, 0xf64000, 0xf640c0]:
    # Read 256 u32 or bytes
    try:
        vals = struct.unpack_from('<256I', data, addr)
        print(f"  0x{addr:08x}: first={vals[0]} last={vals[-1]} unique={len(set(vals))}")
    except:
        pass

# Also check function at 0xcf292c (called for initialization before decompress)
print("\n=== Initialization function at 0xcf292c ===")
import sys
sys.path.insert(0, r'C:\Users\NGEONG\Videos\MLA')
# This function sets up the tables based on the key
# Let's look at it in the next step
