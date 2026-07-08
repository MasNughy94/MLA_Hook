#!/usr/bin/env python3
"""
Phase 4: The lmF@ format requires XOR on bytes 14-29 (0x0E-0x1D) with 0xEC,
then decompress from offset 14. Test this transformation.
"""
import struct, zlib, sys

KEY = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
SAMPLE_MT = r"C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump\sample.mt"
EXPECTED_LUA = r"C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump\sample.mt.lua"

with open(SAMPLE_MT, 'rb') as f:
    mt_data = f.read()
with open(EXPECTED_LUA, 'rb') as f:
    expected = f.read()

from Crypto.Cipher import AES
cipher = AES.new(KEY, AES.MODE_CBC, iv=b'\x00'*16)
decrypted = cipher.decrypt(mt_data[0x10:0x10+9760])

print("=== Original lmF@ header ===")
print(f"Magic: {decrypted[0:4]}")
print(f"Header bytes [4:14]: {decrypted[4:14].hex()}")

# Size field at offset 10-13 XOR'd with 0x3EA
size_field = struct.unpack('<I', decrypted[10:14])[0]
decomp_size = size_field ^ 0x3EA
print(f"Size field [10:14]: 0x{size_field:08x} XOR 0x3EA = 0x{decomp_size:08x} ({decomp_size})")

# Now XOR bytes 14-29 (0x0E-0x1D) with 0xEC
data = bytearray(decrypted)
for i in range(14, min(30, len(data))):
    data[i] ^= 0xEC

print(f"\n=== After XOR with 0xEC on bytes [14:30] ===")
print(f"Bytes [14:30] before: {decrypted[14:30].hex()}")
print(f"Bytes [14:30] after:  {data[14:30].hex()}")

# Now the compressed data starts at offset 14
compressed = bytes(data[14:])
print(f"\nCompressed data: {len(compressed)} bytes (offset 14 to end)")
print(f"First 4 bytes: {compressed[:4].hex()}")

# Try zlib decompress
print(f"\n=== Trying zlib decompress ===")
try:
    decomp = zlib.decompress(compressed)
    print(f"SUCCESS: {len(decomp)} bytes decompressed")
    print(f"First 32 hex: {decomp[:32].hex()}")
    print(f"First 32 ASCII: {''.join(chr(b) if 32<=b<127 else '.' for b in decomp[:32])}")
    if decomp == expected:
        print(f"*** MATCHES sample.mt.lua! ***")
    else:
        if len(decomp) == len(expected):
            match = sum(1 for a,b in zip(decomp, expected) if a==b)
            print(f"Same size, {match}/{len(decomp)} bytes match")
        else:
            print(f"Size mismatch: {len(decomp)} vs {len(expected)}")
            # Check if the expected is contained within decomp or vice versa
            if decomp[:len(expected)] == expected:
                print(f"*** Expected is prefix of decomp!")
            elif expected[:len(decomp)] == decomp:
                print(f"*** Decomp is prefix of expected!")
except Exception as e:
    print(f"zlib error: {e}")

# Also try: maybe the XOR is applied to ALL data, not just first 16 bytes
print(f"\n=== Trying full XOR with 0xEC ===")
data2 = bytearray(decrypted)
for i in range(14, len(data2)):
    data2[i] ^= 0xEC
compressed2 = bytes(data2[14:])
try:
    decomp2 = zlib.decompress(compressed2)
    print(f"SUCCESS: {len(decomp2)} bytes")
    if decomp2 == expected:
        print(f"*** MATCHES! ***")
except Exception as e:
    print(f"Error: {e}")

# Or maybe the original size should be derived from the actual compressed data?
print(f"\n=== Check: what does the compressed data look like? ===")
print(f"Bytes [14:50] = {data[14:50].hex()}")
print(f"Byte 0 = 0x{data[14]:02x}, Byte 1 = 0x{data[15]:02x}")

# The decompress function at 0xcf2b2c might use a CUSTOM algorithm
# Let's check what's at 0xcf2b2c
print(f"\n=== Trying different decompression offsets ===")
for off in range(14, min(30, len(data))):
    chunk = bytes(data[off:])
    for wbits in [15, -15, 31, 47]:
        try:
            d = zlib.decompress(chunk, wbits)
            print(f"  offset={off}, wbits={wbits}: {len(d)} bytes")
            if d == expected:
                print(f"  *** MATCHES! ***")
            if len(d) == decomp_size:
                print(f"  ** Matches expected size {decomp_size}!")
        except:
            pass

# Also: maybe the decomp function doesn't use zlib at all
# Let's dump the first 256 bytes for analysis
print(f"\n=== First 256 bytes of compressed data (after XOR) ===")
for i in range(0, min(256, len(data)-14), 32):
    chunk = bytes(data[14+i:14+min(i+32, len(data))])
    print(f"  {i:04x}: {chunk.hex()}")
