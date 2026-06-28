#!/usr/bin/env python3
"""
PoC Phase 2: The AES decryption works. Now find the zlib stream in the "lmF@" output.
"""
import struct
import zlib
import sys

SAMPLE_MT = r"C:\Users\NGEONG\Videos\VSCODE\mt_dump\sample.mt"
EXPECTED_LUA = r"C:\Users\NGEONG\Videos\VSCODE\mt_dump\sample.mt.lua"
SAMPLE_DEC = r"C:\Users\NGEONG\Videos\VSCODE\mt_dump\sample.dec"

KEY = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
IV = b'\x00' * 16

with open(SAMPLE_MT, 'rb') as f:
    mt_data = f.read()
with open(EXPECTED_LUA, 'rb') as f:
    expected = f.read()

try:
    from Crypto.Cipher import AES
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pycryptodome'])
    from Crypto.Cipher import AES

# Decrypt with zero IV, offset 0x10, length 9760
payload = mt_data[0x10:0x10+9760]
cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
decrypted = cipher.decrypt(payload)

print(f"=== AES-128-CBC decryption result ===")
print(f"Key:           {KEY.hex()}")
print(f"IV:            {IV.hex()} (zero IV)")
print(f"Ciphertext:    offset 0x10, {len(payload)} bytes")
print(f"Decrypted:     {len(decrypted)} bytes")
print(f"First 4 bytes: {decrypted[:4]} = {decrypted[:4].hex()} = 'lmF@'")
print(f"")

# Hex dump first 64 bytes
print("Hex dump of first 64 bytes:")
for i in range(0, min(64, len(decrypted)), 16):
    line = ' '.join(f'{b:02x}' for b in decrypted[i:i+16])
    ascii = ''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted[i:i+16])
    print(f"  {i:04x}: {line:48s} |{ascii}|")

print("")

# Parse the "lmF@" format
# Looking at the structure:
# 6C 6D 46 40 = "lmF@" magic (4 bytes)
# Followed by various fields

magic = decrypted[0:4]
field1 = struct.unpack('<I', decrypted[4:8])[0]   # 5D 00 00 04 -> 0x0400005D
field2 = struct.unpack('<I', decrypted[8:12])[0]  # 00 B4 C3 7C -> 0x7CC3B400
field3 = struct.unpack('<I', decrypted[12:16])[0] # 00 00 EC E1 -> 0xE1EC0000

print(f"=== Parse 'lmF@' header ===")
print(f"lmF@         : {magic} ({magic.hex()})")
print(f"field [4:8]  : 0x{field1:08x} = {field1}")
print(f"field [8:12] : 0x{field2:08x} = {field2}")
print(f"field [12:16]: 0x{field3:08x} = {field3}")

# What if the header is just 4 bytes and the rest is data?
# Look for valid zlib headers (0x78xx where xx%31==0)
print(f"\n=== Looking for zlib streams in decrypted data ===")
for off in range(0, min(256, len(decrypted)-2)):
    if decrypted[off] == 0x78:
        cmf = decrypted[off]
        flg = decrypted[off+1]
        header_val = (cmf << 8) | flg
        if header_val % 31 == 0:
            print(f"  Valid zlib header at offset {off}: {cmf:02x} {flg:02x} (checksum OK)")

# Also look for raw deflate (no zlib header) - check for 0x9C 0x78 or similar
# Or simply try zlib decompress at various offsets
print(f"\n=== Trying zlib.decompress at various offsets ===")
for off in range(0, min(128, len(decrypted)-4)):
    try:
        decompressed = zlib.decompress(decrypted[off:])
        print(f"  zlib OK @ offset {off}: {len(decompressed)} bytes decompressed")
        print(f"    First 32 bytes hex: {decompressed[:32].hex()}")
        print(f"    First 32 ASCII: {''.join(chr(b) if 32<=b<127 else '.' for b in decompressed[:32])}")
        if decompressed == expected:
            print(f"    *** MATCHES sample.mt.lua ***")
        elif off == 0 and decompressed[:4] == b'\x1bLua':
            print(f"    *** Lua bytecode! (header: {decompressed[0:4]}) ***")
    except Exception as e:
        pass

# Also try: maybe first 16 bytes are a header, remaining is zlib?
print(f"\n=== Hypotheses ===")

# H1: Header = first 16 bytes, data = rest (zlib starting at offset 16)
for hdr_size in [4, 8, 12, 16]:
    data = decrypted[hdr_size:]
    try:
        decompressed = zlib.decompress(data)
        print(f"  HEADER={hdr_size} bytes, zlib OK: {len(decompressed)} bytes, "
              f"cmp expected: {decompressed == expected}, "
              f"first 32 ASCII: {''.join(chr(b) if 32<=b<127 else '.' for b in decompressed[:32])}")
    except:
        pass

# H2: Maybe the mode parameter affects the output?
# w4 = mode = xor_mask ^ 0xabcdef = 0x00262615
# This might be a non-standard mode (like CBC-CTS or custom padding)
# Let me try with just the decrypted data as-is (maybe it IS the expected output?)
print(f"\nComparing decrypted vs expected (direct):")
if len(decrypted) == len(expected):
    diffs = sum(1 for a, b in zip(decrypted, expected) if a != b)
    print(f"  Same size ({len(decrypted)}) but {diffs} bytes differ")
else:
    print(f"  Size mismatch: {len(decrypted)} vs {len(expected)}")

# Try: What if I need to skip the lmF@ header entirely? 9760 - 16 = 9744
# and decompress from offset 16?
if len(decrypted) >= 16:
    print(f"\n=== Trying skip first 16 bytes, zlib the rest ===")
    rest = decrypted[16:]
    print(f"  Remaining: {len(rest)} bytes")
    try:
        d = zlib.decompress(rest)
        print(f"  zlib OK: {len(d)} bytes, cmp expected: {d == expected}")
        print(f"  First 32: {d[:32].hex()}")
    except Exception as e:
        print(f"  zlib error: {e}")
    # Try to decompress with wbits for raw deflate
    try:
        d = zlib.decompress(rest, -zlib.MAX_WBITS)
        print(f"  raw deflate OK: {len(d)} bytes, cmp expected: {d == expected}")
        print(f"  First 32: {d[:32].hex()}")
    except Exception as e:
        print(f"  raw deflate error: {e}")

# Actually wait - look at the original decryptData flow for Type 1:
# aes_decrypt(in_place) -> Data.buffer = x24 -> Data.size = mode -> inflate(Data)
# But the decrypted data is IN the original buffer, not in x24!
# Maybe Data::clear() at 0xc828f8 already copies or references the right buffer?
print(f"\n=== Maybe the lmF@ DOES inflate to the expected output? ===")
# Check if it's a single large zlib stream
try:
    d = zlib.decompress(decrypted)
    print(f"Full decompress: {len(d)} bytes")
    print(f"First 32 hex: {d[:32].hex()}")
    print(f"ASCII: {''.join(chr(b) if 32<=b<127 else '.' for b in d[:32])}")
    if d == expected:
        print("*** MATCHES expected output ***")
except Exception as e:
    print(f"Error: {e}")
    # Maybe try with different window bits
    for wbits in [15, -15, 31, 47]:
        try:
            d = zlib.decompress(decrypted, wbits)
            print(f"  wbits={wbits}: {len(d)} bytes, cmp expected: {d == expected}")
            if d == expected:
                print("  *** MATCHES expected output ***")
        except:
            pass
