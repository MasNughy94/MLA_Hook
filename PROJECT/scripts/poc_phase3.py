#!/usr/bin/env python3
"""
Phase 3: Deep analysis of the lmF@ format.
The AES output starts with "lmF@" but isn't zlib. Let's analyze the structure.
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

print("=== lmF@ Header Analysis ===")
print(f"Total decrypted: {len(decrypted)} bytes")
print(f"Expected Lua:    {len(expected)} bytes")

# The lmF@ magic
lmF_header = decrypted[:16]
print(f"\nFirst 16 bytes (header?): {lmF_header.hex()}")
print(f"  [0:4]  lmF@ magic:     {lmF_header[0:4]}")
print(f"  [4:8]  field (LE u32):  {struct.unpack('<I', lmF_header[4:8])[0]} (0x{struct.unpack('<I', lmF_header[4:8])[0]:08x})")
print(f"  [8:12] field (LE u32):  {struct.unpack('<I', lmF_header[8:12])[0]} (0x{struct.unpack('<I', lmF_header[8:12])[0]:08x})")
print(f"  [12:16] field (LE u32): {struct.unpack('<I', lmF_header[12:16])[0]} (0x{struct.unpack('<I', lmF_header[12:16])[0]:08x})")

# Bytes at offset 16 onwards
rest = decrypted[16:]
print(f"\nRest from offset 16: {len(rest)} bytes")
print(f"First 16 of rest:   {rest[:16].hex()}")

# The rest data: does any offset produce valid zlib?
# Also try raw inflate with various offsets and wbits
print("\n=== Trying zlib/raw inflate at various offsets ===")
for wbits in [15, -15, 31, 47]:
    for off in range(0, min(256, len(decrypted)-2)):
        try:
            d = zlib.decompress(decrypted[off:], wbits)
            if len(d) > 100:
                print(f"  OFFSET {off}, wbits={wbits}: {len(d)} bytes decompressed")
                print(f"    First 16 hex: {d[:16].hex()}")
                head = d[:32].decode('latin-1')
                head_clean = ''.join(c if 32<=ord(c)<127 else '.' for c in head)
                print(f"    ASCII: {head_clean}")
                if d == expected:
                    print(f"    *** MATCHES EXPECTED! ***")
                    sys.exit(0)
                # Check for Lua header
                if d[:4] == b'\x1bLua':
                    print(f"    *** Lua bytecode! Version={d[4]}, format={d[5]} ***")
        except:
            pass

# What if the lmF@ data needs a different IV? The mode = 0x00262615
# Maybe the IV is derived from the header?
print("\n=== Trying IV variations from header ===")
# The header fields at offset 4,8,12 as IV
header_ivs = {
    "xor_mask_padded": mt_data[8:12] + b'\x00'*12,
    "header_4_19": mt_data[4:20],
    "mode_as_iv": struct.pack('<I', 0x00262615) + b'\x00'*12,
    "bytes_8_23": mt_data[8:24],
}
for name, iv in header_ivs.items():
    if len(iv) < 16:
        continue
    iv = iv[:16]
    try:
        c = AES.new(KEY, AES.MODE_CBC, iv=iv)
        d = c.decrypt(mt_data[0x10:0x10+9760])
        print(f"  {name}: first 16: {d[:16].hex()} starts with 'lmF@'={d[:4]==b'lmF@'}")
        if d[:4] == b'lmF@':
            # Try to decompress
            for wbits in [15, -15, 31]:
                for off in range(0, min(128, len(d)-2)):
                    try:
                        dec = zlib.decompress(d[off:], wbits)
                        if len(dec) > 100:
                            print(f"    zlib ok @ off {off}, wbits={wbits}: {len(dec)} bytes")
                    except:
                        pass
    except:
        pass

# Maybe the IV is taken from the original CIPHERTEXT (first 16 bytes at offset 0x10)
print("\n=== What if IV is first 16 bytes of CIPHERTEXT (not header)? ===")
ct = mt_data[0x10:0x10+9760]
iv = ct[:16]
rest_ct = ct[16:]
try:
    c = AES.new(KEY, AES.MODE_CBC, iv=iv)
    d = c.decrypt(rest_ct)
    print(f"  First 16: {d[:16].hex()}")
    print(f"  Starts with lmF@: {d[:4]==b'lmF@'}")
    # Try zlib
    for off in range(0, min(128, len(d)-2)):
        try:
            dec = zlib.decompress(d[off:])
            if len(dec) > 100:
                print(f"    zlib @ off {off}: {len(dec)} bytes, first 16: {dec[:16].hex()}")
                if dec == expected:
                    print(f"    *** MATCHES! ***")
        except:
            pass
except Exception as e:
    print(f"  Error: {e}")

# Maybe the decryption is done on SHORTER data?
# The "aligned" length truncated 1 byte from 9761. 
# What if the correct length is 9761 with a padding byte?
print("\n=== Trying with PKCS7 padding / different lengths ===")
# Try AES-CBC with padding (pycryptodome's default is PKCS7)
try:
    c = AES.new(KEY, AES.MODE_CBC, iv=b'\x00'*16)
    d = c.decrypt(mt_data[0x10:0x10+9761])  # includes the 1 extra byte
    # The last byte is PKCS7 padding value
    pad_val = d[-1]
    if 1 <= pad_val <= 16:
        unpadded = d[:-pad_val]
        print(f"  PKCS7 padding: pad_val={pad_val}, unpadded={len(unpadded)} bytes")
        print(f"  First 16: {unpadded[:16].hex()}")
        try:
            for off in range(0, min(128, len(unpadded)-2)):
                dec = zlib.decompress(unpadded[off:])
                if len(dec) > 100:
                    print(f"    zlib @ off {off}: {len(dec)} bytes")
                    if dec == expected:
                        print(f"    *** MATCHES! ***")
        except:
            pass
except Exception as e:
    print(f"  Error: {e}")

# Perhaps the first 16 bytes of the decrypted data IS the Lua bytecode?
# Check if it matches a known format
print("\n=== Checking decrypted data against known formats ===")
# Lua 5.1 bytecode header: 1B 4C 75 61 51 00 01 04
# Lua 5.2: 1B 4C 75 61 52 00 01 04
# Lua 5.3: 1B 4C 75 61 53 00 01 04
# LuaJIT: 1B 4C 4A 01
# ZIP: 50 4B 03 04
# PNG: 89 50 4E 47

# What if lmF@ is just the game's internal format and the expected lua output is different?
# Compare decrypted with expected at byte level
print(f"\n=== Direct comparison ===")
print(f"Are they the same? {decrypted == expected}")
if len(decrypted) == len(expected):
    matching = sum(1 for a,b in zip(decrypted, expected) if a==b)
    print(f"Matching bytes: {matching}/{len(decrypted)} ({100*matching/len(decrypted):.1f}%)")
else:
    print(f"Different sizes: {len(decrypted)} vs {len(expected)}")

# Maybe the expected Lua file has been decrypted from a DIFFERENT format?
# Let's check if sample.mt.dec_raw (9768 bytes) was from this pipeline
dec_raw_path = r"C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump\sample.mt.dec_raw"
with open(dec_raw_path, 'rb') as f:
    dec_raw = f.read()
print(f"\nsample.mt.dec_raw: {len(dec_raw)} bytes")
print(f"First 16: {dec_raw[:16].hex()}")

# Try to XOR decrypted with dec_raw to see if there's a relationship
if len(decrypted) <= len(dec_raw):
    xored = bytes(a^b for a,b in zip(decrypted, dec_raw[:len(decrypted)]))
    print(f"XOR of decrypted with dec_raw: {xored[:32].hex()}")
