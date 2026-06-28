#!/usr/bin/env python3
"""Deep analysis of lmF@ structure to find correct decompression"""
import os, struct, zlib
from Crypto.Cipher import AES

FIXED_KEY = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
base = r"C:\Users\NGEONG\Videos\MLA\mt_dump\assets"

def decrypt(path):
    with open(path, "rb") as fh:
        data = fh.read()
    payload = data[16:]
    payload_realigned = payload[:len(payload) - (len(payload) % 16)]
    dec = AES.new(FIXED_KEY, AES.MODE_ECB).decrypt(payload_realigned)
    return dec[:len(payload)]

# Analyze one file in detail
path = os.path.join(base, "0", sorted(os.listdir(os.path.join(base, "0")))[0])
dec = decrypt(path)
print(f"Decrypted size: {len(dec)} bytes\n")

# Check: is there zlib magic ANYWHERE with any XOR?
print("=== Searching for zlib magic with XOR transforms ===")
found = []
for offset in range(0, len(dec) - 1):
    b0, b1 = dec[offset], dec[offset+1]
    # If XOR of b0,b1 with same byte gives 78 9c
    xor_val = b0 ^ 0x78
    if b1 ^ xor_val == 0x9c:
        # Check 16 more bytes to verify
        test = bytes(b ^ xor_val for b in dec[offset:offset+20])
        if test[:2] == b"\x78\x9c":
            try:
                d = zlib.decompress(bytes(b ^ xor_val for b in dec[offset:]))
                found.append((offset, xor_val, d, "single-byte XOR"))
                print(f"  Offset {offset:#x} XOR 0x{xor_val:02x}: ZLIB! {len(d)} bytes")
            except:
                for wb in [-15, 15, 31, -31, 47]:
                    try:
                        d = zlib.decompress(bytes(b ^ xor_val for b in dec[offset:]), wb)
                        found.append((offset, xor_val, d, f"wb={wb}"))
                        print(f"  Offset {offset:#x} XOR 0x{xor_val:02x} wb={wb}: ZLIB! {len(d)} bytes")
                        break
                    except: pass

if not found:
    print("  No single-byte XOR zlib found anywhere")

    # Try 2-byte repeating XOR
    print("\n=== Searching with 2-byte repeating XOR ===")
    for offset in range(0, min(256, len(dec) - 2)):
        for x0 in range(256):
            x1 = dec[offset] ^ 0x78
            # Check if second byte works
            if dec[offset+1] ^ x1 == 0x9c:
                # Verify with 4 bytes
                xor_pattern = bytes([x0, x1])
                test = bytearray(dec[offset:offset+20])
                for i in range(len(test)):
                    test[i] ^= xor_pattern[i % 2]
                if test[:2] == b"\x78\x9c":
                    full = bytearray(dec)
                    for i in range(len(full)):
                        full[i] ^= xor_pattern[i % 2]
                    try:
                        d = zlib.decompress(bytes(full))
                        print(f"  Offset {offset:#x} 2-byte XOR {xor_pattern.hex()}: ZLIB! {len(d)} bytes")
                        break
                    except: pass

# Maybe the data isn't zlib-compressed at all
# Let's check entropy to determine if it's likely compressed
print("\n=== Entropy analysis ===")
import math
for start in [0x10, 0x100, 0x1000]:
    chunk = dec[start:start+256]
    if len(chunk) < 256: continue
    freq = [0] * 256
    for b in chunk:
        freq[b] += 1
    entropy = -sum(f / 256 * math.log2(f / 256) for f in freq if f > 0)
    print(f"  Offset {start:#x}: entropy = {entropy:.4f} (encrypted/compressed: >7.5, text: <5)")

# Try decompressing various portions without XOR
print("\n=== Try raw zlib/deflate at various offsets ===")
for offset in range(0, len(dec) - 2):
    if dec[offset:offset+2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda", b"\x78\x5e"):
        print(f"  zlib at offset {offset:#x}!")
        try:
            d = zlib.decompress(dec[offset:])
            print(f"    ZLIB: {len(d)} bytes")
        except: pass

# Check for LZ4, LZMA or other compression signatures  
print("\n=== Check for other compression signatures ===")
sigs = {
    b"\x1bLua": "Lua bytecode",
    b"\x1bLJ": "LuaJIT",
    b"\x89PNG": "PNG",
    b"\xff\xd8": "JPEG",
    b"PK\x03\x04": "ZIP",
    b"{\"": "JSON",
    b"<": "XML",
    b"BZh": "BZ2",
    b"\xfd7zXZ": "XZ/LZMA",
    b"\x28\xb5\x2f\xfd": "Zstandard",
    b"\x04\x22\x4d\x18": "LZ4 frame",
    b"\x89LZMA": "LZMA",
}
for sig, name in sigs.items():
    pos = dec.find(sig)
    if pos >= 0:
        print(f"  {name} at offset {pos:#x}")

# Check if maybe the lmF@ header has TEA-encrypted content after it
# The decrypted AES payload contains lmF@ header + ??? data
# Maybe the actual game data is TEA-encrypted INSIDE the lmF@ container
print("\n=== Try TEA decrypt on data after lmF@ header ===")
DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF

def tea_decrypt_block(v0, v1, k):
    s = (DELTA * 32) & MASK
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3])) & MASK)) & MASK
        v0 = (v0 - ((((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1])) & MASK)) & MASK
        s = (s - DELTA) & MASK
    return v0, v1

def tea_ecb(data, key):
    k = struct.unpack("<4I", key[:16])
    result = bytearray()
    for i in range(0, len(data) - (len(data) % 8), 8):
        block = data[i:i+8]
        if len(block) < 8: break
        v = struct.unpack("<2I", block)
        vd = tea_decrypt_block(v[0], v[1], k)
        result.extend(struct.pack("<2I", *vd))
    return bytes(result)

payload_after_lmf = dec[16:]
for kname, key in [("fixed", FIXED_KEY), ("fn_md5", FIXED_KEY[:16])]:
    try:
        td = tea_ecb(payload_after_lmf, FIXED_KEY)
        if td[:4] == b"\x1bLua":
            print(f"  TEA on payload: LUAC!")
        elif td[:2] in (b"\x78\x9c", b"\x78\x01"):
            print(f"  TEA on payload: zlib!")
            try:
                d = zlib.decompress(td)
                print(f"    ZLIB: {len(d)} bytes")
            except: pass
    except: pass

print("\n=== Last resort: show decrypted data as potential Lua source ===")
# Maybe it's not compressed at all - just encrypted Lua bytecode
if dec[16:20] == b"\x1bLua":
    print("  Lua bytecode found directly!")
print(f"  First 64 chars as text: {''.join(chr(b) if 32<=b<127 else '.' for b in dec[16:80])}")
