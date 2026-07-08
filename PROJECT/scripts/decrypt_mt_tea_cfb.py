#!/usr/bin/env python3
"""
Decrypt .mt files using the ACTUAL game algorithm: TEA-CFB
Based on reverse-engineering of libagame.so:
- getkey @ 0x43b33c: converts hex string (filename) to 16-byte key
- oi_symmetry_decrypt2 @ 0x43ae3c: TEA-CFB with plaintext feedback
"""
import os, struct, zlib

DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF

def tea_decrypt_block(v0, v1, k):
    """Standard TEA decryption, 32 cycles"""
    k0, k1, k2, k3 = k
    s = (DELTA * 32) & MASK
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3)) & MASK)) & MASK
        v0 = (v0 - ((((v1 << 4) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1)) & MASK)) & MASK
        s = (s - DELTA) & MASK
    return v0, v1

def getkey(hex_string):
    """Convert hex string to 16-byte key (reverse of getkey @ 0x43b33c)"""
    return bytes.fromhex(hex_string)

def make_key_swapped(hex_bytes):
    """The game uses REV32 on key words (byte swap within each word)"""
    k = list(struct.unpack("<IIII", hex_bytes))
    return [struct.unpack(">I", struct.pack("<I", w))[0] for w in k]

def tea_cfb_decrypt(data, key):
    """
    TEA-CFB with plaintext feedback (oi_symmetry_decrypt2)
    data[0:8] = IV/state
    data[8:]  = encrypted payload
    """
    if len(data) < 8:
        return b""
    
    state = data[:8]
    payload = data[8:]
    result = bytearray()
    
    # Get the key words (swapped endianness per game convention)
    k_swapped = make_key_swapped(key)
    # Also convert to LE for the TEA function
    k = [struct.unpack("<I", struct.pack(">I", w))[0] for w in k_swapped]
    
    while payload:
        # Decrypt state with TEA -> keystream
        s0 = struct.unpack("<I", state[0:4])[0]
        s1 = struct.unpack("<I", state[4:8])[0]
        
        # Apply REV32 (byte swap within word) as game does
        s0_swapped = struct.unpack(">I", struct.pack("<I", s0))[0]
        s1_swapped = struct.unpack(">I", struct.pack("<I", s1))[0]
        
        ks0, ks1 = tea_decrypt_block(s0_swapped, s1_swapped, k_swapped)
        
        # Apply REV32 back
        ks0 = struct.unpack("<I", struct.pack(">I", ks0))[0]
        ks1 = struct.unpack("<I", struct.pack(">I", ks1))[0]
        
        keystream = struct.pack("<II", ks0, ks1)
        
        chunk = payload[:8]
        plain = bytes(a ^ b for a, b in zip(chunk, keystream))
        result.extend(plain)
        
        # Plaintext feedback: use plaintext as next state
        state = plain
        payload = payload[8:]
    
    return bytes(result)

def try_decrypt_file(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    
    fname = os.path.basename(path).replace(".mt", "")
    
    # Derive key from filename (hex string)
    try:
        key = getkey(fname)
    except:
        return None
    
    print(f"\n=== {os.path.basename(os.path.dirname(path))}/{os.path.basename(path)} ({len(raw)}b) ===")
    print(f"Key from filename: {key.hex()}")
    
    # Try different header sizes
    for hs in [0, 8, 10, 16, 17, 18]:
        payload = raw[hs:]
        if len(payload) < 16:
            continue
        
        # TEA-CFB expects: first 8 bytes = state, rest = encrypted
        dec = tea_cfb_decrypt(payload, key)
        
        if len(dec) == 0:
            continue
        
        # Check results
        print(f"  hdr={hs} TEA-CFB: first={dec[:16].hex()}")
        
        # Check for Lua bytecode
        if dec[:4] == b"\x1bLua":
            print(f"    *** LUAC v{dec[4]}.{dec[5]} ***")
            return dec
        
        # Check for zlib
        if dec[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
            print(f"    *** ZLIB ***")
            try:
                d = zlib.decompress(dec)
                print(f"    Decompressed: {len(d)} bytes")
                preview = "".join(chr(b) if 32 <= b < 127 else "." for b in d[:200])
                print(f"    Preview: {preview}")
                return d
            except: pass
        
        # Check for lmF@ magic
        if len(dec) >= 4:
            magic = struct.unpack("<I", dec[:4])[0]
            if magic == 0x40466d6c:
                print(f"    *** lmF@ ***")
                # Try to decompress lmF@ contents
                raw_sz = struct.unpack("<I", dec[0x0A:0x0E])[0]
                decomp_sz = raw_sz ^ 0x3EA
                compressed = bytearray(dec[0x0E:])
                for i in range(min(16, len(compressed))):
                    compressed[i] ^= 0xEC
                for wb in [15, -15, 31, -31, 47]:
                    try:
                        d = zlib.decompress(bytes(compressed), wb)
                        print(f"    lmF@ ZLIB: {len(d)} bytes")
                        preview = "".join(chr(b) if 32 <= b < 127 else "." for b in d[:200])
                        print(f"    Preview: {preview}")
                        return d
                    except: pass
                print(f"    lmF@ (zlib failed on {len(compressed)}b)")
        
        # Check for text
        printable = sum(1 for b in dec[:50] if 32 <= b < 127)
        if printable > 40:
            print(f"    Possible text: {dec[:80]}")
            return dec
        
        # Check for known types
        for sig, name in [(b"\x89PNG", "PNG"), (b"\xff\xd8", "JPEG"), (b"PK\x03\x04", "ZIP")]:
            if dec[:len(sig)] == sig:
                print(f"    *** {name} ***")
                return dec

    return None

# Test on all files from the e/ directory
base = r"C:\Users\ADMIN SERVICE\Videos\MLA"
dirs_to_test = [
    os.path.join(base, "e"),
    os.path.join(base, "mt_dump"),
]

for d in dirs_to_test:
    for f in sorted(os.listdir(d)):
        if f.endswith(".mt"):
            path = os.path.join(d, f)
            dec = try_decrypt_file(path)
            if dec and len(dec) > 100:
                print(f"  RESULT: {len(dec)} bytes")
