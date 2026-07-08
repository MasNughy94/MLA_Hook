#!/usr/bin/env python3
"""
Final .mt decrypter - decrypts ALL files using AES-128-ECB + fixed key
with proper padded handling. Then tries to decompress the lmF@ inner format.
"""
import os, struct, zlib
from Crypto.Cipher import AES

FIXED_KEY = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
BASE_SRC = r"C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump\assets"
BASE_OUT = r"C:\Users\ADMIN SERVICE\Videos\MLA\decrypted_output"
os.makedirs(BASE_OUT, exist_ok=True)

def decrypt_mt(filepath):
    """Decrypt .mt file: strip 16-byte Antm header, AES-ECB with null padding"""
    with open(filepath, "rb") as f:
        raw = f.read()
    payload = raw[16:]
    # Align to 16 bytes with null padding
    pad = (16 - len(payload) % 16) % 16
    if pad:
        payload_padded = payload + b"\x00" * pad
    else:
        payload_padded = payload
    cipher = AES.new(FIXED_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(payload_padded)
    return decrypted[:len(payload)]  # strip padding

def process_lmf(dec, fname):
    """Try to decompress lmF@ format with various approaches"""
    if len(dec) < 16:
        return None
    
    magic = struct.unpack("<I", dec[:4])[0]
    if magic != 0x40466d6c:
        return None
    
    # The lmF@ header is 16 bytes
    # [0:4]  = magic "lmF@"
    # [4:8]  = flags (5d000004)
    # [8:12] = some value (varies)
    # [12:16] = 0000ece1 (fixed footer)
    
    raw_data = dec[16:]  # Data after 16-byte lmF@ header
    
    results = []
    
    # Approach 1: Try single-byte XOR on the data
    for xor_k in range(256):
        test = bytes(b ^ xor_k for b in raw_data[:32])
        if test[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda", b"\x78\x5e"):
            full = bytes(b ^ xor_k for b in raw_data)
            for wb in [15, -15, 31, -31, 47]:
                try:
                    decomp = zlib.decompress(full, wb)
                    results.append(("ZLIB", decomp, f"XOR0x{xor_k:02x}_wb{wb}"))
                    break
                except: pass
    
    if results:
        return results
    
    # Approach 2: Try raw deflate (no zlib header)
    for xor_k in range(256):
        test = bytes(b ^ xor_k for b in raw_data[:4])
        if test[:2] in (b"\x4c\x5a", b"\x1b\x01"):  # LZ4 or other
            break
    
    # Approach 3: Try zlib on the ENTIRE decrypted data (not just after lmF@)
    for xor_k in range(256):
        full_test = dec[16:]
        test = bytes(b ^ xor_k for b in full_test[:32])
        if test[:2] in (b"\x78\x9c", b"\x78\x01"):
            full = bytes(b ^ xor_k for b in full_test)
            for wb in [15, -15, 31, -31, 47]:
                try:
                    decomp = zlib.decompress(full, wb)
                    results.append(("ZLIB_FULL", decomp, f"XOR0x{xor_k:02x}"))
                    break
                except: pass
    
    if results:
        return results
    
    # Approach 4: Try 2-byte repeating XOR using last 2 bytes of header (0xEC, oxE1)
    xor_pattern = dec[14:16]  # ec e1
    result = bytearray(len(raw_data))
    for i, b in enumerate(raw_data):
        result[i] = b ^ xor_pattern[i % 2]
    
    if bytes(result[:2]) in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
        for wb in [15, -15, 31, -31, 47]:
            try:
                decomp = zlib.decompress(bytes(result), wb)
                results.append(("ZLIB_2XOR", decomp, f"pat{xor_pattern.hex()}"))
                break
            except: pass
    
    if results:
        return results
    
    # Approach 5: Maybe data is NOT compressed - just return as-is
    # Check if it looks like Lua bytecode
    if raw_data[:4] == b"\x1bLua":
        results.append(("LUAC", raw_data, "direct"))
        return results
    
    # Check if it looks like text
    printable = sum(1 for b in raw_data[:200] if 32 <= b < 127 or b in (9, 10, 13))
    if printable > 160:
        results.append(("TEXT", raw_data, "direct"))
        return results
    
    # Return raw data as unknown
    results.append(("UNKNOWN", raw_data, "raw"))
    return results

# Decrypt and process all files
total = 0
success = 0
for root, dirs, files in os.walk(BASE_SRC):
    for f in files:
        if not f.endswith(".mt"):
            continue
        
        total += 1
        path = os.path.join(root, f)
        rel_dir = os.path.relpath(root, BASE_SRC).replace("\\", "_").replace("/", "_")
        if rel_dir == ".":
            rel_dir = "root"
        
        try:
            dec = decrypt_mt(path)
        except Exception as e:
            print(f"  ERROR decrypting {rel_dir}/{f}: {e}")
            continue
        
        results = process_lmf(dec, f)
        if not results:
            continue
        
        kind, data, method = results[0]
        safe_method = method.replace("\\x", "").replace("\\", "").replace("/", "").replace(":", "")
        outname = f"{rel_dir}_{f.replace('.mt','')}_{kind}_{safe_method[:20]}" 
        outpath = os.path.join(BASE_OUT, outname)
        
        with open(outpath, "wb") as fh:
            fh.write(data)
        
        success += 1
        
        if kind in ("ZLIB", "ZLIB_FULL", "ZLIB_2XOR", "TEXT", "LUAC"):
            preview = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:150])
            print(f"  {kind:12s} | {method:20s} | {rel_dir}/{f[:30]:30s} | {preview[:60]}")

print(f"\nTotal: {total} .mt files, {success} processed")
print(f"Output: {BASE_OUT}")
