#!/usr/bin/env python3
"""
Comprehensive .mt file decryption.
Tests multiple header sizes, key derivations, and cipher modes.
"""
import os, struct, zlib
from Crypto.Cipher import AES
import hashlib

FIXED_KEY = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
OUT_DIR = r"C:\Users\NGEONG\Videos\MLA\decrypted_output"
os.makedirs(OUT_DIR, exist_ok=True)

def aes_ecb(data, key):
    """AES-ECB with null padding"""
    pad = (16 - len(data) % 16) % 16
    pp = data + b"\x00" * pad if pad else data
    dec = AES.new(key, AES.MODE_ECB).decrypt(pp)
    return dec[:len(data)]

def try_all(data, fname):
    """Try every decryption approach on a file"""
    results = []
    
    # Approach 1: 16-byte header, AES-ECB, fixed key
    for hs in [16, 17]:
        payload = data[hs:]
        if len(payload) < 16:
            continue
        
        # Keys to try
        keys = [
            ("fixed", FIXED_KEY),
        ]
        
        # Filename as key
        bn = fname.replace(".mt", "")
        try:
            fkey = bytes.fromhex(bn)
            if len(fkey) == 16:
                keys.append(("fname", fkey))
        except: pass
        
        # MD5 of filename
        try:
            md5_fn = hashlib.md5(bn.encode()).digest()[:16]
            keys.append(("md5fn", md5_fn))
        except: pass
        
        # SHA256 of filename truncated
        try:
            sha_fn = hashlib.sha256(bn.encode()).digest()[:16]
            keys.append(("sha256fn", sha_fn))
        except: pass
        
        for kname, key in keys:
            # ECB
            try:
                dec = aes_ecb(payload, key)
                check_results(dec, results, hs, kname, "ECB")
            except: pass
            
            # CBC with zero IV
            if len(payload) >= 16:
                aligned = payload[:len(payload) - (len(payload) % 16)]
                if aligned:
                    try:
                        dec = AES.new(key, AES.MODE_CBC, iv=b"\x00"*16).decrypt(aligned)
                        check_results(dec, results, hs, kname, "CBC0")
                    except: pass
            
            # CBC with first 16 bytes of payload as IV
            if len(payload) >= 32:
                iv = payload[:16]
                ct = payload[16:]
                aligned = ct[:len(ct) - (len(ct) % 16)]
                if aligned:
                    try:
                        dec = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(aligned)
                        check_results(dec, results, hs, kname, "CBCiv")
                    except: pass
        
        # Try first 16 bytes of Antm header as AES key
        antm_key = data[:16]
        try:
            dec = aes_ecb(payload, antm_key)
            check_results(dec, results, hs, "antmkey", "ECB")
        except: pass
        
        # Try MD5 of Antm header as key
        md5_antm = hashlib.md5(data[:17]).digest()[:16]
        try:
            dec = aes_ecb(payload, md5_antm)
            check_results(dec, results, hs, "md5antm", "ECB")
        except: pass
    
    return results

def check_results(dec, results, hs, kname, mode):
    """Check decrypted data for recognizable formats"""
    if len(dec) < 4:
        return
    magic = struct.unpack("<I", dec[:4])[0]
    
    if magic == 0x40466d6c:
        # Try lmF@ format: size XOR + zlib
        raw_sz = struct.unpack("<I", dec[0x0A:0x0E])[0]
        decomp_sz = raw_sz ^ 0x3EA
        compressed = bytearray(dec[0x0E:])
        for i in range(min(16, len(compressed))):
            compressed[i] ^= 0xEC
        
        for wb in [15, -15, 31, -31, 47]:
            try:
                d = zlib.decompress(bytes(compressed), wb)
                results.append(("LUA", hs, kname, mode, d))
                return
            except: pass
        
        # Raw deflate
        try:
            import bz2, lzma
        except: pass
        
        results.append(("lmF@", hs, kname, mode, dec))
    
    elif dec[:4] == b"\x1bLua":
        results.append(("LUAC", hs, kname, mode, dec))
    
    elif dec[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda", b"\x78\x5e"):
        try:
            d = zlib.decompress(dec)
            results.append(("ZLIB", hs, kname, mode, d))
        except: pass
    
    else:
        printable = sum(1 for b in dec[:100] if 32 <= b < 127)
        if printable > 80:
            results.append(("TEXT", hs, kname, mode, dec))

# Test files from various directories
base = r"C:\Users\NGEONG\Videos\MLA\mt_dump\assets"
all_results = {}

for d in ["0", "1", "5", "a", "e"]:
    dirpath = os.path.join(base, d)
    cnt = 0
    for f in sorted(os.listdir(dirpath))[:50]:
        if not f.endswith(".mt"):
            continue
        path = os.path.join(dirpath, f)
        with open(path, "rb") as fh:
            data = fh.read()
        
        results = try_all(data, f)
        if results:
            all_results[f"{d}/{f}"] = results
            cnt += 1
    print(f"  {d}/: {cnt}/50 files decrypted")

# Print results
print(f"\n=== Summary: {len(all_results)} files decrypted ===")
for fname, results in list(all_results.items())[:20]:
    print(f"\n{fname}:")
    for kind, hs, kname, mode, _ in results[:3]:
        print(f"  {kind} hdr={hs} key={kname} mode={mode}")

# Save successful decryptions
print("\n=== Saving decrypted files ===")
saved = 0
for fname, results in all_results.items():
    for kind, hs, kname, mode, data in results:
        if kind in ("LUA", "LUAC", "ZLIB", "TEXT"):
            safe_name = fname.replace("/", "_").replace(".", "_")
            ext = ".lua" if kind in ("LUA",) else ".luac" if kind == "LUAC" else ".bin"
            outpath = os.path.join(OUT_DIR, f"{safe_name}_{kind}_{hs}_{kname}_{mode}{ext}")
            with open(outpath, "wb") as f:
                f.write(data)
            saved += 1
            # Show preview
            if kind == "LUA":
                preview = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:200])
                print(f"\n  {safe_name}:")
                print(f"  {preview}")
            break  # Only save first successful result per file

print(f"\nSaved {saved} files to {OUT_DIR}")
