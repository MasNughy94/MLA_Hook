#!/usr/bin/env python3
"""
Comprehensive test of all .mt decryption approaches
Test all identified keys and algorithms
"""
import os, struct, zlib, hashlib
from Crypto.Cipher import AES

base = r"C:\Users\NGEONG\Videos\MLA\mt_dump\assets"
outdir = r"C:\Users\NGEONG\Videos\MLA\decrypted_output"
os.makedirs(outdir, exist_ok=True)

# All key candidates found in the binary
key_candidates = {
    "f0a193d5": bytes.fromhex("f0a193d50ade553e9835595f5cd75ddd"),
    "f5a193d5": bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd"),
    "183abd29": bytes.fromhex("183abd29fc496f55536e7d904e0abae4"),
    "34361f19": bytes.fromhex("34361f192e41ed6e4e8f9aca80a4ea7e"),
    "moontonAG": b"moontonAGame1234",
}

def aes_ecb(data, key):
    pad = (16 - len(data) % 16) % 16
    pp = data + b"\x00" * pad if pad else data
    dec = AES.new(key, AES.MODE_ECB).decrypt(pp)
    return dec[:len(data)]

def check_content(dec, fname, kname, hdr_size, mode):
    """Check decrypted data for any recognizable content"""
    if len(dec) < 4:
        return None
    
    results = []
    
    # 1. Lua bytecode
    if dec[:4] == b"\x1bLua":
        results.append(("LUAC", dec))
    
    # 2. lmF@ format - try decompression
    magic = struct.unpack("<I", dec[:4])[0]
    if magic == 0x40466d6c:
        # Try different XOR keys on the compressed portion
        for xor_k in range(256):
            compressed = bytearray(dec[0x10:])  # skip 16-byte lmF@ header
            if len(compressed) < 2: continue
            for i in range(len(compressed)):
                compressed[i] ^= xor_k
            if compressed[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
                for wb in [15, -15, 31, -31, 47]:
                    try:
                        d = zlib.decompress(bytes(compressed), wb)
                        results.append((f"lmF@+XOR{xor_k:02x}", d))
                        break
                    except: pass
                if not results:
                    results.append((f"lmF@_XOR{xor_k:02x}_nozlib", dec))
                break
        else:
            results.append(("lmF@_uncompressed", dec))
    
    # 3. zlib directly
    if dec[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda", b"\x78\x5e"):
        for wb in [15, -15, 31, -31, 47]:
            try:
                d = zlib.decompress(dec, wb)
                results.append((f"ZLIB_wb{wb}", d))
                break
            except: pass
    
    # 4. PNG, JPEG, ZIP, etc
    for sig, name in [(b"\x89PNG", "PNG"), (b"\xff\xd8", "JPEG"), 
                      (b"PK\x03\x04", "ZIP"), (b"OggS", "OGG"),
                      (b"RIFF", "WAV/AVI")]:
        if dec[:len(sig)] == sig:
            results.append((name, dec))
    
    # 5. Text content
    printable = sum(1 for b in dec[:100] if 32 <= b < 127 or b in (9, 10, 13))
    if printable > 80:
        # Check if it's valid text
        try:
            text = dec[:200].decode("utf-8", errors="replace")
            # Filter out obviously binary stuff
            if all(c.isprintable() or c in "\n\r\t" for c in text[:100]):
                results.append(("TEXT", dec))
        except:
            pass
    
    # 6. XML
    if dec[:1] == b"<":
        results.append(("XML", dec))
    
    # 7. JSON
    if dec[:1] == b"{" and b'"' in dec[:50]:
        results.append(("JSON", dec))
    
    return results if results else None

# Test multiple files with all approaches
print("Testing all decryption approaches...")
total_success = 0
files_tested = 0

for d in ["0", "1", "5", "a", "e"]:
    dirpath = os.path.join(base, d)
    files = sorted(os.listdir(dirpath))[:10]
    for f in files:
        if not f.endswith(".mt"): continue
        path = os.path.join(dirpath, f)
        with open(path, "rb") as fh:
            data = fh.read()
        files_tested += 1
        
        for hdr_size in [16, 17]:
            payload = data[hdr_size:]
            if len(payload) < 16: continue
            
            for kname, key in key_candidates.items():
                try:
                    dec = aes_ecb(payload, key)
                except: continue
                
                results = check_content(dec, f, kname, hdr_size, "ECB")
                if results:
                    for kind, content in results:
                        fname_safe = f.replace(".mt", "")
                        out_path = os.path.join(outdir, f"{d}_{fname_safe}_{kind}_{kname}_hdr{hdr_size}")
                        with open(out_path, "wb") as fh:
                            fh.write(content)
                        
                        preview = "".join(chr(b) if 32 <= b < 127 else "." for b in content[:150])
                        print(f"  {kind:25s} | {kname:10s} | HDR{hdr_size} | {d}/{f[:20]:20s} | {preview[:60]}")
                        total_success += 1

print(f"\nTested {files_tested} files, got {total_success} matches")

# Show what was found
print("\n=== Saved files ===")
for f in sorted(os.listdir(outdir)):
    sz = os.path.getsize(os.path.join(outdir, f))
    print(f"  {f} ({sz} bytes)")
