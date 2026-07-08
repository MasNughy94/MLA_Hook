#!/usr/bin/env python3
"""
Ekstrak dan decrypt .mt files dari APK Mobile Legends Adventure.

Usage:
  python3 extract_mt.py list                              # List semua .mt files
  python3 extract_mt.py find <hash>                        # Cari file by hash
  python3 extract_mt.py extract <hash> [output_dir]        # Ekstrak + decrypt 1 file
  python3 extract_mt.py extract-lua [output_dir]           # Ekstrak semua candidate Lua
  python3 extract_mt.py info <hash>                        # Info header+ds
"""

import os, sys, struct, zipfile
from Crypto.Cipher import AES

AES_KEY = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
APK = '/storage/emulated/0/Download/ML_ Adventure_1.1.664.apk'

def aes_decrypt(data):
    pad = (16 - len(data) % 16) % 16
    if pad: data = data + b"\x00" * pad
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return cipher.decrypt(data)[:len(data) - pad] if pad else cipher.decrypt(data)

def parse_lmf_header(data):
    """Parse lmF@ header, return dict of parameters"""
    if data[:4] != b'lmF@':
        return None
    hdr = data[:14]
    e = hdr[4]
    ws = e // 9
    r9 = e % 9
    ps = (ws * 0xCCCCCCCD) >> 34
    r5 = ws - ps * 5
    te = (0x300 << (r5 + r9)) + 0x736
    mk = (1 << ps) - 1
    ds = struct.unpack_from('<I', data, 0x0A)[0] ^ 0x3EA
    return {
        'e': e, 'ws': ws, 'r9': r9, 'ps': ps, 'r5': r5,
        'te': te, 'mk': mk, 'ds': ds,
        'header_hex': hdr.hex(),
        'raw_size': len(data),
    }

def find_mt(search_hash=None, target_ds=None):
    """Find .mt files in APK matching criteria"""
    if not os.path.exists(APK):
        print(f"APK not found: {APK}")
        return []
    
    results = []
    with zipfile.ZipFile(APK) as z:
        mt_files = sorted([f for f in z.namelist() if f.endswith('.mt')])
        
        for fname in mt_files:
            if search_hash and search_hash.lower() not in fname.lower():
                continue
            
            raw = z.read(fname)
            if len(raw) < 32 or raw[:4] != b'Antm':
                continue
            
            dec = aes_decrypt(raw[16:])
            if dec[:4] != b'lmF@':
                continue
            
            info = parse_lmf_header(dec)
            if info:
                if target_ds and info['ds'] != target_ds:
                    continue
                info['filename'] = fname
                info['apk_size'] = len(raw)
                results.append(info)
        
    return results

def extract_file(fname, output_dir):
    """Extract and decrypt a .mt file"""
    os.makedirs(output_dir, exist_ok=True)
    
    with zipfile.ZipFile(APK) as z:
        raw = z.read(fname)
    
    basename = os.path.splitext(os.path.basename(fname))[0]
    
    # Save original
    orig_path = os.path.join(output_dir, basename + '.mt')
    with open(orig_path, 'wb') as f:
        f.write(raw)
    print(f"Original: {orig_path} ({len(raw)} bytes)")
    
    # AES decrypt
    dec = aes_decrypt(raw[16:])
    dec_path = os.path.join(output_dir, basename + '.lmf')
    with open(dec_path, 'wb') as f:
        f.write(dec)
    print(f"AES dec:  {dec_path} ({len(dec)} bytes)")
    
    # Parse info
    info = parse_lmf_header(dec)
    if info:
        print(f"  ds={info['ds']}, te={info['te']}, mk={info['mk']}")
        print(f"  e={info['e']}, ws={info['ws']}, r9={info['r9']}, ps={info['ps']}, r5={info['r5']}")
    
    return dec

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    
    cmd = sys.argv[1]
    
    if cmd == 'list':
        results = find_mt()
        print(f"Total .mt files: {len(results)}")
        print(f"\nFirst 20:")
        for r in results[:20]:
            lua = "← LUA!" if r['ds'] == 12585 else ""
            print(f"  {r['filename']}: {r['apk_size']:>7}B → ds={r['ds']:>6}B r5={r['r5']} ps={r['ps']} r9={r['r9']}{lua}")
        
        # Show largest files
        largest = sorted(results, key=lambda x: -x['ds'])[:10]
        print(f"\n10 largest by decompressed size:")
        for r in largest:
            print(f"  {r['filename']}: {r['apk_size']:>7}B → ds={r['ds']:>7}B")
        
        # Show files with specific ds values
        print(f"\nFiles with ds=12585 (Lua candidate):")
        for r in results:
            if r['ds'] == 12585:
                print(f"  {r['filename']}: {r['apk_size']}B, "
                      f"e={r['e']}, r5={r['r5']}, ps={r['ps']}, r9={r['r9']}")
    
    elif cmd == 'find':
        if len(sys.argv) < 3:
            print("Usage: find <hash>")
            return
        results = find_mt(search_hash=sys.argv[2])
        if results:
            for r in results:
                print(f"  {r['filename']}: {r['apk_size']}B → ds={r['ds']}B")
        else:
            print("Not found")
    
    elif cmd == 'extract':
        if len(sys.argv) < 3:
            print("Usage: extract <hash> [output_dir]")
            return
        outdir = sys.argv[3] if len(sys.argv) >= 4 else "extracted"
        
        results = find_mt(search_hash=sys.argv[2])
        if not results:
            print(f"No file matching hash: {sys.argv[2]}")
            return
        for r in results:
            extract_file(r['filename'], outdir)
    
    elif cmd == 'extract-lua':
        outdir = sys.argv[2] if len(sys.argv) >= 3 else "lua_extracted"
        results = find_mt(target_ds=12585)
        print(f"Found {len(results)} Lua candidate files (ds=12585)")
        for r in results:
            print(f"\nExtracting: {r['filename']}...")
            dec = extract_file(r['filename'], outdir)
            # Save as .lmf for PC processing
    
    elif cmd == 'info':
        if len(sys.argv) < 3:
            print("Usage: info <hash>")
            return
        results = find_mt(search_hash=sys.argv[2])
        if results:
            for r in results:
                print(f"File: {r['filename']}")
                print(f"  APK size: {r['apk_size']} bytes")
                print(f"  Header: {r['header_hex']}")
                for k in ['e', 'ws', 'r9', 'ps', 'r5', 'te', 'mk']:
                    print(f"  {k}: {r[k]}")
                print(f"  ds (decompressed): {r['ds']} bytes")
                print(f"  raw_size after AES: {r['raw_size']} bytes")
        else:
            print("Not found")
    
    else:
        print(f"Unknown command: {cmd}")


if __name__ == '__main__':
    main()
