#!/usr/bin/env python3
"""
Comprehensive .MT File Processor — FIXED VERSION
- Scans directories recursively for .mt files
- Decrypts AES-ECB layer  
- Decompresses lmF@ with CORRECT match copy, bounds check, binary tree literal
- Detects output format (Lua, Roo, Unknown)
- Saves all intermediate files for analysis

Fixes applied:
  1. Match copy advances source pointer (was always copying same byte)
  2. Bounds check on match length & source position
  3. Binary tree literal decoding (instead of formula-based)
  4. _db(pr) model matching native implementation

Usage:
  python3 process_mt_all.py scan [directory]      # Scan for .mt files
  python3 process_mt_all.py process [directory]    # Process all .mt files
  python3 process_mt_all.py process-file <file>    # Process a single .mt
"""

import os, sys, struct, json, glob, shutil
from datetime import datetime
from collections import Counter

# AES
from Crypto.Cipher import AES

AES_KEY = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
ANTM_MAGIC = b"Antm"
LMF_MAGIC = b"lmF@"
ROO_MAGIC = b"\x1bL\x6d\x00"
LUA_MAGIC = b"\x1bLua"

# Range coder constants
_P_INIT = 0x400
_P_MAX = 0x800
_P_SHIFT = 5
_RBITS = 11
_RENORM = 0x1000000

def _upd(prob, bit):
    """Update probability after decoding a bit"""
    if bit == 0:
        return (prob + ((_P_MAX - prob) >> _P_SHIFT)) & 0xFFFF
    else:
        return (prob - (prob >> _P_SHIFT)) & 0xFFFF


# ============== AES ==============
def aes_decrypt(data):
    pad = (16 - len(data) % 16) % 16
    if pad: data = data + b"\x00" * pad
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return cipher.decrypt(data)[:len(data) - pad] if pad else cipher.decrypt(data)


# ============== LMF DECOMPRESSOR ==============
class LmfDecompressor:
    """
    lmF@ decompressor — FIXED implementation.
    
    Key fixes from original:
    - Binary tree literal decoding (matches native)
    - _db(pr) model: caller manages table updates
    - Match copy advances through source bytes (src + i)
    - Bounds check on source position
    - Clamp match length to remaining output
    """
    
    def __init__(self, data):
        if data[:4] != b'lmF@':
            raise ValueError(f'Not lmF@: {data[:4]}')
        
        hdr = data[:14]
        e = hdr[4]
        ws = e // 9
        r9 = e % 9
        ps = (ws * 0xCCCCCCCD) >> 34
        r5 = ws - ps * 5
        self.te = (0x300 << (r5 + r9)) + 0x736
        self.mk = (1 << ps) - 1
        self.ds = struct.unpack_from('<I', data, 0x0A)[0] ^ 0x3EA
        
        # XOR payload
        cd = bytearray(data)
        xor_len = min(self.ds, 16)
        for i in range(xor_len):
            cd[0x0E + i] ^= 0xEC
        self.cd = bytes(cd[0x0E:])
        
        # Initial context
        self.ctx = [self.cd[0], self.cd[1], self.cd[2], self.cd[3], self.cd[4]]
        self.si = self.ctx[0] & 0xF
        
        # Range decoder state
        self.dp = 5
        self.h = 0xFFFFFFFF
        self.l = (self.ctx[1] << 24) | (self.ctx[2] << 16) | (self.ctx[3] << 8) | self.ctx[4]
        
        # Probability table
        self.tbl = [_P_INIT] * self.te
        
        # Output and window
        self.out = bytearray()
        self.w = bytearray(4096)
        self.wp = 0
        self.bc = 0
        self.pb = 0
    
    def _rn(self):
        """Renormalize range decoder"""
        while self.h < _RENORM:
            self.h = (self.h << 8) & 0xFFFFFFFF
            if self.dp < len(self.cd):
                self.l = ((self.l << 8) | self.cd[self.dp]) & 0xFFFFFFFF
                self.dp += 1
            else:
                self.l = (self.l << 8) & 0xFFFFFFFF
    
    def _db(self, pr):
        """Decode one bit using given probability value (caller manages table)"""
        self._rn()
        m = ((self.h >> _RBITS) * pr) & 0xFFFFFFFF
        if self.l < m:
            self.h = m
            bit = 0
        else:
            self.l = (self.l - m) & 0xFFFFFFFF
            self.h = (self.h - m) & 0xFFFFFFFF
            bit = 1
        return bit
    
    def _shift_ctx(self, byte):
        """Shift context window with new byte"""
        self.ctx[0], self.ctx[1], self.ctx[2], self.ctx[3], self.ctx[4] = \
            self.ctx[1], self.ctx[2], self.ctx[3], self.ctx[4], byte
        self.si = self.ctx[0] & 0xF
    
    def _decode_literal(self):
        """Decode one byte using binary tree (no context)"""
        ii = 1
        while ii <= 0xFF:
            pr = self.tbl[0x736 + ii]
            b = self._db(pr)
            self.tbl[0x736 + ii] = _upd(pr, b)
            ii = (ii << 1) | b
        return ii & 0xFF
    
    def _decode_match_length(self):
        """Decode match length"""
        si2 = self.si + 0xC0
        if si2 >= self.te: si2 = 0xC0
        pr = self.tbl[si2]
        bs = self._db(pr)
        self.tbl[si2] = _upd(pr, bs)
        
        if bs == 0:
            ii = 1
            while ii <= 7:
                idx = 0x332 + ii
                if idx >= self.te: break
                pr = self.tbl[idx]
                b = self._db(pr)
                self.tbl[idx] = _upd(pr, b)
                ii = (ii << 1) | b
            l2 = (ii & 0xFF) + 3
        else:
            l2 = 0
            for i in range(5):
                idx = (self.si << 4) + 0xCC + i
                if idx >= self.te: break
                pr = self.tbl[idx]
                b = self._db(pr)
                self.tbl[idx] = _upd(pr, b)
                l2 = (l2 << 1) | b
                if b == 0: break
            l2 += 3
        return l2
    
    def _decode_match_distance(self, l2):
        """Decode match distance (LZMA-like)"""
        sc = min(l2 - 3, 3)
        sb = 0x1B0 + sc * 64
        
        sl = 0
        for i in range(6):
            idx = sb + i
            if idx >= self.te: break
            pr = self.tbl[idx]
            b = self._db(pr)
            self.tbl[idx] = _upd(pr, b)
            sl = (sl << 1) | b
            if b == 0: break
        
        if sl < 4:
            d2 = sl + 1
        else:
            ex = (sl >> 1) - 1
            d2 = ((2 + (sl & 1)) << ex) + 1
            for i in range(ex):
                idx = sb + 6 + i
                if idx >= self.te: break
                pr = self.tbl[idx]
                b = self._db(pr)
                self.tbl[idx] = _upd(pr, b)
                d2 = (d2 << 1) | b
        return d2
    
    def decompress(self):
        """Main decompression loop — FIXED"""
        remaining = self.ds
        
        while remaining > 0 and self.dp < len(self.cd) + 10:
            # Main decision (literal vs match)
            ci = (self.si << 4) + (self.bc & self.mk)
            pr = self.tbl[ci]
            is_match = self._db(pr)
            self.tbl[ci] = _upd(pr, is_match)
            
            if is_match == 0:
                # === LITERAL ===
                v = self._decode_literal()
                self.out.append(v)
                self.w[self.wp & 0xFFF] = v
                self.wp += 1
                self.pb = v
                self._shift_ctx(v)
                self.bc += 1
                remaining -= 1
            else:
                # === MATCH ===
                l2 = self._decode_match_length()
                
                # Bounds check
                if l2 > remaining:
                    l2 = remaining
                
                d2 = self._decode_match_distance(l2)
                
                self.bc += 1
                
                # FIXED: advance through source bytes
                src_base = self.wp - d2
                for i in range(l2):
                    if 0 <= src_base < 4096:
                        src = (src_base + i) & 0xFFF
                        by = self.w[src]
                    else:
                        by = 0
                    self.out.append(by)
                    self.w[self.wp & 0xFFF] = by
                    self.wp += 1
                    self.pb = by
                    self._shift_ctx(by)
                
                remaining -= l2
        
        return bytes(self.out[:self.ds])


# ============== SCAN ==============
def scan_mt_files(directory="."):
    """Scan directory recursively for .mt files"""
    results = []
    for root, dirs, files in os.walk(directory):
        skip = False
        parts = root.replace(os.sep, '/').split('/')
        for p in parts:
            if p.startswith('.') and p not in ('.', '..'):
                skip = True
                break
        if skip:
            continue
        for fname in files:
            if fname.endswith('.mt'):
                path = os.path.join(root, fname)
                try:
                    size = os.path.getsize(path)
                    with open(path, 'rb') as f:
                        magic = f.read(4)
                    results.append({
                        'path': path,
                        'filename': fname,
                        'size': size,
                        'magic': magic.hex() if magic else '?',
                        'is_valid_mt': magic == ANTM_MAGIC,
                    })
                except:
                    pass
    return results


def scan_apk_mt_files(apk_path="."):
    """Scan APK files for .mt inside"""
    results = []
    import zipfile
    for root, dirs, files in os.walk(apk_path):
        for fname in files:
            if fname.endswith('.apk'):
                path = os.path.join(root, fname)
                try:
                    with zipfile.ZipFile(path) as z:
                        mt_list = sorted([f for f in z.namelist() if f.endswith('.mt')])
                        if mt_list:
                            results.append({
                                'apk': path,
                                'count': len(mt_list),
                                'files': mt_list[:5],
                                'total_size': sum(z.getinfo(f).file_size for f in mt_list),
                            })
                except:
                    pass
    return results


# ============== PROCESS ==============
def process_mt_file(mt_path, output_dir="processed_out", save_lmf=True, save_bin=True, save_json=True):
    """Process a single .mt file through the full pipeline"""
    basename = os.path.splitext(os.path.basename(mt_path))[0]
    out_subdir = os.path.join(output_dir, basename)
    os.makedirs(out_subdir, exist_ok=True)
    
    result = {
        'source': mt_path,
        'basename': basename,
        'size': 0,
        'steps': [],
    }
    
    with open(mt_path, 'rb') as f:
        raw = f.read()
    result['size'] = len(raw)
    result['magic'] = raw[:4].hex()
    
    if raw[:4] != ANTM_MAGIC:
        result['error'] = f"Not a valid .mt file (magic: {raw[:4]})"
        return result
    
    # Step 1: AES Decrypt
    dec = aes_decrypt(raw[16:])
    dec_path = os.path.join(out_subdir, basename + '.lmf')
    if save_lmf:
        with open(dec_path, 'wb') as f:
            f.write(dec)
    
    result['aes_decrypted'] = {
        'size': len(dec),
        'magic': dec[:4].hex(),
        'saved_to': dec_path,
    }
    result['steps'].append('aes_decrypt')
    
    if dec[:4] != LMF_MAGIC:
        result['error'] = f"AES decryption produced non-lmF@ format: {dec[:4]}"
        return result
    
    # Step 2: Parse lmF@ header
    hdr = dec[:14]
    e = hdr[4]
    ws = e // 9
    r9 = e % 9
    ps = (ws * 0xCCCCCCCD) >> 34
    r5 = ws - ps * 5
    te = (0x300 << (r5 + r9)) + 0x736
    mk = (1 << ps) - 1
    ds = struct.unpack_from('<I', dec, 0x0A)[0] ^ 0x3EA
    
    result['lmf_header'] = {
        'e': e, 'ws': ws, 'r9': r9, 'ps': ps, 'r5': r5,
        'te': te, 'mk': mk, 'ds': ds,
        'header_hex': hdr.hex(),
    }
    result['steps'].append('header_parse')
    
    # Step 3: Decompress
    try:
        decomp = LmfDecompressor(dec)
        best_out = decomp.decompress()
    except Exception as ex:
        result['error'] = f"Decompression failed: {ex}"
        return result
    
    result['decompression'] = {
        'output_size': len(best_out),
    }
    
    if best_out:
        out_path = os.path.join(out_subdir, basename + '.bin')
        if save_bin:
            with open(out_path, 'wb') as f:
                f.write(best_out)
        result['decompression']['saved_to'] = out_path
        
        # Detect format
        detected_format = "unknown"
        if best_out[:4] == LUA_MAGIC:
            detected_format = "Lua bytecode"
            lua_path = os.path.join(out_subdir, basename + '.luac')
            if save_bin:
                shutil.copy(out_path, lua_path)
            result['decompression']['lua_path'] = lua_path
        elif best_out[:4] == ROO_MAGIC:
            detected_format = "Roo Binary"
            try:
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                from roo_parser import parse_roo
                roo = parse_roo(best_out)
                result['decompression']['roo_info'] = {
                    'entries': roo.get('entry_count', 0),
                    'records': roo.get('record_count', 0),
                    'type': roo.get('detected_type', 'Unknown'),
                }
                if save_json:
                    json_path = os.path.join(out_subdir, basename + '.json')
                    with open(json_path, 'w') as f:
                        json.dump(roo, f, indent=2, default=str)
                    result['decompression']['json_path'] = json_path
            except Exception as e:
                result['decompression']['roo_error'] = str(e)
        else:
            text_ratio = sum(1 for b in best_out[:min(1000, len(best_out))] if 32 <= b < 127) / min(1000, len(best_out))
            if text_ratio > 0.8:
                detected_format = "text"
            else:
                detected_format = "binary"
        
        result['decompression']['format'] = detected_format
        
        # Preview
        preview = ""
        for b in best_out[:200]:
            if 32 <= b < 127:
                preview += chr(b)
            else:
                preview += '.'
        result['decompression']['preview'] = preview
        
        result['steps'].append('decompress')
    
    # Step 4: Save info JSON
    if save_json:
        info_path = os.path.join(out_subdir, basename + '_info.json')
        with open(info_path, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        result['info_saved_to'] = info_path
    
    return result


def process_directory(directory=".", output_dir="processed_out"):
    """Process all .mt files in a directory tree"""
    mt_files = scan_mt_files(directory)
    print(f"Found {len(mt_files)} .mt files in '{directory}'")
    
    results = []
    for i, info in enumerate(mt_files):
        path = info['path']
        print(f"\n[{i+1}/{len(mt_files)}] Processing: {path}")
        print(f"  Size: {info['size']} bytes, Magic: {info['magic']}")
        
        if not info['is_valid_mt']:
            print(f"  ⚠ Skipping: invalid magic")
            continue
        
        try:
            res = process_mt_file(path, output_dir)
            results.append(res)
            
            print(f"  ✓ AES decrypted: {res['aes_decrypted']['size']} bytes")
            lmf = res.get('lmf_header', {})
            print(f"  ✓ Header: ds={lmf.get('ds','?')}")
            
            dec = res.get('decompression', {})
            if dec.get('format'):
                print(f"  ✓ Decompressed: {dec.get('output_size',0)} bytes [{dec.get('format','?')}]")
            else:
                print(f"  ✗ Decompression failed")
        except Exception as e:
            print(f"  ✗ Error: {e}")
            import traceback
            traceback.print_exc()
    
    total = len(results)
    decomp_ok = sum(1 for r in results if r.get('decompression', {}).get('format'))
    lua_count = sum(1 for r in results if r.get('decompression', {}).get('format') == 'Lua bytecode')
    roo_count = sum(1 for r in results if r.get('decompression', {}).get('format') == 'Roo Binary')
    
    print(f"\n{'='*60}")
    print(f"SUMMARY: Scanned {len(mt_files)} files, Processed {total}")
    print(f"  Decompressed: {decomp_ok}/{total}")
    print(f"  Lua bytecode: {lua_count}")
    print(f"  Roo Binary:   {roo_count}")
    print(f"  Output: {os.path.abspath(output_dir)}/")
    
    return results


# ============== MAIN ==============
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    
    cmd = sys.argv[1]
    
    if cmd == 'scan':
        directory = sys.argv[2] if len(sys.argv) >= 3 else "."
        print(f"Scanning for .mt files in: {directory}")
        
        mt_files = scan_mt_files(directory)
        print(f"\nFound {len(mt_files)} .mt files:")
        for f in mt_files:
            valid = "✓" if f['is_valid_mt'] else "✗"
            print(f"  [{valid}] {f['size']:>8}B  {f['path']}")
        
        print(f"\nScanning APK files for embedded .mt files...")
        apk_mt = scan_apk_mt_files(directory)
        print(f"Found {len(apk_mt)} APKs with .mt files:")
        for a in apk_mt:
            print(f"  {a['apk']}: {a['count']} files, {a['total_size']:,} bytes total")
            for f in a['files'][:3]:
                print(f"    - {f}")
            if a['count'] > 3:
                print(f"    ... and {a['count']-3} more")
    
    elif cmd == 'process':
        directory = sys.argv[2] if len(sys.argv) >= 3 else "."
        output = sys.argv[3] if len(sys.argv) >= 4 else "processed_out"
        process_directory(directory, output)
    
    elif cmd == 'process-file':
        if len(sys.argv) < 3:
            print("Usage: process-file <file.mt> [output_dir]")
            return
        fpath = sys.argv[2]
        output = sys.argv[3] if len(sys.argv) >= 4 else "processed_out"
        
        if not os.path.exists(fpath):
            print(f"File not found: {fpath}")
            return
        
        res = process_mt_file(fpath, output)
        
        print(f"\nResult for {fpath}:")
        print(json.dumps(res, indent=2, default=str))
    
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)


if __name__ == '__main__':
    main()
