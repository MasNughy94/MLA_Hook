#!/usr/bin/env python3
"""
MT Tool v2 — Full pipeline: .mt → AES → lmF@ → Roo Binary
Based on Claude reverse engineering resume (29 Juni 2026).

Perbaikan kunci:
1. Formula 5 untuk literal tree bit-level context (verified)
2. Match/LZ77 copy handling lengkap
3. Roo Binary parser
"""

import os, sys, struct, json

# ============================================================
# CONSTANTS
# ============================================================
AES_KEY = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
ANTM_MAGIC = b"Antm"
LMF_MAGIC = b"lmF@"
ROO_MAGIC = b"\x1bL\x6d\x00"

_P_INIT = 0x400
_P_MAX = 0x800
_P_SHIFT = 5
_RBITS = 11
_RENORM = 0x1000000

# 8 formula untuk literal bit context
FORMULAS = [
    lambda bc, bp: (bc & 3) + bp * 4,                     # 0
    lambda bc, bp: (bc & 3) + bp * 16,                    # 1
    lambda bc, bp: bp + (bc & 0xF) * 4,                   # 2
    lambda bc, bp: bp + (bc & 3) * 8,                     # 3
    lambda bc, bp: ((bc & 3) << 4) + (bp << 6) + (bc & 0xF),  # 4
    lambda bc, bp: (bc & 3) + (bc & 0xF) * 4,             # 5 (VERIFIED)
    lambda bc, bp: bp + ((bc & 3) << 4),                  # 6
    lambda bc, bp: bp * 2 + (bc >> 4) * 16 + (bc & 3),    # 7
]

def _upd(prob, bit):
    return ((prob + ((_P_MAX - prob) >> _P_SHIFT)) if bit == 0 else (prob - (prob >> _P_SHIFT))) & 0xFFFF


# ============================================================
# AES
# ============================================================
def aes_decrypt(data):
    try:
        from Crypto.Cipher import AES
    except ImportError:
        raise ImportError("pip install pycryptodome")
    pad = (16 - len(data) % 16) % 16
    if pad: data = data + b"\x00" * pad
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return cipher.decrypt(data)[:len(data) - pad] if pad else cipher.decrypt(data)


# ============================================================
# LMF DECOMPRESSOR
# ============================================================
class LmfDecompressor:
    """lmF@ range decoder dengan formula 5 untuk literal bits + LZ77 match"""
    
    def __init__(self, data, formula_idx=5, max_extra=100000):
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
        
        # Range state
        self.dp = 5
        self.h = 0xFFFFFFFF
        self.l = (self.ctx[1] << 24) | (self.ctx[2] << 16) | (self.ctx[3] << 8) | self.ctx[4]
        
        # Tables & buffers
        self.tbl = [_P_INIT] * self.te
        self.out = bytearray()
        self.w = bytearray(4096)  # sliding window
        self.wp = 0
        self.bc = 0     # byte counter (for main decision context)
        self._bc_byte = 0  # partial byte (for literal context)
        
        self.formula = FORMULAS[formula_idx]
        self.formula_idx = formula_idx
        self.max_extra = max_extra
    
    def _rn(self):
        while self.h < _RENORM:
            self.h = (self.h << 8) & 0xFFFFFFFF
            if self.dp < len(self.cd):
                self.l = ((self.l << 8) | self.cd[self.dp]) & 0xFFFFFFFF
                self.dp += 1
            else:
                self.l = (self.l << 8) & 0xFFFFFFFF
    
    def _db(self, idx):
        self._rn()
        pr = self.tbl[idx]
        m = ((self.h >> _RBITS) * pr) & 0xFFFFFFFF
        if self.l < m:
            self.h = m
            bit = 0
        else:
            self.l = (self.l - m) & 0xFFFFFFFF
            self.h = (self.h - m) & 0xFFFFFFFF
            bit = 1
        self.tbl[idx] = _upd(pr, bit)
        return bit
    
    def _shift_ctx(self, byte):
        self.ctx[0], self.ctx[1], self.ctx[2], self.ctx[3], self.ctx[4] = \
            self.ctx[1], self.ctx[2], self.ctx[3], self.ctx[4], byte
        self.si = self.ctx[0] & 0xF
    
    def _decode_literal_formula(self):
        """Decode 8 bits using formula-based context (NO binary tree)"""
        partial = 0
        for bit_pos in range(8):
            ci = self.formula(partial, bit_pos)
            if ci >= self.te:
                ci = ci % self.te
            b = self._db(ci)
            partial = (partial << 1) | b
        return partial
    
    def _decode_literal_tree(self):
        """Decode byte using binary tree (original approach)"""
        ii = 1
        while ii <= 0xFF:
            b = self._db(0x736 + ii)
            ii = (ii << 1) | b
            if ii >= self.te:
                break
        return ii & 0xFF
    
    def _decode_match_length(self):
        """Decode match length"""
        si2 = self.si + 0xC0
        if si2 >= self.te: si2 = 0xC0
        bs = self._db(si2)
        self.tbl[si2] = _upd(self.tbl[si2], bs)
        
        if bs == 0:
            # Short length via tree
            ii = 1
            while ii <= 7:
                idx = 0x332 + ii
                if idx >= self.te: break
                b = self._db(idx)
                self.tbl[idx] = _upd(self.tbl[idx], b)
                ii = (ii << 1) | b
            l2 = (ii & 0xFF) + 3
        else:
            # Extra bits
            l2 = 0
            for i in range(5):
                idx = (self.si << 4) + 0xCC + i
                if idx >= self.te: break
                b = self._db(idx)
                self.tbl[idx] = _upd(self.tbl[idx], b)
                l2 = (l2 << 1) | b
                if b == 0: break
            l2 += 3
        return l2
    
    def _decode_match_distance(self, l2):
        """Decode match distance"""
        sc = min(l2 - 3, 3)
        sb = 0x1B0 + sc * 64
        
        sl = 0
        for i in range(6):
            idx = sb + i
            if idx >= self.te: break
            b = self._db(idx)
            self.tbl[idx] = _upd(self.tbl[idx], b)
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
                b = self._db(idx)
                self.tbl[idx] = _upd(self.tbl[idx], b)
                d2 = (d2 << 1) | b
        return d2
    
    def decompress(self):
        """Main decompression"""
        target = self.ds * 3  # safety limit
        while len(self.out) < self.ds and len(self.out) < target and self.dp < len(self.cd) + 10:
            # === MAIN DECISION (literal vs match) ===
            # Context: (si << 4) + (bc & mk) — verified working
            ci = (self.si << 4) + (self.bc & self.mk)
            if ci >= self.te: ci = 0
            b = self._db(ci)
            
            if b == 0:
                # === LITERAL ===
                v = self._decode_literal_formula()
                self.out.append(v)
                self.w[self.wp & 0xFFF] = v
                self.wp += 1
                self.pb = v
                self._shift_ctx(v)
                self.bc += 1
            else:
                # === MATCH (LZ77 copy) ===
                l2 = self._decode_match_length()
                d2 = self._decode_match_distance(l2)
                
                self.bc += 1
                for i in range(l2):
                    src = self.wp - d2
                    if src < 0: src = 0
                    by = self.w[(src + i) & 0xFFF] if (src + i) < 4096 else 0
                    self.out.append(by)
                    self.w[self.wp & 0xFFF] = by
                    self.wp += 1
                    self.pb = by
                    self._shift_ctx(by)
            
            if len(self.out) % 10000 == 0 and len(self.out) > 0:
                pass  # progress
        
        return bytes(self.out[:self.ds])
    
    @staticmethod
    def try_all(data):
        """Try all 8 formulas, return best"""
        best_score = -1
        best_f = 0
        best_out = None
        for fidx in range(8):
            try:
                dec = LmfDecompressor(data, formula_idx=fidx)
                out = dec.decompress()
                score = 0
                if len(out) >= 69:
                    if out[:4] == ROO_MAGIC: score += 10000
                    if b"Roo" in out[:69]: score += 5000
                    if out[:4] == b"\x1bLua": score += 3000
                    printable = sum(1 for b in out[:200] if 32 <= b < 127)
                    score += printable
                    # Check for non-zero data
                    non_zero = sum(1 for b in out[:200] if b != 0)
                    score += non_zero
                if score > best_score:
                    best_score = score
                    best_f = fidx
                    best_out = out
            except:
                pass
        return best_f, best_out, best_score


# ============================================================
# ROO BINARY PARSER
# ============================================================
def parse_roo(data):
    """Parse Roo Binary Format (69-byte header + 3-byte records)"""
    if len(data) < 69:
        return {"error": f"Too small: {len(data)} bytes"}
    if data[:4] != ROO_MAGIC:
        return {"error": f"Not Roo: magic={data[:4].hex()}"}
    
    body = data[69:]
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        records.append({"tag": tag, "v1": v1, "v2": v2, "offset": i // 3})
    
    # Cluster into entries (gap threshold = 30 bytes = 10 records)
    entries = []
    cur = []
    last_offset = -1
    for r in records:
        if r["tag"] == 0 and r["v1"] == 0 and r["v2"] == 0:
            continue
        if r["tag"] != 0:
            if last_offset >= 0 and (r["offset"] - last_offset) > 10 and len(cur) > 0:
                entries.append(cur)
                cur = []
            last_offset = r["offset"]
        cur.append(r)
    if cur: entries.append(cur)
    
    # Build result
    result = {
        "magic": data[:4].hex(),
        "roo_str": str(data[6:10]),
        "format_byte": f"0x{data[10]:02X}",
        "body_size": len(body),
        "total_size": len(data),
        "record_count": len(records),
        "entry_count": len(entries),
    }
    
    # Format entries
    entry_list = []
    for ei, entry in enumerate(entries[:500]):  # limit
        fields = []
        for r in entry:
            raw = (r["v1"] << 8) | r["v2"]
            vtype = "unknown"
            if r["v1"] == 0 and r["v2"] == 0: vtype = "zero"
            elif r["v2"] == 0 and r["v1"] <= 8: vtype = "enum"
            elif r["v1"] == r["v2"]: vtype = "pair"
            elif r["v1"] < 0x10: vtype = "sparse"
            fields.append({
                "tag_hex": f"0x{r['tag']:02X}",
                "v1": r["v1"], "v2": r["v2"], "raw": raw, "type": vtype
            })
        
        sig = "-".join(sorted(set(f["tag_hex"] for f in fields)))
        entry_list.append({
            "index": ei,
            "field_count": len(fields),
            "signature": sig,
            "fields": fields
        })
    
    result["entries"] = entry_list
    
    # Detect entity type
    if entry_list:
        sig = entry_list[0]["signature"]
        patterns = {
            "0x17": "HeroRosterDB", "0x25": "SkillDB",
            "0x0C": "EquipDB", "0x11": "StageDB",
            "0x20": "HeroStatDB", "0x0A": "MasterDB",
            "0xF1": "MonsterDB",
        }
        for tag, etype in patterns.items():
            if tag in sig:
                result["detected_type"] = etype
                break
        if "detected_type" not in result:
            result["detected_type"] = f"Unknown({sig[:40]})"
    
    return result


# ============================================================
# MAIN
# ============================================================
def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  mt_tool_v2.py info <file>")
        print("  mt_tool_v2.py extract <file.mt> [output_dir]")
        print("  mt_tool_v2.py parse-roo <file.bin>")
        print("  mt_tool_v2.py test [sample.dec]")
        return
    
    cmd = sys.argv[1]
    
    if cmd == 'test':
        sample = sys.argv[2] if len(sys.argv) >= 3 else "/storage/emulated/0/Alarms/sampel/0000488d.dec"
        if not os.path.exists(sample):
            print(f"Sample not found: {sample}")
            return
        
        with open(sample, 'rb') as f:
            data = f.read()
        print(f"Sample: {os.path.basename(sample)} ({len(data)} bytes)")
        
        for fidx in range(8):
            try:
                dec = LmfDecompressor(data, formula_idx=fidx)
                out = dec.decompress()
                is_roo = "✓ROO" if out[:4] == ROO_MAGIC else ""
                is_lua = "✓LUA" if out[:4] == b"\x1bLua" else ""
                printable = sum(1 for b in out[:200] if 32 <= b < 127)
                non_zero = sum(1 for b in out[:200] if b != 0)
                print(f"  F{fidx}: {len(out)}B magic={out[:4].hex()} {is_roo}{is_lua} "
                      f"print={printable}/200 nz={non_zero}/200")
            except Exception as e:
                print(f"  F{fidx}: ERROR - {e}")
    
    elif cmd == 'extract':
        if len(sys.argv) < 3:
            print("Usage: extract <file.mt> [output_dir]")
            return
        fpath = sys.argv[2]
        outdir = sys.argv[3] if len(sys.argv) >= 4 else "extracted"
        os.makedirs(outdir, exist_ok=True)
        
        base = os.path.splitext(os.path.basename(fpath))[0]
        
        # AES decrypt
        with open(fpath, 'rb') as f:
            raw = f.read()
        if raw[:4] != ANTM_MAGIC:
            print("Not a .mt file")
            return
        dec = aes_decrypt(raw[16:])
        dec_path = os.path.join(outdir, base + ".dec")
        with open(dec_path, 'wb') as f:
            f.write(dec)
        print(f"AES decrypted: {len(raw)} → {len(dec)} bytes")
        
        if dec[:4] != LMF_MAGIC:
            print(f"Not lmF@ after AES: {dec[:4]}")
            return
        
        # Try all formulas
        best_f, best_out, best_score = LmfDecompressor.try_all(dec)
        print(f"Best formula: {best_f} (score={best_score})")
        
        if best_out:
            out_path = os.path.join(outdir, base + ".bin")
            with open(out_path, 'wb') as f:
                f.write(best_out)
            print(f"Decompressed: {len(best_out)} bytes -> {out_path}")
            
            if best_out[:4] == ROO_MAGIC:
                print("✓ Roo Binary Format!")
                roo = parse_roo(best_out)
                print(f"  Entries: {roo['entry_count']}, Records: {roo['record_count']}")
                print(f"  Type: {roo.get('detected_type', '?')}")
                json_path = os.path.join(outdir, base + ".json")
                with open(json_path, 'w') as f:
                    json.dump(roo, f, indent=2)
                print(f"  JSON: {json_path}")
            elif best_out[:4] == b"\x1bLua":
                print("✓ Lua bytecode!")
                lua_path = os.path.join(outdir, base + ".luac")
                with open(lua_path, 'wb') as f:
                    f.write(best_out)
            else:
                print(f"Unknown format: {best_out[:8].hex()}")
                printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in best_out[:100])
                print(f"  ASCII: {printable}")
    
    elif cmd == 'parse-roo':
        if len(sys.argv) < 3:
            return
        with open(sys.argv[2], 'rb') as f:
            data = f.read()
        roo = parse_roo(data)
        if "error" in roo:
            print(f"Error: {roo['error']}")
            return
        print(f"Roo Binary:")
        print(f"  Magic: {roo['magic']}")
        print(f"  Format: {roo['format_byte']}")
        print(f"  Body: {roo['body_size']} bytes")
        print(f"  Records: {roo['record_count']}")
        print(f"  Entries: {roo['entry_count']}")
        print(f"  Type: {roo.get('detected_type', '?')}")
        for ei, e in enumerate(roo['entries'][:3]):
            print(f"\n  Entry {ei}: {e['field_count']} fields [{e['signature'][:60]}]")
            for f in e['fields'][:16]:
                print(f"    [{f['tag_hex']}] v1={f['v1']:3d} v2={f['v2']:3d} raw={f['raw']:5d} {f['type']}")
            if len(e['fields']) > 16:
                print(f"    ... ({len(e['fields'])-16} more)")
        if len(roo['entries']) > 3:
            print(f"\n  ... ({len(roo['entries'])-3} more entries)")
    
    elif cmd == 'info':
        with open(sys.argv[2], 'rb') as f:
            data = f.read()
        print(f"Size: {len(data)} bytes, Magic: {data[:4]}")
        if data[:4] == ANTM_MAGIC:
            print("Format: .mt (Antm encrypted)")
        elif data[:4] == LMF_MAGIC:
            print("Format: lmF@ (AES-decrypted)")
        elif data[:4] == ROO_MAGIC:
            print("Format: Roo Binary")
        else:
            print(f"Unknown: {data[:16].hex()}")
    
    else:
        print(f"Unknown: {cmd}")


if __name__ == '__main__':
    main()
