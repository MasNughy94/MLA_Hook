#!/usr/bin/env python3
"""
V6: Binary tree literal decoding (proper LZMA approach).
Based on lmf_fix.py FixedLmfDecompressor.
Uses tree: idx = 0x736 + combined * 0x300 + tree_node
Where combined = (prev_byte >> (8-lc)) + ((bc & lp_mask) << lc)
"""
import os, sys, struct, glob

ROO_MAGIC = b"\x1bL\x6d\x00"
LUA_MAGIC = b"\x1bLua"

_P_INIT = 0x400
_P_MAX = 0x800
_P_SHIFT = 5
_RBITS = 11
_RENORM = 0x1000000  # Keep original


class LmfDecompressor_V6:
    """V6: Binary tree literal with proper LZMA context"""
    
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
        
        # LZMA context parameters
        self.lc = r9   # literal context bits
        self.lp = ps   # position bits
        self.lp_mask = self.mk
        self.pb = 0    # prev_byte for literal context
        
        # XOR payload (keep original approach)
        cd = bytearray(data)
        xor_len = min(self.ds, 16)
        for i in range(xor_len):
            cd[0x0E + i] ^= 0xEC
        self.cd = bytes(cd[0x0E:])
        
        # Original initial state from prefix
        self.ctx = [self.cd[0], self.cd[1], self.cd[2], self.cd[3], self.cd[4]]
        self.si = self.ctx[0] & 0xF
        
        # Range decoder init (original approach)
        self.dp = 5
        self.h = 0xFFFFFFFF
        self.l = (self.ctx[1] << 24) | (self.ctx[2] << 16) | (self.ctx[3] << 8) | self.ctx[4]
        
        self.tbl = [_P_INIT] * self.te
        self.out = bytearray()
        self.w = bytearray(4096)
        self.wp = 0
        self.bc = 0
        self.prev_byte = 0
    
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
        if idx >= self.te:
            idx = 0  # fallback to 0
        pr = self.tbl[idx]
        m = ((self.h >> _RBITS) * pr) & 0xFFFFFFFF
        if self.l < m:
            self.h = m
            bit = 0
        else:
            self.l = (self.l - m) & 0xFFFFFFFF
            self.h = (self.h - m) & 0xFFFFFFFF
            bit = 1
        # Update probability
        if bit == 0:
            self.tbl[idx] = (pr + ((_P_MAX - pr) >> _P_SHIFT)) & 0xFFFF
        else:
            self.tbl[idx] = (pr - (pr >> _P_SHIFT)) & 0xFFFF
        return bit
    
    def _shift_ctx(self, byte):
        self.ctx[0], self.ctx[1], self.ctx[2], self.ctx[3], self.ctx[4] = \
            self.ctx[1], self.ctx[2], self.ctx[3], self.ctx[4], byte
        self.si = self.ctx[0] & 0xF
    
    # ========== BINARY TREE LITERAL ==========
    def _decode_literal_tree(self):
        """Decode one literal byte using binary tree with LZMA context"""
        # Calculate context
        if self.bc == 0:
            combined = 0  # first byte, no context
        else:
            lc_part = self.prev_byte >> (8 - self.lc) if self.lc > 0 else 0
            pos_part = (self.bc & self.lp_mask) << self.lc
            combined = lc_part + pos_part
        
        # Binary tree: start at node 1, traverse 8 levels
        ii = 1
        while ii <= 0xFF:
            idx = 0x736 + combined * 0x300 + ii
            if idx >= self.te:
                idx = 0x736 + ii  # fallback without context
            b = self._db(idx)
            ii = (ii << 1) | b
        
        return ii & 0xFF
    
    # ========== FORMULA LITERAL ==========
    def _decode_literal_formula5(self):
        """Formula 5 literal: (bc & 3) + (bc & 0xF) * 4"""
        partial = 0
        for bit_pos in range(8):
            # Formula 5: doesn't use bit_pos
            ci = (partial & 3) + (partial & 0xF) * 4
            if ci >= self.te:
                ci = ci % self.te
            b = self._db(ci)
            partial = (partial << 1) | b
        return partial
    
    # ========== MATCH LENGTH (original) ==========
    def _decode_match_length(self):
        si2 = self.si + 0xC0
        if si2 >= self.te: si2 = 0xC0
        bs = self._db(si2)
        
        if bs == 0:
            ii = 1
            while ii <= 7:
                idx = 0x332 + ii
                if idx >= self.te: break
                b = self._db(idx)
                ii = (ii << 1) | b
            l2 = (ii & 0xFF) + 3  # Keep original: 11..18
        else:
            l2 = 0
            for i in range(5):
                idx = (self.si << 4) + 0xCC + i
                if idx >= self.te: break
                b = self._db(idx)
                l2 = (l2 << 1) | b
                if b == 0: break
            l2 += 3
        return l2
    
    # ========== MATCH DISTANCE (original) ==========
    def _decode_match_distance(self, l2):
        sc = min(l2 - 3, 3)
        sb = 0x1B0 + sc * 64
        
        sl = 0
        for i in range(6):
            idx = sb + i
            if idx >= self.te: break
            b = self._db(idx)
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
                d2 = (d2 << 1) | b
        return d2
    
    # ========== MAIN ==========
    def decompress(self):
        max_iters = max(50000, self.ds * 3)
        iters = 0
        
        while len(self.out) < self.ds and self.dp < len(self.cd) + 10 and iters < max_iters:
            iters += 1
            
            # MAIN DECISION
            ci = (self.si << 4) + (self.bc & self.mk)
            if ci >= self.te: ci = 0
            is_match = self._db(ci)
            
            if is_match == 0:
                # LITERAL using binary tree
                v = self._decode_literal_tree()
                self.out.append(v)
                self.w[self.wp & 0xFFF] = v
                self.wp += 1
                self._shift_ctx(v)
                self.prev_byte = v
                self.bc += 1
            else:
                # MATCH
                l2 = self._decode_match_length()
                d2 = self._decode_match_distance(l2)
                
                self.bc += 1
                for i in range(l2):
                    src = (self.wp - d2) & 0xFFF
                    by = self.w[src]
                    self.out.append(by)
                    self.w[self.wp & 0xFFF] = by
                    self.wp = (self.wp + 1) & 0xFFF
                    self._shift_ctx(by)
                    self.prev_byte = by
        
        return bytes(self.out[:self.ds])


# ============================================================
# V7: Binary tree literal with FIXED match length (2..9)
# ============================================================
class LmfDecompressor_V7(LmfDecompressor_V6):
    """V7: Tree literal + fixed match length (2..9)"""
    
    def _decode_match_length(self):
        si2 = self.si + 0xC0
        if si2 >= self.te: si2 = 0xC0
        bs = self._db(si2)
        
        if bs == 0:
            ii = 1
            while ii <= 7:
                idx = 0x332 + ii
                if idx >= self.te: break
                b = self._db(idx)
                ii = (ii << 1) | b
            l2 = (ii & 7) + 2  # FIX: 2..9
        else:
            l2 = 0
            for i in range(5):
                idx = (self.si << 4) + 0xCC + i
                if idx >= self.te: break
                b = self._db(idx)
                l2 = (l2 << 1) | b
                if b == 0: break
            l2 += 2  # FIX: min 2
        return l2
    
    def _decode_match_distance(self, l2):
        sc = min(l2 - 2, 3)  # FIX
        sb = 0x1B0 + sc * 64
        
        sl = 0
        for i in range(6):
            idx = sb + i
            if idx >= self.te: break
            b = self._db(idx)
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
                d2 = (d2 << 1) | b
        return d2


# ============================================================
# V8: Formula 5 literal + fixed match length
# ============================================================
class LmfDecompressor_V8(LmfDecompressor_V6):
    """V8: Formula 5 literal + fixed match length"""
    
    def _decode_literal(self):
        """Use formula 5: (bc & 3) + (bc & 0xF) * 4"""
        partial = 0
        for bit_pos in range(8):
            ci = (partial & 3) + (partial & 0xF) * 4
            if ci >= self.te:
                ci = ci % self.te
            b = self._db(ci)
            partial = (partial << 1) | b
        return partial
    
    def decompress(self):
        max_iters = max(50000, self.ds * 3)
        iters = 0
        
        while len(self.out) < self.ds and self.dp < len(self.cd) + 10 and iters < max_iters:
            iters += 1
            
            ci = (self.si << 4) + (self.bc & self.mk)
            if ci >= self.te: ci = 0
            is_match = self._db(ci)
            
            if is_match == 0:
                v = self._decode_literal()
                self.out.append(v)
                self.w[self.wp & 0xFFF] = v
                self.wp += 1
                self._shift_ctx(v)
                self.prev_byte = v
                self.bc += 1
            else:
                l2 = self._decode_match_length()
                d2 = self._decode_match_distance(l2)
                
                self.bc += 1
                for i in range(l2):
                    src = (self.wp - d2) & 0xFFF
                    by = self.w[src]
                    self.out.append(by)
                    self.w[self.wp & 0xFFF] = by
                    self.wp = (self.wp + 1) & 0xFFF
                    self._shift_ctx(by)
                    self.prev_byte = by
        
        return bytes(self.out[:self.ds])


# ============================================================
# TEST
# ============================================================
def test_file(fpath, label=""):
    if not os.path.exists(fpath):
        return
    
    with open(fpath, 'rb') as f:
        data = f.read()
    
    basename = os.path.basename(fpath)
    print(f"\n{'='*60}")
    print(f"FILE: {basename} ({label})")
    print(f"  Size: {len(data)}B")
    
    # Check if .luac reference exists
    luac_path = None
    if 'test_vectors' in fpath:
        luac_path = fpath[:-4] + '.luac'
        if not os.path.exists(luac_path):
            luac_path = None
    
    expected = None
    if luac_path:
        with open(luac_path, 'rb') as f:
            expected = f.read()
        print(f"  Reference .luac: {len(expected)}B, magic={expected[:4]}")
    
    tests = [
        ("V6_tree_literal", LmfDecompressor_V6),
        ("V7_tree+fixlen", LmfDecompressor_V7),
        ("V8_formula5+fixlen", LmfDecompressor_V8),
    ]
    
    for name, cls in tests:
        print(f"\n  {name}:")
        try:
            d = cls(data)
            out = d.decompress()
            
            status = ""
            if out[:4] == ROO_MAGIC: status = " 🟢ROO!"
            elif out[:4] == LUA_MAGIC: status = " 🟢LUA!"
            
            print(f"    {len(out)}B, {out[:8].hex()}{status}")
            
            if expected:
                match = sum(1 for i in range(min(len(out), len(expected))) if out[i] == expected[i])
                pct = match / len(expected) * 100
                print(f"    Match with .luac: {match}/{len(expected)} ({pct:.1f}%)")
                if match > len(expected) * 0.9:
                    print(f"    ✓ HIGH MATCH!")
            
            if status:
                print(f"    ✓ VALID OUTPUT!")
                for i in range(0, min(64, len(out)), 16):
                    hexs = ' '.join(f'{b:02x}' for b in out[i:i+16])
                    asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in out[i:i+16])
                    print(f"    {i:04x}: {hexs}  {asc}")
        except Exception as e:
            print(f"    ERROR: {e}")
            import traceback
            traceback.print_exc()


def test_all_vectors():
    """Quick test all 92 vectors with V7 (tree+fixlen)"""
    lmf_dir = 'downloads/mt_test_vectors'
    lmf_files = sorted(glob.glob(f'{lmf_dir}/*.lmf'))
    
    roo_count = 0
    lua_count = 0
    total = 0
    best_match = 0
    
    for fpath in lmf_files:
        with open(fpath, 'rb') as f:
            data = f.read()
        
        luac_path = fpath[:-4] + '.luac'
        expected = None
        if os.path.exists(luac_path):
            with open(luac_path, 'rb') as f:
                expected = f.read()
        
        try:
            d = LmfDecompressor_V7(data)
            out = d.decompress()
            
            total += 1
            if out[:4] == ROO_MAGIC:
                roo_count += 1
                print(f"  🟢ROO: {os.path.basename(fpath)}")
            elif out[:4] == LUA_MAGIC:
                lua_count += 1
                print(f"  🟢LUA: {os.path.basename(fpath)}")
            
            if expected:
                match = sum(1 for i in range(min(len(out), len(expected))) if out[i] == expected[i])
                if match > best_match:
                    best_match = match
                if match > len(expected) * 0.5:
                    print(f"  📊 {os.path.basename(fpath)[:30]}: {match}/{len(expected)} ({100*match/len(expected):.1f}%)")
        except:
            pass
    
    print(f"\n{'='*50}")
    print(f"Total: {total} files")
    print(f"ROO: {roo_count}")
    print(f"LUA: {lua_count}")
    print(f"Best match with .luac: {best_match}")


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'all':
        test_all_vectors()
    else:
        files = [
            ('downloads/mt_test_vectors/0_01a6925ff75d22deafd5859cb6d32990.mt.lmf', 'test vector 0'),
            ('output_mt/0000488d2f64199aca0cc7d54e7d11c0/0000488d2f64199aca0cc7d54e7d11c0.lmf', 'game asset'),
        ]
        for fpath, label in files:
            test_file(fpath, label)
