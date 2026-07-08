#!/usr/bin/env python3
"""
V9: Binary tree literal + PROPER LZMA STATE MACHINE.
Key fixes:
1. Binary tree literal: idx = 0x736 + combined * 0x300 + tree_node
2. Separate state variable (not derived from ctx[0] & 0xF)
3. State update:
   - After literal: if state < 4 → state=0; else state -= 3
   - After match: state = 7
4. State used for: main decision, match length choice
"""
import os, sys, struct, glob

ROO_MAGIC = b"\x1bL\x6d\x00"
LUA_MAGIC = b"\x1bLua"

_P_INIT = 0x400
_P_MAX = 0x800
_P_SHIFT = 5
_RBITS = 11
_RENORM = 0x1000000


class LmfDecompressor_V9:
    """V9: Tree literal + proper state machine"""
    
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
        
        self.lc = r9
        self.lp = ps
        self.lp_mask = self.mk
        
        # XOR payload
        cd = bytearray(data)
        xor_len = min(self.ds, 16)
        for i in range(xor_len):
            cd[0x0E + i] ^= 0xEC
        self.cd = bytes(cd[0x0E:])
        
        # Context window (for literal context only, NOT for state)
        self.ctx = [self.cd[0], self.cd[1], self.cd[2], self.cd[3], self.cd[4]]
        
        # Range decoder init
        self.dp = 5
        self.h = 0xFFFFFFFF
        self.l = (self.ctx[1] << 24) | (self.ctx[2] << 16) | (self.ctx[3] << 8) | self.ctx[4]
        
        self.tbl = [_P_INIT] * self.te
        self.out = bytearray()
        self.w = bytearray(4096)
        self.wp = 0
        self.bc = 0
        self.prev_byte = 0
        
        # PROPER STATE MACHINE (not from ctx[0] & 0xF)
        self.state = 0
    
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
            idx = 0
        pr = self.tbl[idx]
        m = ((self.h >> _RBITS) * pr) & 0xFFFFFFFF
        if self.l < m:
            self.h = m
            bit = 0
        else:
            self.l = (self.l - m) & 0xFFFFFFFF
            self.h = (self.h - m) & 0xFFFFFFFF
            bit = 1
        if bit == 0:
            self.tbl[idx] = (pr + ((_P_MAX - pr) >> _P_SHIFT)) & 0xFFFF
        else:
            self.tbl[idx] = (pr - (pr >> _P_SHIFT)) & 0xFFFF
        return bit
    
    def _shift_ctx(self, byte):
        self.ctx[0], self.ctx[1], self.ctx[2], self.ctx[3], self.ctx[4] = \
            self.ctx[1], self.ctx[2], self.ctx[3], self.ctx[4], byte
    
    # ========== LITERAL (binary tree) ==========
    def _decode_literal(self):
        """Decode literal using binary tree with LZMA context"""
        # Context = (prev_byte >> (8 - lc)) + ((bc & lp_mask) << lc)
        if self.bc == 0:
            combined = 0
        else:
            lc_part = self.prev_byte >> (8 - self.lc) if self.lc > 0 else 0
            pos_part = (self.bc & self.lp_mask) << self.lc
            combined = lc_part + pos_part
        
        ii = 1
        while ii <= 0xFF:
            idx = 0x736 + combined * 0x300 + ii
            if idx >= self.te:
                idx = 0x736 + ii
            b = self._db(idx)
            ii = (ii << 1) | b
        return ii & 0xFF
    
    # ========== MATCH LENGTH ==========
    def _decode_match_length(self):
        """Match length using state (not si)"""
        # First bit: short (0) vs long (1) — using state
        idx = 0xC0 + self.state
        if idx >= self.te: idx = 0xC0
        bs = self._db(idx)
        
        if bs == 0:
            # SHORT: 3-bit tree → 0..7, length = 2 + value
            ii = 1
            while ii <= 7:
                idx = 0x332 + ii
                if idx >= self.te: break
                b = self._db(idx)
                ii = (ii << 1) | b
            l2 = (ii & 7) + 2  # 2..9
        else:
            # LONG: extra bits with early termination
            l2 = 0
            for i in range(5):
                idx = (self.state << 4) + 0xCC + i  # Use state, not si
                if idx >= self.te: break
                b = self._db(idx)
                l2 = (l2 << 1) | b
                if b == 0: break
            l2 += 2  # 2, 4, 8, 16, 32, 64
        return l2
    
    # ========== MATCH DISTANCE ==========
    def _decode_match_distance(self, l2):
        sc = min(l2 - 2, 3)
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
        max_iters = max(50000, self.ds * 5)
        iters = 0
        
        while len(self.out) < self.ds and self.dp < len(self.cd) + 10 and iters < max_iters:
            iters += 1
            
            # MAIN DECISION using state
            ci = (self.state << 4) + (self.bc & self.mk)
            if ci >= self.te: ci = 0
            is_match = self._db(ci)
            
            if is_match == 0:
                # === LITERAL ===
                v = self._decode_literal()
                
                self.out.append(v)
                self.w[self.wp & 0xFFF] = v
                self.wp = (self.wp + 1) & 0xFFF
                self._shift_ctx(v)
                self.prev_byte = v
                self.bc += 1
                
                # LZMA literal state update
                if self.state < 4:
                    self.state = 0
                else:
                    self.state -= 3
            else:
                # === MATCH ===
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
                
                # LZMA match state update
                self.state = 7
        
        return bytes(self.out[:self.ds])


# ============================================================
# V10: V9 + also fix match length in distance calc
# Keep l2-2 in distance (already done in V9)
# ============================================================
class LmfDecompressor_V10(LmfDecompressor_V9):
    """V10: Same as V9 but try original match length formula (+3 instead of +2)"""
    
    def _decode_match_length(self):
        idx = 0xC0 + self.state
        if idx >= self.te: idx = 0xC0
        bs = self._db(idx)
        
        if bs == 0:
            ii = 1
            while ii <= 7:
                idx = 0x332 + ii
                if idx >= self.te: break
                b = self._db(idx)
                ii = (ii << 1) | b
            l2 = (ii & 0xFF) + 3  # ORIGINAL: +3
        else:
            l2 = 0
            for i in range(5):
                idx = (self.state << 4) + 0xCC + i
                if idx >= self.te: break
                b = self._db(idx)
                l2 = (l2 << 1) | b
                if b == 0: break
            l2 += 3  # ORIGINAL: +3
        return l2
    
    def _decode_match_distance(self, l2):
        sc = min(l2 - 3, 3)  # ORIGINAL: l2-3
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
# V11: State machine with different state values
# LZMA state transitions more accurate
# ============================================================
class LmfDecompressor_V11(LmfDecompressor_V9):
    """V11: Different state mapping - use 0-12 like real LZMA"""
    
    def _decode_match_length(self):
        idx = 0xC0 + self.state
        if idx >= self.te: idx = 0xC0
        bs = self._db(idx)
        
        if bs == 0:
            ii = 1
            while ii <= 7:
                idx = 0x332 + ii
                if idx >= self.te: break
                b = self._db(idx)
                ii = (ii << 1) | b
            l2 = (ii & 7) + 2
        else:
            l2 = 0
            for i in range(5):
                idx = (self.state << 4) + 0xCC + i
                if idx >= self.te: break
                b = self._db(idx)
                l2 = (l2 << 1) | b
                if b == 0: break
            l2 += 2
        return l2
    
    def decompress(self):
        max_iters = max(50000, self.ds * 5)
        iters = 0
        
        while len(self.out) < self.ds and self.dp < len(self.cd) + 10 and iters < max_iters:
            iters += 1
            
            # MAIN DECISION: state in [0,12], posState = bc & mk
            ci = (self.state << 4) + (self.bc & self.mk)
            if ci >= self.te: ci = 0
            is_match = self._db(ci)
            
            if is_match == 0:
                v = self._decode_literal()
                
                self.out.append(v)
                self.w[self.wp & 0xFFF] = v
                self.wp = (self.wp + 1) & 0xFFF
                self._shift_ctx(v)
                self.prev_byte = v
                self.bc += 1
                
                # LZMA literal state update (exact from LZMA SDK)
                if self.state < 4:
                    self.state = 0
                elif self.state < 10:
                    self.state -= 3
                else:
                    self.state -= 6
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
                
                # LZMA: after match, state = 7 (or 7 + rep for rep matches)
                self.state = 7
        
        return bytes(self.out[:self.ds])


# ============================================================
# TEST
# ============================================================
def test_file(fpath, label=""):
    if not os.path.exists(fpath):
        return
    
    with open(fpath, 'rb') as f:
        data = f.read()
    
    print(f"\n{'='*60}")
    print(f"FILE: {os.path.basename(fpath)} ({label})")
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
        ("V9_tree+state", LmfDecompressor_V9),
        ("V10_tree+state+origlen", LmfDecompressor_V10),
        ("V11_tree+state_exact", LmfDecompressor_V11),
    ]
    
    for name, cls in tests:
        print(f"\n  {name}:")
        try:
            d = cls(data)
            out = d.decompress()
            
            status = ""
            if out[:4] == ROO_MAGIC: status = " 🟢ROO!"
            elif out[:4] == LUA_MAGIC: status = " 🟢LUA!"
            
            print(f"    {len(out)}B, {out[:16].hex()}{status}")
            
            if expected:
                match = sum(1 for i in range(min(len(out), len(expected))) if out[i] == expected[i])
                pct = match / len(expected) * 100
                print(f"    Match with .luac: {match}/{len(expected)} ({pct:.1f}%)")
                if match > 0:
                    # Find first difference
                    for i in range(min(len(out), len(expected))):
                        if out[i] != expected[i]:
                            # Show context around diff
                            start = max(0, i - 4)
                            end = min(len(out), i + 12)
                            ctx_out = ' '.join(f'{b:02x}' for b in out[start:end])
                            ctx_exp = ' '.join(f'{b:02x}' for b in expected[start:end])
                            marker = ' ' * (3 * (i - start)) + '^^^'
                            print(f"      First diff at byte {i}:")
                            print(f"      out: {ctx_out}")
                            print(f"      exp: {ctx_exp}")
                            print(f"           {marker}")
                            break
            
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


if __name__ == '__main__':
    files = [
        ('downloads/mt_test_vectors/0_01a6925ff75d22deafd5859cb6d32990.mt.lmf', 'test vector 0'),
        ('downloads/mt_test_vectors/0_063e55e004040b18f45a7b327cd1eba7.mt.lmf', 'test vector 1'),
        ('downloads/mt_test_vectors/0_06fb9a986a26d8debbec8a8ad4c1abec.mt.lmf', 'test vector 2'),
        ('output_mt/0000488d2f64199aca0cc7d54e7d11c0/0000488d2f64199aca0cc7d54e7d11c0.lmf', 'game asset'),
    ]
    for fpath, label in files:
        test_file(fpath, label)
