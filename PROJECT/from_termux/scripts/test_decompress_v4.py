#!/usr/bin/env python3
"""
V4: Fix range decoder initialization.
Key changes from V3:
1. Initial state = 0 (not derived from ctx[0])
2. Initial code read from cd[5:9] (not cd[1:5]) — matching native input+5
3. Binary tree literal with proper context
4. RENORM threshold = 0xFFFFFF (from doc)
"""
import os, sys, struct, glob

ROO_MAGIC = b"\x1bL\x6d\x00"
LUA_MAGIC = b"\x1bLua"

_P_INIT = 0x400
_P_MAX = 0x800
_P_SHIFT = 5
_RBITS = 11
_RENORM = 0xFFFFFF  # FIX: was 0x1000000, doc says 0xFFFFFF

FORMULAS = [
    lambda bc, bp: (bc & 3) + bp * 4,
    lambda bc, bp: (bc & 3) + bp * 16,
    lambda bc, bp: bp + (bc & 0xF) * 4,
    lambda bc, bp: bp + (bc & 3) * 8,
    lambda bc, bp: ((bc & 3) << 4) + (bp << 6) + (bc & 0xF),
    lambda bc, bp: (bc & 3) + (bc & 0xF) * 4,
    lambda bc, bp: bp + ((bc & 3) << 4),
    lambda bc, bp: bp * 2 + (bc >> 4) * 16 + (bc & 3),
]

def _upd(prob, bit):
    return ((prob + ((_P_MAX - prob) >> _P_SHIFT)) if bit == 0 else (prob - (prob >> _P_SHIFT))) & 0xFFFF


class LmfDecompressor_V4:
    """V4: Fixed init + binary tree literal + formula literal hybrid"""
    
    def __init__(self, data, formula_idx=5, use_tree=False):
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
        
        # Prefix bytes (first 5 of cd) - might be metadata/config
        # The native function receives input+5, skipping these
        self.prefix = self.cd[:5]
        
        # Range decoder state - initialized to read from cd[5:]
        self.dp = 5
        self.h = 0xFFFFFFFF
        # Initial code: read 4 bytes from cd[5:9] (like native range decoder)
        self.l = 0
        for _ in range(4):
            if self.dp < len(self.cd):
                self.l = ((self.l << 8) | self.cd[self.dp]) & 0xFFFFFFFF
                self.dp += 1
        
        self.tbl = [_P_INIT] * self.te
        self.out = bytearray()
        self.w = bytearray(4096)
        self.wp = 0
        self.bc = 0
        self.prev_byte = 0
        self.state = 0  # FIX: start at 0, not from prefix
        
        # Context for binary tree literal
        self.ctx = [0] * 5
        
        self.formula = FORMULAS[formula_idx]
        self.formula_idx = formula_idx
        self.use_tree = use_tree
    
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
            idx = idx % self.te
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
    
    def _decode_literal_formula(self):
        """Formula-based literal (original)"""
        partial = 0
        for bit_pos in range(8):
            ci = self.formula(partial, bit_pos)
            if ci >= self.te:
                ci = ci % self.te
            b = self._db(ci)
            partial = (partial << 1) | b
        return partial
    
    def _decode_literal_tree(self):
        """Binary tree literal with context (from lmf_fix.py)"""
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
    
    def _decode_match_length(self):
        """Match length (uses state)"""
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
            l2 = (ii & 7) + 2  # 2..9
        else:
            l2 = 0
            for i in range(5):
                idx = (self.state << 4) + 0xCC + i
                if idx >= self.te: break
                b = self._db(idx)
                l2 = (l2 << 1) | b
                if b == 0: break
            l2 += 2  # 2,4,8,16,32,64
        return l2
    
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
    
    def decompress(self):
        max_iters = max(50000, self.ds * 5)
        iters = 0
        
        while len(self.out) < self.ds and self.dp < len(self.cd) + 10 and iters < max_iters:
            iters += 1
            
            ci = (self.state << 4) + (self.bc & self.mk)
            if ci >= self.te: ci = 0
            is_match = self._db(ci)
            
            if is_match == 0:
                if self.use_tree:
                    v = self._decode_literal_tree()
                else:
                    v = self._decode_literal_formula()
                
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
                
                self.state = 7  # match state
        
        return bytes(self.out[:self.ds])


# ============================================================
# V5: Same as V4 but WITHOUT the separate state machine
# (Keep original state derivation but fix init and RENORM)
# ============================================================
class LmfDecompressor_V5:
    """V5: Fix init + RENORM + match length, but keep original state"""
    
    def __init__(self, data, formula_idx=5):
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
        
        cd = bytearray(data)
        xor_len = min(self.ds, 16)
        for i in range(xor_len):
            cd[0x0E + i] ^= 0xEC
        self.cd = bytes(cd[0x0E:])
        
        # Initial context from first 5 bytes (prefix)
        self.ctx = [self.cd[0], self.cd[1], self.cd[2], self.cd[3], self.cd[4]]
        self.si = self.ctx[0] & 0xF
        
        # FIX: Read initial code from cd[5:9] instead of cd[1:5]
        self.dp = 5
        self.h = 0xFFFFFFFF
        # Initial code: read 4 bytes from cd[5:9]
        self.l = 0
        for _ in range(4):
            if self.dp < len(self.cd):
                self.l = ((self.l << 8) | self.cd[self.dp]) & 0xFFFFFFFF
                self.dp += 1
        
        self.tbl = [_P_INIT] * self.te
        self.out = bytearray()
        self.w = bytearray(4096)
        self.wp = 0
        self.bc = 0
        
        self.formula = FORMULAS[formula_idx]
        self.formula_idx = formula_idx
    
    def _rn(self):
        while self.h < _RENORM:  # FIX: 0xFFFFFF instead of 0x1000000
            self.h = (self.h << 8) & 0xFFFFFFFF
            if self.dp < len(self.cd):
                self.l = ((self.l << 8) | self.cd[self.dp]) & 0xFFFFFFFF
                self.dp += 1
            else:
                self.l = (self.l << 8) & 0xFFFFFFFF
    
    def _db(self, idx):
        self._rn()
        if idx >= self.te:
            idx = idx % self.te
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
        partial = 0
        for bit_pos in range(8):
            ci = self.formula(partial, bit_pos)
            if ci >= self.te:
                ci = ci % self.te
            b = self._db(ci)
            partial = (partial << 1) | b
        return partial
    
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
            l2 = (ii & 7) + 2  # FIX: was +3, now +2
        else:
            l2 = 0
            for i in range(5):
                idx = (self.si << 4) + 0xCC + i
                if idx >= self.te: break
                b = self._db(idx)
                l2 = (l2 << 1) | b
                if b == 0: break
            l2 += 2  # FIX: was +3, now +2
        return l2
    
    def _decode_match_distance(self, l2):
        sc = min(l2 - 2, 3)  # FIX: was l2-3
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
    
    def decompress(self):
        target = self.ds * 5
        max_iters = max(50000, self.ds * 3)
        iters = 0
        
        while len(self.out) < self.ds and self.dp < len(self.cd) + 10 and iters < max_iters:
            iters += 1
            ci = (self.si << 4) + (self.bc & self.mk)
            if ci >= self.te: ci = 0
            b = self._db(ci)
            
            if b == 0:
                v = self._decode_literal_formula()
                self.out.append(v)
                self.w[self.wp & 0xFFF] = v
                self.wp += 1
                self._shift_ctx(v)
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
        
        return bytes(self.out[:self.ds])


# ============================================================
# TEST
# ============================================================
def test_file(fpath, label=""):
    if not os.path.exists(fpath):
        print(f"  NOT FOUND: {fpath}")
        return
    
    with open(fpath, 'rb') as f:
        data = f.read()
    
    print(f"\n{'='*60}")
    print(f"FILE: {os.path.basename(fpath)} ({label})")
    print(f"  Size: {len(data)}B, ds from header analysis...")
    
    # First show cd[0:16] for diagnostic
    cd = bytearray(data)
    hdr = data[:14]
    ds = struct.unpack_from('<I', data, 0x0A)[0] ^ 0x3EA
    xor_len = min(ds, 16)
    for i in range(xor_len):
        cd[0x0E + i] ^= 0xEC
    cd = bytes(cd[0x0E:])
    print(f"  cd[0:16]: {cd[:16].hex()}")
    print(f"  cd[0]: 0x{cd[0]:02x}, cd[0]&0xF = {cd[0]&0xF}")
    print(f"  cd[1:5] (old init code): {cd[1:5].hex()}")
    print(f"  cd[5:9] (new init code): {cd[5:9].hex()}")
    
    # Test V1 (original)
    from test_decompress_fix import LmfDecompressor_V1
    print(f"\n  V1 (original, F5): ", end="")
    try:
        d = LmfDecompressor_V1(data, formula_idx=5)
        out = d.decompress()
        status = ""
        if out[:4] == ROO_MAGIC: status = " 🟢ROO!"
        elif out[:4] == LUA_MAGIC: status = " 🟢LUA!"
        print(f"{len(out)}B {out[:8].hex()}{status}")
    except Exception as e:
        print(f"ERROR: {e}")
    
    # Test V5 (fix init + RENORM + match len)
    for name, cls, fidx in [
        ("V5_fix_ALL_F0", LmfDecompressor_V5, 0),
        ("V5_fix_ALL_F5", LmfDecompressor_V5, 5),
    ]:
        print(f"  {name}: ", end="")
        try:
            d = cls(data, formula_idx=fidx)
            out = d.decompress()
            status = ""
            if out[:4] == ROO_MAGIC: status = " 🟢ROO!"
            elif out[:4] == LUA_MAGIC: status = " 🟢LUA!"
            print(f"{len(out)}B {out[:8].hex()}{status}")
            if status:
                print(f"    ✓ VALID OUTPUT!")
                # Show more
                for i in range(0, min(64, len(out)), 16):
                    hexs = ' '.join(f'{b:02x}' for b in out[i:i+16])
                    asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in out[i:i+16])
                    print(f"    {i:04x}: {hexs}  {asc}")
        except Exception as e:
            print(f"ERROR: {e}")
    
    # Test V4 (separate state + binary tree) - just F5
    for name, cls, fidx, use_tree in [
        ("V4_state+F5_formula", LmfDecompressor_V4, 5, False),
        ("V4_state+F5_tree", LmfDecompressor_V4, 5, True),
    ]:
        print(f"  {name}: ", end="")
        try:
            d = cls(data, formula_idx=fidx, use_tree=use_tree)
            out = d.decompress()
            status = ""
            if out[:4] == ROO_MAGIC: status = " 🟢ROO!"
            elif out[:4] == LUA_MAGIC: status = " 🟢LUA!"
            print(f"{len(out)}B {out[:8].hex()}{status}")
            if status:
                print(f"    ✓ VALID OUTPUT!")
        except Exception as e:
            print(f"ERROR: {e}")


if __name__ == '__main__':
    files = [
        ('downloads/mt_test_vectors/0_01a6925ff75d22deafd5859cb6d32990.mt.lmf', 'test vector 0'),
        ('output_mt/0000488d2f64199aca0cc7d54e7d11c0/0000488d2f64199aca0cc7d54e7d11c0.lmf', 'game asset'),
    ]
    for fpath, label in files:
        test_file(fpath, label)
