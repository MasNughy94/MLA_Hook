#!/usr/bin/env python3
"""
Test harness untuk fix decompressor lmF@.
Mencoba berbagai kombinasi parameter dan melaporkan hasil.
"""
import os, sys, struct, glob, json
from Crypto.Cipher import AES

AES_KEY = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
ANTM_MAGIC = b"Antm"
LMF_MAGIC = b"lmF@"
ROO_MAGIC = b"\x1bL\x6d\x00"
LUA_MAGIC = b"\x1bLua"

_P_INIT = 0x400
_P_MAX = 0x800
_P_SHIFT = 5
_RBITS = 11
_RENORM = 0x1000000

# 8 formulas
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


# ============================================================
# VERSION 1: Original (baseline)
# ============================================================
class LmfDecompressor_V1:
    """Original version from process_mt_all.py"""
    
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
        
        cd = bytearray(data)
        xor_len = min(self.ds, 16)
        for i in range(xor_len):
            cd[0x0E + i] ^= 0xEC
        self.cd = bytes(cd[0x0E:])
        
        self.ctx = [self.cd[0], self.cd[1], self.cd[2], self.cd[3], self.cd[4]]
        self.si = self.ctx[0] & 0xF
        
        self.dp = 5
        self.h = 0xFFFFFFFF
        self.l = (self.ctx[1] << 24) | (self.ctx[2] << 16) | (self.ctx[3] << 8) | self.ctx[4]
        
        self.tbl = [_P_INIT] * self.te
        self.out = bytearray()
        self.w = bytearray(4096)
        self.wp = 0
        self.bc = 0
        self._bc_byte = 0
        
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
        self.tbl[si2] = _upd(self.tbl[si2], bs)
        
        if bs == 0:
            ii = 1
            while ii <= 7:
                idx = 0x332 + ii
                if idx >= self.te: break
                b = self._db(idx)
                self.tbl[idx] = _upd(self.tbl[idx], b)
                ii = (ii << 1) | b
            l2 = (ii & 0xFF) + 3
        else:
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
# VERSION 2: Fix match length (+2 instead of +3)
# ============================================================
class LmfDecompressor_V2:
    """Fix: match length min = 2 instead of 3"""
    
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
        
        self.ctx = [self.cd[0], self.cd[1], self.cd[2], self.cd[3], self.cd[4]]
        self.si = self.ctx[0] & 0xF
        
        self.dp = 5
        self.h = 0xFFFFFFFF
        self.l = (self.ctx[1] << 24) | (self.ctx[2] << 16) | (self.ctx[3] << 8) | self.ctx[4]
        
        self.tbl = [_P_INIT] * self.te
        self.out = bytearray()
        self.w = bytearray(4096)
        self.wp = 0
        self.bc = 0
        
        self.formula = FORMULAS[formula_idx]
        self.formula_idx = formula_idx
    
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
        """FIXED: short match = 2..9, long match starts at 2"""
        si2 = self.si + 0xC0
        if si2 >= self.te: si2 = 0xC0
        bs = self._db(si2)
        self.tbl[si2] = _upd(self.tbl[si2], bs)
        
        if bs == 0:
            # SHORT: 3-bit tree → value 0..7, length = 2 + value = 2..9
            ii = 1
            while ii <= 7:
                idx = 0x332 + ii
                if idx >= self.te: break
                b = self._db(idx)
                self.tbl[idx] = _upd(self.tbl[idx], b)
                ii = (ii << 1) | b
            l2 = (ii & 7) + 2  # FIX: was (ii & 0xFF) + 3
        else:
            # LONG: extra bits with early termination
            l2 = 0
            for i in range(5):
                idx = (self.si << 4) + 0xCC + i
                if idx >= self.te: break
                b = self._db(idx)
                self.tbl[idx] = _upd(self.tbl[idx], b)
                l2 = (l2 << 1) | b
                if b == 0: break
            l2 += 2  # FIX: was += 3, now min match = 2
        return l2
    
    def _decode_match_distance(self, l2):
        """FIXED: sc based on l2-2 instead of l2-3"""
        sc = min(l2 - 2, 3)  # FIX: was l2 - 3
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
# VERSION 3: Fix match length + separate state machine
# ============================================================
class LmfDecompressor_V3:
    """Fix: match length + LZMA-like state machine"""
    
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
        
        self.lc = r9
        self.lp = ps
        self.lp_mask = self.mk
        
        cd = bytearray(data)
        xor_len = min(self.ds, 16)
        for i in range(xor_len):
            cd[0x0E + i] ^= 0xEC
        self.cd = bytes(cd[0x0E:])
        
        self.ctx = [self.cd[0], self.cd[1], self.cd[2], self.cd[3], self.cd[4]]
        
        self.dp = 5
        self.h = 0xFFFFFFFF
        self.l = (self.ctx[1] << 24) | (self.ctx[2] << 16) | (self.ctx[3] << 8) | self.ctx[4]
        
        self.tbl = [_P_INIT] * self.te
        self.out = bytearray()
        self.w = bytearray(4096)
        self.wp = 0
        self.bc = 0
        self.prev_byte = 0
        
        # Separate state variable (0-12 like LZMA)
        self.state = 0
        
        self.formula = FORMULAS[formula_idx]
        self.formula_idx = formula_idx
    
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
    
    def _decode_literal(self):
        """Binary tree literal with proper context (lc, lp, prev_byte)"""
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
                idx = 0x736 + ii  # fallback
            b = self._db(idx)
            ii = (ii << 1) | b
        return ii & 0xFF
    
    def _decode_literal_formula(self):
        """Formula-based literal (original approach)"""
        partial = 0
        for bit_pos in range(8):
            ci = self.formula(partial, bit_pos)
            if ci >= self.te:
                ci = ci % self.te
            b = self._db(ci)
            partial = (partial << 1) | b
        return partial
    
    def _decode_match_length(self):
        """FIXED match length"""
        # Use state for match length decision
        # In LZMA: choice index uses state
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
                idx = (self.state << 4) + 0xCC + i  # use state, not si
                if idx >= self.te: break
                b = self._db(idx)
                l2 = (l2 << 1) | b
                if b == 0: break
            l2 += 2  # 2, 4, 8, 16, 32, 64
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
            
            # MAIN DECISION: use state + posState
            ci = (self.state << 4) + (self.bc & self.mk)  # FIX: use state, not si
            if ci >= self.te: ci = 0
            is_match = self._db(ci)
            
            if is_match == 0:
                # === LITERAL ===
                # Try formula-based first, fallback to binary tree
                v = self._decode_literal_formula()
                
                self.out.append(v)
                self.w[self.wp & 0xFFF] = v
                self.wp = (self.wp + 1) & 0xFFF
                self._shift_ctx(v)
                self.prev_byte = v
                self.bc += 1
                
                # Update state: after literal, state decreases toward 0
                if self.state < 4:
                    self.state = 0
                else:
                    self.state -= 3  # LZMA: state - 3 for state >= 4
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
                
                # Update state: after match, state goes to 7
                self.state = 7
        
        return bytes(self.out[:self.ds])


# ============================================================
# TEST HARNESS
# ============================================================
def process_one(decoder_class, data, formula_idx=5, label=""):
    """Try to decompress with given decoder class and formula"""
    try:
        dec = decoder_class(data, formula_idx=formula_idx)
        out = dec.decompress()
        
        is_lua = out[:4] == LUA_MAGIC
        is_roo = out[:4] == ROO_MAGIC
        is_valid = is_lua or is_roo
        
        printable = sum(1 for b in out[:200] if 32 <= b < 127)
        non_zero = sum(1 for b in out[:200] if b != 0)
        
        return {
            'success': True,
            'size': len(out),
            'first_bytes': out[:8].hex(),
            'is_lua': is_lua,
            'is_roo': is_roo,
            'is_valid': is_valid,
            'printable': printable,
            'non_zero': non_zero,
            'label': label,
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'label': label,
        }


def test_all():
    """Run all decoder versions on all 92 test vectors"""
    lmf_dir = 'downloads/mt_test_vectors'
    lmf_files = sorted(glob.glob(f'{lmf_dir}/*.lmf'))
    
    print(f"Found {len(lmf_files)} lmf test files\n")
    
    DECODERS = [
        ('V1_stock', LmfDecompressor_V1),
        ('V2_fixlen', LmfDecompressor_V2),
        ('V3_fixlen+state', LmfDecompressor_V3),
    ]
    
    for dname, dclass in DECODERS:
        print(f"\n{'='*70}")
        print(f"TESTING: {dname}")
        print(f"{'='*70}")
        
        roo_count = 0
        lua_count = 0
        valid_count = 0
        total = 0
        
        for i, fpath in enumerate(lmf_files):
            with open(fpath, 'rb') as f:
                data = f.read()
            
            # Try all 8 formulas, pick best
            best_result = None
            best_score = -1
            
            for fidx in range(8):
                result = process_one(dclass, data, formula_idx=fidx, label=f"F{fidx}")
                if result['success']:
                    # Score: valid format > size match > printable
                    score = 0
                    if result['is_roo']: score += 10000
                    if result['is_lua']: score += 8000
                    score += result['printable']
                    score += result['non_zero']
                    
                    if score > best_score:
                        best_score = score
                        best_result = result
                        best_result['formula'] = fidx
            
            fname = os.path.basename(fpath)
            total += 1
            
            if best_result and best_result['success']:
                if best_result['is_roo']: roo_count += 1
                if best_result['is_lua']: lua_count += 1
                if best_result['is_valid']: valid_count += 1
            
            # Show first/last few
            if i < 3 or i >= len(lmf_files) - 2 or (best_result and best_result['is_valid']):
                if best_result:
                    status = ""
                    if best_result['is_roo']: status = " 🟢ROO!"
                    elif best_result['is_lua']: status = " 🟢LUA!"
                    else: status = " ❌"
                    
                    word = fname.replace('.mt.lmf', '')
                    print(f"  [{word[:20]:20}] F{best_result.get('formula','?')} "
                          f"sz={best_result['size']:>6} "
                          f"hex={best_result['first_bytes']}{status}")
        
        print(f"\n  RESULT: {valid_count}/{total} valid "
              f"(ROO={roo_count} LUA={lua_count})")
        if valid_count == 0:
            # Show best attempt
            print(f"  No valid output. Best scores:")
            for fpath in lmf_files[:3]:
                with open(fpath, 'rb') as f:
                    data = f.read()
                for fidx in [5, 0, 1, 2]:
                    r = process_one(dclass, data, formula_idx=fidx, label=f"F{fidx}")
                    if r['success']:
                        fname = os.path.basename(fpath)
                        print(f"    {fname[:30]:30} F{fidx}: {r['size']}B {r['first_bytes']}")


def test_specific_files():
    """Test specific files in detail"""
    files_to_test = [
        'downloads/mt_test_vectors/0_01a6925ff75d22deafd5859cb6d32990.mt.lmf',
        'output_mt/0000488d2f64199aca0cc7d54e7d11c0/0000488d2f64199aca0cc7d54e7d11c0.lmf',
    ]
    
    DECODERS = [
        ('V1_stock', LmfDecompressor_V1),
        ('V2_fixlen', LmfDecompressor_V2),
        ('V3_fixlen+state', LmfDecompressor_V3),
    ]
    
    for fpath in files_to_test:
        if not os.path.exists(fpath):
            continue
        fname = os.path.basename(fpath)
        print(f"\n{'='*60}")
        print(f"FILE: {fname}")
        
        with open(fpath, 'rb') as f:
            data = f.read()
        print(f"  Size: {len(data)} bytes, Magic: {data[:4]}")
        
        for dname, dclass in DECODERS:
            print(f"\n  --- {dname} ---")
            for fidx in range(8):
                r = process_one(dclass, data, formula_idx=fidx)
                if r['success']:
                    status = ""
                    if r['is_roo']: status = " 🟢ROO!"
                    elif r['is_lua']: status = " 🟢LUA!"
                    print(f"    F{fidx}: {r['size']:>6}B {r['first_bytes']}{status}")
                else:
                    print(f"    F{fidx}: ERROR {r.get('error','')}")


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'detailed':
        test_specific_files()
    else:
        test_all()
