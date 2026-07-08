#!/usr/bin/env python3
"""
V12-V14: Test berbagai kombinasi literal decoding + state machine.
Plus: diagnostik prefix bytes untuk pahami initial state.
"""
import os, sys, struct, glob

ROO_MAGIC = b"\x1bL\x6d\x00"
LUA_MAGIC = b"\x1bLua"

_P_INIT = 0x400
_P_MAX = 0x800
_P_SHIFT = 5
_RBITS = 11
_RENORM = 0x1000000

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


class BaseDecompressor:
    """Base class with shared range decoder + match handling"""
    
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
        
        # Prefix (first 5 bytes) - might contain initial config
        self.prefix = self.cd[:5]
        
        # Range decoder init: l from prefix bytes 1-4, dp=5
        self.dp = 5
        self.h = 0xFFFFFFFF
        self.l = (self.cd[1] << 24) | (self.cd[2] << 16) | (self.cd[3] << 8) | self.cd[4]
        
        self.tbl = [_P_INIT] * self.te
        self.out = bytearray()
        self.w = bytearray(4096)
        self.wp = 0
        self.bc = 0
        self.prev_byte = 0
        self.state = 0  # Separate state machine
    
    def _rn(self):
        while self.h < _RENORM:
            self.h = (self.h << 8) & 0xFFFFFFFF
            if self.dp < len(self.cd):
                self.l = ((self.l << 8) | self.cd[self.dp]) & 0xFFFFFFFF
                self.dp += 1
            else:
                self.l = (self.l << 8) & 0xFFFFFFFF
    
    def _db_plain(self, idx):
        """Decode bit without table update tracking"""
        self._rn()
        if idx >= self.te: idx = 0
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
    
    def _decode_literal_tree(self):
        """Binary tree literal with LZMA context"""
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
            b = self._db_plain(idx)
            ii = (ii << 1) | b
        return ii & 0xFF
    
    def _decode_literal_formula(self, formula):
        """Formula-based literal"""
        partial = 0
        for bit_pos in range(8):
            ci = formula(partial, bit_pos)
            if ci >= self.te:
                ci = ci % self.te
            b = self._db_plain(ci)
            partial = (partial << 1) | b
        return partial
    
    def _decode_match_length_v1(self):
        """Original match length (+3)"""
        idx = 0xC0 + self.state
        if idx >= self.te: idx = 0xC0
        bs = self._db_plain(idx)
        if bs == 0:
            ii = 1
            while ii <= 7:
                idx = 0x332 + ii
                if idx >= self.te: break
                b = self._db_plain(idx)
                ii = (ii << 1) | b
            l2 = (ii & 0xFF) + 3  # 11..18
        else:
            l2 = 0
            for i in range(5):
                idx = (self.state << 4) + 0xCC + i
                if idx >= self.te: break
                b = self._db_plain(idx)
                l2 = (l2 << 1) | b
                if b == 0: break
            l2 += 3  # 3,5,9,17,33,65
        return l2
    
    def _decode_match_length_v2(self):
        """Fixed match length (+2)"""
        idx = 0xC0 + self.state
        if idx >= self.te: idx = 0xC0
        bs = self._db_plain(idx)
        if bs == 0:
            ii = 1
            while ii <= 7:
                idx = 0x332 + ii
                if idx >= self.te: break
                b = self._db_plain(idx)
                ii = (ii << 1) | b
            l2 = (ii & 7) + 2  # 2..9
        else:
            l2 = 0
            for i in range(5):
                idx = (self.state << 4) + 0xCC + i
                if idx >= self.te: break
                b = self._db_plain(idx)
                l2 = (l2 << 1) | b
                if b == 0: break
            l2 += 2  # 2,4,8,16,32,64
        return l2
    
    def _decode_match_distance_v1(self, l2):
        """Original distance (l2-3)"""
        sc = min(l2 - 3, 3)
        sb = 0x1B0 + sc * 64
        sl = 0
        for i in range(6):
            idx = sb + i
            if idx >= self.te: break
            b = self._db_plain(idx)
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
                b = self._db_plain(idx)
                d2 = (d2 << 1) | b
        return d2
    
    def _decode_match_distance_v2(self, l2):
        """Fixed distance (l2-2)"""
        sc = min(l2 - 2, 3)
        sb = 0x1B0 + sc * 64
        sl = 0
        for i in range(6):
            idx = sb + i
            if idx >= self.te: break
            b = self._db_plain(idx)
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
                b = self._db_plain(idx)
                d2 = (d2 << 1) | b
        return d2


# ================================================================
# V12: Formula 5 literal + proper state + fixlen (V2)
# ================================================================
class V12_Formula5_State_FixLen(BaseDecompressor):
    def decompress(self):
        max_iters = max(50000, self.ds * 5)
        iters = 0
        while len(self.out) < self.ds and self.dp < len(self.cd) + 10 and iters < max_iters:
            iters += 1
            ci = (self.state << 4) + (self.bc & self.mk)
            if ci >= self.te: ci = 0
            is_match = self._db_plain(ci)
            if is_match == 0:
                v = self._decode_literal_formula(FORMULAS[5])
                self.out.append(v)
                self.w[self.wp & 0xFFF] = v
                self.wp = (self.wp + 1) & 0xFFF
                self.prev_byte = v
                self.bc += 1
                if self.state < 4: self.state = 0
                else: self.state -= 3
            else:
                l2 = self._decode_match_length_v2()
                d2 = self._decode_match_distance_v2(l2)
                self.bc += 1
                for i in range(l2):
                    src = (self.wp - d2) & 0xFFF
                    by = self.w[src]
                    self.out.append(by)
                    self.w[self.wp & 0xFFF] = by
                    self.wp = (self.wp + 1) & 0xFFF
                    self.prev_byte = by
                self.state = 7
        return bytes(self.out[:self.ds])


# ================================================================
# V13: Binary tree literal + proper state + ORIGINAL match len (V1)
# ================================================================
class V13_Tree_State_OrigLen(BaseDecompressor):
    def decompress(self):
        max_iters = max(50000, self.ds * 5)
        iters = 0
        while len(self.out) < self.ds and self.dp < len(self.cd) + 10 and iters < max_iters:
            iters += 1
            ci = (self.state << 4) + (self.bc & self.mk)
            if ci >= self.te: ci = 0
            is_match = self._db_plain(ci)
            if is_match == 0:
                v = self._decode_literal_tree()
                self.out.append(v)
                self.w[self.wp & 0xFFF] = v
                self.wp = (self.wp + 1) & 0xFFF
                self.prev_byte = v
                self.bc += 1
                if self.state < 4: self.state = 0
                else: self.state -= 3
            else:
                l2 = self._decode_match_length_v1()
                d2 = self._decode_match_distance_v1(l2)
                self.bc += 1
                for i in range(l2):
                    src = (self.wp - d2) & 0xFFF
                    by = self.w[src]
                    self.out.append(by)
                    self.w[self.wp & 0xFFF] = by
                    self.wp = (self.wp + 1) & 0xFFF
                    self.prev_byte = by
                self.state = 7
        return bytes(self.out[:self.ds])


# ================================================================
# V14: ALL 8 FORMULAS try with proper state + fixed match len
# ================================================================
class V14_AllFormulas_State_FixLen(BaseDecompressor):
    def __init__(self, data, formula_idx=5):
        self.formula_idx = formula_idx
        super().__init__(data)
    
    def decompress(self):
        formula = FORMULAS[self.formula_idx]
        max_iters = max(50000, self.ds * 5)
        iters = 0
        while len(self.out) < self.ds and self.dp < len(self.cd) + 10 and iters < max_iters:
            iters += 1
            ci = (self.state << 4) + (self.bc & self.mk)
            if ci >= self.te: ci = 0
            is_match = self._db_plain(ci)
            if is_match == 0:
                v = self._decode_literal_formula(formula)
                self.out.append(v)
                self.w[self.wp & 0xFFF] = v
                self.wp = (self.wp + 1) & 0xFFF
                self.prev_byte = v
                self.bc += 1
                if self.state < 4: self.state = 0
                else: self.state -= 3
            else:
                l2 = self._decode_match_length_v2()
                d2 = self._decode_match_distance_v2(l2)
                self.bc += 1
                for i in range(l2):
                    src = (self.wp - d2) & 0xFFF
                    by = self.w[src]
                    self.out.append(by)
                    self.w[self.wp & 0xFFF] = by
                    self.wp = (self.wp + 1) & 0xFFF
                    self.prev_byte = by
                self.state = 7
        return bytes(self.out[:self.ds])
    
    @staticmethod
    def try_all(data):
        best_score = -1
        best_f = 0
        best_out = None
        for fidx in range(8):
            try:
                d = V14_AllFormulas_State_FixLen(data, formula_idx=fidx)
                out = d.decompress()
                score = 0
                if out[:4] == ROO_MAGIC: score += 10000
                if out[:4] == LUA_MAGIC: score += 8000
                printable = sum(1 for b in out[:200] if 32 <= b < 127)
                score += printable + sum(1 for b in out[:200] if b != 0)
                if score > best_score:
                    best_score = score
                    best_f = fidx
                    best_out = out
            except: pass
        return best_f, best_out, best_score


# ================================================================
# DIAGNOSTIC
# ================================================================
def show_prefix_info(fpath):
    """Show details about the prefix bytes"""
    with open(fpath, 'rb') as f:
        data = f.read()
    
    hdr = data[:14]
    e = hdr[4]
    ws = e // 9
    r9 = e % 9
    ps = (ws * 0xCCCCCCCD) >> 34
    r5 = ws - ps * 5
    ds = struct.unpack_from('<I', data, 0x0A)[0] ^ 0x3EA
    
    cd = bytearray(data)
    xor_len = min(ds, 16)
    for i in range(xor_len):
        cd[0x0E + i] ^= 0xEC
    cd = bytes(cd[0x0E:])
    
    print(f"\n  Prefix (cd[0:5]): {cd[:5].hex()}")
    print(f"  cd[0]=0x{cd[0]:02x}, cd[0]&0xF = {cd[0]&0xF}")
    print(f"  Initial code (l): 0x{(cd[1]<<24)|(cd[2]<<16)|(cd[3]<<8)|cd[4]:08x}")
    print(f"  ds={ds}, lc={r9}, lp={ps}, mk={cd[0]&0xF}")
    print(f"  te={0x736 + (0x300 << (r5 + r9))}")


# ================================================================
# TEST
# ================================================================
def test_all():
    lmf_files = sorted(glob.glob('downloads/mt_test_vectors/*.lmf'))
    
    print(f"\n{'='*60}")
    print(f"TESTING ALL {len(lmf_files)} VECTORS")
    print(f"{'='*60}")
    
    # First, check prefix bytes pattern
    print(f"\n--- Prefix diagnostics (first 5 files) ---")
    for fpath in lmf_files[:5]:
        fname = os.path.basename(fpath)
        print(f"\n  {fname}:")
        show_prefix_info(fpath)
    
    # Test V14 (all formulas) on first 10 files
    print(f"\n--- V14: All 8 formulas + state + fixlen (first 10 files) ---")
    for fpath in lmf_files[:10]:
        fname = os.path.basename(fpath)
        with open(fpath, 'rb') as f:
            data = f.read()
        
        best_f, best_out, best_score = V14_AllFormulas_State_FixLen.try_all(data)
        
        status = ""
        if best_out and best_out[:4] == ROO_MAGIC: status = " 🟢ROO!"
        elif best_out and best_out[:4] == LUA_MAGIC: status = " 🟢LUA!"
        
        luac_path = fpath[:-4] + '.luac'
        if os.path.exists(luac_path):
            with open(luac_path, 'rb') as f:
                expected = f.read()
            match = sum(1 for i in range(min(len(best_out), len(expected))) if best_out[i] == expected[i]) if best_out else 0
            pct = 100 * match / len(expected) if len(expected) > 0 else 0
            print(f"  F{best_f}: {len(best_out) if best_out else 0}B match={match}/{len(expected)} ({pct:.1f}%){status} {best_out[:8].hex() if best_out else 'FAIL'}")
        else:
            print(f"  F{best_f}: {len(best_out) if best_out else 0}B{status} {best_out[:8].hex() if best_out else 'FAIL'}")


def test_detailed():
    files = [
        ('downloads/mt_test_vectors/0_01a6925ff75d22deafd5859cb6d32990.mt.lmf', 'vec0'),
        ('downloads/mt_test_vectors/0_063e55e004040b18f45a7b327cd1eba7.mt.lmf', 'vec1'),
        ('output_mt/0000488d2f64199aca0cc7d54e7d11c0/0000488d2f64199aca0cc7d54e7d11c0.lmf', 'asset'),
    ]
    
    for fpath, label in files:
        if not os.path.exists(fpath): continue
        with open(fpath, 'rb') as f:
            data = f.read()
        
        print(f"\n{'='*60}")
        print(f"FILE: {os.path.basename(fpath)} ({label})")
        show_prefix_info(fpath)
        
        luac_path = fpath[:-4] + '.luac'
        expected = None
        if os.path.exists(luac_path):
            with open(luac_path, 'rb') as f:
                expected = f.read()
            print(f"  Expected: {len(expected)}B, magic={expected[:4]}")
        
        configs = [
            ("V12_Formula5+State+F ixLen", lambda: V12_Formula5_State_FixLen(data).decompress()),
            ("V13_Tree+State+OrigL en", lambda: V13_Tree_State_OrigLen(data).decompress()),
        ]
        
        for name, fn in configs:
            try:
                out = fn()
                status = ""
                if out[:4] == ROO_MAGIC: status = " 🟢ROO!"
                elif out[:4] == LUA_MAGIC: status = " 🟢LUA!"
                print(f"\n  {name}: {len(out)}B, {out[:16].hex()}{status}")
                if expected:
                    match = sum(1 for i in range(min(len(out), len(expected))) if out[i] == expected[i])
                    print(f"    Match: {match}/{len(expected)} ({100*match/len(expected):.1f}%)")
                    if match < len(expected) and match > 0:
                        for i in range(min(len(out), len(expected))):
                            if out[i] != expected[i]:
                                ctx_out = ' '.join(f'{b:02x}' for b in out[max(0,i-2):i+8])
                                ctx_exp = ' '.join(f'{b:02x}' for b in expected[max(0,i-2):i+8])
                                print(f"    Diff at byte {i}: out={ctx_out} exp={ctx_exp}")
                                break
            except Exception as e:
                print(f"\n  {name}: ERROR {e}")


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'all':
        test_all()
    else:
        test_detailed()
