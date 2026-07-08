#!/usr/bin/env python3
"""
Improved lmF@ Decompressor using binary tree for literal decoding
(based on native code disassembly analysis)
"""

import struct, os, sys

# Range coder constants
_P_INIT = 0x400
_P_MAX = 0x800
_P_SHIFT = 5
_RBITS = 11
_RENORM = 0x1000000

def _upd(prob, bit):
    if bit == 0:
        return (prob + ((_P_MAX - prob) >> _P_SHIFT)) & 0xFFFF
    else:
        return (prob - (prob >> _P_SHIFT)) & 0xFFFF


class FixedLmfDecompressor:
    """
    Fixed lmF@ decompressor.
    
    Key differences from mt_tool_v2:
    1. Uses BINARY TREE for literal decoding (matching native code)
    2. Proper context calculation: combined = (prev_byte >> (8-lc)) + ((bc & lp_mask) << lc)
    3. Tree indices: 0x736 + combined * 0x300 + tree_node
    4. Match length/distance follow LZMA-like structure
    """
    
    def __init__(self, data, max_extra=100000):
        if data[:4] != b'lmF@':
            raise ValueError(f'Not lmF@: {data[:4]}')
        
        # Parse header
        hdr = data[:14]
        e = hdr[4]                     # main config byte
        ws = e // 9                    # window size bits
        r9 = e % 9                     # literal context bits (lc)
        ps = (ws * 0xCCCCCCCD) >> 34   # position bits (lp)
        r5 = ws - ps * 5               # (ws // 9) % 5, not directly used in calc
        
        self.te = (0x300 << (r5 + r9)) + 0x736
        self.mk = (1 << ps) - 1        # position mask
        self.ds = struct.unpack_from('<I', data, 0x0A)[0] ^ 0x3EA
        
        self.lc = r9   # literal context bits
        self.lp = ps   # position bits
        self.lp_mask = self.mk
        
        # XOR payload (first 16 bytes or ds, whichever smaller)
        cd = bytearray(data)
        xor_len = min(self.ds, 16)
        for i in range(xor_len):
            cd[0x0E + i] ^= 0xEC
        self.cd = bytes(cd[0x0E:])
        
        if len(self.cd) < 5:
            raise ValueError(f"Compressed data too short: {len(self.cd)}")
        
        # Initial context from first 5 raw bytes
        self.ctx = [self.cd[0], self.cd[1], self.cd[2], self.cd[3], self.cd[4]]
        self.state = self.ctx[0] & 0xF  # main state
        
        # Range decoder state
        self.dp = 5  # data pointer in cd
        self.h = 0xFFFFFFFF
        self.l = ((self.ctx[1] << 24) | (self.ctx[2] << 16) | 
                  (self.ctx[3] << 8) | self.ctx[4]) & 0xFFFFFFFF
        
        # Probability table
        self.tbl = [_P_INIT] * self.te
        
        # Output and window
        self.out = bytearray()
        self.w = bytearray(4096)
        self.wp = 0
        self.bc = 0           # byte counter (for position context)
        self.prev_byte = 0    # previous byte (for literal context)
        
        # Stats
        self.max_extra = max_extra
    
    def _rn(self):
        """Renormalize range decoder"""
        while self.h < _RENORM:
            self.h = (self.h << 8) & 0xFFFFFFFF
            if self.dp < len(self.cd):
                self.l = ((self.l << 8) | self.cd[self.dp]) & 0xFFFFFFFF
                self.dp += 1
            else:
                self.l = (self.l << 8) & 0xFFFFFFFF
    
    def _db(self, idx):
        """Decode one bit using probability table at idx"""
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
        """Shift context window with new byte"""
        self.ctx[0], self.ctx[1], self.ctx[2], self.ctx[3], self.ctx[4] = \
            self.ctx[1], self.ctx[2], self.ctx[3], self.ctx[4], byte
        self.state = self.ctx[0] & 0xF
    
    # ========== Literal decoding (binary tree) ==========
    def _decode_literal(self):
        """Decode a literal byte using binary tree with context"""
        # Calculate context
        if self.bc == 0:
            combined = 0  # first byte, no context
        else:
            lc_part = self.prev_byte >> (8 - self.lc) if self.lc > 0 else 0
            pos_part = (self.bc & self.lp_mask) << self.lc
            combined = lc_part + pos_part
        
        # Binary tree: start at root node 1, traverse 8 levels
        ii = 1
        while ii <= 0xFF:
            idx = 0x736 + combined * 0x300 + ii
            if idx >= self.te:
                idx = 0x736 + ii  # fallback
            b = self._db(idx)
            ii = (ii << 1) | b
        
        return ii & 0xFF
    
    def _decode_literal_no_context(self):
        """Decode literal without context (fallback)"""
        ii = 1
        while ii <= 0xFF:
            b = self._db(0x736 + ii)
            ii = (ii << 1) | b
        return ii & 0xFF
    
    # ========== Match decoding ==========
    def _decode_match_length(self):
        """Decode match length"""
        si = self.state
        
        # First bit: short vs long match
        # Decision index based on state
        idx = 0xC0 + (si & 0x1F)
        if idx >= self.te:
            idx = 0xC0
        bs = self._db(idx)
        
        if bs == 0:
            # SHORT match: decode via small tree (3 levels = lengths 2-9)
            ii = 1
            for _ in range(3):
                idx = 0x332 + ii
                if idx >= self.te:
                    break
                b = self._db(idx)
                ii = (ii << 1) | b
            match_len = (ii & 0xFF) + 2
        else:
            # LONG match: extra bits
            match_len = 0
            for i in range(5):
                idx = (si << 4) + 0xCC + i
                if idx >= self.te:
                    idx = 0xCC + i
                b = self._db(idx)
                match_len = (match_len << 1) | b
                if b == 0:
                    break
            match_len += 2
        
        return match_len
    
    def _decode_match_distance(self, match_len):
        """Decode match distance"""
        # Position slot based on match length
        sc = min(match_len - 2, 3)
        base_idx = 0x1B0 + sc * 64
        
        # Get position slot (6 bits max)
        slot = 0
        for i in range(6):
            idx = base_idx + i
            if idx >= self.te:
                idx = 0x1B0 + i
                if idx >= self.te:
                    break
            b = self._db(idx)
            slot = (slot << 1) | b
            if b == 0:
                break
        
        if slot < 4:
            return slot + 1
        else:
            extra_bits = (slot >> 1) - 1
            dist = ((2 + (slot & 1)) << extra_bits) + 1
            for i in range(extra_bits):
                idx = base_idx + 6 + i
                if idx >= self.te:
                    idx = 0x1B6 + i
                    if idx >= self.te:
                        break
                b = self._db(idx)
                dist = (dist << 1) | b
            return dist
    
    # ========== Main decompression ==========
    def decompress(self):
        """Main decompression loop"""
        max_iters = max(100000, self.ds * 5)
        iters = 0
        
        while len(self.out) < self.ds and iters < max_iters:
            iters += 1
            
            # === MAIN DECISION: literal or match ===
            # ci = (state << 4) + (bc & mk)
            ci = (self.state << 4) + (self.bc & self.mk)
            if ci >= self.te:
                ci = ci % self.te
            
            is_match = self._db(ci)
            
            if is_match == 0:
                # === LITERAL ===
                v = self._decode_literal()
                
                self.out.append(v)
                self.w[self.wp & 0xFFF] = v
                self.wp = (self.wp + 1) & 0xFFF
                self.prev_byte = v
                self._shift_ctx(v)
                self.bc += 1
            else:
                # === MATCH (LZ77 copy) ===
                match_len = self._decode_match_length()
                distance = self._decode_match_distance(match_len)
                
                if distance == 0:
                    distance = 1
                
                self.bc += 1
                for i in range(match_len):
                    src = (self.wp - distance) & 0xFFF
                    by = self.w[src]
                    self.out.append(by)
                    self.w[self.wp & 0xFFF] = by
                    self.wp = (self.wp + 1) & 0xFFF
                    self.prev_byte = by
                    # Don't shift context for match bytes? Or do we?
                    # Native code shifts context for each match byte
                    self._shift_ctx(by)
        
        return bytes(self.out[:self.ds])
    
    @staticmethod
    def try_all(data):
        """Try decompression, return result"""
        try:
            dec = FixedLmfDecompressor(data)
            out = dec.decompress()
            return out
        except Exception as e:
            return None


# ============== TEST ==============
def main():
    import glob
    
    if len(sys.argv) >= 2:
        # Process specific file(s)
        paths = sys.argv[1:]
        for path in paths:
            if os.path.isdir(path):
                for f in sorted(glob.glob(os.path.join(path, '*.lmf'))):
                    test_one(f)
            elif os.path.isfile(path):
                test_one(path)
    else:
        # Test with known vectors
        tv_dir = 'downloads/mt_test_vectors'
        if os.path.exists(tv_dir):
            for f in sorted(glob.glob(os.path.join(tv_dir, '*.lmf'))):
                test_one(f)
        else:
            print("No test directory found. Usage: python3 lmf_fix.py <file.lmf>")


def test_one(path):
    """Test decompression on one .lmf file"""
    with open(path, 'rb') as f:
        lmf_data = f.read()
    
    basename = os.path.basename(path)
    
    # Check if .luac exists
    luac_path = path[:-4] + '.luac'
    expected = None
    if os.path.exists(luac_path):
        expected = open(luac_path, 'rb').read()
    
    try:
        dec = FixedLmfDecompressor(lmf_data)
        out = dec.decompress()
        
        print(f"\n{'='*60}")
        print(f"File: {basename}")
        print(f"  Size: {len(out)} bytes")
        print(f"  Magic: {out[:4].hex()} = {out[:4]}")
        print(f"  ds={dec.ds}, lc={dec.lc}, lp={dec.lp}, te={dec.te}")
        
        if expected:
            match = sum(1 for i in range(min(len(out), len(expected))) if out[i] == expected[i])
            pct = match / len(expected) * 100
            print(f"  Match: {match}/{len(expected)} ({pct:.1f}%)")
            
            if match == len(expected) and len(out) == len(expected):
                print(f"  ✓ PERFECT MATCH!")
            else:
                for i in range(min(len(out), len(expected))):
                    if out[i] != expected[i]:
                        print(f"  First diff at byte {i}: got 0x{out[i]:02x} exp 0x{expected[i]:02x}")
                        # Show context
                        start = max(0, i-8)
                        end = min(len(out), i+16)
                        print(f"  Context: {out[start:end].hex()}")
                        print(f"  Expected:{expected[start:end].hex()}")
                        break
        else:
            printable = sum(1 for b in out[:200] if 32 <= b < 127)
            non_zero = sum(1 for b in out[:200] if b != 0)
            print(f"  Printable: {printable}/200, Non-zero: {non_zero}/200")
            if out[:4] == b'\x1bLua':
                print(f"  ✓ Valid Lua bytecode!")
            elif out[:4] == b'\x1bL\x6d\x00':
                print(f"  ✓ Roo Binary Format!")
            preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in out[:100])
            print(f"  Preview: {preview}")
        
    except Exception as e:
        print(f"\n{basename}: ERROR - {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
