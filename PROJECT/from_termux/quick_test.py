#!/usr/bin/env python3
"""Quick test lmF@ decompression — jalankan: python3 quick_test.py [file.lmf]"""
import struct, sys, os, glob

_P_INIT = 0x400; _P_MAX = 0x800; _P_SHIFT = 5; _RBITS = 11; _RENORM = 0x1000000
def _upd(p, b):
    return ((p + ((_P_MAX - p) >> _P_SHIFT)) if b == 0 else (p - (p >> _P_SHIFT))) & 0xFFFF

class LmfDecompress:
    """lmF@ decompressor — FIXED version"""
    def __init__(self, data):
        assert data[:4] == b'lmF@', f"Bad magic: {data[:4]}"
        hdr = data[:14]; e = hdr[4]; ws = e // 9; r9 = e % 9
        ps = (ws * 0xCCCCCCCD) >> 34; r5 = ws - ps * 5
        self.te = (0x300 << (r5 + r9)) + 0x736; self.mk = (1 << ps) - 1
        self.ds = struct.unpack_from('<I', data, 0x0A)[0] ^ 0x3EA
        cd = bytearray(data)
        for i in range(min(self.ds, 16)): cd[0x0E + i] ^= 0xEC
        self.cd = bytes(cd[0x0E:])
        ctx = [self.cd[0], self.cd[1], self.cd[2], self.cd[3], self.cd[4]]
        self.si = ctx[0] & 0xF
        self.dp = 5; self.h = 0xFFFFFFFF
        self.l = (ctx[1] << 24) | (ctx[2] << 16) | (ctx[3] << 8) | ctx[4]
        self.tbl = [_P_INIT] * self.te
        self.out = bytearray(); self.w = bytearray(4096)
        self.wp = 0; self.bc = 0; self.pb = 0

    def _rn(self):
        while self.h < _RENORM:
            self.h = (self.h << 8) & 0xFFFFFFFF
            if self.dp < len(self.cd):
                self.l = ((self.l << 8) | self.cd[self.dp]) & 0xFFFFFFFF; self.dp += 1
            else: self.l = (self.l << 8) & 0xFFFFFFFF

    def _db(self, pr):
        self._rn()
        m = ((self.h >> _RBITS) * pr) & 0xFFFFFFFF
        if self.l < m: self.h = m; return 0
        else: self.l = (self.l - m) & 0xFFFFFFFF; self.h = (self.h - m) & 0xFFFFFFFF; return 1

    def _decode_literal(self):
        ii = 1
        while ii <= 0xFF:
            pr = self.tbl[0x736 + ii]; b = self._db(pr)
            self.tbl[0x736 + ii] = _upd(pr, b); ii = (ii << 1) | b
        return ii & 0xFF

    def _decode_match_length(self):
        si2 = self.si + 0xC0
        if si2 >= self.te: si2 = 0xC0
        pr = self.tbl[si2]; bs = self._db(pr); self.tbl[si2] = _upd(pr, bs)
        if bs == 0:
            ii = 1
            while ii <= 7:
                pr = self.tbl[0x332 + ii]; b = self._db(pr)
                self.tbl[0x332 + ii] = _upd(pr, b); ii = (ii << 1) | b
            l2 = (ii & 0xFF) + 3
        else:
            l2 = 0
            for i in range(5):
                idx = (self.si << 4) + 0xCC + i
                if idx >= self.te: break
                pr = self.tbl[idx]; b = self._db(pr); self.tbl[idx] = _upd(pr, b)
                l2 = (l2 << 1) | b
                if b == 0: break
            l2 += 3
        return l2

    def _decode_match_distance(self, l2):
        sc = min(l2 - 3, 3); sb = 0x1B0 + sc * 64
        sl = 0
        for i in range(6):
            pr = self.tbl[sb + i]; b = self._db(pr); self.tbl[sb + i] = _upd(pr, b)
            sl = (sl << 1) | b
            if b == 0: break
        if sl < 4: d2 = sl + 1
        else:
            ex = (sl >> 1) - 1
            d2 = ((2 + (sl & 1)) << ex) + 1
            for i in range(ex):
                pr = self.tbl[sb + 6 + i]; b = self._db(pr); self.tbl[sb + 6 + i] = _upd(pr, b)
                d2 = (d2 << 1) | b
        return d2

    def decompress(self):
        remaining = self.ds
        while remaining > 0 and self.dp < len(self.cd) + 10:
            ci = (self.si << 4) + (self.bc & self.mk)
            b = self._db(self.tbl[ci]); self.tbl[ci] = _upd(self.tbl[ci], b)
            if b == 0:
                v = self._decode_literal()
                self.out.append(v); self.w[self.wp & 0xFFF] = v; self.wp += 1
                self.pb = v; self._shift_ctx(v); self.bc += 1; remaining -= 1
            else:
                l2 = self._decode_match_length()
                if l2 > remaining: l2 = remaining
                d2 = self._decode_match_distance(l2)
                self.bc += 1
                src_base = self.wp - d2
                for i in range(l2):
                    by = self.w[(src_base + i) & 0xFFF] if 0 <= src_base < 4096 else 0
                    self.out.append(by); self.w[self.wp & 0xFFF] = by
                    self.wp += 1; self.pb = by; self._shift_ctx(by)
                remaining -= l2
        return bytes(self.out[:self.ds])

    def _shift_ctx(self, byte):
        pass  # implemented inline

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 quick_test.py <file.lmf>")
        sys.exit(1)
    with open(sys.argv[1], 'rb') as f: data = f.read()
    out = LmfDecompress(data).decompress()
    print(f"Output: {len(out)} bytes")
    print(f"Magic: {out[:4].hex()} {'🟢LUA' if out[:4]==b'\\x1bLua' else '🟢ROO' if out[:4]==b'\\x1bL\\x6d\\x00' else '🔴unknown'}")
    preview = ''.join(chr(b) if 32<=b<127 else '.' for b in out[:128])
    print(f"Preview: {preview}")
