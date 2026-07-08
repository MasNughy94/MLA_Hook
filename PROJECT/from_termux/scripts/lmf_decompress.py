#!/usr/bin/env python3
import struct, sys, os

P = 0x400
PM = 0x800
PS = 5
RB = 11
RT = 0x1000000

def upd(prob, bit):
    return ((prob + ((PM - prob) >> PS)) if bit == 0 else (prob - (prob >> PS))) & 0xFFFF

class LmfDecompressor:
    def __init__(self, data):
        if data[:4] != b'lmF@':
            raise ValueError('Not lmF@ format')
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
        for i in range(min(self.ds, 16)):
            cd[0x0E + i] ^= 0xEC
        self.cd = bytes(cd[0x0E:])
        ctx = [self.cd[0], self.cd[1], self.cd[2], self.cd[3], self.cd[4]]
        self.si = ctx[0] & 0xF
        self.dp = 5
        self.h = 0xFFFFFFFF
        self.l = (ctx[1] << 24) | (ctx[2] << 16) | (ctx[3] << 8) | ctx[4]
        self.tbl = [P] * self.te
        self.out = bytearray()
        self.w = bytearray(4096)
        self.wp = 0
        self.bc = 0
        self.pb = 0
        self.ctx = ctx

    def _rn(self):
        while self.h < RT:
            self.h = (self.h << 8) & 0xFFFFFFFF
            if self.dp < len(self.cd):
                self.l = ((self.l << 8) | self.cd[self.dp]) & 0xFFFFFFFF
                self.dp += 1
            else:
                self.l = (self.l << 8) & 0xFFFFFFFF

    def _db(self, pr):
        self._rn()
        m = ((self.h >> RB) * pr) & 0xFFFFFFFF
        if self.l < m:
            self.h = m
            return 0
        else:
            self.l = (self.l - m) & 0xFFFFFFFF
            self.h = (self.h - m) & 0xFFFFFFFF
            return 1

    def _shift_ctx(self, byte):
        self.ctx[0], self.ctx[1], self.ctx[2], self.ctx[3], self.ctx[4] = \
            self.ctx[1], self.ctx[2], self.ctx[3], self.ctx[4], byte
        self.si = self.ctx[0] & 0xF

    def decompress(self):
        while len(self.out) < self.ds:
            ci = (self.si << 4) + (self.bc & self.mk)
            b = self._db(self.tbl[ci])
            self.tbl[ci] = upd(self.tbl[ci], b)
            if b == 0:
                ii = 1
                while ii <= 0xFF:
                    pr = self.tbl[0x736 + ii]
                    b2 = self._db(pr)
                    self.tbl[0x736 + ii] = upd(pr, b2)
                    ii = (ii << 1) | b2
                v = ii & 0xFF
                self.out.append(v)
                self.w[self.wp & 0xFFF] = v
                self.wp += 1
                self.pb = v
                self._shift_ctx(v)
                self.bc += 1
            else:
                si2 = self.si + 0xC0
                bs = self._db(self.tbl[si2])
                self.tbl[si2] = upd(self.tbl[si2], bs)
                if bs == 0:
                    ii = 1
                    while ii <= 7:
                        pr = self.tbl[0x332 + ii]
                        b2 = self._db(pr)
                        self.tbl[0x332 + ii] = upd(pr, b2)
                        ii = (ii << 1) | b2
                    l2 = (ii & 0xFF) + 3
                else:
                    l2 = 0
                    for i in range(5):
                        pr = self.tbl[(self.si << 4) + 0xCC + i]
                        b2 = self._db(pr)
                        self.tbl[(self.si << 4) + 0xCC + i] = upd(pr, b2)
                        l2 = (l2 << 1) | b2
                        if b2 == 0:
                            break
                    l2 += 3
                sc = min(l2 - 3, 3)
                sb = 0x1B0 + sc * 64
                sl = 0
                for i in range(6):
                    pr = self.tbl[sb + i]
                    b2 = self._db(pr)
                    self.tbl[sb + i] = upd(pr, b2)
                    sl = (sl << 1) | b2
                    if b2 == 0:
                        break
                if sl < 4:
                    d2 = sl + 1
                else:
                    ex = (sl >> 1) - 1
                    d2 = ((2 + (sl & 1)) << ex) + 1
                    for i in range(ex):
                        pr = self.tbl[sb + 6 + i]
                        b2 = self._db(pr)
                        self.tbl[sb + 6 + i] = upd(pr, b2)
                        d2 = (d2 << 1) | b2
                self.bc += 1
                for i in range(l2):
                    src = self.wp - d2
                    by = self.w[(src + i) & 0xFFF] if 0 <= src < 4096 else 0
                    self.out.append(by)
                    self.w[self.wp & 0xFFF] = by
                    self.wp += 1
                    self.pb = by
                    self._shift_ctx(by)
        return bytes(self.out)

def process_file(input_path, output_path=None):
    with open(input_path, 'rb') as f:
        data = f.read()
    print(f"\n{'='*60}")
    print(f"Input: {os.path.basename(input_path)} ({len(data)} bytes)")
    if data[:4] != b'lmF@':
        print(f"  ERROR: Not lmF@ format")
        return None
    dec = LmfDecompressor(data)
    result = dec.decompress()
    print(f"  Decoded: {len(result)} bytes")
    if result:
        print(f"  First 32: {result[:32].hex()}")
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in result[:64])
        print(f"  ASCII: {printable}")
        if result[:3] == b'\x1bLua':
            print("  Lua bytecode!")
        elif result[:4] == b'\x1b\x00\x00\x00':
            print("  LuaJIT bytecode")
        elif result[:4] == b'LuaQ':
            print("  LuaQ bytecode")
        else:
            print(f"  Magic: {result[:8].hex()}")
    if output_path and result:
        with open(output_path, 'wb') as f:
            f.write(result)
        print(f"  Saved to {output_path}")
    return result

if __name__ == '__main__':
    dec_dir = "decrypted"
    files = sorted([f for f in os.listdir(dec_dir) if f.endswith('.dec')])
    for fname in files[:5]:
        path = os.path.join(dec_dir, fname)
        process_file(path, os.path.join(dec_dir, fname + '.out2'))
