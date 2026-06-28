#!/usr/bin/env python3
"""Brute-force test: what initial match_flag and tree probs produce 0x78 as first byte?"""
import struct
from Crypto.Cipher import AES

key = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
iv = b"\x00" * 16

with open(r"C:\Users\NGEONG\Videos\VSCODE\mt_dump\sample.mt", "rb") as f:
    mt_data = f.read()

ct = mt_data[0x10:]
ct = ct[: (len(ct) // 16) * 16]
dec = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)

encoded = struct.unpack_from("<I", dec, 0x0A)[0]
decomp_size = encoded ^ 0x3EA
buf = bytearray(dec)
limit = min(decomp_size, 16)
for i in range(limit):
    buf[0x0E + i] ^= 0xEC
comp_data = bytes(buf[0x0E:])

INITIAL_RANGE = 0xFFFFFFFF
INITIAL_VALUE = 0x0D940DE2
PROB_MAX = 0x800
PROB_SHIFT = 5
RANGE_BITS = 11
RENORM_THRESH = 0x1000000

class BitDecoder:
    def __init__(self, data):
        self.data = data
        self.pos = 5
        self.end = len(data)
        self.high = INITIAL_RANGE
        self.low = INITIAL_VALUE
    def renorm(self):
        while self.high < RENORM_THRESH:
            self.high = (self.high << 8) & 0xFFFFFFFF
            if self.pos < self.end:
                self.low = ((self.low << 8) | self.data[self.pos]) & 0xFFFFFFFF
                self.pos += 1
            else:
                self.low = (self.low << 8) & 0xFFFFFFFF
    def decode_bit(self, prob):
        self.renorm()
        mid = ((self.high >> RANGE_BITS) * prob) & 0xFFFFFFFF
        if self.low < mid:
            self.high = mid; return 0
        else:
            self.low = (self.low - mid) & 0xFFFFFFFF
            self.high = (self.high - mid) & 0xFFFFFFFF; return 1

def update_prob(prob, bit):
    if bit == 0:
        prob += (PROB_MAX - prob) >> PROB_SHIFT
    else:
        prob -= prob >> PROB_SHIFT
    return prob & 0xFFFF

# Test 1: what match_flag prob value produces bit=1 (match)?
print("=== Match flag threshold ===")
bd = BitDecoder(comp_data)
for prob in range(1, 1025):
    bd2 = BitDecoder(comp_data)
    bit = bd2.decode_bit(prob)
    if bit == 1:
        print(f"  prob={prob:#x} ({prob}) gives bit=1 (MATCH)")
        break
else:
    print("  No prob value gives bit=1")

# Test 2: instead of uniform 0x400, try setting tree probs to 0x100 (25% prob)
print("\n=== Tree with probs=0x100 ===")
bd = BitDecoder(comp_data)
tbl = [0x100] * 8000
p = tbl[0]
mf_bit = bd.decode_bit(p)
tbl[0] = update_prob(p, mf_bit)
print(f"Match flag: bit={mf_bit}")
if mf_bit == 0:
    idx = 1
    bits = []
    while idx <= 255:
        p = tbl[0x736 + idx]
        bit = bd.decode_bit(p)
        tbl[0x736 + idx] = update_prob(p, bit)
        bits.append(str(bit))
        idx = (idx << 1) | bit
    byte = idx & 0xFF
    print(f"Tree: byte=0x{byte:02x} bits={''.join(bits)}")

# Test 3: try probs = 0x80
print("\n=== Tree with probs=0x80 ===")
bd = BitDecoder(comp_data)
tbl = [0x80] * 8000
p = tbl[0]
mf_bit = bd.decode_bit(p)
tbl[0] = update_prob(p, mf_bit)
print(f"Match flag: bit={mf_bit}")
if mf_bit == 0:
    idx = 1
    bits = []
    while idx <= 255:
        p = tbl[0x736 + idx]
        bit = bd.decode_bit(p)
        tbl[0x736 + idx] = update_prob(p, bit)
        bits.append(str(bit))
        idx = (idx << 1) | bit
    byte = idx & 0xFF
    print(f"Tree: byte=0x{byte:02x} bits={''.join(bits)}")

# Test 4: try probs = 0x200 (50% prob)
print("\n=== Tree with probs=0x200 ===")
bd = BitDecoder(comp_data)
tbl = [0x200] * 8000
p = tbl[0]
mf_bit = bd.decode_bit(p)
tbl[0] = update_prob(p, mf_bit)
print(f"Match flag: bit={mf_bit}")
if mf_bit == 0:
    idx = 1
    bits = []
    while idx <= 255:
        p = tbl[0x736 + idx]
        bit = bd.decode_bit(p)
        tbl[0x736 + idx] = update_prob(p, bit)
        bits.append(str(bit))
        idx = (idx << 1) | bit
    byte = idx & 0xFF
    print(f"Tree: byte=0x{byte:02x} bits={''.join(bits)}")

# Test 5: what if we DON'T decode the match flag before the tree?
# (i.e., match flag is always assumed literal, skip the decode)
print("\n=== Skip match flag decode ===")
bd = BitDecoder(comp_data)
idx = 1
bits = []
while idx <= 255:
    p = 0x400  # reset prob each time? no, use initial table
    # Actually, just use the tree with default probs, no match flag
    p = 0x400
    bit = bd.decode_bit(p)
    bits.append(str(bit))
    idx = (idx << 1) | bit
byte = idx & 0xFF
print(f"Tree: byte=0x{byte:02x} bits={''.join(bits)}")

# Test 6: what if we use a DIFFERENT initial range?
print("\n=== Different initial values ===")
for high, low in [(0xFFFFFFFF, 0x0D940DE2), (0x0D940DE2, 0xFFFFFFFF)]:
    print(f"  range=0x{high:08x} value=0x{low:08x}")
