#!/usr/bin/env python3
import struct
from Crypto.Cipher import AES

key = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
iv = b"\x00" * 16

with open(r"C:\Users\NGEONG\Videos\VSCODE\mt_dump\sample.mt", "rb") as f:
    mt_data = f.read()
ct = mt_data[0x10:]
ct = ct[: (len(ct) // 16) * 16]
dec = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)
enc = struct.unpack_from("<I", dec, 0x0A)[0]
decomp_size = enc ^ 0x3EA
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
            self.high = mid
            return 0
        else:
            self.low = (self.low - mid) & 0xFFFFFFFF
            self.high = (self.high - mid) & 0xFFFFFFFF
            return 1

def update_prob(prob, bit):
    if bit == 0:
        prob += (PROB_MAX - prob) >> PROB_SHIFT
    else:
        prob -= prob >> PROB_SHIFT
    return prob & 0xFFFF

# Test: table all zeros
print("=== All zeros table ===")
bd = BitDecoder(comp_data)
tbl = [0] * 8000
p = tbl[0]
bit = bd.decode_bit(p)
print(f"Match flag with prob=0: bit={bit}")
tbl[0] = update_prob(p, bit)
if bit == 0:
    idx = 1
    bits = []
    while idx <= 255:
        p = tbl[0x736 + idx]
        bit = bd.decode_bit(p)
        tbl[0x736 + idx] = update_prob(p, bit)
        bits.append(str(bit))
        idx = (idx << 1) | bit
    print(f"Result: byte=0x{idx & 0xFF:02x} bits={''.join(bits)}")

# Test: table all 0x100 (256)
print("\n=== Table all 0x100 ===")
bd = BitDecoder(comp_data)
tbl = [0x100] * 8000
p = tbl[0]
bit = bd.decode_bit(p)
print(f"Match flag: bit={bit}")
tbl[0] = update_prob(p, bit)
if bit == 0:
    idx = 1
    bits = []
    while idx <= 255:
        p = tbl[0x736 + idx]
        bit = bd.decode_bit(p)
        tbl[0x736 + idx] = update_prob(p, bit)
        bits.append(str(bit))
        idx = (idx << 1) | bit
    print(f"Result: byte=0x{idx & 0xFF:02x} bits={''.join(bits)}")

# Test: table all 0x040 (64)
print("\n=== Table all 0x040 ===")
bd = BitDecoder(comp_data)
tbl = [0x040] * 8000
p = tbl[0]
bit = bd.decode_bit(p)
print(f"Match flag: bit={bit}")
tbl[0] = update_prob(p, bit)
if bit == 0:
    idx = 1
    bits = []
    while idx <= 255:
        p = tbl[0x736 + idx]
        bit = bd.decode_bit(p)
        tbl[0x736 + idx] = update_prob(p, bit)
        bits.append(str(bit))
        idx = (idx << 1) | bit
    print(f"Result: byte=0x{idx & 0xFF:02x} bits={''.join(bits)}")

# Test with match flag at 0x420 (after 1 MPS update), tree at 0x400
print("\n=== Match flag = 0x420, tree = 0x400 ===")
bd = BitDecoder(comp_data)
tbl = [0x400] * 8000
tbl[0] = 0x420  # pre-updated match flag
p = tbl[0]
bit = bd.decode_bit(p)
print(f"Match flag: bit={bit}")
tbl[0] = update_prob(p, bit)
if bit == 0:
    idx = 1
    bits = []
    while idx <= 255:
        p = tbl[0x736 + idx]
        bit = bd.decode_bit(p)
        tbl[0x736 + idx] = update_prob(p, bit)
        bits.append(str(bit))
        idx = (idx << 1) | bit
    print(f"Result: byte=0x{idx & 0xFF:02x} bits={''.join(bits)}")
