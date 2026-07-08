#!/usr/bin/env python3
"""Test various decode approaches for the first byte."""
import struct
from Crypto.Cipher import AES

key = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
iv = b"\x00" * 16

with open(r"C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump\sample.mt", "rb") as f:
    mt_data = f.read()
ct = mt_data[0x10:]
ct = ct[: (len(ct) // 16) * 16]
dec = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)

flags = bytearray(5)
flags[0] = dec[4]
flags[1] = dec[5]
flags[2] = dec[6]
flags[3] = dec[7] ^ 5
flags[4] = dec[8]
encoded = struct.unpack_from("<I", dec, 0x0A)[0]
decomp_size = encoded ^ 0x3EA
buf = bytearray(dec)
limit = min(decomp_size, 16)
for i in range(limit):
    buf[0x0E + i] ^= 0xEC
comp_data = bytes(buf[0x0E:])

PROB_INIT = 0x400
PROB_MAX = 0x800
PROB_SHIFT = 5
RANGE_BITS = 11
RENORM_THRESH = 0x1000000


class BitDecoder:
    def __init__(self, data):
        self.data = data
        self.pos = 5
        self.end = len(data)
        self.high = 0xFFFFFFFF
        self.low = 0x0D940DE2

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


# Test 1: Current approach - match flag at idx 0, tree at 0x736
print("=== Approach 1: match flag idx=0, tree at 0x736 ===")
bd = BitDecoder(comp_data)
tbl = [PROB_INIT] * 8000
p = tbl[0]
bit = bd.decode_bit(p)
tbl[0] = update_prob(p, bit)
print(f"Match flag bit={bit}")
if bit == 0:
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

# Test 2: match flag at idx = state_idx*16 + 0xC = 12
print("\n=== Approach 2: match flag idx=12, nibble decode ===")
bd = BitDecoder(comp_data)
tbl = [PROB_INIT] * 8000
p = tbl[12]
bit = bd.decode_bit(p)
tbl[12] = update_prob(p, bit)
print(f"Match flag bit={bit}")
if bit == 0:
    # Nibble decode using indices state_idx*16 + nibble*4 + bit
    nib0 = 0
    nib1 = 0
    for nib in range(2):
        for bitpos in [3, 2, 1, 0]:
            idx = 0 + nib * 4 + bitpos
            p = tbl[idx]
            b = bd.decode_bit(p)
            tbl[idx] = update_prob(p, b)
            if nib == 0:
                nib0 = (nib0 << 1) | b
            else:
                nib1 = (nib1 << 1) | b
    byte = (nib0 << 4) | nib1
    print(f"Nibble decode: byte=0x{byte:02x} (nib0={nib0:#x} nib1={nib1:#x})")

# Test 3: match flag at idx = state_idx*16 + 0xC0 = 192, tree at 0x736
print("\n=== Approach 3: match flag idx=192, tree at 0x736 ===")
bd = BitDecoder(comp_data)
tbl = [PROB_INIT] * 8000
p = tbl[192]
bit = bd.decode_bit(p)
tbl[192] = update_prob(p, bit)
print(f"Match flag bit={bit}")
if bit == 0:
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
