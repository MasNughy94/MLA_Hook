#!/usr/bin/env python3
"""Use Unicorn to emulate a snippet of the range decoder to find the truth."""
import struct
from Crypto.Cipher import AES
from unicorn import *
from unicorn.arm64_const import *

# Load the binary
so_path = r"C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so"
with open(so_path, "rb") as f:
    so_data = f.read()

# AES decrypt and prepare compressed data
key = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
iv = b"\x00" * 16
with open(r"C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump\sample.mt", "rb") as f:
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

# Set up emulation
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# Memory map
BASE = 0x1000000
TABLE_ADDR = 0x2000000
WINDOW_ADDR = 0x3000000
INPUT_ADDR = 0x4000000
STACK_ADDR = 0x5000000
CTX_ADDR = 0x6000000

mu.mem_map(BASE, 0x1000000)
mu.mem_map(TABLE_ADDR, 0x100000)
mu.mem_map(WINDOW_ADDR, 0x100000)
mu.mem_map(INPUT_ADDR, 0x10000)
mu.mem_map(STACK_ADDR, 0x100000)
mu.mem_map(CTX_ADDR, 0x10000)

# Set up context
FIELD_00 = 2  # computed from header
FIELD_04 = 4  # computed from header
FIELD_08 = 2  # computed from header
INIT_RANGE = 0xFFFFFFFF
INIT_VALUE = 0x0D940DE2
PROB_INIT = 0x400  # ALL entries

# Write context
mu.mem_write(CTX_ADDR + 0x00, struct.pack("<I", FIELD_00))
mu.mem_write(CTX_ADDR + 0x04, struct.pack("<I", FIELD_04))
mu.mem_write(CTX_ADDR + 0x08, struct.pack("<I", FIELD_08))
mu.mem_write(CTX_ADDR + 0x10, struct.pack("<Q", TABLE_ADDR))  # table pointer
mu.mem_write(CTX_ADDR + 0x18, struct.pack("<Q", WINDOW_ADDR))  # window pointer
mu.mem_write(CTX_ADDR + 0x28, struct.pack("<I", INIT_RANGE))  # range
mu.mem_write(CTX_ADDR + 0x2C, struct.pack("<I", INIT_VALUE))  # value
mu.mem_write(CTX_ADDR + 0x40, struct.pack("<I", 0))  # block_cnt
mu.mem_write(CTX_ADDR + 0x44, struct.pack("<I", 0))  # block_remain
mu.mem_write(CTX_ADDR + 0x48, struct.pack("<I", 0))  # state_idx
mu.mem_write(CTX_ADDR + 0x4C, struct.pack("<I", 0))
mu.mem_write(CTX_ADDR + 0x50, struct.pack("<I", 0))
mu.mem_write(CTX_ADDR + 0x54, struct.pack("<I", 0))
mu.mem_write(CTX_ADDR + 0x58, struct.pack("<I", 0))
mu.mem_write(CTX_ADDR + 0x0C, struct.pack("<I", 0))  # field_0C
mu.mem_write(CTX_ADDR + 0x30, struct.pack("<Q", 0))  # ctx[0x30]
mu.mem_write(CTX_ADDR + 0x38, struct.pack("<Q", WINDOW_ADDR))  # window end

# Initialize probability table with 0x400
table_data = struct.pack("<H", PROB_INIT) * 8000
mu.mem_write(TABLE_ADDR, table_data)

# Compressed data (after context bytes) starts at input
input_data = comp_data[5:]  # skip 5 context bytes
mu.mem_write(INPUT_ADDR, input_data)

# Now, let me just manually compute what the match flag and first few tree bits
# would produce by using a Python implementation (since Unicorn for ARM64 is complex)

# Actually let me first verify the simple case by writing a manual decoder
# and tracing through step by step

print("=== Manual verification with Python ===")
range_val = 0xFFFFFFFF
value = 0x0D940DE2
prob_init = 0x400
PROB_MAX = 0x800

def decode_bit(high, low, prob):
    renorm_thresh = 0xFFFFFF
    mid = ((high >> 11) * prob) & 0xFFFFFFFF
    if low < mid:
        return 0, mid, low  # MPS
    else:
        return 1, (high - mid) & 0xFFFFFFFF, (low - mid) & 0xFFFFFFFF  # LPS

# Simulate block decoder exact match flag + tree logic
# But instead of reading input, track when renorm would happen

high = range_val
low = value

print(f"Initial range=0x{high:08x} value=0x{low:08x}")

# Match flag at table[0] = 0x400
prob = prob_init
bit, new_high, new_low = decode_bit(high, low, prob)
print(f"Match flag: prob=0x{prob:04x} mid=0x{(high>>11)*prob:08x} bit={bit}")
print(f"  -> range=0x{new_high:08x} value=0x{new_low:08x}")
high, low = new_high, new_low

# Tree decode with 8 bits
tree_idx = 1
for step in range(8):
    prob = prob_init
    bit, new_high, new_low = decode_bit(high, low, prob)
    tree_idx = (tree_idx << 1) | bit
    print(f"Tree step {step+1} (idx={tree_idx>>1}->{tree_idx}): prob=0x{prob:04x} mid=0x{((high>>11)*prob)&0xFFFFFFFF:08x} bit={bit}")
    print(f"  -> range=0x{new_high:08x} value=0x{new_low:08x}")
    high, low = new_high, new_low

result = tree_idx & 0xFF
print(f"\nResult: tree_idx={tree_idx} -> byte=0x{result:02x} ({result})")
print(f"Final range=0x{high:08x} value=0x{low:08x}")
print(f"Expected first byte: 0x78")
