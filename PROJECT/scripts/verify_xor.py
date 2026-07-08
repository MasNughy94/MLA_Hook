#!/usr/bin/env python3
"""Verify the XOR and compressed data."""
import struct
from Crypto.Cipher import AES

key = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
iv = b"\x00" * 16

with open(r"C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump\sample.mt", "rb") as f:
    mt_data = f.read()

print(f"File size: {len(mt_data)}")
print(f"File header: {mt_data[:16].hex()}")

# AES decrypt (skip first 16 bytes of file)
ct = mt_data[0x10:]
ct = ct[: (len(ct) // 16) * 16]
dec = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)

print(f"\nDecrypted size: {len(dec)}")
print(f"dec[0x00:0x10] = {dec[0x00:0x10].hex()}")

# lmF@ header
print(f"\nlmF@ magic: {dec[0x00:0x04]}")
field_08 = dec[0x08]
print(f"field_08 byte (dec[0x08]): 0x{field_08:02x}")
field_0C = dec[0x0C]
field_0D = dec[0x0D]
print(f"field_0C = 0x{field_0C:02x}, field_0D = 0x{field_0D:02x}")

# decomp_size from offset 0x0A
enc = struct.unpack_from("<I", dec, 0x0A)[0]
print(f"enc at dec+0x0A: 0x{enc:08x}")
decomp_size = enc ^ 0x3EA
print(f"decomp_size: {decomp_size} (0x{decomp_size:x})")

# Bytes at offset 0x0E before XOR
print(f"\ndec[0x0E:0x0E+5] before XOR: {dec[0x0E:0x0E+5].hex()}")
for i in range(5):
    print(f"  dec[0x{0x0E+i:02x}] = 0x{dec[0x0E+i]:02x} = {dec[0x0E+i]}")

# XOR
buf = bytearray(dec)
limit = min(decomp_size, 16)
for i in range(limit):
    buf[0x0E + i] ^= 0xEC

print(f"\nbuf[0x0E:0x0E+5] after XOR: {bytes(buf[0x0E:0x0E+5]).hex()}")
comp_data = bytes(buf[0x0E:])
print(f"comp_data[0] = 0x{comp_data[0]:02x} (would be loaded into ctx[0x70])")
print(f"comp_data[0] is zero? {comp_data[0] == 0}")

# Also check what value would be assembled
# ctx[0x71] = comp_data[1]
# ctx[0x72] = comp_data[2]
# ctx[0x73] = comp_data[3]
# ctx[0x74] = comp_data[4]
value = (comp_data[1] << 24) | (comp_data[2] << 16) | (comp_data[3] << 8) | comp_data[4]
print(f"\nAssembled value after XOR: 0x{value:08x}")
print(f"Range: 0xFFFFFFFF")

# Compare with INIT_VALUE used in decoder
print(f"\nDecoder uses range=0xFFFFFFFF, value=0x0D940DE2")
print(f"Actual assembled range=0xFFFFFFFF, value=0x{value:08x}")

# Is there a different XOR? Maybe the _first_ byte is NOT XOR'd?
print("\n--- Alternative: Maybe XOR starts at different offset? ---")
for start_offset in [0x0E, 0x0F, 0x10]:
    buf2 = bytearray(dec)
    limit = min(decomp_size, 16)
    for i in range(limit):
        buf2[start_offset + i] ^= 0xEC
    if start_offset == 0x0E:
        continue  # already checked
    print(f"  XOR start=0x{start_offset:02x}: buf[0x0E:0x0E+5] = {bytes(buf2[0x0E:0x0E+5]).hex()}")

# Maybe the XOR is applied differently?
# buf[0x0E + i] ^= 0xEC for i in range(decomp_size)
# And decomp_size might be smaller?
print(f"\n--- Alternative: decomp_size different ---")
for j in range(5):
    dec_copy = bytearray(dec)
    limit = j
    for i in range(limit):
        dec_copy[0x0E + i] ^= 0xEC
    val = (dec_copy[0x0F] << 24) | (dec_copy[0x10] << 16) | (dec_copy[0x11] << 8) | dec_copy[0x12]
    print(f"  XOR {j} bytes: ctx[0x70]=0x{dec_copy[0x0E]:02x}, value=0x{val:08x}")
