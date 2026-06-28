"""
Compute the IV needed to make the first block decrypt to Lua bytecode header.
If the computed IV looks meaningful (e.g., part of the file header), we found the key.
"""
import os, struct
from Crypto.Cipher import AES

MT_DIR = r"H:\PROJECTMOD\_decompiled\assets"
TEST_FILE = r"5\5ebc64abedbf55a2e4ab8fb34260f31a.mt"

with open(os.path.join(MT_DIR, TEST_FILE), "rb") as f:
    data = f.read()

# Key from filename
filename = os.path.splitext(os.path.basename(TEST_FILE))[0]
key = bytes.fromhex(filename)

# First encrypted block (starting at offset 17)
c1 = data[17:33]
print(f"First encrypted block C1: {c1.hex()}")

# Decrypt C1 with standard AES-ECB (to get Dec(C1))
cipher = AES.new(key, AES.MODE_ECB)
dec_c1 = cipher.decrypt(c1)
print(f"Dec(C1) = {dec_c1.hex()}")

# Lua bytecode header (Lua 5.1 - 5.4)
# 0x1B 0x4C 0x75 0x61 0x51-0x54 0x00 0x01 0x04 0x04 0x04 0x08 0x00
lua_headers = [
    b"\x1bLua\x51\x00\x01\x04\x04\x04\x08\x00",  # Lua 5.1
    b"\x1bLua\x52\x00\x01\x04\x04\x04\x08\x00",  # Lua 5.2
    b"\x1bLua\x53\x00\x01\x04\x04\x04\x08\x00",  # Lua 5.3
    b"\x1bLua\x54\x00\x01\x04\x04\x04\x08\x00",  # Lua 5.4
]

print(f"\nComputing IV from Dec(C1) XOR Lua header...")
for lua_hdr in lua_headers:
    # Pad to 16 bytes
    padded = lua_hdr + b"\x00" * (16 - len(lua_hdr))
    iv = bytes(a ^ b for a, b in zip(dec_c1, padded))
    print(f"  IV for {lua_hdr[:4].decode()}+v{lua_hdr[4]:d}: {iv.hex()}")

# Check if any of these IVs looks like it could be derived from the file
print(f"\nFile header (17 bytes): {data[:17].hex()}")
print(f"Bytes 5-20: {data[5:21].hex()}")
print(f"Bytes 10-25: {data[10:26].hex()}")

# What if the IV is embedded in the header?
# Header bytes 5-20 = 16 bytes = could be IV!
iv_candidate = data[5:21]
print(f"\nIV candidate (bytes 5-20): {iv_candidate.hex()}")

# Try decrypting with this IV
cipher2 = AES.new(key, AES.MODE_CBC, iv=iv_candidate)
pt = cipher2.decrypt(data[17:])
print(f"  First block: {pt[:16].hex()}")
print(f"  Lua header: {pt[0] == 0x1B}")

# Try other 16-byte chunks from the header
for start in range(0, 10):
    if start + 16 <= len(data):
        iv_test = data[start:start+16]
        cipher_t = AES.new(key, AES.MODE_CBC, iv=iv_test)
        pt_t = cipher_t.decrypt(data[17:33])
        if pt_t[0] == 0x1B:
            print(f"  FOUND! IV at bytes {start}-{start+15}: {iv_test.hex()}")

# Also try: IV = MD5 of first encrypted block
import hashlib
iv_md5 = hashlib.md5(c1).digest()
cipher_m = AES.new(key, AES.MODE_CBC, iv=iv_md5)
pt_m = cipher_m.decrypt(data[17:33])
print(f"\nIV=MD5(C1): {iv_md5.hex()} first_block={pt_m[:16].hex()} Lua={pt_m[0]==0x1B}")

# Try: IV = SHA1 truncated
iv_sha1 = hashlib.sha1(key).digest()[:16]
cipher_s = AES.new(key, AES.MODE_CBC, iv=iv_sha1)
pt_s = cipher_s.decrypt(data[17:33])
print(f"IV=SHA1(key)[:16]: {iv_sha1.hex()} first={pt_s[:16].hex()} Lua={pt_s[0]==0x1B}")

# Try: IV from the 'aa' pattern at bytes 10-15 + key bytes
for prefix_len in range(0, 17):
    for suffix_len in range(0, 17 - prefix_len):
        if prefix_len + suffix_len > 16:
            continue
        mid_len = 16 - prefix_len - suffix_len
        iv_try = data[5:5+prefix_len] + b"\x00" * mid_len + key[:suffix_len]
        if len(iv_try) == 16:
            cipher_t = AES.new(key, AES.MODE_CBC, iv=iv_try)
            pt_t = cipher_t.decrypt(data[17:33])
            if pt_t[0] == 0x1B and pt_t[1] == 0x4C:
                print(f"\n  FOUND IV construction: header[{prefix_len}] + zeros[{mid_len}] + key[{suffix_len}]")
                print(f"  IV = {iv_try.hex()}")
