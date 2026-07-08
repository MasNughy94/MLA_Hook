#!/usr/bin/env python3
"""
PoC: AES-128-CBC decrypt sample.mt using the reconstructed key.
Tests multiple IV hypotheses, ciphertext offsets, and lengths.
"""
import struct
import zlib
import sys

SAMPLE_MT = r"C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump\sample.mt"
EXPECTED_LUA = r"C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump\sample.mt.lua"

# The key (16 bytes, from _getKeyv -> fromHex -> m_sKey)
KEY_HEX = "f5a193d50ade553e9835595f5cd75ddd"
KEY = bytes.fromhex(KEY_HEX)

with open(SAMPLE_MT, 'rb') as f:
    mt_data = f.read()

with open(EXPECTED_LUA, 'rb') as f:
    expected = f.read()

print(f"=== sample.mt ===")
print(f"Total size: {len(mt_data)} bytes")
print(f"Magic:      {mt_data[0:4]} (0x{struct.unpack('<I', mt_data[0:4])[0]:08x})")
print(f"enc_type:   {mt_data[4]} (offset 4)")
print(f"bytes 5-7:  {mt_data[5:8].hex()}")
print(f"xor_mask:   {mt_data[8:12].hex()} (LE={struct.unpack('<I', mt_data[8:12])[0]:08x})")
print(f"bytes 12-15:{mt_data[12:16].hex()}")
print(f"")
print(f"=== Expected output (sample.mt.lua) ===")
print(f"Size: {len(expected)} bytes")
print(f"First 16 bytes: {expected[:16].hex()}")
print(f"First 32 ASCII: {''.join(chr(b) if 32<=b<127 else '.' for b in expected[:32])}")
print(f"")

# ----------------------------------------------------------------
# Try AES-128-CBC decryption with various IV and offset hypotheses
# ----------------------------------------------------------------
try:
    from Crypto.Cipher import AES
except ImportError:
    print("WARNING: pycryptodome not installed, trying...")
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pycryptodome'])
    from Crypto.Cipher import AES

# Payload starts at offset 0x10
payload_offset = 0x10
payload = mt_data[payload_offset:]

# Hypothesis matrix
hypotheses = []

# IV candidates
iv_candidates = {
    "zero_iv": b'\x00' * 16,
    "first_16_bytes_of_payload": payload[:16],
    "header_field_8_23": mt_data[8:24],  # xor_mask + next 12 bytes
    "header_field_0_15": mt_data[0:16],  # full header
    "file_hash_or_iv": mt_data[0x10:0x20],  # first 16 payload bytes
}

# Data length candidates
# aes_decrypt(buf, end, ...): length = end - buf = file_size - 16 = 9761
# But must be multiple of 16 for AES-CBC
raw_len = len(mt_data) - 16  # 9761
aligned_len = raw_len & ~0xF  # 9760 (round down to 16)
unrounded_len = raw_len       # 9761

length_candidates = {
    f"aligned_16_{aligned_len}": aligned_len,
    f"raw_{raw_len}": raw_len,
}

# Mode/enc_type possibilities (Type 1: AES then inflate)
for iv_name, iv in iv_candidates.items():
    for len_name, data_len in length_candidates.items():
        # Take the first `data_len` bytes of payload
        ciphertext = payload[:data_len]
        
        try:
            cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
            decrypted = cipher.decrypt(ciphertext)
            
            # Check for lmF@ marker
            lmF_pos = decrypted.find(b"lmF@")
            zlib_hdr = decrypted[:2] if len(decrypted) >= 2 else b""
            is_zlib = zlib_hdr in [b'\x78\x01', b'\x78\x5e', b'\x78\x9c', b'\x78\xda']
            
            print(f"[{iv_name}][{len_name}] first 32: {decrypted[:32].hex()} | lmF@ at {lmF_pos} | zlib={is_zlib}")
            
            # If looks like zlib, try to decompress
            if is_zlib or decrypted[:2] == b'\x78\x9c' or decrypted[:2] == b'\x78\x01':
                try:
                    decompressed = zlib.decompress(decrypted)
                    print(f"  >>> ZLIB DECOMPRESSED: {len(decompressed)} bytes, first 32: {decompressed[:32].hex()}")
                    # Check if decompressed matches expected
                    if decompressed == expected:
                        print(f"  *** MATCHES expected output! ***")
                    elif len(decompressed) == len(expected):
                        diffs = sum(1 for a,b in zip(decompressed, expected) if a!=b)
                        print(f"  *** Same size ({len(decompressed)}), {diffs} byte differences ***")
                except Exception as e:
                    pass
                    
            # Try zlib decompression starting from offset within decrypted data
            if not is_zlib and len(decrypted) > 2:
                for off in range(0, min(64, len(decrypted)-2)):
                    try:
                        decompressed = zlib.decompress(decrypted[off:])
                        print(f"  >>> ZLIB @ offset {off}: {len(decompressed)} bytes, first 32: {decompressed[:32].hex()}")
                        if decompressed == expected:
                            print(f"  *** MATCHES expected output! ***")
                    except:
                        continue
                        
        except Exception as e:
            print(f"[{iv_name}][{len_name}] ERROR: {e}")

# Also try: what if the first 16 bytes of payload are IV, remaining is ciphertext?
print(f"\n--- Hypothesis: IV = first 16 bytes of payload ---")
iv = payload[:16]
ct = payload[16:]
for len_name, data_len in [("aligned_9760", 9760), ("remaining", len(ct))]:
    ciphertext = ct[:data_len]
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
        decrypted = cipher.decrypt(ciphertext)
        print(f"[payload_iv_as_iv][{len_name}] first 32: {decrypted[:32].hex()}")
        dec_size = len(decrypted)
        # Try decompress
        try:
            decompressed = zlib.decompress(decrypted)
            print(f"  >>> ZLIB OK: {len(decompressed)} bytes, cmp expected: {decompressed == expected}")
        except:
            # Try with offset
            for off in range(0, min(32, len(decrypted)-2)):
                try:
                    decompressed = zlib.decompress(decrypted[off:])
                    print(f"  >>> ZLIB @ offset {off}: {len(decompressed)} bytes")
                    if decompressed == expected:
                        print(f"  *** MATCHES! ***")
                except:
                    continue
    except Exception as e:
        print(f"[payload_iv_as_iv][{len_name}] ERROR: {e}")

# Also try: maybe the mode parameter changes things?
# In aes_decrypt: w4 = mode = xor_mask ^ 0xabcdef = 0x00262615
# Maybe mode affects block size or IV?
print(f"\n=== Summary ===")
print(f"KEY: {KEY.hex()}")
print(f"Payload offset: 0x{payload_offset:x}")
print(f"Raw payload: {raw_len} bytes (9761, not 16-aligned)")
print(f"Aligned payload: {aligned_len} bytes (9760, 16-aligned)")
print(f"Expected lua: {len(expected)} bytes")
