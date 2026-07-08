"""Test various AES-based decryption approaches on the inner lmF@ payload."""
import struct, os, sys, zlib
sys.path.insert(0, r'C:\Users\ADMIN SERVICE\Videos\MLA')
from mt_tool import decrypt_layer1
from Crypto.Cipher import AES
import hashlib

def parse_lmf_v2(data):
    if data[:4] != b'lmF@':
        return None
    size_coded = struct.unpack('<I', data[10:14])[0]
    uncomp_size = size_coded ^ 0x3EA
    key = bytes([data[4], data[5], data[6], data[7] ^ 5, data[8]])
    compressed = bytearray(data[14:])
    xor_count = min(16, uncomp_size, len(compressed))
    for i in range(xor_count):
        compressed[i] ^= 0xEC
    return {
        'uncompressed_size': uncomp_size,
        'key': key,
        'compressed': bytes(compressed),
    }

def test_file(fp):
    with open(fp, 'rb') as fh:
        raw = fh.read()
    dec = decrypt_layer1(raw)
    lmf = parse_lmf_v2(dec)
    if not lmf or lmf['uncompressed_size'] < 50:
        return None, None
    return lmf, dec

# Find files recursively
mt_dir = r'C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump\assets'
found = []
for root, dirs, files in os.walk(mt_dir):
    for f in files:
        if f.endswith('.mt'):
            fp = os.path.join(root, f)
            sz = os.path.getsize(fp)
            if 5000 < sz < 20000:
                found.append(fp)
                if len(found) >= 3:
                    break
    if len(found) >= 3:
        break

print(f'Found {len(found)} candidate files')
for fp in found:
    lmf, dec = test_file(fp)
    if lmf:
        print(f'\n{"="*60}')
        print(f'File: {os.path.relpath(fp, mt_dir)}')
        print(f'lmF@ key: {lmf["key"].hex()}')
        print(f'Uncomp size: {lmf["uncompressed_size"]}')
        print(f'Compressed size: {len(lmf["compressed"])}')
        
        cdata = lmf['compressed']
        aes_key = lmf['key'] + b'\x00' * 11
        derived = hashlib.sha256(lmf['key']).digest()[:16]
        
        # Try AES-ECB with zero-padded key
        for name, key in [
            ('AES-ECB zero-padded', aes_key),
            ('AES-ECB SHA256', derived),
            ('AES-ECB all-zero', b'\x00' * 16),
        ]:
            try:
                cipher = AES.new(key, AES.MODE_ECB)
                result = cipher.decrypt(cdata[:len(cdata) & ~15])
                printable = sum(1 for b in result[:100] if 32 <= b < 127)
                entropy = sum(result[:100]) / max(len(result[:100]), 1)
                print(f'  {name}: {len(result)} bytes, {printable}/100 printable')
            except Exception as e:
                print(f'  {name}: Error: {e}')
        
        # Try zlib with various window bits
        for wb in [-15, 15, 31, -47]:
            try:
                result = zlib.decompress(cdata, wb)
                printable = sum(1 for b in result[:100] if 32 <= b < 127)
                print(f'  zlib wb={wb}: {len(result)} bytes, {printable}/100 printable')
                break
            except:
                pass
        else:
            print(f'  zlib: all wbits failed')
        
        # Try AES-CTR
        for name, key in [
            ('AES-CTR zero-padded', aes_key),
            ('AES-CTR SHA256', derived),
        ]:
            try:
                cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=0)
                result = cipher.decrypt(cdata)
                printable = sum(1 for b in result[:100] if 32 <= b < 127)
                print(f'  {name}: {len(result)} bytes, {printable}/100 printable')
            except Exception as e:
                print(f'  {name}: Error: {e}')
