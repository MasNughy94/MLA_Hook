"""Try various standard decompression algorithms on the inner lmF@ payload."""
import struct, os, sys, json
sys.path.insert(0, r'C:\Users\NGEONG\Videos\MLA')
from mt_tool import decrypt_layer1

import lz4.block as lz4b
import zstandard
import bz2
import lzma

print('Libraries loaded')

def parse_lmf(data):
    if data[:4] != b'lmF@':
        return None
    sz = struct.unpack('<I', data[10:14])[0] ^ 0x3EA
    key = bytes([data[4], data[5], data[6], data[7] ^ 5, data[8]])
    comp = bytearray(data[14:])
    for i in range(min(16, sz, len(comp))):
        comp[i] ^= 0xEC
    return {'usize': sz, 'key': key, 'data': bytes(comp)}

mt_dir = r'C:\Users\NGEONG\Videos\MLA\mt_dump\assets'
tested = 0

for root, dirs, files in os.walk(mt_dir):
    for f in files:
        if not f.endswith('.mt'):
            continue
        fp = os.path.join(root, f)
        with open(fp, 'rb') as fh:
            raw = fh.read()
        dec = decrypt_layer1(raw)
        lmf = parse_lmf(dec)
        if lmf and 5000 < lmf['usize'] < 200000:
            d = lmf['data']
            print('\nFile: %s' % f)
            print('  Sizes: raw=%d dec=%d inner=%d uncomp=%d' % (
                len(raw), len(dec), len(d), lmf['usize']))
            print('  First 32 bytes of inner data:')
            for i in range(0, 32, 4):
                val = struct.unpack('<I', d[i:i+4])[0] if i+4 <= len(d) else 0
                print('    [%02d] = 0x%08x' % (i, val))
            
            # LZ4 block
            try:
                res = lz4b.decompress(d)
                p = sum(1 for b in res[:200] if 32 <= b < 127)
                print('  lz4 block: %d bytes, %d/200 printable' % (len(res), p))
            except Exception as e:
                print('  lz4 block: %s' % str(e)[:60])
            
            # Zstandard
            try:
                dctx = zstandard.ZstdDecompressor()
                res = dctx.decompress(d, max_output_size=lmf['usize'] * 2)
                p = sum(1 for b in res[:200] if 32 <= b < 127)
                print('  zstd: %d bytes, %d/200 printable' % (len(res), p))
            except Exception as e:
                print('  zstd: %s' % str(e)[:60])
            
            # BZ2
            try:
                res = bz2.decompress(d)
                p = sum(1 for b in res[:200] if 32 <= b < 127)
                print('  bzip2: %d bytes, %d/200 printable' % (len(res), p))
            except:
                print('  bzip2: failed')
            
            # LZMA
            try:
                res = lzma.decompress(d)
                p = sum(1 for b in res[:200] if 32 <= b < 127)
                print('  lzma: %d bytes, %d/200 printable' % (len(res), p))
            except:
                print('  lzma: failed')
            
            tested += 1
            if tested >= 2:
                break
    if tested >= 2:
        break
