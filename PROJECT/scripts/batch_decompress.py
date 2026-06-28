#!/usr/bin/env python3
"""
Batch decompress all .mt files from assets/0/ through assets/f/
Pipeline: .mt -> AES-128-CBC -> lmF@ header -> Custom decompressor -> .dec
"""
import struct, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mt_decoder import decrypt_aes, parse_lmf_header, decompress_lmf, LMF_MAGIC

ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'decoded_apk', 'assets')
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dec_batch')

def decompress_one(mt_path):
    with open(mt_path, 'rb') as f:
        mt_data = f.read()
    magic = struct.unpack_from('<I', mt_data, 0)[0]
    if magic != 0x6d746e41:
        return None, f"Bad magic: {magic:#x}"
    ct = mt_data[0x10:]
    ct_len = (len(ct) // 16) * 16
    ct = ct[:ct_len]
    decrypted = decrypt_aes(ct)
    if decrypted[:4] != LMF_MAGIC:
        return None, f"Bad lmF@: {decrypted[:4]}"
    decomp_size, flags, comp_data = parse_lmf_header(decrypted)
    result = decompress_lmf(comp_data, decomp_size, flags)
    if result is None:
        return None, "Decompression failed"
    return result, None

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    
    mt_files = []
    for hex_dir in ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']:
        d = os.path.join(ASSETS_DIR, hex_dir)
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.endswith('.mt'):
                    mt_files.append((os.path.join(d, f), f))
    
    total = len(mt_files)
    print(f"Found {total} .mt files")
    
    ok = errors = 0
    t0 = time.time()
    
    for i, (mt_path, fname) in enumerate(mt_files):
        result, err = decompress_one(mt_path)
        if err:
            errors += 1
            if errors <= 10:
                print(f"ERR [{i+1}/{total}] {fname}: {err}")
        else:
            ok += 1
            out_path = os.path.join(OUT_DIR, fname + '.dec')
            with open(out_path, 'wb') as f:
                f.write(result)
        
        if (i+1) % 500 == 0 or i == total - 1:
            elapsed = time.time() - t0
            rate = (i+1) / elapsed
            eta = (total - i - 1) / rate if rate > 0 else 0
            print(f"[{i+1}/{total}] ok={ok} err={errors} {elapsed:.0f}s {rate:.0f}files/s eta={eta:.0f}s")
    
    t = time.time() - t0
    print(f"\nDone: {ok} OK, {errors} errors in {t:.0f}s ({total/t:.0f} files/s)")

if __name__ == '__main__':
    main()
