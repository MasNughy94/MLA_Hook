import os, sys, struct
from Crypto.Cipher import AES

# Import LMF decoder
import importlib.util
spec = importlib.util.spec_from_file_location("lmf", r"C:\Users\NGEONG\AppData\Local\Temp\opencode\lmf_decoder.py")
lmf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lmf)
decode_lmf = lmf.decode_lmf

AES_KEY = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
AES_IV = b"\x00" * 16

files = [
    r"C:\Users\NGEONG\Videos\VSCODE\mt_dump\assets\0\0000488d2f64199aca0cc7d54e7d11c0.mt",
    r"C:\Users\NGEONG\Videos\VSCODE\mt_dump\assets\0\00378c64fbd63011a81dccef6bf6e2bd.mt",
    r"C:\Users\NGEONG\Videos\VSCODE\mt_dump\assets\0\008fea3143557d628ac845a13a254e8a.mt",
]

for fpath in files:
    fname = os.path.basename(fpath)
    with open(fpath, "rb") as f:
        mt_data = f.read()
    
    fsize = len(mt_data)
    
    ct = mt_data[0x10:]
    ct_aligned = ct[:len(ct) - (len(ct) % 16)]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV)
    aes_out = cipher.decrypt(ct_aligned)
    
    # Full pipeline: aes_out already has lmF@ header
    result = decode_lmf(aes_out)
    
    print(f"=== {fname} ===")
    print(f"File size: {fsize} bytes")
    print(f"Decompressed size: {len(result)} bytes")
    print(f"First 64 bytes (hex): {result[:64].hex()}")
    
    # ASCII strings in first 256 bytes
    ascii_strs = []
    current = ""
    for b in result[:256]:
        if 32 <= b < 127:
            current += chr(b)
        else:
            if len(current) >= 4:
                ascii_strs.append(current)
            current = ""
    if len(current) >= 4:
        ascii_strs.append(current)
    
    print(f"ASCII strings in first 256 bytes: {ascii_strs}")
    print()
    
    # Save to temp file
    outpath = os.path.join(r"C:\Users\NGEONG\AppData\Local\Temp\opencode", fname + ".dec")
    with open(outpath, "wb") as f:
        f.write(result)
    print(f"Saved to: {outpath}")
    print()
