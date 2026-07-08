import struct, os, sys
sys.path.insert(0, r'C:\Users\ADMIN SERVICE\Videos\MLA')
from mt_tool import decrypt_layer1

def parse_lmf_v2(data):
    """Parse lmF@ based on the disassembly findings."""
    if data[:4] != b'lmF@':
        return None
    
    # From the uncompressData function:
    # offset 0xA (10): size_u32 XOR 0x3EA = uncompressed_size
    size_coded = struct.unpack('<I', data[10:14])[0]
    uncomp_size = size_coded ^ 0x3EA
    
    # Build 5-byte key: [4], [5], [6], [7]^5, [8]
    key = bytes([
        data[4],
        data[5],
        data[6],
        data[7] ^ 5,
        data[8],
    ])
    
    # Compressed data starts at offset 0xE (14)
    compressed = bytearray(data[14:])
    
    # First 16 bytes of compressed are XORed with 0xEC
    # But only up to the uncompressed_size
    xor_count = min(16, uncomp_size, len(compressed))
    for i in range(xor_count):
        compressed[i] ^= 0xEC
    
    return {
        'uncompressed_size': uncomp_size,
        'key': key.hex(),
        'compressed': bytes(compressed),
        'size_coded_raw': size_coded,
    }

# Test on all decrypted files
mt_dir = r'C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump\assets'

# First, load one small file
import glob

decrypted_dir = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\lmf_test'
os.makedirs(decrypted_dir, exist_ok=True)

files = []
for root, dirs, fs in os.walk(mt_dir):
    for f in fs:
        if f.endswith('.mt'):
            files.append(os.path.join(root, f))
            if len(files) >= 100:
                break
    if len(files) >= 100:
        break

print(f'Testing {len(files)} files...')
stats = {}
for fp in files:
    with open(fp, 'rb') as f:
        raw = f.read()
    dec = decrypt_layer1(raw)
    
    lmf = parse_lmf_v2(dec)
    if lmf is None:
        print(f'{os.path.basename(fp)}: Not lmF@!')
        continue
    
    sz = len(raw)
    csz = len(lmf['compressed'])
    usz = lmf['uncompressed_size']
    
    # Track stats
    for k in ['key']:
        stats[lmf[k]] = stats.get(lmf[k], 0) + 1
    
    # Check if size makes sense
    if usz > 0 and csz > 0:
        ratio = csz / usz
        if ratio < 0.3 or ratio > 1.5:
            print(f'{os.path.basename(fp)}: unusual ratio sz={sz} csz={csz} usz={usz} ratio={ratio:.2f} key={lmf["key"]}')
    else:
        if usz == 0:
            print(f'{os.path.basename(fp)}: uncomp_size=0! sz={sz} csz={csz}')

print(f'\nUnique keys: {len(stats)}')
print('Key distribution (top 10):')
for k, v in sorted(stats.items(), key=lambda x: -x[1])[:10]:
    print(f'  {k}: {v}')
