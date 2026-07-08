import struct, os, shutil

so_path = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\decoded_apk\lib\arm64-v8a\libagame.so'
backup_path = so_path + '.orig'

# Backup if not already backed up
if not os.path.exists(backup_path):
    shutil.copy2(so_path, backup_path)
    print('Backup created')

with open(so_path, 'rb') as f:
    data = bytearray(f.read())

print(f'libagame.so size: {len(data)} bytes')

# Patch 1: BL at 0x409A8C -> B 0x427A20
patch1_addr = 0x409A8C
patch1_data = struct.pack('<I', 0x140077E5)
for i, b in enumerate(patch1_data):
    data[patch1_addr + i] = b

# Trampoline 1 at 0x427A20
tramp1_addr = 0x427A20
tramp1_data = struct.pack('<IIIII', 0x52847E00, 0xF2A92E80, 0xB90043A0, 0xB90047A0, 0x13F88818)
for i, b in enumerate(tramp1_data):
    data[tramp1_addr + i] = b

# Patch 2: BL at 0x409C30 -> B 0x427E00
patch2_addr = 0x409C30
patch2_data = struct.pack('<I', 0x14007874)
for i, b in enumerate(patch2_data):
    data[patch2_addr + i] = b

# Trampoline 2 at 0x427E00
tramp2_addr = 0x427E00
b_imm26 = (-0x7877) & 0x3FFFFFF
b_enc = 0x14000000 | b_imm26
tramp2_data = struct.pack('<IIIII', 0x52847E00, 0xF2A92E80, 0xB90043A0, 0xB90047A0, b_enc)
for i, b in enumerate(tramp2_data):
    data[tramp2_addr + i] = b

with open(so_path, 'wb') as f:
    f.write(data)

print('PATCH COMPLETE')

# Verify
with open(so_path, 'rb') as f:
    for addr in [0x409A8C, 0x427A20, 0x409C30, 0x427E00]:
        f.seek(addr)
        val = struct.unpack('<I', f.read(4))[0]
        print(f'  0x{addr:08x}: 0x{val:08x}')
