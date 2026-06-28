import struct

so_path = r'C:\Users\NGEONG\Videos\MLA\libagame.so'
with open(so_path, 'rb') as f:
    data = f.read()

# Parse ELF for section info
e_shoff = struct.unpack('<Q', data[0x28:0x30])[0]
e_shentsize = struct.unpack('<H', data[0x3A:0x3C])[0]
e_shnum = struct.unpack('<H', data[0x3C:0x3E])[0]
e_shstrndx = struct.unpack('<H', data[0x3E:0x40])[0]

shstrtab_off = e_shoff + e_shstrndx * e_shentsize
sh_off_val = struct.unpack('<Q', data[shstrtab_off+0x18:shstrtab_off+0x20])[0]
sh_size_val = struct.unpack('<Q', data[shstrtab_off+0x20:shstrtab_off+0x28])[0]
section_names = data[sh_off_val:sh_off_val+sh_size_val]

# Find what section contains offset 0x10B1E0
target_off = 0x10B1E0
print(f'Section containing file offset 0x{target_off:x}:')
for i in range(e_shnum):
    sh = data[e_shoff + i*e_shentsize : e_shoff + (i+1)*e_shentsize]
    sh_name_idx = struct.unpack('<I', sh[0:4])[0]
    sh_type = struct.unpack('<I', sh[4:8])[0]
    sh_offset = struct.unpack('<Q', sh[0x18:0x20])[0]
    sh_size = struct.unpack('<Q', sh[0x20:0x28])[0]
    sh_addralign = struct.unpack('<Q', sh[0x30:0x38])[0]
    name = section_names[sh_name_idx:].split(b'\x00')[0].decode('utf-8', errors='replace')
    
    if sh_offset <= target_off < sh_offset + sh_size:
        print(f'  Section {i}: {name} (type={sh_type}, addr=0x{sh_offset:x}, size=0x{sh_size:x}, align={sh_addralign})')
        # Show surrounding context
        sh_addr = struct.unpack('<Q', sh[0x10:0x18])[0]
        print(f'  Virtual addr: 0x{sh_addr:x}')
        print(f'  Data at 0x{target_off:x}:')
        for j in range(-3, 4):
            off = target_off + j*8
            if sh_offset <= off < sh_offset + sh_size:
                val = struct.unpack('<Q', data[off:off+8])[0]
                print(f'    [{off:#010x}] = 0x{val:016x}')

# Find sections containing the four target functions
print()
print('Sections containing our functions:')
for func_name, func_addr in [('getkey', 0x43B33C), ('TEA-CFB', 0x43AE3C), ('TEA core', 0x43AA80), ('caller', 0x43B488)]:
    for i in range(e_shnum):
        sh = data[e_shoff + i*e_shentsize : e_shoff + (i+1)*e_shentsize]
        sh_offset = struct.unpack('<Q', sh[0x18:0x20])[0]
        sh_size = struct.unpack('<Q', sh[0x20:0x28])[0]
        name = section_names[sh_name_idx:].split(b'\x00')[0].decode('utf-8', errors='replace')
        if sh_offset <= func_addr < sh_offset + sh_size:
            print(f'  {func_name} at 0x{func_addr:x} in section {name}')
            break

# Also show the .got and .plt sections as they might contain function pointers
for i in range(e_shnum):
    sh = data[e_shoff + i*e_shentsize : e_shoff + (i+1)*e_shentsize]
    sh_name_idx = struct.unpack('<I', sh[0:4])[0]
    sh_offset = struct.unpack('<Q', sh[0x18:0x20])[0]
    name = section_names[sh_name_idx:].split(b'\x00')[0].decode('utf-8', errors='replace')
    if 'got' in name or 'plt' in name or 'data' in name or 'bss' in name:
        sh_size = struct.unpack('<Q', sh[0x20:0x28])[0]
        sh_addr = struct.unpack('<Q', sh[0x10:0x18])[0]
        print(f'  Section {name}: file=0x{sh_offset:x}, vaddr=0x{sh_addr:x}, size=0x{sh_size:x}')
