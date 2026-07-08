import struct, os, re

BINARY = r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so'
with open(BINARY, 'rb') as f:
    data = f.read()
endian = '<'
e_phoff = struct.unpack_from(endian + 'Q', data, 0x20)[0]
e_phentsize = struct.unpack_from(endian + 'H', data, 0x36)[0]
e_phnum = struct.unpack_from(endian + 'H', data, 0x38)[0]

def virt_to_offset(va):
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        if p_type != 1: continue
        p_offset = struct.unpack_from('<Q', data, off + 8)[0]
        p_vaddr = struct.unpack_from('<Q', data, off + 0x10)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 0x20)[0]
        if p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr)
    return None

# Read the pointer stored at 0x11E4670 (via RELA addend = 0x124EB50)
target_va = 0x124EB50
off = virt_to_offset(target_va)
print(f'File offset for 0x{target_va:x}: {off}')
if off is not None:
    raw = data[off:off+64]
    null_idx = raw.find(b'\x00')
    if null_idx >= 0:
        s = raw[:null_idx]
    else:
        s = raw.rstrip(b'\x00')
    print(f'Raw bytes ({len(s)}): {s.hex()}')
    print(f'ASCII: {s.decode("ascii", errors="replace")}')
else:
    # Check segments
    for i in range(e_phnum):
        off_ph = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off_ph)[0]
        p_vaddr = struct.unpack_from('<Q', data, off_ph + 0x10)[0]
        p_memsz = struct.unpack_from('<Q', data, off_ph + 0x28)[0]
        p_filesz = struct.unpack_from('<Q', data, off_ph + 0x20)[0]
        if p_vaddr <= target_va < p_vaddr + p_memsz:
            print(f'In segment {i}: vaddr=0x{p_vaddr:x} memsz=0x{p_memsz:x} filesz=0x{p_filesz:x}')
            if p_filesz > 0:
                p_offset = struct.unpack_from('<Q', data, off_ph + 8)[0]
                file_off = p_offset + (target_va - p_vaddr)
                if file_off < len(data):
                    s = data[file_off:file_off+64]
                    idx = s.find(b'\x00')
                    if idx >= 0: s = s[:idx]
                    print(f'File data: {s.hex()} = {s.decode("ascii", errors="replace")}')
            break

# Also check if there's a .bss section that contains this address
e_shoff = struct.unpack_from(endian + 'Q', data, 0x28)[0]
e_shentsize = struct.unpack_from(endian + 'H', data, 0x3A)[0]
e_shnum = struct.unpack_from(endian + 'H', data, 0x3C)[0]
print(f'\nSections containing 0x{target_va:x}:')
for i in range(e_shnum):
    off_hdr = e_shoff + i * e_shentsize
    sh_addr = struct.unpack_from('<Q', data, off_hdr + 0x10)[0]
    sh_size = struct.unpack_from('<Q', data, off_hdr + 0x20)[0]
    if sh_addr <= target_va < sh_addr + sh_size:
        print(f'  Section[{i}]: addr=0x{sh_addr:x} size=0x{sh_size:x}')
