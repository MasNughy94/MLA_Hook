"""
Find all sections and their names.
"""

import struct

so = open(r'C:\Users\NGEONG\Videos\VSCODE\libagame.so', 'rb').read()

e_shoff = struct.unpack_from('<Q', so, 0x28)[0]
e_shentsize = struct.unpack_from('<H', so, 0x3A)[0]
e_shnum = struct.unpack_from('<H', so, 0x3C)[0]
e_shstrndx = struct.unpack_from('<H', so, 0x3E)[0]

# Read section header string table
shstrtab_off = e_shoff + e_shstrndx * e_shentsize
shstrtab_sh_offset = struct.unpack_from('<Q', so, shstrtab_off + 0x18)[0]
shstrtab_sh_size = struct.unpack_from('<Q', so, shstrtab_off + 0x20)[0]

exec_sections = []
print('All sections:')
for i in range(e_shnum):
    sh_off = e_shoff + i * e_shentsize
    sh_name_idx = struct.unpack_from('<I', so, sh_off)[0]
    sh_type = struct.unpack_from('<I', so, sh_off + 4)[0]
    sh_flags = struct.unpack_from('<Q', so, sh_off + 8)[0]
    sh_addr = struct.unpack_from('<Q', so, sh_off + 0x10)[0]
    sh_offset = struct.unpack_from('<Q', so, sh_off + 0x18)[0]
    sh_size = struct.unpack_from('<Q', so, sh_off + 0x20)[0]
    
    name = so[shstrtab_off + sh_name_idx:].split(b'\x00')[0].decode('ascii', errors='replace')
    
    flag_str = ''
    if sh_flags & 0x1: flag_str += 'WRITE '
    if sh_flags & 0x2: flag_str += 'ALLOC '
    if sh_flags & 0x4: flag_str += 'EXEC '
    
    print('  [{}] addr=0x{:08x} off=0x{:08x} size=0x{:08x} flags={} {}'.format(
        i, sh_addr, sh_offset, sh_size, flag_str, name))
    
    if sh_flags & 0x4:  # EXEC
        exec_sections.append((name, sh_addr, sh_offset, sh_size))

print('\nExecutable sections:')
for name, addr, off, sz in exec_sections:
    print('  {}: addr=0x{:x} off=0x{:x} size=0x{:x}'.format(name, addr, off, sz))
