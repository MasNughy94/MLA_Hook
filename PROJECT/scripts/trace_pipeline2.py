"""
Trace 0xC828A0 - first function called in the Antm pipeline.
Also quickly check imports.
"""

import struct

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    agame = f.read()

hades_path = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\lib\arm64-v8a\libhades.so'
with open(hades_path, 'rb') as f:
    hades = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def disasm(addr, count=30):
    """Simple disassembly returning raw bytes."""
    start = addr - TEXT_ADDR + TEXT_OFF
    result = []
    for i in range(count):
        off = start + i * 4
        if off >= TEXT_OFF + TEXT_SIZE:
            break
        result.append(struct.unpack_from('<I', agame, off)[0])
    return result

def find_func_start(addr):
    """Find function start by STP prologue."""
    file_off = addr - TEXT_ADDR + TEXT_OFF
    for lookback in range(0, 500):
        check_off = file_off - lookback * 4
        check_addr = addr - lookback * 4
        if check_off < TEXT_OFF:
            break
        instr = struct.unpack_from('<I', agame, check_off)[0]
        
        # STP X29, X30, [SP, #imm]!
        if (instr & 0xFF000000) == 0xA8000000:
            rt = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            rt2 = (instr >> 10) & 0x1F
            if rt == 29 and rt2 == 30 and rn == 31:
                return check_addr
        # STP X29, X30, [SP, #imm]  (offset)
        if (instr & 0xFF000000) == 0xA9000000:
            rt = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            rt2 = (instr >> 10) & 0x1F
            if rt == 29 and rt2 == 30 and rn == 31:
                return check_addr
    return None

# 1. Trace function 0xC828A0
print('=== Function 0xC828A0 ===')
fs = find_func_start(0xC828A0)
print('Start: 0x{:x}'.format(fs))
for i, instr in enumerate(disasm(fs, 20)):
    addr = fs + i * 4
    # Decode BL
    if (instr >> 26) == 0x25:
        imm26 = instr & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 |= 0xFC000000
        target = addr + (imm26 << 2)
        print('  0x{:x}: BL 0x{:x}'.format(addr, target))
    elif instr == 0xD65F03C0:
        print('  0x{:x}: RET'.format(addr))
        break
    else:
        print('  0x{:x}: {:08x}'.format(addr, instr))

# 2. Check libhades imports quickly
def find_section(data, name):
    import struct
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
    shstrtab_off = e_shoff + e_shstrndx * e_shentsize
    shstrtab_sh_offset = struct.unpack_from('<Q', data, shstrtab_off + 0x18)[0]
    
    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack_from('<I', data, sh_off)[0]
        sh_addr = struct.unpack_from('<Q', data, sh_off + 0x10)[0]
        sh_offset = struct.unpack_from('<Q', data, sh_off + 0x18)[0]
        sh_size = struct.unpack_from('<Q', data, sh_off + 0x20)[0]
        n = data[shstrtab_sh_offset + sh_name_idx:].split(b'\x00')[0].decode('ascii', errors='replace')
        if n == name:
            return sh_addr, sh_offset, sh_size
    return None, None, None

dynsym_a, off_a, sz_a = find_section(agame, '.dynsym')
dynstr_a, off_str_a, sz_str_a = find_section(agame, '.dynstr')

# List key exports
print('\n=== Key libagame exports ===')
has_dynsym = dynsym_a is not None
if has_dynsym:
    num = sz_a // 24
    for i in range(num):
        sym_off = off_a + i * 24
        st_name = struct.unpack_from('<I', agame, sym_off)[0]
        st_info = agame[sym_off + 4]
        st_value = struct.unpack_from('<Q', agame, sym_off + 8)[0]
        bind = st_info >> 4
        type = st_info & 0xF
        if bind == 1 and type == 2 and st_value != 0:
            name = agame[off_str_a + st_name:].split(b'\x00')[0].decode('ascii', errors='replace')
            if 'Java' in name or 'nativ' in name.lower():
                print('  0x{:x}: {}'.format(st_value, name))

# Just list a few exports
print('\nAll libagame exports (first 30):')
count = 0
for i in range(num):
    sym_off = off_a + i * 24
    st_name = struct.unpack_from('<I', agame, sym_off)[0]
    st_info = agame[sym_off + 4]
    st_value = struct.unpack_from('<Q', agame, sym_off + 8)[0]
    bind = st_info >> 4
    type = st_info & 0xF
    if bind == 1 and (type == 2 or type == 0) and st_value != 0:
        name = agame[off_str_a + st_name:].split(b'\x00')[0].decode('ascii', errors='replace')
        count += 1
        if count <= 30:
            print('  0x{:x}: {} (type={}, size={})'.format(st_value, name, type, 
                  struct.unpack_from('<Q', agame, sym_off + 16)[0]))
