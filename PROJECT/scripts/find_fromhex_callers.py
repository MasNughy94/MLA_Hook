import struct

with open(r'C:\Users\NGEONG\Videos\MLA\libagame.so', 'rb') as f:
    elf = f.read()

# Parse sections
e_shoff = struct.unpack_from('<Q', elf, 0x28)[0]
e_shentsize = struct.unpack_from('<H', elf, 0x3a)[0]
e_shnum = struct.unpack_from('<H', elf, 0x3c)[0]
e_shstrndx = struct.unpack_from('<H', elf, 0x3e)[0]
shstrtab_hdr = e_shoff + e_shstrndx * e_shentsize
shstrtab_off = struct.unpack_from('<Q', elf, shstrtab_hdr + 0x18)[0]

def section_name(idx):
    s = e_shoff + idx * e_shentsize
    no = struct.unpack_from('<I', elf, s)[0]
    end = elf.find(b'\x00', shstrtab_off + no, shstrtab_off + no + 128)
    return elf[shstrtab_off+no:end].decode()

sections = {}
for i in range(e_shnum):
    name = section_name(i)
    s = e_shoff + i * e_shentsize
    sections[name] = {
        'addr': struct.unpack_from('<Q', elf, s + 0x10)[0],
        'offset': struct.unpack_from('<Q', elf, s + 0x18)[0],
        'size': struct.unpack_from('<Q', elf, s + 0x20)[0],
    }

text_s = sections.get('.text', {})
TEXT_START = text_s['addr']
TEXT_SIZE = text_s['size']
TEXT_OFF = text_s['offset']

# Symbols
dynsym_s = sections.get('.dynsym', {})
dynstr_s = sections.get('.dynstr', {})
sym_map = {}
total = dynsym_s['size'] // 24
for i in range(total):
    so = dynsym_s['offset'] + i * 24
    st_value = struct.unpack_from('<Q', elf, so + 8)[0]
    st_size = struct.unpack_from('<Q', elf, so + 0x10)[0]
    st_info = struct.unpack_from('<B', elf, so + 4)[0]
    if (st_info & 0xf) == 2:
        name = elf[dynstr_s['offset'] + struct.unpack_from('<I', elf, so)[0]:].split(b'\x00')[0].decode(errors='replace')
        sym_map[st_value] = (name, st_size)

def sym_name(addr):
    best = None
    for sa, (n, sz) in sym_map.items():
        if sa <= addr < sa + max(sz, 1):
            offset = addr - sa
            return f"{n}+{offset}" if offset else n
    return f"sub_{addr:x}"

# Find callers of fromHex (0xcec900)
callers_fh = []
for addr in range(TEXT_START, TEXT_START + TEXT_SIZE, 4):
    if addr + 4 > TEXT_START + TEXT_SIZE:
        break
    word = struct.unpack_from('<I', elf, TEXT_OFF + (addr - TEXT_START))[0]
    if (word >> 26) == 0x25:
        imm = word & 0x3ffffff
        if imm & 0x2000000: imm |= ~0x3ffffff
        target = addr + (imm << 2)
        if target == 0xcec900:
            callers_fh.append(addr)

# Find callers of sub_9aeb8c (0x9aeb8c)
callers_9aeb8c = []
for addr in range(TEXT_START, TEXT_START + TEXT_SIZE, 4):
    if addr + 4 > TEXT_START + TEXT_SIZE:
        break
    word = struct.unpack_from('<I', elf, TEXT_OFF + (addr - TEXT_START))[0]
    if (word >> 26) == 0x25:
        imm = word & 0x3ffffff
        if imm & 0x2000000: imm |= ~0x3ffffff
        target = addr + (imm << 2)
        if target == 0x9aeb8c:
            callers_9aeb8c.append(addr)

print(f"fromHex (0xcec900) callers: {len(callers_fh)}")
for ca in callers_fh:
    print(f"  0x{ca:x} ({sym_name(ca)})")

print(f"\nsub_9aeb8c (0x9aeb8c) callers: {len(callers_9aeb8c)}")
for ca in callers_9aeb8c:
    print(f"  0x{ca:x} ({sym_name(ca)})")

both = set(callers_fh) & set(callers_9aeb8c)
print(f"\nFunctions calling BOTH fromHex AND sub_9aeb8c: {len(both)}")
for ca in both:
    print(f"  0x{ca:x} ({sym_name(ca)})")
