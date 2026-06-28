import struct

with open(r'C:\Users\NGEONG\Videos\MLA\libagame.so', 'rb') as f:
    elf = f.read()

e_shoff = struct.unpack_from('<Q', elf, 0x28)[0]
e_shentsize = struct.unpack_from('<H', elf, 0x3a)[0]
e_shnum = struct.unpack_from('<H', elf, 0x3c)[0]
e_shstrndx = struct.unpack_from('<H', elf, 0x3e)[0]
shstrtab_hdr = e_shoff + e_shstrndx * e_shentsize
shstrtab_off = struct.unpack_from('<Q', elf, shstrtab_hdr + 0x18)[0]
shstrtab_size = struct.unpack_from('<Q', elf, shstrtab_hdr + 0x20)[0]
shstrtab = elf[shstrtab_off:shstrtab_off+shstrtab_size]

def section_name(idx):
    no = struct.unpack_from('<I', elf, e_shoff + idx * e_shentsize)[0]
    end = shstrtab.find(b'\x00', no)
    return shstrtab[no:end].decode()

sections = {}
for i in range(e_shnum):
    name = section_name(i)
    s = e_shoff + i * e_shentsize
    sections[name] = {
        'addr': struct.unpack_from('<Q', elf, s + 0x10)[0],
        'offset': struct.unpack_from('<Q', elf, s + 0x18)[0],
        'size': struct.unpack_from('<Q', elf, s + 0x20)[0],
    }

text = sections.get('.text', {})
TEXT_ADDR = text['addr']
TEXT_OFF = text['offset']
TEXT_SIZE = text['size']

rodata = sections.get('.rodata', {})
RODATA_ADDR = rodata['addr']
RODATA_OFF = rodata['offset']
RODATA_SIZE = rodata['size']

got = sections.get('.got', {})
GOT_ADDR = got.get('addr', 0)
GOT_OFF = got.get('offset', 0)

def read_rodata(va, size):
    offset = va - RODATA_ADDR
    if 0 <= offset < RODATA_SIZE:
        return elf[RODATA_OFF + offset : RODATA_OFF + offset + size]
    return None

def disassemble(func_va, max_size=0x200):
    offset = func_va - TEXT_ADDR
    if offset < 0 or offset + max_size > TEXT_SIZE:
        max_size = TEXT_SIZE - offset
    data = elf[TEXT_OFF + offset : TEXT_OFF + offset + max_size]
    insns = []
    for i in range(0, len(data), 4):
        if i + 4 > len(data):
            break
        word = struct.unpack_from('<I', data, i)[0]
        insns.append((func_va + i, word))
    return insns

print(f"GOT: 0x{GOT_ADDR:x} (size 0x{got.get('size',0):x})")
print(f"RODATA: 0x{RODATA_ADDR:x} (size 0x{RODATA_SIZE:x})")

insns = disassemble(0xcebd20, 0x200)
print("\n" + "="*80)
print("FULL DISASSEMBLY OF _getKeyv (0xcebd20)")
print("="*80)
for va, word in insns:
    print(f"  0x{va:x}: 0x{word:08x}")
