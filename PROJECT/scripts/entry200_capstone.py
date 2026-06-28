import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open(r'C:\Users\NGEONG\Videos\MLA\libagame.so', 'rb') as f:
    elf = f.read()

e_shoff = struct.unpack_from('<Q', elf, 0x28)[0]
e_shentsize = struct.unpack_from('<H', elf, 0x3a)[0]
e_shnum = struct.unpack_from('<H', elf, 0x3c)[0]
e_shstrndx = struct.unpack_from('<H', elf, 0x3e)[0]

shstrtab_hdr = e_shoff + e_shstrndx * e_shentsize
shstrtab_off = struct.unpack_from('<Q', elf, shstrtab_hdr + 0x18)[0]
shstrtab_sz = struct.unpack_from('<Q', elf, shstrtab_hdr + 0x20)[0]
shstrtab = elf[shstrtab_off:shstrtab_off+shstrtab_sz]

text_addr = text_off = text_size = 0
for i in range(e_shnum):
    s = e_shoff + i * e_shentsize
    no = struct.unpack_from('<I', elf, s)[0]
    end = shstrtab.find(b'\x00', no)
    name = shstrtab[no:end].decode()
    a = struct.unpack_from('<Q', elf, s + 0x10)[0]
    o = struct.unpack_from('<Q', elf, s + 0x18)[0]
    z = struct.unpack_from('<Q', elf, s + 0x20)[0]
    if name == '.text':
        text_addr, text_off, text_size = a, o, z

print(f"text: 0x{text_addr:x} off=0x{text_off:x} sz=0x{text_size:x}")

raw = elf[text_off + (0x407130 - text_addr) : text_off + (0x407130 - text_addr) + 0xd8]
print(f"got {len(raw)} bytes")

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
print("== ENTRY 200 (0x407130) ==")
for insn in md.disasm(raw, 0x407130):
    print(f"  0x{insn.address:08x}: {insn.mnemonic:8s} {insn.op_str}")
