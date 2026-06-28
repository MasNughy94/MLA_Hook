import struct, sys

with open(r'C:\Users\NGEONG\Videos\MLA\libagame.so', 'rb') as f:
    elf = f.read()

e_shoff = struct.unpack_from('<Q', elf, 0x28)[0]
e_shentsize = struct.unpack_from('<H', elf, 0x3a)[0]
e_shnum = struct.unpack_from('<H', elf, 0x3c)[0]

# Find dynsym and dynstr by looking for SHT_DYNSYM (type 11) and SHT_STRTAB (type 3)
dynsym_off = dynsym_sz = dynstr_off = 0
for i in range(e_shnum):
    s = e_shoff + i * e_shentsize
    sh_type = struct.unpack_from('<I', elf, s + 4)[0]
    sh_addr = struct.unpack_from('<Q', elf, s + 0x10)[0]
    sh_offset = struct.unpack_from('<Q', elf, s + 0x18)[0]
    sh_size = struct.unpack_from('<Q', elf, s + 0x20)[0]
    if sh_type == 11:  # SHT_DYNSYM
        dynsym_off, dynsym_sz = sh_offset, sh_size
    elif sh_type == 3 and sh_addr == 0:  # SHT_STRTAB (not the section header table)
        # there are multiple strtabs; find the one used by dynsym
        pass

# Actually, let me find .dynstr differently: look at sh_link of .dynsym
# The sh_info field of the section header contains the link
for i in range(e_shnum):
    s = e_shoff + i * e_shentsize
    sh_type = struct.unpack_from('<I', elf, s + 4)[0]
    if sh_type == 11:  # SHT_DYNSYM
        sh_link = struct.unpack_from('<I', elf, s + 0x28)[0]  # sh_link
        # The strtab section for this dynsym is at index sh_link
        strtab_hdr = e_shoff + sh_link * e_shentsize
        dynstr_off = struct.unpack_from('<Q', elf, strtab_hdr + 0x18)[0]
        dynstr_sz = struct.unpack_from('<Q', elf, strtab_hdr + 0x20)[0]
        dynsym_off = sh_offset
        dynsym_sz = sh_size
        break

print(f"dynsym: off=0x{dynsym_off:x} sz=0x{dynsym_sz:x}", file=sys.stderr)
print(f"dynstr: off=0x{dynstr_off:x} sz=0x{dynstr_sz:x}", file=sys.stderr)

targets = ['decryptData', 'getKey', 'aes_decrypt', 'aes_encrypt', 'uncompressData', 
           'inflate', 'decrypt', 'Data', 'setupKey', 'setKey', 'fromHex', 'AES',
           'EVP', 'aes']

total = dynsym_sz // 24
found = []
for i in range(total):
    so = dynsym_off + i * 24
    st_name = struct.unpack_from('<I', elf, so)[0]
    st_val = struct.unpack_from('<Q', elf, so + 8)[0]
    st_sz = struct.unpack_from('<Q', elf, so + 0x10)[0]
    st_info = struct.unpack_from('<B', elf, so + 4)[0]
    if st_val == 0 or st_sz == 0:
        continue
    # Read name only if in .text range
    if st_val < 0x3fc000 or st_val >= 0xdf61ec:
        continue
    name = elf[dynstr_off + st_name:].split(b'\x00')[0].decode(errors='replace')
    st_type = st_info & 0xf
    if st_type != 2:  # not FUNC
        continue
    for t in targets:
        if t.lower() in name.lower():
            found.append((st_val, st_sz, name))
            break

print(f"Found {len(found)} matching functions\n")
for va, sz, name in sorted(found):
    print(f"  0x{va:08x}: sz=0x{sz:04x} {name}")
