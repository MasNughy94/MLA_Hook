import struct

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

sections = {}
for i in range(e_shnum):
    s = e_shoff + i * e_shentsize
    no = struct.unpack_from('<I', elf, s)[0]
    end = shstrtab.find(b'\x00', no)
    name = shstrtab[no:end].decode()
    a = struct.unpack_from('<Q', elf, s + 0x10)[0]
    o = struct.unpack_from('<Q', elf, s + 0x18)[0]
    z = struct.unpack_from('<Q', elf, s + 0x20)[0]
    sections[name] = {'addr': a, 'offset': o, 'size': z}

dynsym = sections.get('.dynsym', {})
dynstr = sections.get('.dynstr', {})

targets = ['decryptData', 'getKey', 'aes_decrypt', 'aes_encrypt', 'uncompress', 'inflate', 
           'CCCrypto', 'decrypt', 'Data', 'setupKey', 'setKey', 'fromHex', 'AES', 
           'EVP_Decrypt', 'EVP_CIPHER', 'AES_set_decrypt', 'AES_decrypt']
found = {}

total = dynsym['size'] // 24
for i in range(total):
    so = dynsym['offset'] + i * 24
    st_name = struct.unpack_from('<I', elf, so)[0]
    st_val = struct.unpack_from('<Q', elf, so + 8)[0]
    st_sz = struct.unpack_from('<Q', elf, so + 0x10)[0]
    st_info = struct.unpack_from('<B', elf, so + 4)[0]
    st_bind = st_info >> 4
    st_type = st_info & 0xf
    name = elf[dynstr['offset'] + st_name:].split(b'\x00')[0].decode(errors='replace')
    for t in targets:
        if t in name and st_val and st_sz:
            if t not in found or st_val > 0x3fc000:  # prefer .text entries
                key = (t, name)
                if key not in found:
                    found[key] = []
                found[key].append((st_val, st_sz, st_bind, st_type, name))

print("=== TARGET FUNCTIONS ===")
for (t, name), entries in sorted(found.items()):
    for st_val, st_sz, st_bind, st_type, fullname in entries:
        bind_str = ['LOCAL', 'GLOBAL', 'WEAK'][st_bind-1] if 1 <= st_bind <= 3 else f'BIND_{st_bind}'
        type_str = ['NOTYPE', 'OBJECT', 'FUNC', 'SECTION'][st_type] if st_type <= 3 else f'TYPE_{st_type}'
        if st_val >= 0x3fc000 and st_val < 0xdf6200:
            print(f"  {fullname:70s} va=0x{st_val:08x} sz=0x{st_sz:04x} {bind_str:6s} {type_str}")
