import struct

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    elf = f.read()

DYNSYM_OFF = 0x41bf0
DYNSYM_SZ = 0xc9b70
DYNSTR = elf[0x10b760:0x10b760+0x1706c4]

total = DYNSYM_SZ // 24
out = []

for i in range(total):
    so = DYNSYM_OFF + i * 24
    st_name_off = struct.unpack_from('<I', elf, so)[0]
    st_val = struct.unpack_from('<Q', elf, so + 8)[0]
    st_sz = struct.unpack_from('<Q', elf, so + 0x10)[0]
    
    if st_val == 0 or st_sz == 0:
        continue
    if not (0x3fc000 <= st_val < 0xdf61ec):
        continue
    if (struct.unpack_from('<B', elf, so + 4)[0] & 0xf) != 2:
        continue
    
    # Read name
    end = DYNSTR.find(b'\x00', st_name_off)
    name = DYNSTR[st_name_off:end].decode(errors='replace')
    
    nl = name.lower()
    if ('decrypt' in nl) or ('getkey' in nl) or ('setkey' in nl) or ('fromhex' in nl) \
       or ('aes_' in nl) or ('uncompress' in nl) or ('inflate' in nl) \
       or ('setupkey' in nl) or ('4data' in nl) \
       or ('encrypt' in nl):
        out.append((st_val, st_sz, name))

out.sort()
print(f"Found {len(out)} functions:\n")
for va, sz, name in out:
    print(f"  0x{va:08x}: sz=0x{sz:04x} {name}")
