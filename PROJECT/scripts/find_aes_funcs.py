import struct, sys

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    elf = f.read()

# Direct offsets from section headers
DYNSYM_OFF = 0x41bf0
DYNSYM_SZ = 0xc9b70   # 826,736 bytes
DYNSTR_OFF = 0x10b760

targets = ['decryptData', 'getKey', 'aes_decrypt', 'aes_encrypt', 
           'uncompressData', 'inflate', 'setupKey', 'fromHex']

total = DYNSYM_SZ // 24
print(f"Total symbols: {total}", file=sys.stderr)

found = []
for i in range(total):
    so = DYNSYM_OFF + i * 24
    st_name_off = struct.unpack_from('<I', elf, so)[0]
    st_info = struct.unpack_from('<B', elf, so + 4)[0]
    st_other = struct.unpack_from('<B', elf, so + 5)[0]
    st_shndx = struct.unpack_from('<H', elf, so + 6)[0]
    st_val = struct.unpack_from('<Q', elf, so + 8)[0]
    st_sz = struct.unpack_from('<Q', elf, so + 0x10)[0]
    st_type = st_info & 0xf
    st_bind = st_info >> 4
    
    if st_val == 0 and st_sz == 0:
        continue
    
    # Only interested in .text functions
    if not (0x3fc000 <= st_val < 0xdf61ec):
        continue
    if st_type != 2:  # FUNC
        continue
    
    # Read the name
    name = elf[DYNSTR_OFF + st_name_off:].split(b'\x00')[0].decode(errors='replace')
    
    # Check targets
    tl = name.lower()
    for t in targets:
        if t.lower() in tl:
            found.append((st_val, st_sz, name, st_bind))
            break

print(f"Found {len(found)} matching functions:\n")
for va, sz, name, bind in sorted(found):
    bind_s = ['', 'LOCAL', 'GLOBAL', 'WEAK'][bind] if 0 <= bind <= 3 else f'BIND_{bind}'
    print(f"  0x{va:08x}: sz=0x{sz:04x} [{bind_s:6s}] {name}")

print()
# Now search specifically for any function containing "Data" as class prefix
# That would be mangled as _ZN4Data* or similar
print("=== Searching for Data::* functions ===")
data_funcs = []
for i in range(total):
    so = DYNSYM_OFF + i * 24
    st_name_off = struct.unpack_from('<I', elf, so)[0]
    st_val = struct.unpack_from('<Q', elf, so + 8)[0]
    st_sz = struct.unpack_from('<Q', elf, so + 0x10)[0]
    st_info = struct.unpack_from('<B', elf, so + 4)[0]
    st_type = st_info & 0xf
    if st_val == 0 or st_sz == 0:
        continue
    if not (0x3fc000 <= st_val < 0xdf61ec) or st_type != 2:
        continue
    name = elf[DYNSTR_OFF + st_name_off:].split(b'\x00')[0].decode(errors='replace')
    if '4Data' in name or 'decryptData' in name or ('decrypt' in name.lower() and 'Data' in name):
        data_funcs.append((st_val, st_sz, name))

for va, sz, name in sorted(data_funcs):
    print(f"  0x{va:08x}: sz=0x{sz:04x} {name}")
