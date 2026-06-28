import mmap, struct, io
from elftools.elf.elffile import ELFFile

f = open('C:/Users/NGEONG/Videos/MLA/libagame.so', 'rb')
data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

# Find RELA
for sec in ELFFile(f).iter_sections():
    if sec.name == '.rela.dyn':
        rela_offset = sec.header.sh_offset
        rela_size = sec.header.sh_size
        rela_data = data[rela_offset:rela_offset+rela_size]
        print(f'.rela.dyn: offset=0x{rela_offset:x} size=0x{rela_size:x}')
        break

targets = {
    0x7d2f38: 'FileUtilsAndroid::getDataFromFile',
    0x7d2e38: 'FileUtilsAndroid::getStringFromFile',
    0x7d2888: 'FileUtilsAndroid::getData',
    0x7d278c: 'FileUtilsAndroid::setassetmanager',
}

print('\nSearching RELA for FileUtilsAndroid function pointers...')
for addr, name in targets.items():
    addr_bytes = struct.pack('<Q', addr)
    found_any = False
    for pos in range(24, len(rela_data) - 8, 24):
        addend = rela_data[pos+16:pos+24]
        if addend == addr_bytes:
            r_offset = struct.unpack('<Q', rela_data[pos:pos+8])[0]
            print(f'  {name} @ 0x{addr:x}: r_offset=0x{r_offset:x}')
            found_any = True
    if not found_any:
        print(f'  {name}: NOT found')

print('\nSearching data sections for vtable arrays...')
elf = ELFFile(f)
for sec in elf.iter_sections():
    if sec.name in ['.data', '.rodata']:
        start = sec.header.sh_offset
        sz = sec.header.sh_size
        sec_data = data[start:start+sz]
        for t in [0x7d2f38, 0x7d2888, 0x7d2e38]:
            tb = struct.pack('<Q', t)
            pos = 0
            while True:
                found = sec_data.find(tb, pos)
                if found == -1:
                    break
                va = sec.header.sh_addr + found
                next_vals = []
                for i in range(1, 4):
                    off = found + i*8
                    if off + 8 <= len(sec_data):
                        val = struct.unpack('<Q', sec_data[off:off+8])[0]
                        next_vals.append(f'0x{val:x}')
                nstr = ', '.join(next_vals)
                print(f'  0x{t:x} -> {sec.name}[0x{va:x}]  next: {nstr}')
                pos = found + 1

print('\nData at RELA r_offset locations...')
for roff in [0x1174000, 0x11d2050, 0x11d2130, 0x11d2140]:
    for sec in elf.iter_sections():
        s_va = sec.header.sh_addr
        s_end = s_va + sec.header.sh_size
        if s_va <= roff < s_end:
            foff = sec.header.sh_offset + (roff - s_va)
            vals = []
            for i in range(5):
                val = struct.unpack('<Q', data[foff+i*8:foff+i*8+8])[0]
                vals.append(f'0x{val:x}')
            vstr = ', '.join(vals)
            print(f'  r_offset 0x{roff:x} [{sec.name}]: {vstr}')
            break

# Now also look at what references these VTABLE addresses
# Search for ADRP instructions referencing pages near these vtable addresses
print('\nSearching for ADRP references to vtable pages...')
text_va = 0x3fc000
text_offset = text_va

# VTable pages: 0x11d2000, 0x1174000
vtable_pages = [0x11d2000, 0x1174000]
text_data = data[text_offset:text_offset + 0x9fa1ec]

for vpage in vtable_pages:
    count = 0
    for i in range(0, len(text_data) - 4, 4):
        inst = int.from_bytes(text_data[i:i+4], 'little')
        # ADRP encoding
        if (inst & 0x9F000000) == 0x90000000:
            rd = inst & 0x1F
            immhi = (inst >> 5) & 0x7FFFF
            immlo = (inst >> 29) & 0x3
            imm = (immhi << 14) | (immlo << 12)
            if imm & 0x100000000:
                imm |= -0x200000000
            target_page = (text_va + i) & ~0xFFF
            target_page += imm
            if target_page == vpage:
                if count < 10:
                    print(f'  ADRP x{rd}, 0x{vpage:x} at 0x{text_va+i:x}')
                count += 1
    print(f'  Total ADRP references to 0x{vpage:x}: {count}')

f.close()
