import struct

so_path = r'C:\Users\NGEONG\Videos\MLA\libagame.so'
with open(so_path, 'rb') as f:
    data = f.read()

# Find xxtea_decrypt string position
dynstr_start = 0x10b760
name_off = 0x11ec34 - dynstr_start  # = 0x134D4

print(f'xxtea_decrypt string at dynstr offset {name_off} (0x{name_off:x})')

# .rela.dyn section at 0x28cb78, size 0x169830
# Each rela entry: r_offset(8), r_info(8), r_addend(8) = 24 bytes
# r_info = symbol_index << 32 | r_type

rela_dyn_start = 0x28cb78
rela_dyn_size = 0x169830
rela_plt_start = 0x3f63a8
rela_plt_size = 0x3048

print('\n=== Searching .rela.dyn for references to xxtea_decrypt ===')
# Search for addend or symbol that references this name
# R_AARCH64_GLOB_DAT uses the symbol index
# R_AARCH64_ABS64 uses the symbol index + addend

for section_start, section_name, section_size in [
    (rela_dyn_start, '.rela.dyn', rela_dyn_size),
    (rela_plt_start, '.rela.plt', rela_plt_size),
]:
    count = 0
    for j in range(0, section_size, 24):
        r_offset = struct.unpack('<Q', data[section_start+j:section_start+j+8])[0]
        r_info = struct.unpack('<Q', data[section_start+j+8:section_start+j+16])[0]
        r_addend = struct.unpack('<q', data[section_start+j+16:section_start+j+24])[0]
        
        sym_idx = r_info >> 32
        r_type = r_info & 0xFFFFFFFF
        
        # Check if addend matches the name offset
        if r_addend == name_off or r_addend == name_off + dynstr_start:
            count += 1
            if count <= 5:
                print(f'  {section_name}[{j//24}]: r_offset=0x{r_offset:x}, sym={sym_idx}, addend=0x{r_addend:x}')
    
    print(f'  {count} total matches in {section_name}')

# Also try to find the symbol entry
print('\n=== Checking .dynsym for xxtea-related function symbols ===')
# .dynsym at 0x41bf0, size 0xc9b70, entries count = 0xc9b70 / 24 = 34426
dynsym_start = 0x41bf0

# Check a few specific name offsets related to decryption
interesting_offs = []
# Search for common key strings in dynstr
dynstr_data = data[dynstr_start:dynstr_start+0x1706c4]
import re
for match in re.finditer(b'[a-zA-Z_][a-zA-Z0-9_]*key[a-zA-Z0-9_]*|[a-zA-Z_][a-zA-Z0-9_]*Key[a-zA-Z0-9_]*|xxtea|XXTEA', dynstr_data):
    off = match.start()
    name = match.group().decode('utf-8', errors='replace')
    if name not in ['op_key'] and len(name) > 2:
        interesting_offs.append((off, name))

print(f'Found {len(interesting_offs)} interesting name offsets in .dynstr')
for off, name in interesting_offs[:20]:
    # Check if .dynsym references this offset
    print(f'  dynstr+0x{off:x}: {name}')
    # Quick check first few dynsym entries
    for k in range(min(100, 34426)):
        entry = data[dynsym_start + k*24 : dynsym_start + (k+1)*24]
        st_name = struct.unpack('<I', entry[0:4])[0]
        if st_name == off:
            st_value = struct.unpack('<Q', entry[8:16])[0]
            st_size = struct.unpack('<Q', entry[16:24])[0]
            print(f'    -> SYM[{k}]: value=0x{st_value:x}, size=0x{st_size:x}')
