"""
Check raw .mt files to verify magic strings and look for patterns
across all native libraries.
"""

import struct, os

# 1. Check a few raw .mt files for magic strings
mt_dir = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\decoded_apk\assets\f'
mt_files = os.listdir(mt_dir)[:5]

print('=== Raw .mt file headers (first 64 bytes) ===')
for fname in mt_files:
    path = os.path.join(mt_dir, fname)
    with open(path, 'rb') as f:
        header = f.read(64)
    # Show hex and ASCII
    hex_str = ' '.join('{:02x}'.format(b) for b in header[:32])
    ascii_str = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in header[:32])
    print('{} ({} bytes):'.format(fname[:16], os.path.getsize(path)))
    print('  {}'.format(hex_str))
    print('  {}'.format(ascii_str))

# 2. Check ALL raw .mt files - how many start with "Antm"?
print('\n=== Magic distribution across all .mt files ===')
magic_counts = {}
for root, dirs, files in os.walk(r'C:\Users\NGEONG\AppData\Local\Temp\opencode\decoded_apk\assets'):
    for f in files:
        if f.endswith('.mt'):
            path = os.path.join(root, f)
            with open(path, 'rb') as fp:
                magic = fp.read(8)
            key = magic[:4]
            magic_counts[key] = magic_counts.get(key, 0) + 1

for magic, count in sorted(magic_counts.items(), key=lambda x: -x[1]):
    print('  {} ({}): {} files'.format(magic.hex(), repr(magic), count))

# 3. Search ALL native libraries for "Antm" and "lmF@" 
print('\n=== Searching ALL native libraries for magic strings ===')
lib_dir = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\decoded_apk\lib\arm64-v8a'
for fname in os.listdir(lib_dir):
    if fname.endswith('.so'):
        path = os.path.join(lib_dir, fname)
        with open(path, 'rb') as f:
            data = f.read()
        
        antm = data.find(b'Antm')
        lmf = data.find(b'lmF@')
        lmf3 = data.find(b'lmF')
        magic = data.find(b'\x1bLm')
        hades = data.find(b'hades')
        
        results = []
        if antm != -1: results.append('Antm@0x{:x}'.format(antm))
        if lmf != -1: results.append('lmF@@0x{:x}'.format(lmf))
        if lmf3 != -1: results.append('lmF@0x{:x}'.format(lmf3))
        if magic != -1: results.append('magic@0x{:x}'.format(magic))
        if hades != -1: results.append('hades@0x{:x}'.format(hades))
        
        if results:
            print('  {}: {}'.format(fname, ', '.join(results)))
        else:
            print('  {}: no matches'.format(fname))

# 4. Also search for the magic integers in .text section
print('\n=== Searching for 32-bit encoding of "Antm" (0x6D746E41, 0x416E746D) in .text ===')
# Load libagame.so
lib_path = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\decoded_apk\lib\arm64-v8a\libagame.so'
with open(lib_path, 'rb') as f:
    lib_data = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

# Search for MOVZ with antm values
# "Antm" as LE integer: b'A'=0x41, b'n'=0x6E, b't'=0x74, b'm'=0x6D => 0x6D746E41
# "Antm" as BE: 0x416E746D
antm_le = 0x6D746E41
antm_be = 0x416E746D
lmf_be = 0x6C6D4640
lmf_le = 0x40466D6C

# Check for instruction patterns
# MOVZ Wd, #imm16: 0x52800000 | (imm16 << 5) | Rd
# MOVK Wd, #imm16: 0x72800000 | (hw << 29) | (imm16 << 5) | Rd

# For a 2-instruction sequence loading 0x6D746E41:
# MOVZ Wd, #0x6E41 => 0x52800000 | (0x6E41 << 5) | Rd  = 0x528DC820 (Rd=0)
# MOVK Wd, #0x6D74, LSL #16 => ... depends on Rd

# Just look for 0x6E41 as imm16 in MOVZ (searching 8 bytes at a time for pairs)
print('  Searching for MOVZ Wd, #0x6E41...')
for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 8, 4):
    instr = struct.unpack_from('<I', lib_data, file_off)[0]
    # MOVZ: sf=0, opc=10, hw=00 => 0x52800000 | (imm16 << 5) | Rd
    if (instr & 0xFF000000) == 0x52000000:  # Could be MOVZ
        # Check for MOVZ specifically: bit[30]=0 for MOVZ (opc=10 means bit30=1, bit29=0)
        # Actually: bits[31]=0, bits[30:29]=10 for MOVZ 32-bit
        if (instr >> 29) & 3 == 2:  # bits[30:29] = 10
            hw = (instr >> 21) & 3
            imm16 = (instr >> 5) & 0xFFFF
            if hw == 0 and imm16 == 0x6E41:
                # Check next instruction for MOVK
                next_instr = struct.unpack_from('<I', lib_data, file_off + 4)[0]
                if (next_instr >> 29) & 3 == 3:  # bits[30:29] = 11 (MOVK)
                    next_hw = (next_instr >> 21) & 3
                    next_imm16 = (next_instr >> 5) & 0xFFFF
                    if next_hw == 1 and next_imm16 == 0x6D74:
                        Rd = instr & 0x1F
                        next_Rd = next_instr & 0x1F
                        if Rd == next_Rd:
                            func_addr = TEXT_ADDR + (file_off - TEXT_OFF)
                            print('    Found at 0x{:x}: MOVZ W{}, #0x6E41; MOVK W{}, #0x6D74, LSL #16 => 0x{:08x}'.format(
                                func_addr, Rd, Rd, (0x6D74 << 16) | 0x6E41))
                            # Show context
                            for co in range(max(TEXT_OFF, file_off - 16), min(TEXT_OFF + TEXT_SIZE, file_off + 20), 4):
                                ci = struct.unpack_from('<I', lib_data, co)[0]
                                ca = TEXT_ADDR + (co - TEXT_OFF)
                                marker = ' <-- HERE' if co >= file_off and co < file_off + 8 else ''
                                print('      0x{:x}: {:08x}{}'.format(ca, ci, marker))

# Also search for "lmF@" similarly
print('  Searching for MOVZ Wd, #0x6D6C or #0x466D...')
# lmF@ = 0x6C 6D 46 40 = 0x40466D6C (LE) or 0x6C6D4640 (BE)
for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 8, 4):
    instr = struct.unpack_from('<I', lib_data, file_off)[0]
    if (instr >> 29) & 3 == 2:  # MOVZ 32-bit
        hw = (instr >> 21) & 3
        imm16 = (instr >> 5) & 0xFFFF
        if hw == 0 and (imm16 == 0x466D or imm16 == 0x6D6C):
            target = 0
            if imm16 == 0x466D:
                # MOVZ W?, #0x466D => loading lower bits of 0x6C6D4640?
                # 0x6C6D4640 has lower 16 bits = 0x4640, not 0x466D
                # For 0x40466D6C: lower 16 bits = 0x6D6C
                pass
            next_instr = struct.unpack_from('<I', lib_data, file_off + 4)[0]
            if (next_instr >> 29) & 3 == 3:  # MOVK
                next_hw = (next_instr >> 21) & 3
                next_imm16 = (next_instr >> 5) & 0xFFFF
                Rd = instr & 0x1F
                next_Rd = next_instr & 0x1F
                if Rd == next_Rd and next_hw == 1:
                    full_val = (next_imm16 << 16) | imm16
                    func_addr = TEXT_ADDR + (file_off - TEXT_OFF)
                    print('    Found at 0x{:x}: MOVZ W{}, #0x{:04x}; MOVK W{}, #0x{:04x}, LSL #16 => 0x{:08x}'.format(
                        func_addr, Rd, imm16, Rd, next_imm16, full_val))
