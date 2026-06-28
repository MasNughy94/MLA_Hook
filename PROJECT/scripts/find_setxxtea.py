import struct, re

so_path = r'C:\Users\NGEONG\Videos\MLA\libagame.so'
with open(so_path, 'rb') as f:
    data = f.read()

dynstr_start = 0x10b760
dynsym_start = 0x41bf0
dynsym_entries = 34426

# Names we care about
targets = {
    0xc810: '_Z6getkeyPKcPc',
    0x12d42: '_ZN7cocos2d8LuaStack22cleanupXXTEAKeyAndSignEv',
    0x12e25: '_ZN7cocos2d8LuaStack18setXXTEAKeyAndSignEPKciS2_i',
    0x134d4: 'xxtea',
}

# Find their dynsym entries
print('=== Finding target function addresses ===')
for name_off, demangled in targets.items():
    for k in range(dynsym_entries):
        entry = data[dynsym_start + k*24 : dynsym_start + (k+1)*24]
        st_name = struct.unpack('<I', entry[0:4])[0]
        if st_name == name_off:
            st_value = struct.unpack('<Q', entry[8:16])[0]
            st_size = struct.unpack('<Q', entry[16:24])[0]
            st_info = entry[4]
            st_shndx = struct.unpack('<H', entry[6:8])[0]
            type_ = st_info & 0xF
            bind = st_info >> 4
            print(f'  {demangled}:')
            print(f'    addr=0x{st_value:x}, size=0x{st_size:x}, type={type_}, bind={bind}')
            break
    else:
        print(f'  {demangled}: NOT FOUND in .dynsym')

# Now find all callers of setXXTEAKeyAndSign
print()
target_addr = None
for k in range(dynsym_entries):
    entry = data[dynsym_start + k*24 : dynsym_start + (k+1)*24]
    st_name = struct.unpack('<I', entry[0:4])[0]
    if st_name == 0x12e25:  # setXXTEAKeyAndSign
        target_addr = struct.unpack('<Q', entry[8:16])[0]
        break

if target_addr:
    print(f'setXXTEAKeyAndSign at 0x{target_addr:x}')
    # Find BL callers
    callers = []
    for off in range(0, len(data) - 4, 4):
        word = struct.unpack('<I', data[off:off+4])[0]
        if (word >> 26) == 0x25:  # BL
            imm26 = word & 0x3FFFFFF
            if imm26 & 0x2000000:
                imm26 |= 0xFC000000
            bl_target = off + imm26 * 4
            if bl_target == target_addr:
                callers.append(off)
    
    print(f'  Callers: {len(callers)}')
    for c in callers[:5]:
        print(f'    0x{c:x}')
        # Show instructions before call
        from capstone import *
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        start = max(0, c - 0x40)
        func_bytes = data[start:c+4]
        count = 0
        for insn in md.disasm(func_bytes, start):
            if insn.address >= c - 0x30:
                arrow = '>>>' if insn.address == c else '   '
                print(f'      {arrow} 0x{insn.address:x}: {insn.mnemonic:10s} {insn.op_str}')
            count += 1
            if insn.address >= c:
                break
