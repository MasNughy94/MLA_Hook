import struct

DEX = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\classes.dex'
data = open(DEX, 'rb').read()
END = len(data)

sio = struct.unpack_from('<I', data, 0x3C)[0]
tio = struct.unpack_from('<I', data, 0x44)[0]
mio = struct.unpack_from('<I', data, 0x5C)[0]
mis = struct.unpack_from('<I', data, 0x58)[0]
cdo = struct.unpack_from('<I', data, 0x64)[0]
cds = struct.unpack_from('<I', data, 0x60)[0]
fio = struct.unpack_from('<I', data, 0x4C)[0]

TARGET = 0x4126a8
DBG = 0x465ecc

def uleb_safe(data, off):
    if off >= END: return -1, off
    r, s = 0, 0
    for _ in range(5):
        if off >= END: return -2, off
        b = data[off]; off += 1
        r |= (b & 0x7F) << s; s += 7
        if not (b & 0x80): return r, off
    return -3, off

# Strategy: scan DEX linearly for code_item header with debug_info_off == DBG
print("Strategy 1: Scan all possible code_item headers for debug_info_off match")
count = 0
for off in range(0, END - 16, 2):
    regs = struct.unpack_from('<H', data, off)[0]
    ins  = struct.unpack_from('<H', data, off+2)[0]
    outs = struct.unpack_from('<H', data, off+4)[0]
    tries= struct.unpack_from('<H', data, off+6)[0]
    dbg  = struct.unpack_from('<I', data, off+8)[0]
    insns= struct.unpack_from('<I', data, off+12)[0]
    if dbg != DBG: continue
    if not (0 <= regs <= 256): continue
    if not (0 <= ins <= regs): continue
    if not (0 <= outs <= regs): continue
    if not (0 < insns < 100000): continue
    if tries > 1000: continue
    if off == TARGET:
        print('  MATCH: code_item at 0x%x (THIS IS THE TARGET!)' % off)
        print('    regs=%d ins=%d outs=%d tries=%d dbg=0x%x insns=%d' % (regs, ins, outs, tries, dbg, insns))
        count += 1
    else:
        print('  code_item candidate at 0x%x (NOT target)' % off)

if count == 0:
    print('  No code_item with debug_info_off=0x%x found!' % DBG)

# Strategy 2: find all references to TARGET as code_off
print()
print("Strategy 2: Find which class_data references code_off 0x%x" % TARGET)
print("  Listing class_defs with class_data_off near target...")
candidates = []
for i in range(cds):
    off = cdo + i * 0x20
    cda = struct.unpack_from('<I', data, off + 0x14)[0]
    if cda == 0: continue
    if cda <= TARGET < cda + 0x20000:  # code_item should be reasonably close
        candidates.append((i, cda, cda - TARGET))

candidates.sort(key=lambda x: abs(x[2]))
print("  Top 20 classes with class_data_off near target:")
for i, cda, delta in candidates[:20]:
    ti = struct.unpack_from('<I', data, cdo + i * 0x20)[0]
    noff = struct.unpack_from('<I', data, tio + ti * 4)[0]
    s, p = uleb_safe(data, noff)
    cn = data[p:p+s].decode('latin-1') if s > 0 else '?'
    print('    class_def[%d]: class_data_off=0x%x (delta=%+d) class=%s' % (i, cda, delta, cn))

# Strategy 3: Check if TARGET might actually be a fill-array-data payload that contains a reference
print()
print("Strategy 3: Check context around target...")
for off in range(TARGET - 32, TARGET + 64):
    if 0 <= off < END:
        marker = ''
        if off == TARGET: marker = ' <-- TARGET(code_item)'
        elif off == TARGET + 16: marker = ' <-- instructions start'
        elif off == 0x4126c0: marker = ' <-- fill-array-data instr'
        elif off == 0x4126cc: marker = ' <-- fill-array-data payload'
        elif off == 0x4126d4: marker = ' <-- "moontonAGame1234"'
        elif off == 0x4126e4: marker = ' <-- end of code_item'
        print('  0x%x: 0x%02x%s' % (off, data[off], marker))
