import struct

DEX = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\classes.dex'
data = open(DEX, 'rb').read()
END = len(data)
TARGET_FIELD = 0xa781

sio = struct.unpack_from('<I', data, 0x3C)[0]
tio = struct.unpack_from('<I', data, 0x44)[0]
mio = struct.unpack_from('<I', data, 0x5C)[0]
cdo = struct.unpack_from('<I', data, 0x64)[0]
cds = struct.unpack_from('<I', data, 0x60)[0]

def uleb(off):
    r = 0; s = 0
    for _ in range(5):
        if off >= END: return -1, off
        b = data[off]; off += 1
        r |= (b & 0x7F) << s; s += 7
        if not (b & 0x80): return r, off
    return -1, off

def raw_str(off):
    sz, p = uleb(off)
    if sz < 0: return b'?'
    return data[p:p+sz]

def cls_name(ti):
    s = raw_str(struct.unpack_from('<I', data, tio + ti * 4)[0])
    return s.decode('utf-8', errors='replace')

def mth_name(mi):
    s = raw_str(struct.unpack_from('<I', data, sio + struct.unpack_from('<I', data, mio + mi * 8 + 4)[0] * 4)[0])
    return s.decode('utf-8', errors='replace')

field_bytes = struct.pack('<H', TARGET_FIELD)

# Correct opcodes:
# 0x5c = sget-object (read static object field)
# 0x63 = sput-object (write static object field)
# 0x62 = sput-wide (NOT what we want)
# 0x5a = sget

results = []
for i in range(cds):
    off = cdo + i * 0x20
    ci = struct.unpack_from('<I', data, off)[0]
    cda = struct.unpack_from('<I', data, off + 0x18)[0]
    if cda == 0 or cda >= END: continue
    pos = cda
    sfs, pos = uleb(pos); ifs, pos = uleb(pos); dms, pos = uleb(pos); vms, pos = uleb(pos)
    if any(x < 0 or x > 50000 for x in (sfs, ifs, dms, vms)): continue
    ok = True
    for _ in range(sfs + ifs):
        p1, pos = uleb(pos); p2, pos = uleb(pos)
        if -1 in (p1, p2): ok = False; break
    if not ok: continue
    for mcount, kind in [(dms, 'direct'), (vms, 'virtual')]:
        pm = 0
        for _ in range(mcount):
            df, pos = uleb(pos)
            if df < 0: ok = False; break
            pm += df
            _, pos = uleb(pos)
            co, pos = uleb(pos)
            if co < 0: ok = False; break
            if co == 0: continue
            insns_size = struct.unpack_from('<I', data, co + 12)[0]
            insns_off = co + 16
            if insns_off + insns_size * 2 > END: continue
            code = data[insns_off:insns_off + insns_size * 2]
            for ci_off in range(0, len(code) - 3):
                op = code[ci_off]
                if op in (0x5c, 0x63) and code[ci_off+2:ci_off+4] == field_bytes:
                    cn = cls_name(ci)
                    mn = mth_name(pm)
                    reg = code[ci_off+1]
                    opname = 'sget-object' if op == 0x5c else 'sput-object'
                    results.append((cn, mn, kind, opname, reg, co, insns_off + ci_off))
                    break

print('Methods referencing field@0xa781 (keyValue):\n')
for cn, mn, kind, opname, reg, co, abs_off in results:
    print('  %s %s: %s v%d, field@0xa781 at 0x%x (code_item at 0x%x)' % (cn, mn, opname, reg, abs_off, co))

if not results:
    print('No sget-object or sput-object found for field@0xa781')
    print('\nRaw scan for 5c (sget-object) and 63 (sput-object) with 81 a7:')
    for off in range(END - 3):
        op = data[off]
        if op in (0x5c, 0x63) and data[off+2] == 0x81 and data[off+3] == 0xa7:
            opname = 'sget-object' if op == 0x5c else 'sput-object'
            reg = data[off+1]
            print('  0x%x: %s v%d' % (off, opname, reg))
