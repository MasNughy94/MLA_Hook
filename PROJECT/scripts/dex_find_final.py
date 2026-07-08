import struct

DEX = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\classes.dex'
data = open(DEX, 'rb').read()
END = len(data)
TARGET = 0x4126a8

sio = struct.unpack_from('<I', data, 0x3C)[0]
tio = struct.unpack_from('<I', data, 0x44)[0]
mio = struct.unpack_from('<I', data, 0x5C)[0]
cdo = struct.unpack_from('<I', data, 0x64)[0]
cds = struct.unpack_from('<I', data, 0x60)[0]
fio = struct.unpack_from('<I', data, 0x4C)[0]

def uleb(off):
    r = 0; s = 0
    for _ in range(5):
        if off >= END: return -1, off
        b = data[off]; off += 1
        r |= (b & 0x7F) << s; s += 7
        if not (b & 0x80): return r, off
    return -1, off

def safe_str(off):
    sz, p = uleb(off)
    if sz < 0: return '?'
    return data[p:p+sz].decode('latin-1')

def cls_name(ti):
    return safe_str(struct.unpack_from('<I', data, tio + ti * 4)[0])

result = None
for i in range(cds):
    off = cdo + i * 0x20
    cda = struct.unpack_from('<I', data, off + 0x18)[0]
    if cda == 0 or cda >= END: continue
    pos = cda
    sfs, pos = uleb(pos)
    ifs, pos = uleb(pos)
    dms, pos = uleb(pos)
    vms, pos = uleb(pos)
    if any(x < 0 or x > 50000 for x in (sfs, ifs, dms, vms)): continue
    ok = True
    for _ in range(sfs + ifs):
        p1, pos = uleb(pos); p2, pos = uleb(pos)
        if -1 in (p1, p2): ok = False; break
    if not ok: continue
    pm = 0
    for _ in range(dms):
        df, pos = uleb(pos)
        if df < 0: ok = False; break
        pm += df
        _, pos = uleb(pos)
        co, pos = uleb(pos)
        if co < 0: ok = False; break
        if co == TARGET:
            ci = struct.unpack_from('<I', data, off)[0]
            cn = cls_name(ci)
            mn = safe_str(struct.unpack_from('<I', data, sio + struct.unpack_from('<I', data, mio + pm * 8 + 4)[0] * 4)[0])
            result = (cn, mn, i)
            break
    if result: break
    pm = 0
    for _ in range(vms):
        df, pos = uleb(pos)
        if df < 0: ok = False; break
        pm += df
        _, pos = uleb(pos)
        co, pos = uleb(pos)
        if co < 0: ok = False; break
        if co == TARGET:
            ci = struct.unpack_from('<I', data, off)[0]
            cn = cls_name(ci)
            mn = safe_str(struct.unpack_from('<I', data, sio + struct.unpack_from('<I', data, mio + pm * 8 + 4)[0] * 4)[0])
            result = (cn, mn, i)
            break
    if result: break

if result:
    cn, mn, idx = result
    foff = fio + 0xa781 * 8
    fc = cls_name(struct.unpack_from('<H', data, foff)[0])
    ft = cls_name(struct.unpack_from('<H', data, foff+2)[0])
    fn = safe_str(struct.unpack_from('<I', data, foff+4)[0])
    with open(r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\RESULT.txt', 'w', encoding='utf-8') as f:
        f.write('CLASS: %s\nMETHOD: %s\nCLASS_DEF_IDX: %d\nFIELD[0xa781]: %s.%s : %s\n' % (cn, mn, idx, fc, fn, ft))
    print('OK - hasil di RESULT.txt')
else:
    print('NOT FOUND')
