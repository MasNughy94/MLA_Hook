import struct, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DEX = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\classes.dex'
data = open(DEX, 'rb').read()
END = len(data)

TARGET_CODE_OFF = 0x4126a8
DEBUG_INFO_OFF  = 0x465ecc
TARGET_FIELD_IDX = 0xa781

sio = struct.unpack_from('<I', data, 0x3C)[0]
tio = struct.unpack_from('<I', data, 0x44)[0]
mio = struct.unpack_from('<I', data, 0x5C)[0]
cdo = struct.unpack_from('<I', data, 0x64)[0]
cds = struct.unpack_from('<I', data, 0x60)[0]
fio = struct.unpack_from('<I', data, 0x4C)[0]

def uleb(data, off):
    r, s = 0, 0
    for _ in range(6):
        if off >= END:
            return -1, off
        b = data[off]
        r |= (b & 0x7F) << s
        off += 1
        s += 7
        if not (b & 0x80):
            return r, off
    return -1, off

MAX_COUNT = 50000

def rstr(off):
    s, p = uleb(data, off)
    if s < 0: return '?'
    return data[p:p+s].decode('utf-8', errors='replace')

def resolve_type(ti):
    return rstr(struct.unpack_from('<I', data, tio + ti * 4)[0])

def resolve_method(mi):
    off = mio + mi * 8
    ci = struct.unpack_from('<H', data, off)[0]
    ni = struct.unpack_from('<I', data, off + 4)[0]
    return resolve_type(ci), rstr(struct.unpack_from('<I', data, sio + ni * 4)[0])

print('=== OPTIMIZED DEX CLASS FINDER ===')
print('Target code_off = 0x%x' % TARGET_CODE_OFF)
print('Total classes   = %d' % cds)
print()

found = None
errors = 0

for i in range(cds):
    off = cdo + i * 0x20
    cda = struct.unpack_from('<I', data, off + 0x18)[0]
    if cda == 0 or cda >= END:
        continue

    pos = cda
    sfs, pos = uleb(data, pos)
    ifs, pos = uleb(data, pos)
    dms, pos = uleb(data, pos)
    vms, pos = uleb(data, pos)
    if -1 in (sfs, ifs, dms, vms):
        errors += 1
        continue
    if any(x > MAX_COUNT for x in (sfs, ifs, dms, vms)):
        errors += 1
        continue

    ok = True
    for _ in range(sfs + ifs):
        if pos >= END:
            ok = False
            break
        p1, pos = uleb(data, pos)
        p2, pos = uleb(data, pos)
        if -1 in (p1, p2):
            ok = False
            break
    if not ok:
        errors += 1
        continue

    pm = 0
    for _ in range(dms):
        if pos >= END:
            ok = False
            break
        df, pos = uleb(data, pos)
        if df < 0:
            ok = False
            break
        pm += df
        _, pos = uleb(data, pos)
        co, pos = uleb(data, pos)
        if co < 0:
            ok = False
            break
        if co == TARGET_CODE_OFF:
            cn, mn = resolve_method(pm)
            print('>>> FOUND DIRECT: %s.%s()' % (cn, mn))
            print('    class_data_off = 0x%x, class_def idx = %d' % (cda, i))
            found = (cn, mn, 'direct', pm, i)
            break
    if found: break
    if not ok:
        errors += 1
        continue

    pm = 0
    for _ in range(vms):
        if pos >= END:
            ok = False
            break
        df, pos = uleb(data, pos)
        if df < 0:
            ok = False
            break
        pm += df
        _, pos = uleb(data, pos)
        co, pos = uleb(data, pos)
        if co < 0:
            ok = False
            break
        if co == TARGET_CODE_OFF:
            cn, mn = resolve_method(pm)
            print('>>> FOUND VIRTUAL: %s.%s()' % (cn, mn))
            print('    class_data_off = 0x%x, class_def idx = %d' % (cda, i))
            found = (cn, mn, 'virtual', pm, i)
            break
    if found: break

if not found:
    print('code_off match: NOT FOUND (%d classes skipped due to errors)' % errors)
    print()
    print('=== FALLBACK: Scanning via debug_info_off ===')
    for i in range(cds):
        off = cdo + i * 0x20
        cda = struct.unpack_from('<I', data, off + 0x18)[0]
        if cda == 0 or cda >= END: continue
        pos = cda
        sfs, pos = uleb(data, pos)
        ifs, pos = uleb(data, pos)
        dms, pos = uleb(data, pos)
        vms, pos = uleb(data, pos)
        if -1 in (sfs, ifs, dms, vms): continue
        if any(x > MAX_COUNT for x in (sfs, ifs, dms, vms)): continue
        ok = True
        for _ in range(sfs + ifs):
            if pos >= END: ok = False; break
            p1, pos = uleb(data, pos)
            p2, pos = uleb(data, pos)
            if -1 in (p1, p2): ok = False; break
        if not ok: continue
        pm = 0
        for _ in range(dms + vms):
            if pos >= END: break
            df, pos = uleb(data, pos)
            if df < 0: break
            pm += df
            _, pos = uleb(data, pos)
            co, pos = uleb(data, pos)
            if co < 0: break
            if co == 0: continue
            if co + 16 > END: continue
            dbg = struct.unpack_from('<I', data, co + 8)[0]
            if dbg == DEBUG_INFO_OFF:
                cn, mn = resolve_method(pm)
                kind = 'virtual' if _ >= dms else 'direct'
                print('>>> FOUND via debug_info_off: %s.%s() [%s]' % (cn, mn, kind))
                print('    code_off = 0x%x, class_def idx = %d' % (co, i))
                found = (cn, mn, kind, pm, i)
                break
        if found: break

print()
if found:
    cn, mn, kind, pm, cd_idx = found
    print('=== FIELD TRACE ===')
    foff = fio + TARGET_FIELD_IDX * 8
    fclass = resolve_type(struct.unpack_from('<H', data, foff)[0])
    ftype  = resolve_type(struct.unpack_from('<H', data, foff + 2)[0])
    fname = rstr(struct.unpack_from('<I', data, foff + 4)[0])
    print('  Field[0x%x]: %s.%s : %s' % (TARGET_FIELD_IDX, fclass, fname, ftype))
else:
    print('Class still not identified after both passes.')
