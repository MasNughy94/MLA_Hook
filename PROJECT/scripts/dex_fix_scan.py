import struct

dex_path = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\classes.dex'
with open(dex_path, 'rb') as f:
    data = f.read()

string_ids_off = struct.unpack_from('<I', data, 0x3C)[0]
string_ids_size = struct.unpack_from('<I', data, 0x38)[0]
type_ids_off = struct.unpack_from('<I', data, 0x44)[0]
method_ids_off = struct.unpack_from('<I', data, 0x5C)[0]
method_ids_size = struct.unpack_from('<I', data, 0x58)[0]
class_defs_off = struct.unpack_from('<I', data, 0x64)[0]
class_defs_size = struct.unpack_from('<I', data, 0x60)[0]

def rud(data, off):
    r, s = 0, 0
    while off < len(data):
        b = data[off]; r |= (b & 0x7F) << s; s += 7; off += 1
        if not (b & 0x80): return r, off
        if s > 56: return -1, off
    return -1, off

target_code_off = 0x4126a8

print('Searching for class containing code_off = 0x%x...' % target_code_off)
print('Total class_defs:', class_defs_size)

found = False
for cd_idx in range(class_defs_size):
    cd_off = class_defs_off + cd_idx * 0x20
    cdo = struct.unpack_from('<I', data, cd_off + 0x14)[0]
    if cdo == 0: continue
    
    try:
        pos = cdo
        a, pos = rud(data, pos)
        b, pos = rud(data, pos)
        c, pos = rud(data, pos)
        d, pos = rud(data, pos)
        if a < 0 or b < 0 or c < 0 or d < 0: continue
        
        # Read field definitions
        for _ in range(a + b):
            _, pos = rud(data, pos)
            _, pos = rud(data, pos)
        
        # Read direct methods
        pm = 0
        for _ in range(c):
            df, pos = rud(data, pos); pm += df
            _, pos = rud(data, pos)
            co, pos = rud(data, pos)
            if co == target_code_off:
                # Found! Get class and method names
                ci = struct.unpack_from('<I', data, cd_off)[0]
                cn_off = struct.unpack_from('<I', data, type_ids_off + ci * 4)[0]
                s, p = rud(data, cn_off)
                cn = data[p:p+s].decode('latin-1')
                mn_off = struct.unpack_from('<I', data, method_ids_off + pm * 8 + 4)[0]
                s2, p2 = rud(data, string_ids_off + mn_off * 4)
                mn = data[p2:p2+s2].decode('latin-1')
                print('FOUND DIRECT: %s.%s()' % (cn, mn))
                found = True
                break
        
        if found: break
        
        # Read virtual methods
        pm = 0
        for _ in range(d):
            df, pos = rud(data, pos); pm += df
            _, pos = rud(data, pos)
            co, pos = rud(data, pos)
            if co == target_code_off:
                ci = struct.unpack_from('<I', data, cd_off)[0]
                cn_off = struct.unpack_from('<I', data, type_ids_off + ci * 4)[0]
                s, p = rud(data, cn_off)
                cn = data[p:p+s].decode('latin-1')
                mn_off = struct.unpack_from('<I', data, method_ids_off + pm * 8 + 4)[0]
                s2, p2 = rud(data, string_ids_off + mn_off * 4)
                mn = data[p2:p2+s2].decode('latin-1')
                print('FOUND VIRTUAL: %s.%s()' % (cn, mn))
                found = True
                break
        
        if found: break
    except: pass

if not found:
    print('code_off 0x%x not found in any class. Trying nearby offsets...' % target_code_off)
    for delta in [1, 2, -1, -2, 3, 4]:
        test_off = target_code_off + delta
        for cd_idx in range(class_defs_size):
            cd_off = class_defs_off + cd_idx * 0x20
            cdo = struct.unpack_from('<I', data, cd_off + 0x14)[0]
            if cdo == 0: continue
            try:
                pos = cdo
                a, pos = rud(data, pos); b, pos = rud(data, pos)
                c, pos = rud(data, pos); d, pos = rud(data, pos)
                for _ in range(a + b):
                    _, pos = rud(data, pos); _, pos = rud(data, pos)
                pm = 0
                for _ in range(c + d):
                    df, pos = rud(data, pos); pm += df
                    _, pos = rud(data, pos)
                    co, pos = rud(data, pos)
                    if co == test_off:
                        ci = struct.unpack_from('<I', data, cd_off)[0]
                        cn = data[rud(data, struct.unpack_from('<I', data, type_ids_off + ci * 4)[0])[1]:].split(b'\x00')[0].decode('latin-1')
                        mn = data[rud(data, string_ids_off + struct.unpack_from('<I', data, method_ids_off + pm * 8 + 4)[0] * 4)[1]:].split(b'\x00')[0].decode('latin-1')
                        print('  FOUND (off=0x%x): %s.%s()' % (co, cn, mn))
                        found = True
            except: pass
            if found: break
        if found: break
