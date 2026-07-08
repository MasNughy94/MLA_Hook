import struct

DEX = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\classes.dex'
data = open(DEX, 'rb').read()

# DEX version
print('DEX magic:', data[0:8])

# Verify byte at 0x412698
print('\nByte at 0x412698: 0x%02x' % data[0x412698])
print('Bytes 0x412694-0x4126a8:')
for i in range(0x412694, 0x4126a8, 2):
    print('  0x%x: %02x %02x' % (i, data[i], data[i+1] if i+1 < len(data) else 0))

# Verify byte at 0x4126c6 
print('\nByte at 0x4126c6: 0x%02x' % data[0x4126c6])
print('Bytes 0x4126b8-0x4126d0:')
for i in range(0x4126b8, 0x4126d0, 2):
    print('  0x%x: %02x %02x' % (i, data[i], data[i+1] if i+1 < len(data) else 0))

# Look up the type, string, and method refs
sio = struct.unpack_from('<I', data, 0x3C)[0]
tio = struct.unpack_from('<I', data, 0x44)[0]
mio = struct.unpack_from('<I', data, 0x5C)[0]

def uleb(off):
    r = 0; s = 0
    for _ in range(5):
        if off >= len(data): return -1, off
        b = data[off]; off += 1
        r |= (b & 0x7F) << s; s += 7
        if not (b & 0x80): return r, off
    return -1, off

def raw_str(off):
    sz, p = uleb(off)
    if sz < 0: return b'?'
    return data[p:p+sz]

def type_name(ti):
    s = raw_str(struct.unpack_from('<I', data, tio + ti * 4)[0])
    return s.decode('utf-8', errors='replace')

def mth_sig_full(mi):
    off = mio + mi * 8
    class_idx = struct.unpack_from('<H', data, off)[0]
    proto_idx = struct.unpack_from('<H', data, off+2)[0]
    name_idx = struct.unpack_from('<I', data, off+4)[0]
    cls = type_name(class_idx)
    name = raw_str(struct.unpack_from('<I', data, sio + name_idx * 4)[0]).decode('utf-8', errors='replace')
    # proto
    poff_off = struct.unpack_from('<I', data, 0x48)[0]
    prio = poff_off + proto_idx * 12
    rt_idx = struct.unpack_from('<I', data, prio+4)[0]
    pm_off = struct.unpack_from('<I', data, prio+8)[0]
    ret = type_name(rt_idx)
    params = ''
    if pm_off != 0:
        sz, p2 = uleb(pm_off)
        params = '('
        for _ in range(sz):
            ti2, p2 = uleb(p2)
            params += type_name(ti2)
        params += ')'
    else:
        params = '()'
    return '%s.%s:%s%s' % (cls, name, params, ret)

print('\n=== generateKey method refs ===')
print('type@0x1ab0 (%d): %s' % (0x1ab0, type_name(0x1ab0)))
print('string@0x0958 (%d): "%s"' % (0x0958, raw_str(struct.unpack_from('<I', data, sio + 0x0958 * 4)[0]).decode('utf-8', errors='replace')))
print('method@0x9270 (%d): %s' % (0x9270, mth_sig_full(0x9270)))

# Also check the <clinit> refs
print('\n=== <clinit> method refs ===')
print('type@0x2531 (%d): %s' % (0x2531, type_name(0x2531)))
print('field@0xa781 (%d):' % 0xa781)
fis = struct.unpack_from('<I', data, 0x50)[0]
fio = struct.unpack_from('<I', data, 0x54)[0]
foff = fio + 0xa781 * 8
fc = struct.unpack_from('<H', data, foff)[0]
ft = struct.unpack_from('<H', data, foff+2)[0]
fn_idx = struct.unpack_from('<I', data, foff+4)[0]
print('  class: %s' % type_name(fc))
print('  type: %s' % type_name(ft))
print('  name: %s' % raw_str(struct.unpack_from('<I', data, sio + fn_idx * 4)[0]).decode('utf-8', errors='replace'))

# Look at the fill-array-data payload
print('\n=== fill-array-data payload at 0x4126cc ===')
for i in range(0x4126cc, min(0x4126cc + 32, len(data))):
    if i % 16 == 0:
        print('\n  0x%x: ' % i, end='')
    print('%02x ' % data[i], end='')
print()

# Decode payload header
ident = struct.unpack_from('<H', data, 0x4126cc)[0]
elem_w = struct.unpack_from('<H', data, 0x4126ce)[0]
size = struct.unpack_from('<I', data, 0x4126d0)[0]
print('ident: 0x%x, element_width: %d, size: %d' % (ident, elem_w, size))
payload_data = data[0x4126d4:0x4126d4+size*elem_w]
print('payload bytes: ' + ' '.join('%02x' % b for b in payload_data))
print('payload as ASCII: ' + ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in payload_data))

# Also check what the field type is for keyValue more carefully
print('\n### Checking field type ###')
ft_name = type_name(ft)
print('Field type at type_idx %d: "%s"' % (ft, ft_name))
print('Hex of raw string bytes: ' + raw_str(struct.unpack_from('<I', data, tio + ft * 4)[0]).hex(' '))

# Read the method_id for generateKey (method_idx=48445)
print('\n=== generateKey method_id (idx 48445) ===')
off_m = mio + 48445 * 8
cls_m = struct.unpack_from('<H', data, off_m)[0]
proto_m = struct.unpack_from('<H', data, off_m+2)[0]
name_m = struct.unpack_from('<I', data, off_m+4)[0]
print('class: %s' % type_name(cls_m))
print('proto: %d' % proto_m)
print('name: %s' % raw_str(struct.unpack_from('<I', data, sio + name_m * 4)[0]).decode('utf-8', errors='replace'))
