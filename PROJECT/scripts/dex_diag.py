import struct

DEX = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\classes.dex'
data = open(DEX, 'rb').read()
END = len(data)

sio = struct.unpack_from('<I', data, 0x3C)[0]
tio = struct.unpack_from('<I', data, 0x44)[0]
mio = struct.unpack_from('<I', data, 0x5C)[0]
cdo = struct.unpack_from('<I', data, 0x64)[0]
cds = struct.unpack_from('<I', data, 0x60)[0]
fis = struct.unpack_from('<I', data, 0x50)[0]
fio = struct.unpack_from('<I', data, 0x54)[0]

def uleb(off):
    r = 0; s = 0
    for _ in range(5):
        if off >= END: return -1, off
        b = data[off]; off += 1
        r |= (b & 0x7F) << s; s += 7
        if not (b & 0x80): return r, off
    return -1, off

# string_data_off from string_idx
def str_off(string_idx):
    return struct.unpack_from('<I', data, sio + string_idx * 4)[0]

# string bytes from dex offset (string_data_off)
def raw_str_at(off):
    sz, p = uleb(off)
    if sz < 0: return b'ERR'
    return data[p:p+sz]

# string bytes from string_idx
def str_at(string_idx):
    return raw_str_at(str_off(string_idx))

# type name from type_idx
def type_name(ti):
    si = struct.unpack_from('<I', data, tio + ti * 4)[0]
    return str_at(si)

# Class_def at idx 6989
idx = 6989
off = cdo + idx * 0x20
class_idx = struct.unpack_from('<I', data, off)[0]
access = struct.unpack_from('<I', data, off + 4)[0]
super_idx = struct.unpack_from('<I', data, off + 8)[0]
ifaces_off = struct.unpack_from('<I', data, off + 0x0C)[0]
src_file_idx = struct.unpack_from('<I', data, off + 0x10)[0]
annot_off = struct.unpack_from('<I', data, off + 0x14)[0]
class_data_off = struct.unpack_from('<I', data, off + 0x18)[0]
static_off = struct.unpack_from('<I', data, off + 0x1C)[0]

print('=== Class_def[6989] ===')
print('class_idx (type_idx): %d' % class_idx)
print('access_flags: 0x%x' % access)
print('superclass_idx: %d' % super_idx)
print('source_file_idx: %d' % src_file_idx)
print('class_data_off: 0x%x' % class_data_off)
print('static_values_off: 0x%x' % static_off)

print('\n=== Class name ===')
cn = type_name(class_idx)
print('type_name bytes (hex): ' + cn.hex(' '))
print('type_name decoded: ' + cn.decode('utf-8', errors='replace'))

print('\n=== Superclass ===')
scn = type_name(super_idx) if super_idx != 0xFFFFFFFF else b'(none)'
print('super bytes (hex): ' + scn.hex(' '))
print('super decoded: ' + scn.decode('utf-8', errors='replace'))

# field_id at 0xa781
print('\n=== Field_id[0xa781] ===')
foff = fio + 0xa781 * 8
fclass = struct.unpack_from('<H', data, foff)[0]
ftype = struct.unpack_from('<H', data, foff+2)[0]
fname = struct.unpack_from('<I', data, foff+4)[0]
print('class_idx (type_idx): %d' % fclass)
print('type_idx: %d' % ftype)
print('name_idx: %d' % fname)
print('field class: ' + type_name(fclass).decode('utf-8', errors='replace'))
print('field type: ' + type_name(ftype).decode('utf-8', errors='replace'))
print('field name: ' + str_at(fname).decode('utf-8', errors='replace'))

# Look at the actual string_data for the class name
print('\n=== String data for class name ===')
si = struct.unpack_from('<I', data, tio + class_idx * 4)[0]
sdo = str_off(si)
print('string_idx: %d' % si)
print('string_data_off: 0x%x' % sdo)
# Show bytes around the string_data
start = max(0, sdo - 8)
end = min(END, sdo + 32)
print('Context around string_data (hex): ' + data[start:end].hex(' '))
sz, p = uleb(sdo)
print('ULEB128 size: %d, data starts at 0x%x' % (sz, p))
actual = data[p:p+min(sz, 200)]
print('String bytes (hex): ' + actual.hex(' '))
print('String (repr): ' + repr(actual[:100]))

# also show the raw string_data with context
print('\n=== Raw string_data bytes ===')
for i in range(0, 64, 16):
    chunk = data[sdo+i:sdo+i+16]
    if not chunk: break
    seg = ' '.join(f'{b:02x}' for b in chunk)
    asc = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
    print(f'  0x{sdo+i:06x}: {seg:48s} {asc}')
