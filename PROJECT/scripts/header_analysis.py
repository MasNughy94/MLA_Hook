import struct

f1 = open(r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\0000488d2f64199aca0cc7d54e7d11c0.mt.dec', 'rb').read()
f2 = open(r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\00378c64fbd63011a81dccef6bf6e2bd.mt.dec', 'rb').read()
f3 = open(r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\008fea3143557d628ac845a13a254e8a.mt.dec', 'rb').read()

common = f1[:69]
print('Common 69-byte header:')
for i in range(0, len(common), 16):
    chunk = common[i:i+16]
    hexb = ' '.join('{:02x}'.format(b) for b in chunk)
    ascii_str = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
    print('  {:3d} (0x{:02x}): {:<48s} {}'.format(i, i, hexb, ascii_str))

# Parse header fields
print('\n=== Header field breakdown ===')
print('  [0-3]   Magic: {:02x} {:02x} {:02x} {:02x}'.format(common[0], common[1], common[2], common[3]))
print('  [4-5]   unk1:  {:02x} {:02x}'.format(common[4], common[5]))
s = common[6:9].decode('ascii', errors='ignore')
print('  [6-9]   Type:  {:02x} {:02x} {:02x} {:02x} = "{}"'.format(common[6], common[7], common[8], common[9], s))
print('  [10-11] unk2:  {:02x} {:02x}'.format(common[10], common[11]))
print('  [12-20] zeros: (9 zero bytes)')
v1 = struct.unpack('<H', common[21:23])[0]
print('  [21-22] data1: {:02x} {:02x}  (uint16: {})'.format(common[21], common[22], v1))
print('  [37]    data2: {:02x}'.format(common[37]))
v43 = struct.unpack('<H', common[43:45])[0]
print('  [43-44] data3: {:02x} {:02x}  (uint16: {})'.format(common[43], common[44], v43))
v46 = struct.unpack('<H', common[46:48])[0]
print('  [46-47] data4: {:02x} {:02x}  (uint16: {})'.format(common[46], common[47], v46))
v55 = struct.unpack('<H', common[55:57])[0]
print('  [55-56] data5: {:02x} {:02x}  (uint16: {})'.format(common[55], common[56], v55))
v58 = struct.unpack('<H', common[58:60])[0]
print('  [58-59] data6: {:02x} {:02x}  (uint16: {})'.format(common[58], common[59], v58))

# Check where first difference occurs after header
print('\n=== First byte divergence after common header ===')
for i in range(69, min(len(f1), len(f2), len(f3))):
    if not (f1[i] == f2[i] == f3[i]):
        start = max(0, i-8)
        end = min(len(f1), i+16)
        print('First diff at offset {} (0x{:04x}):'.format(i, i))
        print('  f1: {}'.format(' '.join('{:02x}'.format(f1[j]) for j in range(start, end))))
        print('  f2: {}'.format(' '.join('{:02x}'.format(f2[j]) for j in range(start, end))))
        print('  f3: {}'.format(' '.join('{:02x}'.format(f3[j]) for j in range(start, end))))
        break

# Also check for record count field
nonzeros_f1 = sum(1 for b in f1 if b != 0)
nonzeros_f2 = sum(1 for b in f2 if b != 0)
nonzeros_f3 = sum(1 for b in f3 if b != 0)
print('\nNon-zero byte counts: f1={}, f2={}, f3={}'.format(nonzeros_f1, nonzeros_f2, nonzeros_f3))

# Compare key size/count values
print('\nKey header values:')
for offset in [4, 6, 10, 21, 37, 43, 46, 55, 58]:
    if offset >= 69: break
    v1 = struct.unpack('<H', f1[offset:offset+2])[0]
    v2 = struct.unpack('<H', f2[offset:offset+2])[0]
    v3 = struct.unpack('<H', f3[offset:offset+2])[0]
    print('  uint16[{}]: f1={}, f2={}, f3={}'.format(offset, v1, v2, v3))
