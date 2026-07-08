import struct

# Compare two decompressed .mt files to find common structure
f1 = open(r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\0000488d2f64199aca0cc7d54e7d11c0.mt.dec', 'rb').read()
f2 = open(r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\00378c64fbd63011a81dccef6bf6e2bd.mt.dec', 'rb').read()
f3 = open(r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\008fea3143557d628ac845a13a254e8a.mt.dec', 'rb').read()

print(f'File sizes: {len(f1)}, {len(f2)}, {len(f3)}')

# Find common prefix (identical bytes at start)
common_len = 0
while common_len < min(len(f1), len(f2), len(f3)):
    if f1[common_len] == f2[common_len] == f3[common_len]:
        common_len += 1
    else:
        break
print(f'Common prefix length: {common_len} bytes')
print(f'Common prefix hex: {f1[:common_len].hex()}')
print(f'Common prefix ascii: ' + ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in f1[:common_len]))

# Check if files share a common HEADER structure but differ in body
# Compare first 256 bytes
print('\nFirst 256 bytes comparison (X = same, . = different):')
for row in range(16):
    offset = row * 16
    line = f'{offset:04x}: '
    for i in range(16):
        if f1[offset+i] == f2[offset+i] == f3[offset+i]:
            line += 'X'
        else:
            line += '.'
    print(line)

# Check if headers up to certain point are identical
print('\nBytes that differ in first 128 bytes:')
for i in range(min(128, common_len, len(f1), len(f2), len(f3))):
    if not (f1[i] == f2[i] == f3[i]):
        print(f'  offset {i} (0x{i:04x}): f1={f1[i]:02x} f2={f2[i]:02x} f3={f3[i]:02x}')

# Compare total identical content
print(f'\nCross-file byte comparison (f1 vs f2):')
same = sum(1 for i in range(min(len(f1), len(f2))) if f1[i] == f2[i])
print(f'  Identical bytes: {same} / {min(len(f1), len(f2))} ({same*100//min(len(f1),len(f2))}%)')

print(f'\nCross-file byte comparison (f1 vs f3):')
same2 = sum(1 for i in range(min(len(f1), len(f3))) if f1[i] == f3[i])
print(f'  Identical bytes: {same2} / {min(len(f1), len(f3))} ({same2*100//min(len(f1),len(f3))}%)')

# Check if there's a COUNT field somewhere that matches file sizes
# Look for 32-bit values that could be count/size fields
print('\nLooking for potential size/count fields in first 64 bytes:')
for i in range(0, min(64, len(f1)), 2):
    val32_1 = struct.unpack_from('<I', f1, i)[0]
    val32_2 = struct.unpack_from('<I', f2, i)[0]
    val32_3 = struct.unpack_from('<I', f3, i)[0]
    # Check if value relates to file size
    for val, name in [(val32_1, 'f1'), (val32_2, 'f2'), (val32_3, 'f3')]:
        if val > 0 and (abs(val - len(f1)) < 100 or abs(val - len(f2)) < 100 or abs(val - len(f3)) < 100):
            print(f'  offset {i}: {name} value={val} (file sizes: {len(f1)}, {len(f2)}, {len(f3)})')
    
    # Also check 16-bit values
    val16_1 = struct.unpack_from('<H', f1, i)[0]
    val16_2 = struct.unpack_from('<H', f2, i)[0]
    val16_3 = struct.unpack_from('<H', f3, i)[0]
    for val, name in [(val16_1, 'f1'), (val16_2, 'f2'), (val16_3, 'f3')]:
        if val > 0 and (abs(val - len(f1)) < 100 or abs(val - len(f2)) < 100 or abs(val - len(f3)) < 100):
            print(f'  offset {i}: {name} 16-bit value={val}')
