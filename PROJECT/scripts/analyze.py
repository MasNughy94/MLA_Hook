import struct
with open(r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\output.bin', 'rb') as f:
    data = f.read()

print(f'Size: {len(data)}')
print(f'First 256 hex: {data[:256].hex()}')
print(f'First u32 LE: {struct.unpack("<I", data[0:4])[0]}')
for offset in [0, 4, 8, 12, 16, 20, 24]:
    if offset + 4 <= len(data):
        print(f'Offset {offset}: {struct.unpack("<I", data[offset:offset+4])[0]:#010x}')

nonzero = sum(1 for b in data if b != 0)
print(f'Non-zero bytes: {nonzero}/{len(data)}')
# Look for ASCII strings
print()
print('Strings found:')
import re
strings = re.findall(b'[\x20-\x7e]{4,}', data)
for s in strings[:30]:
    print(f'  {s.decode("ascii")}')
