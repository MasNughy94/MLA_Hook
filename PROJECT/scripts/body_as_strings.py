"""
Analyze the body as potential string/array serialization.
Key insight: top bytes are ASCII letters (0x41-0x7A range).
Check if bytes could be characters of a structured string format.
"""

f1 = open(r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\0000488d2f64199aca0cc7d54e7d11c0.mt.dec', 'rb').read()
f2 = open(r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\00378c64fbd63011a81dccef6bf6e2bd.mt.dec', 'rb').read()
f3 = open(r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\008fea3143557d628ac845a13a254e8a.mt.dec', 'rb').read()

bodies = [('f1', f1[69:]), ('f2', f2[69:]), ('f3', f3[69:])]

for name, body in bodies:
    print('=== {} body (first 300 bytes as chars) ==='.format(name))
    chars = []
    for b in body[:300]:
        if b == 0:
            chars.append('.')
        elif 0x20 <= b < 0x7F:
            chars.append(chr(b))
        else:
            chars.append('\\x{:02x}'.format(b))
    print(''.join(chars))
    print()

# Also check: are the first body bytes significant (section marker)?
print('=== First 32 body bytes ===')
for name, body in bodies:
    h = body[:32].hex()
    ascii_str = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in body[:32])
    print('{}: {}  {}'.format(name, h, ascii_str))

# Look at body as 16-bit LE values
print('\n=== First 100 body bytes as uint16 LE ===')
for name, body in bodies:
    vals = []
    for i in range(0, min(100, len(body)), 2):
        if i+1 < len(body):
            v = body[i] | (body[i+1] << 8)
            vals.append(v)
    print('{}: {}'.format(name, ', '.join(str(v) for v in vals[:20])))

# Most common non-zero bytes by category
print('\n=== Non-zero byte categories ===')
for name, body in bodies:
    nz = [b for b in body if b != 0]
    total = len(nz)
    ascii_upper = sum(1 for b in nz if 0x41 <= b <= 0x5A)  # A-Z
    ascii_lower = sum(1 for b in nz if 0x61 <= b <= 0x7A)  # a-z
    ascii_digit = sum(1 for b in nz if 0x30 <= b <= 0x39)  # 0-9
    ascii_other = sum(1 for b in nz if 0x20 <= b <= 0x7E)  # printable
    high_bit = sum(1 for b in nz if b >= 0x80)  # 128-255
    low = sum(1 for b in nz if b < 0x20)  # control
    middle = sum(1 for b in nz if (0x20 > b or b > 0x7E) and b < 0x80)  # 0x20-0x7E non-printable (none basically)
    print('{}: nz={}, A-Z={}, a-z={}, 0-9={}, printable={}, high={}, ctrl={}'.format(
        name, total, ascii_upper, ascii_lower, ascii_digit,
        ascii_upper+ascii_lower+ascii_digit+ascii_other, high_bit, low))
