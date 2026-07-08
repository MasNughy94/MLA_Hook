"""
Use simple binary patterns to find which method references a fill-array-data payload.
Instead of full DEX parsing, search for the fill-array-data structure near the target.
"""
import struct

dex_path = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\classes.dex'
with open(dex_path, 'rb') as f:
    data = f.read()

# We found "moontonAGame1234" at file offset 0x4126d4, 
# and a fill-array-data payload starts at 0x4126cc.
# The fill-array-data instruction is at 0x4126c0.

# But which method contains this instruction?
# Let's look for it using the string itself as a search anchor.

string_bytes = b'moontonAGame1234'
pos = 0
occurrences = []
while True:
    pos = data.find(string_bytes, pos)
    if pos < 0:
        break
    occurrences.append(pos)
    print('Found at file offset 0x%x' % pos)
    # Check what's before it
    for off in range(pos - 32, pos + len(string_bytes) + 32):
        if 0 <= off < len(data):
            pass
    pos += 1

print()
print('Total occurrences in classes.dex: %d' % len(occurrences))

# Now check classes2.dex
dex2_path = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\classes2.dex'
with open(dex2_path, 'rb') as f:
    data2 = f.read()

pos = 0
occ2 = 0
while True:
    pos = data2.find(string_bytes, pos)
    if pos < 0:
        break
    occ2 += 1
    print('Found in classes2.dex at file offset 0x%x' % pos)
    pos += 1

print('Total occurrences in classes2.dex: %d' % occ2)

# The string "moontonAGame1234" appears to be used as an inline fill-array-data payload
# Let me check what's around the first occurrence
if occurrences:
    off = occurrences[0]
    print()
    print('Context around string at 0x%x:' % off)
    # Print 100 bytes before and after
    start = max(0, off - 100)
    end = min(len(data), off + len(string_bytes) + 100)
    for row_start in range(start, end, 16):
        line = ''
        ascii_str = ''
        for col in range(16):
            addr = row_start + col
            if addr < end:
                b = data[addr]
                line += '%02x ' % b
                ascii_str += chr(b) if 32 <= b < 127 else '.'
            else:
                line += '   '
        marker = ' <--- string here' if row_start <= off < row_start + 16 else ''
        print('  0x%05x: %s %s%s' % (row_start, line, ascii_str, marker))
