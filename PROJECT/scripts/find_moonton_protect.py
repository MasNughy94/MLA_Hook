import struct

so_path = r'C:\Users\NGEONG\Videos\MLA\libagame.so'
with open(so_path, 'rb') as f:
    data = f.read()

# Search for MoontonProtect JNI method names in dynstr
dynstr_start = 0x10b760
dynstr_end = dynstr_start + 0x1706c4
dynstr = data[dynstr_start:dynstr_end]

print('=== Moonton/JNI related strings in .dynstr ===')
import re
# Find all strings containing 'Moonton' or 'moonton' or 'Protect' or 'JNI'
pattern = re.compile(rb'[a-zA-Z0-9_/]{8,120}')
for m in pattern.finditer(dynstr):
    s = m.group()
    if b'Moonton' in s or b'moonton' in s or b'Protect' in s:
        if b'MoontonProtect' in s or b'moonton_protect' in s or b'decrypt' in s or b'encrypt' in s:
            off_abs = dynstr_start + m.start()
            print(f'  at 0x{off_abs:x}: {s.decode(errors="replace")}')

# Also search for JNI function name patterns
print()
print('=== JNI decrypt/encrypt functions ===')
pattern2 = re.compile(rb'Java_[a-zA-Z0-9_]+decrypt[a-zA-Z0-9_]*|Java_[a-zA-Z0-9_]+encrypt[a-zA-Z0-9_]*')
for m in pattern2.finditer(dynstr):
    off_abs = dynstr_start + m.start()
    print(f'  at 0x{off_abs:x}: {m.group().decode(errors="replace")}')

# Also look for any 16-byte key-like constant in .rodata that might be the XXTEA key
# used by MoontonProtect
print('\n=== Potential 16-byte keys in .rodata (looking for patterns) ===')
rodata = data[0xDF6200:0xDF6200+0x196440]

# Look for cross-references - functions that have addresses in the 0x4xxxxx range 
# (near setXXTEAKeyAndSign at 0x47112c) that might be the key setup code
# The key setup code would call setXXTEAKeyAndSign(key, len, sign, sign_len)
# Even if called via pointer, the string literals "key" and "sign" might exist

# Search for strings near "setXXTEAKeyAndSign" address region
print('\n=== Searching for key/sign string literals in .rodata ===')
keywords = [b'XXTEAKey', b'XXTEASign', b'tea_key', b'tea_sign', b'GAME_KEY', b'LUA_KEY',
            b'encrypt_key', b'lua_key', b'res_key', b'resource_key']
for kw in keywords:
    pos = data.find(kw, 0xDF6200, 0xDF6200+0x196440)
    if pos >= 0:
        ctx = data[pos:pos+40]
        print(f'  "{kw.decode()}" at 0x{pos:x}: {ctx[:48]}')
