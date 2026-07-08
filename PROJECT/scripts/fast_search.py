"""
Fast search: find ALL .mt string occurrences and related strings in both libraries.
Skip code reference searching (too slow).
"""

import struct, os

def find_all_str(data, needle, max_count=50):
    """Find all occurrences of needle in data."""
    results = []
    offset = 0
    while len(results) < max_count:
        idx = data.find(needle, offset)
        if idx == -1: break
        ctx = data[max(0,idx-12):idx+20]
        ctx_hex = ctx.hex()
        ctx_asc = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in ctx)
        results.append((idx, ctx_hex, ctx_asc))
        offset = idx + 1
    return results

# Load libraries
libraries = {
    'libagame.so': open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb').read(),
    'libhades.so': open(r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\lib\arm64-v8a\libhades.so', 'rb').read(),
}

# Strings to search
searches = [
    # File extensions
    (b'.mt', '.mt'),
    (b'.lua', '.lua'),
    (b'.luac', '.luac'),
    (b'.json', '.json'),
    (b'.plist', '.plist'),
    
    # Directory paths
    (b'assets/f', 'assets/f'),
    (b'assets/level', 'assets/level'),
    (b'assets/', 'assets/'),
    
    # Asset file separators
    (b'/f/', '/f/'),
    (b'/level/', '/level/'),
    (b'script/', 'script/'),
    (b'lua/', 'lua/'),
    
    # File operations
    (b'getFile', 'getFile'),
    (b'FileUtils', 'FileUtils'),
    (b'openFile', 'openFile'),
    (b'getData', 'getData'),
    (b'loadFile', 'loadFile'),
    
    # Roo-related
    (b'Roo', 'Roo'),
    (b'rOO', 'rOO'),
    (b'ROO', 'ROO'),
    
    # Hades-related 
    (b'Hades', 'Hades'),
    (b'hades', 'hades'),
    
    # Decryption/loading
    (b'lmF', 'lmF'),
    (b'LMF', 'LMF'),
    (b'Antm', 'Antm'),
    (b'antm', 'antm'),
    
    # Container format magics
    (b'\x1bLm', '\\x1bLm'),
    (b'\x1bLu', '\\x1bLu'),
    
    # Additional asset loading
    (b'.skeleton', '.skeleton'),
    (b'.skel', '.skel'),
    (b'.atlas', '.atlas'),
    (b'.png', '.png'),
    (b'.jpg', '.jpg'),
]

for lib_name, lib_data in libraries.items():
    print('=' * 70)
    print('{} ({} bytes)'.format(lib_name, len(lib_data)))
    print('=' * 70)
    
    for needle, label in searches:
        results = find_all_str(lib_data, needle, 10)
        if results:
            print('  "{}": {} occurrences'.format(label, len(results)))
            for idx, ctx_hex, ctx_asc in results[:5]:
                print('    0x{:x}: {} | {}'.format(idx, ctx_asc, ctx_hex[:48]))
            if len(results) > 5:
                print('    ... and {} more'.format(len(results)-5))
    print()
