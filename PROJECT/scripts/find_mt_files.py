"""
Examine original .mt files to understand what they represent.
The .mt files are in the extracted APK/data and are loaded by the game.
"""

import os

# Find .mt files on disk
mt_dir = r'C:\Users\ADMIN SERVICE\Videos\MLA'
mt_files = []
for root, dirs, files in os.walk(mt_dir):
    for f in files:
        if f.endswith('.mt'):
            path = os.path.join(root, f)
            sz = os.path.getsize(path)
            mt_files.append((path, sz))

print('Found {} .mt files:'.format(len(mt_files)))
for path, sz in sorted(mt_files, key=lambda x: -x[1])[:30]:
    print('  {} ({} bytes)'.format(path, sz))

# Also look for other .mt files
mt_dir2 = r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode'
for root, dirs, files in os.walk(mt_dir2):
    for f in files:
        if f.endswith('.mt'):
            path = os.path.join(root, f)
            print('  {} ({} bytes)'.format(path, os.path.getsize(path)))
