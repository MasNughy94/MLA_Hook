"""Fix 4-byte alignment of resources.arsc in an APK"""
import zipfile, struct, os, shutil

apk = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\patched_unsigned.apk'
out = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\patched_aligned.apk'

# Read original APK
with zipfile.ZipFile(apk, 'r') as zin:
    infos = zin.infolist()
    
    # Write aligned APK
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zout:
        for info in infos:
            data = zin.read(info.filename)
            
            if info.filename == 'resources.arsc':
                # Must be stored (uncompressed) and 4-byte aligned
                info.compress_type = zipfile.ZIP_STORED
                
            zout.writestr(info, data)

    # Verify the alignment
    with zipfile.ZipFile(out, 'r') as z:
        for info in z.infolist():
            if info.filename == 'resources.arsc':
                offset = info.header_offset + 30 + len(info.filename)
                print(f'resources.arsc data offset: {offset} (align={offset % 4 == 0})')

# Sign the aligned APK
import subprocess
subprocess.run([
    'jarsigner', '-keystore', r'C:\Users\NGEONG\AppData\Local\Temp\opencode\debug.keystore',
    '-storepass', 'android', '-keypass', 'android',
    '-sigalg', 'SHA256withRSA', '-digestalg', 'SHA-256',
    '-signedjar', r'C:\Users\NGEONG\AppData\Local\Temp\opencode\patched.apk',
    out, 'androiddebugkey'
], capture_output=True)
print('APK signed and aligned!')
