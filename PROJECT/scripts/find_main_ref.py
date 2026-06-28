import struct
from capstone import *

so = open(r'C:\Users\NGEONG\Videos\VSCODE\libagame.so', 'rb').read()

# Check string at 0xdf8b98
end = so.find(b'\x00', 0xdf8b98)
s = so[0xdf8b98:end].decode(errors='replace')
print('String at 0xdf8b98:', repr(s))

# Check the 0x5b2714 function (called from XXTEA path in luaLoadBuffer)
print('\n=== Function at 0x5b2714 (called from XXTEA path) ===')
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
code = so[0x5b2714:0x5b2714+0x100]
for i in md.disasm(code, 0x5b2714):
    line = '  0x{:x}: {} {}'.format(i.address, i.mnemonic, i.op_str)
    print(line)

# Also check what the luaU_undump does after reading the header
print('\n=== luaU_undump (0x6825c0) post-header-check ===')
code = so[0x6826c4:0x6826c4+0x80]
for i in md.disasm(code, 0x6826c4):
    line = '  0x{:x}: {} {}'.format(i.address, i.mnemonic, i.op_str)
    print(line)
