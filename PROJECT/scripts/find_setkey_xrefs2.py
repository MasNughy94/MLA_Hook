"""
Find xrefs to setKey/setKey2/_getKeyv functions
"""
import struct

with open(r'H:\PROJECTMOD\OriginalAPK\lib\arm64-v8a\libagame.so', 'rb') as f:
    data = f.read()

targets = {
    'setKey': 0xceca74,
    'setKey2': 0xcecb5c,
    '_getKeyv': 0xcebd20,
    'getKey': 0xcec678,
    'getKey2': 0xcec6a4,
}

# Search for references to these addresses in data sections
data_sections = [
    (0x115db00, 0x11d9db0, '.data.rel.ro'),
    (0x11da030, 0x11e8000, '.got'),
    (0x11e8000, 0x11fef30, '.data'),
]

print('References in data sections:')
for name, addr in targets.items():
    addr_bytes = struct.pack('<Q', addr)
    idx = 0
    while True:
        idx = data.find(addr_bytes, idx)
        if idx < 0:
            break
        section_name = 'unknown'
        for start, end, sname in data_sections:
            if start <= idx < end:
                section_name = sname
                break
        print(f'  {name} (0x{addr:x}) referenced at 0x{idx:x} in {section_name}')
        idx += 8

# Now search for BL instructions in text section
text_start = 0x3fc000
text_end = text_start + 10461676

print(f'\nSearching for BL calls in .text (0x{text_start:x} - 0x{text_end:x})...')
for name, target in targets.items():
    count = 0
    for offset in range(text_start, text_end - 4, 4):
        inst_bytes = data[offset:offset+4]
        inst_val = struct.unpack('<I', inst_bytes)[0]
        opcode = (inst_val >> 26) & 0x3F
        if opcode == 0x25:  # BL
            imm26 = inst_val & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 |= 0xFC000000  # sign extend 26->32
            bl_target = offset + (imm26 << 2)
            if bl_target == target:
                print(f'  BL -> {name} at 0x{offset:x}')
                count += 1
                if count >= 5:
                    break
    print(f'  Total: {count} direct BL calls to {name}')

# Also look at callers through BLR (BLR xN) instructions
# BLR opcode = 0b0110101 at bits 24-31 = 0x35
print('\nChecking for BLR instructions...')
# This would require tracking register values, which is very complex
# Let's just note the function isn't directly called frequently
print('(BLR analysis skipped - too complex for static analysis)')
