"""
Find xrefs to AES decrypt functions - these are the callers that use the key
"""
from capstone import *
import struct

with open(r'H:\PROJECTMOD\OriginalAPK\lib\arm64-v8a\libagame.so', 'rb') as f:
    data = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

text_start = 0x3fc000
text_end = text_start + 10461676

# Targets: all AES-related functions
targets = {
    'aes_decrypt(str,str,str)': 0xcedfe4,
    'aes_decrypt(str,str)': 0xcedffc,
    'aes_decrypt(cstr,cstr,str,str)': 0xcedf34,
    'aes_decrypt(cstr,cstr,str,cstr,int)': 0xcec5c0,
    'aes_encrypt(str,str,str)': 0xced7a8,
    'cbc_decrypt': 0xced91c,
    'cbc_decrypt2': 0xcebe18,
    'fromHex': 0xcec900,
    'uncompressData': 0xcecd24,
}

print('Searching for BL calls to AES functions...')
for name, target in targets.items():
    count = 0
    callers = []
    for offset in range(text_start, text_end - 4, 4):
        inst_bytes = data[offset:offset+4]
        inst_val = struct.unpack('<I', inst_bytes)[0]
        opcode = (inst_val >> 26) & 0x3F
        if opcode == 0x25:  # BL
            imm26 = inst_val & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 |= 0xFC000000
            bl_target = offset + (imm26 << 2)
            if bl_target == target:
                count += 1
                if count <= 5:
                    callers.append(offset)
    print(f'  {name}: {count} BL calls')
    for caller in callers:
        # Show surrounding code
        code = data[max(text_start, caller-20):min(text_end, caller+16)]
        print(f'    Caller at 0x{caller:x}:')
        for i in md.disasm(code, max(text_start, caller-20)):
            marker = ' <--- CALL' if i.address == caller else ''
            print(f'      0x{i.address:x}: {i.mnemonic} {i.op_str}{marker}')

# Also check for Java_com_moonton or JNI functions that might set the key
print('\nSearching for JNI functions related to crypto...')
for offset in range(text_start, text_end - 4, 4):
    inst_bytes = data[offset:offset+4]
    inst_val = struct.unpack('<I', inst_bytes)[0]
    opcode = (inst_val >> 26) & 0x3F
    if opcode == 0x25:  # BL
        imm26 = inst_val & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 |= 0xFC000000
        bl_target = offset + (imm26 << 2)
        # Check if target is setKey or fromHex
        if bl_target in [0xceca74, 0xcecb5c, 0xcec900]:
            # Show context to identify the calling function
            code = data[max(text_start, offset-40):min(text_end, offset+8)]
            disasm = list(md.disasm(code, max(text_start, offset-40)))
            if disasm:
                # Find the function start (look for stp x29, x30 pattern backwards)
                func_start = offset
                for inst in reversed(disasm):
                    if inst.mnemonic == 'stp' and 'x29' in inst.op_str and 'x30' in inst.op_str:
                        func_start = inst.address
                        break
                if func_start == offset:
                    # Try to find function start by looking back in the binary
                    for check in range(offset - 200, offset):
                        try:
                            check_inst = list(md.disasm(data[check:check+4], check))
                            if check_inst and check_inst[0].mnemonic == 'stp' and 'x29' in check_inst[0].op_str:
                                func_start = check
                                break
                        except:
                            pass
                
                fname = f'func_{bl_target:x}_caller'
                target_name = [n for n, a in targets.items() if a == bl_target]
                tname = target_name[0] if target_name else f'0x{bl_target:x}'
                print(f'  {fname} calls {tname} at 0x{offset:x} (func start ~0x{func_start:x})')
