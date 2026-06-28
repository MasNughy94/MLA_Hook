"""
Extract ALL BL calls from the two functions that call the Antm checker.
This traces the full decryption pipeline.
"""

import struct

so = open(r'C:\Users\NGEONG\Videos\VSCODE\libagame.so', 'rb').read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def extract_bl_calls(func_start, max_size=0x1000):
    """Extract all BL instructions from a function."""
    start_off = func_start - TEXT_ADDR + TEXT_OFF
    calls = []
    
    for offset in range(start_off, start_off + max_size, 4):
        if offset >= TEXT_OFF + TEXT_SIZE:
            break
        instr = struct.unpack_from('<I', so, offset)[0]
        addr = TEXT_ADDR + (offset - TEXT_OFF)
        
        if (instr >> 26) == 0x25:  # BL
            imm26 = instr & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 |= 0xFC000000
            target = addr + (imm26 << 2)
            calls.append((addr, target, 'BL'))
        elif instr == 0xD65F03C0:  # RET
            # Found return - this is end of function 
            # (but might not be the only return)
            pass
    
    return calls

# Two callers of Antm checker:
# Function 1: 0x7D2888 contains BL at 0x7D2AC0 -> Antm checker
# Function 2: 0xC62F60 contains BL at 0xC630CC -> Antm checker

print('=' * 60)
print('Function 1 at 0x7D2888 - BL calls:')
print('=' * 60)
calls1 = extract_bl_calls(0x7D2888, 0x800)
for addr, target, kind in sorted(calls1):
    print('  0x{:x}: {} -> 0x{:x}'.format(addr, kind, target))

# Let me also look at the CALLERS of functions in this chain
# Find who calls the orchestrator at 0x7D2888
print('\n' + '=' * 60)
print('Callers of function at 0x7D2888:')
print('=' * 60)
callers_of_f1 = []
for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 4, 4):
    instr = struct.unpack_from('<I', so, file_off)[0]
    if (instr >> 26) == 0x25:
        imm26 = instr & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 |= 0xFC000000
        target = TEXT_ADDR + (file_off - TEXT_OFF) + (imm26 << 2)
        if target == 0x7D2888:
            callers_of_f1.append(TEXT_ADDR + (file_off - TEXT_OFF))

for addr in sorted(callers_of_f1):
    print('  BL from 0x{:x}'.format(addr))

# Now look at function 2
print('\n' + '=' * 60)
print('Function 2 at 0xC62F60 - BL calls:')
print('=' * 60)
calls2 = extract_bl_calls(0xC62F60, 0x800)
for addr, target, kind in sorted(calls2):
    print('  0x{:x}: {} -> 0x{:x}'.format(addr, kind, target))

# Callers of function 2
print('\n')
print('Callers of function at 0xC62F60:')
callers_of_f2 = []
for file_off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 4, 4):
    instr = struct.unpack_from('<I', so, file_off)[0]
    if (instr >> 26) == 0x25:
        imm26 = instr & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 |= 0xFC000000
        target = TEXT_ADDR + (file_off - TEXT_OFF) + (imm26 << 2)
        if target == 0xC62F60:
            callers_of_f2.append(TEXT_ADDR + (file_off - TEXT_OFF))

for addr in sorted(callers_of_f2):
    print('  BL from 0x{:x}'.format(addr))

# Check for a THIRD orchestrator - the .mt entry point
# Search for function that calls both getFileData and the pipeline
print('\n' + '=' * 60)
print('Looking for top-level loader (checks file extension .mt, calls pipeline)')
print('=' * 60)
# We know ".mt" string at 0xDFC1F8 is referenced from 0x47420C and 0x47445C (in cocos2dx_lua_loader)
# Let me check if the pipeline functions are called from cocos2dx_lua_loader
print('Is pipeline called from cocos2dx_lua_loader (0x474028 area)?')
for addr in [0x7D2888, 0xC62F60, 0xC82A80]:
    for file_off in range(0x474028 - TEXT_ADDR + TEXT_OFF, 
                          0x474028 + 2052 - TEXT_ADDR + TEXT_OFF, 4):
        instr = struct.unpack_from('<I', so, file_off)[0]
        caller_addr = TEXT_ADDR + (file_off - TEXT_OFF)
        if (instr >> 26) == 0x25:
            imm26 = instr & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 |= 0xFC000000
            target = caller_addr + (imm26 << 2)
            if target == addr:
                print('  YES: 0x{:x} calls 0x{:x} from lua_loader'.format(caller_addr, addr))
