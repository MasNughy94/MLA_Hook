"""
Full trace of ALL .mt file loading paths.
First, check: does cocos2dx_lua_loader have a fallback that returns raw data to Lua?
Then trace ALL other file loading paths.
"""

import struct

with open(r'C:\Users\NGEONG\Videos\VSCODE\libagame.so', 'rb') as f:
    data = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def show_func(addr, count=80):
    """Show function with BL/B/RET decoded."""
    off = addr - TEXT_ADDR + TEXT_OFF
    for i in range(count):
        if off + i*4 >= TEXT_OFF + TEXT_SIZE: break
        instr = struct.unpack_from('<I', data, off + i*4)[0]
        a = addr + i*4
        
        if (instr >> 26) == 0x25:  # BL
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000: imm26 -= 0x4000000
            target = a + (imm26 << 2)
            if TEXT_ADDR <= target < TEXT_ADDR + TEXT_SIZE:
                print('  0x{:x}: BL      0x{:x}'.format(a, target))
            else:
                print('  0x{:x}: BL      (0x{:x})'.format(a, target))
        elif (instr >> 26) == 0x05:  # B
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000: imm26 -= 0x4000000
            target = a + (imm26 << 2)
            if TEXT_ADDR <= target < TEXT_ADDR + TEXT_SIZE:
                print('  0x{:x}: B       0x{:x}'.format(a, target))
            else:
                print('  0x{:x}: B       (0x{:x})'.format(a, target))
        elif instr == 0xD65F03C0:
            print('  0x{:x}: RET'.format(a))
            return  # stop at RET
        elif (instr >> 24) == 0x34:  # CBZ Wt
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            print('  0x{:x}: CBZ    W{}, 0x{:x}'.format(a, instr & 0x1F, target))
        elif (instr >> 24) == 0x35:  # CBNZ Wt
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            print('  0x{:x}: CBNZ   W{}, 0x{:x}'.format(a, instr & 0x1F, target))
        elif (instr >> 24) == 0xB4:  # CBZ Xt
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            print('  0x{:x}: CBZ    X{}, 0x{:x}'.format(a, instr & 0x1F, target))
        elif (instr >> 24) == 0xB5:  # CBNZ Xt
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            print('  0x{:x}: CBNZ   X{}, 0x{:x}'.format(a, instr & 0x1F, target))
        elif (instr >> 24) == 0x54 or (instr >> 24) == 0x55:  # B.cond
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 >= 0x40000: imm19 |= 0xFFF80000
            target = a + (imm19 << 2)
            cond = instr & 0xF
            print('  0x{:x}: B.{}    0x{:x}'.format(a, cond, target))
        else:
            print('  0x{:x}: {:08x}'.format(a, instr))

# ============================================================
# 1. FULL cocos2dx_lua_loader with all BL targets decoded
# ============================================================
print('=' * 70)
print('1. FULL cocos2dx_lua_loader (0x474028)')
print('=' * 70)
show_func(0x474028, 130)

# ============================================================
# 2. Check what 0x46ECB4 is (file reader?) - called at 0x4742E8
# ============================================================
print('\n' + '=' * 70)
print('2. Function 0x46ECB4 (called from lua_loader - file reader?)')
print('=' * 70)
show_func(0x46ECB4, 80)

# ============================================================
# 3. Check what 0x964510 is (called at 0x474074, 0x47408C)
# ============================================================
print('\n' + '=' * 70)
print('3. Function 0x964510 (cocos2dx header detection?)')
print('=' * 70)
show_func(0x964510, 30)

# ============================================================
# 4. Check what 0x9B14E0 is (called at 0x4742E0)
# ============================================================
print('\n' + '=' * 70)
print('4. Function 0x9B14E0 (called before luaLoadBuffer)')
print('=' * 70)
show_func(0x9B14E0, 30)

# ============================================================
# 5. NOW SEARCH FOR OTHER FILE LOADING PATHS
# Look for functions that call BOTH getFileData AND the Antm pipeline
# Also search for any function that opens files with "library.so" or other binaries
# ============================================================
print('\n' + '=' * 70)
print('5. SEARCHING FOR ALL FUNCTIONS THAT READ FILE DATA AND CONSUME IT')
print('=' * 70)

# First, find ALL functions that call 0x7D27E8 or 0xC62F60 (the pipeline functions)
# outside the already-known paths
antm_pipeline_funcs = [0x7D27E8, 0x7D2888, 0xC62F60, 0xC612BC]

print('\nFunctions that call the Antm pipeline:')
for search_target in antm_pipeline_funcs:
    callers = []
    for off in range(TEXT_OFF, TEXT_OFF + TEXT_SIZE - 4, 4):
        instr = struct.unpack_from('<I', data, off)[0]
        if (instr >> 26) == 0x25:  # BL
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000: imm26 -= 0x4000000
            addr = TEXT_ADDR + (off - TEXT_OFF)
            target = addr + (imm26 << 2)
            if target == search_target:
                callers.append(addr)
    if callers:
        print('  Callers of 0x{:x}:'.format(search_target))
        for c in sorted(callers):
            print('    0x{:x}'.format(c))

# Search for "sprintf" or "snprintf" with .mt format strings
# Looking for functions that construct .mt filenames
print('\nSearching for format strings that could construct .mt paths:')
for s in [b'%s/%s.mt', b'assets/%s/%s.mt', b'%s.mt', b'.mt', b'f/%.*s']:
    idx = data.find(s)
    if idx != -1:
        ctx = data[max(0,idx-4):idx+24]
        print('  "{}" at data+0x{:x}: {}'.format(s.decode(), idx, ctx.hex()))

# Check for CCFileUtilsAndroid::getDataFromFile or other file readers
print('\nSearching for file reading function calls:')
# Check for Android asset manager calls
for s in [b'AAssetManager', b'AAsset_open', b'AAsset_read']:
    idx = data.find(s)
    if idx != -1:
        ctx = data[max(0,idx-4):idx+32]
        asc = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in ctx)
        print('  "{}" at data+0x{:x}: {}'.format(s.decode(), idx, asc))
