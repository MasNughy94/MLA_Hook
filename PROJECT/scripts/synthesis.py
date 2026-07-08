"""
Final synthesis: trace the decompressed buffer from LMF output through all consumers.
Let me also verify the consumer destination 0xC828F8.
"""

import struct

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    data = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def decode_target(addr, instr):
    """Decode B/BL target from instruction."""
    if (instr >> 26) == 0x25 or (instr >> 26) == 0x05:
        imm26 = instr & 0x03FFFFFF
        if imm26 >= 0x2000000: imm26 -= 0x4000000
        target = addr + (imm26 << 2)
        return ('BL' if (instr >> 26) == 0x25 else 'B '), target
    return None, None

def dump(addr, count=30):
    off = addr - TEXT_ADDR + TEXT_OFF
    for i in range(count):
        instr = struct.unpack_from('<I', data, off + i*4)[0]
        a = addr + i*4
        kind, target = decode_target(a, instr)
        if kind:
            print('  0x{:x}: {:08x} {} 0x{:x}'.format(a, instr, kind, target))
        elif instr == 0xD65F03C0:
            print('  0x{:x}: {:08x} RET'.format(a, instr))
            return  # stop at end of tiny function
            break
        else:
            print('  0x{:x}: {:08x}'.format(a, instr))

# 1. The consumer at 0xC82944 is B to 0xC828F8
# Let me check what's at 0xC828F8
print('=== 0xC828F8 (consumer destination) ===')
dump(0xC828F8, 15)

# This is between other functions. Let me expand the region
print('\n=== Full region 0xC828DC-0xC82970 ===')
for a in range(0xC828DC, 0xC82970, 4):
    instr = struct.unpack_from('<I', data, a - TEXT_ADDR + TEXT_OFF)[0]
    kind, target = decode_target(a, instr)
    if kind:
        print('  0x{:x}: {:08x} {} 0x{:x}'.format(a, instr, kind, target))
    elif instr == 0xD65F03C0:
        print('  0x{:x}: {:08x} RET'.format(a, instr))
    else:
        print('  0x{:x}: {:08x}'.format(a, instr))

# Now trace the Antm pipeline through cocos2dx_lua_loader
# Show the FULL cocos2dx_lua_loader function in terms of BL calls
print('\n=== cocos2dx_lua_loader BL calls (0x474028 area) ===')
func_start = 0x474028
off = func_start - TEXT_ADDR + TEXT_OFF
for i in range(220):  # function is ~2052 bytes = 513 instructions
    instr = struct.unpack_from('<I', data, off + i*4)[0]
    a = func_start + i*4
    kind, target = decode_target(a, instr)
    if kind:
        print('  0x{:x}: {} 0x{:x}'.format(a, kind, target))
    elif instr == 0xD65F03C0:
        print('  0x{:x}: RET'.format(a))
        break

# Also check the key call at 0x474300 context more precisely  
print('\n=== Context at 0x474300 (the luaLoadBuffer call site) ===')
dump(0x4742E0, 50)
