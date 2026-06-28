import struct

pipeline_funcs = set()

with open(r'C:\Users\NGEONG\Videos\VSCODE\libagame.so', 'rb') as f:
    data = f.read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

# Check BL instructions in the Antm pipeline areas
areas = [(0x7D2888, 0x7D3100), (0xC62F60, 0xC63800)]

for area_start, area_end in areas:
    for off in range(area_start - TEXT_ADDR + TEXT_OFF, area_end - TEXT_ADDR + TEXT_OFF, 4):
        addr = TEXT_ADDR + (off - TEXT_OFF)
        instr = struct.unpack_from('<I', data, off)[0]
        if (instr >> 26) == 0x25:
            imm26 = instr & 0x03FFFFFF
            if imm26 >= 0x2000000:
                imm26 -= 0x4000000
            target = addr + (imm26 << 2)
            if TEXT_ADDR <= target < TEXT_ADDR + TEXT_SIZE:
                pipeline_funcs.add(target)

print('Functions called from Antm pipeline: {}'.format(len(pipeline_funcs)))

# Also check: is the LMF decompressor (0x5B2400) in the pipeline?
print('LMF decompressor (0x5B2400) in pipeline: {}'.format(0x5B2400 in pipeline_funcs))

# What ARE all the called functions?
for f in sorted(pipeline_funcs):
    if f < 0x40000000:
        print('  0x{:x}'.format(f))
