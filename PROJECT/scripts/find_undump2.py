from capstone import *
import struct

so = open(r'C:\Users\NGEONG\Videos\VSCODE\libagame.so', 'rb').read()

# List error strings from Lua undump
for s in [b'bad header', b'bad constant', b'bad code', b'bad description', 
          b'bad instruction', b'invalid string table value', b'invalid universal']:
    idx = so.find(s)
    if idx >= 0:
        ctx = so[idx-4:idx+len(s)+4]
        hexstr = ' '.join(f'{b:02x}' for b in ctx)
        asciistr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f'  "{s.decode()}" at 0x{idx:x}: {hexstr}  "{asciistr}"')

# Find function that references these error messages
# The Lua undump function normally has instruction like:
# adrp x1, .rodata
# add x1, x1, #offset_of_error_string
# bl _luaG_runerror (or similar)

# Let me search for occurrences of the bad_header address (0xeb7820) in code
# In ARM64, the ADD instruction would compute the address from ADRP
# The ADRP could point to page 0xeb7000 and ADD with 0x820

print('\nLooking for ADRP to page of bad_header strings...')
str_page = 0xeb7000  # page containing 'bad header' at 0xeb7820

# Search for ADRP instructions (bit pattern: 1 0 0 0 0 ...)
# ADRP has top byte 0x90 for positive offsets, 0xB0 for negative
# Actually ADRP format: 1 0 0 0 0 imm_hi 1 0 0 0 0 imm_lo Rd
# Byte pattern varies widely. Let me search for a known instruction pattern.

# Instead, let me search for the function that has both 'bad header' and 'bad constant'
# references. They should be in close functions.

bad_header_addr = 0xeb7820
bad_constant_addr = 0xeb77e8

print(f'bad_header at VA: 0x{bad_header_addr:x}')
print(f'bad_constant at VA: 0x{bad_constant_addr:x}')

# Find code references to these addresses
# In ARM64 with PIC, the pattern would be:
# ADRP Xd, ((addr & ~0xFFF) - PC_adj)
# ADD/LDR Xd, Xd, (addr & 0xFFF)
# Then BL to error handler

# Or maybe use literal pool:
# LDR Xd, [PC, #offset]  where the literal contains the string address

# Let me search for the page number in code sections
# The page 0xeb7000 would be loaded via ADRP with immediate = (0xeb7000 - PC_page) >> 12

# Try another approach: look for LDR pseudo-instructions 
# (ADRP + ADD or LDR literal) that resolve to these pages

# Actually, let me look at what functions call luaL_loadbuffer
# luaL_loadbuffer is the standard Lua loading API
idx = so.find(b'luaL_loadbuffer')
if idx >= 0:
    # Find the nearby function names
    ctx_start = max(0, idx - 80)
    ctx_end = min(len(so), idx + 80)
    ctx = so[ctx_start:ctx_end]
    print(f'\nContext around luaL_loadbuffer:')
    for i in range(0, len(ctx), 16):
        chunk = ctx[i:i+16]
        hexstr = ' '.join(f'{b:02x}' for b in chunk)
        asciistr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'  {ctx_start+i:#x}: {hexstr:<48s} {asciistr}')
