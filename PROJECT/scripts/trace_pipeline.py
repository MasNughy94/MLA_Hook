"""
Trace the full pipeline: find orchestrator function that contains both
the Antm check and the subsequent processing stages.

Start from the callers of the Antm checker, find their enclosing functions,
and trace everything.
"""

import struct

so = open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb').read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def disasm_range(start_addr, count=50):
    """Disassemble a range returning instruction bytes."""
    start_file = start_addr - TEXT_ADDR + TEXT_OFF
    result = {}
    for i in range(count):
        off = start_file + i * 4
        if off >= TEXT_OFF + TEXT_SIZE:
            break
        result[start_addr + i * 4] = struct.unpack_from('<I', so, off)[0]
    return result

def find_func_start(addr, max_lookback=200):
    """Find function prologue going backwards from addr."""
    file_off = addr - TEXT_ADDR + TEXT_OFF
    for lookback in range(0, max_lookback):
        check_off = file_off - lookback * 4
        check_addr = addr - lookback * 4
        if check_off < TEXT_OFF:
            break
        instr = struct.unpack_from('<I', so, check_off)[0]
        
        # Check for common function prologue patterns:
        # 1. STP X29, X30, [SP, #imm]!  (pre-index)
        # Top byte 0xA8 for 64-bit
        if (instr & 0xFF000000) == 0xA8000000:
            rt = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            rt2 = (instr >> 10) & 0x1F
            if rt == 29 and rt2 == 30 and rn == 31:  # X29, X30, SP
                return check_addr, 'STP_pre'
        
        # 2. STP X29, X30, [SP, #imm]  (unsigned offset)
        if (instr & 0xFF000000) == 0xA9000000:
            rt = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            rt2 = (instr >> 10) & 0x1F
            if rt == 29 and rt2 == 30 and rn == 31:
                return check_addr, 'STP_off'
        
        # 3. STP X29, X30, [SP, #imm] - also 0xA9BF7BFD variant
        if instr == 0xA9BF7BFD:  # Exact match for common prologue
            return check_addr, 'STP_exact'
    
    return None, None

def find_bl_callers_in_range(target, start_addr, end_addr):
    """Find BL calls to target within address range."""
    start_file = start_addr - TEXT_ADDR + TEXT_OFF
    end_file = end_addr - TEXT_ADDR + TEXT_OFF
    callers = []
    for file_off in range(start_file, end_file, 4):
        instr = struct.unpack_from('<I', so, file_off)[0]
        if (instr >> 26) == 0x25:  # BL
            imm26 = instr & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 |= 0xFC000000
            target_addr = TEXT_ADDR + (file_off - TEXT_OFF) + (imm26 << 2)
            if target_addr == target:
                callers.append(TEXT_ADDR + (file_off - TEXT_OFF))
    return callers

def show_func_context(func_start, num_instr=80):
    """Show instructions at function start."""
    instrs = disasm_range(func_start, num_instr)
    addrs = sorted(instrs.keys())
    for addr in addrs:
        instr = instrs[addr]
        # Simple decode
        decoded = ''
        if (instr >> 26) == 0x25:  # BL
            imm26 = instr & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 |= 0xFC000000
            target = addr + (imm26 << 2)
            decoded = 'BL      0x{:x}'.format(target)
        elif (instr >> 26) == 0x05:  # B (uncond)
            imm26 = instr & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 |= 0xFC000000
            target = addr + (imm26 << 2)
            decoded = 'B       0x{:x}'.format(target)
        elif (instr & 0xFFFFFC00) == 0xD63F0000:  # BLR
            decoded = 'BLR     X{}'.format(instr & 0x1F)
        elif (instr >> 24) == 0x90:  # ADRP
            immhi = (instr >> 5) & 0x7FFFF
            immlo = (instr >> 29) & 3
            if immhi & 0x40000:
                immhi |= 0xFFF80000
            imm = (immhi << 2) | immlo
            Rd = instr & 0x1F
            target_page = (addr & ~0xFFF) + (imm << 12)
            decoded = 'ADRP    X{}, 0x{:x}'.format(Rd, target_page)
        elif (instr & 0xFF000000) == 0x91000000:  # ADD (immediate, 64-bit)
            Rd = instr & 0x1F
            Rn = (instr >> 5) & 0x1F
            imm12 = (instr >> 10) & 0xFFF
            decoded = 'ADD     X{}, X{}, #0x{:x}'.format(Rd, Rn, imm12)
        elif ((instr >> 29) & 3) == 2 and not (instr & 0x20000000):  # MOVZ 32-bit
            hw = (instr >> 21) & 3
            imm16 = (instr >> 5) & 0xFFFF
            Rd = instr & 0x1F
            shift_str = ', LSL #{}'.format(hw*16) if hw else ''
            decoded = 'MOVZ    W{}, #0x{:04x}{}'.format(Rd, imm16, shift_str)
        elif ((instr >> 29) & 3) == 3 and not (instr & 0x20000000):  # MOVK 32-bit
            hw = (instr >> 21) & 3
            imm16 = (instr >> 5) & 0xFFFF
            Rd = instr & 0x1F
            decoded = 'MOVK    W{}, #0x{:04x}, LSL #{}'.format(Rd, imm16, hw*16)
        elif instr == 0xD65F03C0:  # RET
            decoded = 'RET'
        elif instr == 0xAA0003E0:  # MOV X0, X0 (NOP-like)
            decoded = 'MOV     X0, X0'
        elif (instr >> 25) == 0x54 or (instr >> 25) == 0x55:  # B.cond
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 |= 0xFFF80000
            cond = instr & 0xF
            target = addr + (imm19 << 2)
            decoded = 'B.{}     0x{:x}'.format(cond, target)
        elif (instr >> 24) == 0x34 or (instr >> 24) == 0x35:  # CBZ/CBNZ
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 |= 0xFFF80000
            Rt = instr & 0x1F
            target = addr + (imm19 << 2)
            if (instr >> 24) == 0x34:
                decoded = 'CBZ    W{}, 0x{:x}'.format(Rt, target)
            else:
                decoded = 'CBNZ   W{}, 0x{:x}'.format(Rt, target)
        
        if decoded:
            print('  0x{:x}: {:08x}  {}'.format(addr, instr, decoded))
        else:
            print('  0x{:x}: {:08x}'.format(addr, instr))

# ===== Function at 0x7D2AC0 (caller 1) =====
print('=' * 60)
print('Caller 1: BL at 0x7D2AC0 to Antm checker')
print('=' * 60)

# Find function containing 0x7D2AC0
func_start, prologue_type = find_func_start(0x7D2AB0)
print('Function start: 0x{:x} (type: {})'.format(func_start, prologue_type))
show_func_context(func_start, 40)

print('\n' + '=' * 60)
print('Caller 2: BL at 0xC630CC to Antm checker')
print('=' * 60)

func_start2, pt2 = find_func_start(0xC630BC)
print('Function start: 0x{:x} (type: {})'.format(func_start2, pt2))

# Check if this is the same function as 0xC82AB0 (the larger Antm handler)
print('\nRelation check: is 0xC630CC inside the function at 0xC82AB0?')
if func_start2 == 0xC82AB0:
    print('  YES - same as the function starting at 0xC82AB0')
    show_func_context(0xC82AB0, 120)
else:
    print('  NO - different function')
    show_func_context(func_start2, 40)

# Now let me also look at the FULL IMAGE: 
# What does the loader function look like?
# Search for function that calls itself with filenames
print('\n' + '=' * 60)
print('Looking for .mt file reading (searching for getFileData/CCFileUtils)')
print('=' * 60)

# Search for the function that calls BOTH getFileData AND the Antm pipeline
# Let me look at what the orchestrator calls
# The function at 0xC82AB0 seems important - let me see more of it
print('\nExtended view of function at 0xC82AB0:')
show_func_context(0xC82AB0, 180)
