"""
Trace the function containing the "Antm" magic comparison.
Look for function prologue (STP X29, X30, [SP, #...]!) and
function calls (BL/BLR) to understand the flow.
"""

import struct

so = open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb').read()

TEXT_ADDR = 0x3FC000
TEXT_OFF = 0x3FC000
TEXT_SIZE = 0x9FA1EC

def disasm(addr, count=20):
    """Disassemble a range of instructions, returning list of (addr, hex, mnemonic)."""
    file_off = addr - TEXT_ADDR + TEXT_OFF
    result = []
    for i in range(count):
        off = file_off + i * 4
        if off >= TEXT_OFF + TEXT_SIZE:
            break
        instr = struct.unpack_from('<I', so, off)[0]
        result.append((addr + i * 4, instr))
    return result

def find_function_start(addr):
    """Walk backwards from addr to find function prologue."""
    file_off = addr - TEXT_ADDR + TEXT_OFF
    # Walk back up to 200 instructions (800 bytes)
    for lookback in range(0, 200):
        check_off = file_off - lookback * 4
        check_addr = addr - lookback * 4
        if check_off < TEXT_OFF:
            break
        instr = struct.unpack_from('<I', so, check_off)[0]
        # STP X29, X30, [SP, #imm]!  encoding:
        # STP: opc=10, bits[31:30]=10
        # X29, X30 registers
        # Store Pair: 1010 1001 0|imm7|Rt2|Rn|Rt
        # STP X29, X30, [SP, #imm]!: 
        # RT=X29(29), RT2=X30(30), Rn=SP(31)
        # 101010010 | imm7 | 11110 | 11111 | 11101
        # 0xA9 0x?? | imm7 >> 8 | BE/BL/etc
        # Actually STP (pre-index): 101010010|imm7|Rt2|Rn|Rt
        # For X29, X30 with SP: 101010010|imm7|11110(30)|11111(31)|11101(29)
        # bits[31:24] = 10101001 = 0xA9
        # bits[23:22] = 0|(imm7>>6) = depends on imm7
        # bits[21:16] = imm7[5:0] | Rt2[0]
        # bits[15:10] = Rt2 = 011110 = 30 = X30
        # bits[9:5] = Rn = 11111 = 31 = SP
        # bits[4:0] = Rt = 11101 = 29 = X29
        
        # Check for STP X29, X30, [SP, #imm]!: 
        # 0xA9 ??? ???? where bits[15:10]=011110 (30) and bits[9:5]=11111 (31) and bits[4:0]=11101 (29)
        # Simplified: (instr & 0xFC1F83FF) == 0xA81F83ED? 
        # Let me check:
        # bits[31:24] = 10101001 = 0xA9
        # bits[23:22] = imm7[6:5] (varies)
        # bits[21:16] = imm7[4:0] | Rt2[0]... hmm
        # 
        # Actually, let me just check for the top byte = 0xA9 and appropriate register fields
        # RT2=30=011110 at bits[15:10]
        # Rn=31=11111 at bits[9:5]
        # RT=29=11101 at bits[4:0]
        # So bits[15:0] = 011110 11111 11101 = 0x7BED or 0x7BEF depending
        # Actually: bits[4:0] = 11101 = 29 = X29
        # bits[9:5] = 11111 = 31 = SP
        # bits[15:10] = 011110 = 30 = X30
        # So bits[15:0] = 011110 11111 11101 = 0b0111 1011 1111 1101 = 0x7BFD
        # But wait, this is in little-endian instruction encoding.
        # bits[15:0] as LE halfword: (30 << 10) | (31 << 5) | 29 = 0x7BED
        # 
        # Let me just check a simpler pattern:
        # Top byte = 0xA9 (STP)
        # Check that RT2=X30 and RT=X29 and Rn=SP
        
        if (instr & 0xFF000000) == 0xA9000000 or (instr & 0xFF000000) == 0xA8000000:
            rt = instr & 0x1F
            rn = (instr >> 5) & 0x1F
            rt2 = (instr >> 10) & 0x1F
            if rt == 29 and rt2 == 30 and rn == 31:
                # Found function prologue
                return check_addr, instr
        # Also check for SUB SP, SP, #imm (function prologue with large frame)
        # SUB SP, SP, #imm: 1 0 0 1 0 0 0 1 0 0 | imm12 | Rn(SP=31) | Rd(SP=31)
        # = 0xD1000000 | (imm12 << 10) | (31 << 5) | 31
        # But SUB can also be 0xF1000000 for 64-bit
        if (instr & 0xFFC00000) == 0xD1000000:  # SUB SP, SP, #imm (64-bit)
            rn = (instr >> 5) & 0x1F
            rd = instr & 0x1F
            if rn == 31 and rd == 31:
                imm12 = (instr >> 10) & 0xFFF
                if imm12 > 0:
                    # This is typically after STP, could be function start
                    # But STP is more reliable
                    pass
    
    return None, None

# Function at 0xC82A94 - trace backwards
print('=== Function containing 0xC82A94 ===')
func_start, prologue = find_function_start(0xC82A94)
if func_start:
    print('Function start: 0x{:x}'.format(func_start))
    print('Prologue instr: {:08x}'.format(prologue))
    
    # Show the function body
    instrs = disasm(func_start, 80)
    for i, (addr, instr) in enumerate(instrs):
        marker = ' ***' if addr in (0xC82A94, 0xC82AE8) else ''
        
        # Try to decode common ARM64 instructions for readability
        op0 = (instr >> 25) & 0xF
        
        # BL
        if (instr >> 26) == 0x25:
            imm26 = instr & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 |= 0xFC000000
            target = addr + (imm26 << 2)
            print('  0x{:x}: {:08x}  BL      0x{:x}{}'.format(addr, instr, target, marker))
        # B
        elif (instr >> 26) == 0x05:
            imm26 = instr & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 |= 0xFC000000
            target = addr + (imm26 << 2)
            print('  0x{:x}: {:08x}  B       0x{:x}{}'.format(addr, instr, target, marker))
        # BLR
        elif (instr & 0xFFFFFC00) == 0xD63F0000:
            Rn = instr & 0x1F
            print('  0x{:x}: {:08x}  BLR     X{}{}'.format(addr, instr, Rn, marker))
        # ADRP
        elif (instr >> 24) == 0x90:
            immhi = (instr >> 5) & 0x7FFFF
            immlo = (instr >> 29) & 3
            if immhi & 0x40000:
                immhi |= 0xFFF80000
            imm = (immhi << 2) | immlo
            Rd = instr & 0x1F
            target_page = (addr & ~0xFFF) + (imm << 12)
            print('  0x{:x}: {:08x}  ADRP    X{}, 0x{:x}{}'.format(addr, instr, Rd, target_page, marker))
        # ADD (immediate)
        elif (instr >> 23) == 0x91:  # 0x91 << 1 = 0x122 >> 1 = ... 
            # Actually check top byte = 0x91
            print('  0x{:x}: {:08x}  ADD/...{}'.format(addr, instr, marker))
        # MOVZ
        elif ((instr >> 29) & 3) == 2 and (instr & 0x1F000000) == 0:  # 32-bit MOVZ
            hw = (instr >> 21) & 3
            imm16 = (instr >> 5) & 0xFFFF
            Rd = instr & 0x1F
            print('  0x{:x}: {:08x}  MOVZ    W{}, #0x{:04x}{}'.format(addr, instr, Rd, imm16, marker))
        # MOVK
        elif ((instr >> 29) & 3) == 3 and (instr & 0x1F000000) == 0:  # 32-bit MOVK
            hw = (instr >> 21) & 3
            imm16 = (instr >> 5) & 0xFFFF
            Rd = instr & 0x1F
            print('  0x{:x}: {:08x}  MOVK    W{}, #0x{:04x}, LSL #{}{}'.format(addr, instr, Rd, imm16, hw*16, marker))
        # CBZ
        elif ((instr >> 24) == 0xB4):
            print('  0x{:x}: {:08x}  CBZ/...{}'.format(addr, instr, marker))
        # CMP (SUBS)
        elif ((instr >> 24) == 0xF1):
            print('  0x{:x}: {:08x}  CMP/...{}'.format(addr, instr, marker))
        # B.COND
        elif ((instr >> 25) == 0x54) or ((instr >> 25) == 0x55):
            cond = instr & 0xF
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 |= 0xFFF80000
            target = addr + (imm19 << 2)
            print('  0x{:x}: {:08x}  B.{}   0x{:x}{}'.format(addr, instr, cond, target, marker))
        # LDR (immediate, unsigned)
        elif ((instr >> 24) == 0xF9):
            print('  0x{:x}: {:08x}  LDR/...{}'.format(addr, instr, marker))
        elif ((instr >> 24) == 0xB9):
            print('  0x{:x}: {:08x}  STR/...{}'.format(addr, instr, marker))
        else:
            print('  0x{:x}: {:08x}{}'.format(addr, instr, marker))
else:
    print('Could not find function start')
    # Just show disassembly around 0xC82A94
    instrs = disasm(0xC82A00, 60)
    for addr, instr in instrs:
        marker = ' ***' if addr in (0xC82A94, 0xC82AE8) else ''
        print('  0x{:x}: {:08x}{}'.format(addr, instr, marker))
