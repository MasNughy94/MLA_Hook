import struct
import sys

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    elf = f.read()

e_shoff = struct.unpack_from('<Q', elf, 0x28)[0]
e_shentsize = struct.unpack_from('<H', elf, 0x3a)[0]
e_shnum = struct.unpack_from('<H', elf, 0x3c)[0]
e_shstrndx = struct.unpack_from('<H', elf, 0x3e)[0]
shstrtab_hdr = e_shoff + e_shstrndx * e_shentsize
shstrtab_off = struct.unpack_from('<Q', elf, shstrtab_hdr + 0x18)[0]
shstrtab_sz = struct.unpack_from('<Q', elf, shstrtab_hdr + 0x20)[0]
shstrtab = elf[shstrtab_off:shstrtab_off+shstrtab_sz]

text_addr = text_off = text_size = 0
dynsym_off = 0
dynstr_off = 0
dynsym_sz = 0
gotp_addr = gotp_off = gotp_size = 0
got_addr = got_off = got_size = 0
relaplt_off = relaplt_size = 0

for i in range(e_shnum):
    s = e_shoff + i * e_shentsize
    no = struct.unpack_from('<I', elf, s)[0]
    end = shstrtab.find(b'\x00', no)
    name = shstrtab[no:end].decode()
    a = struct.unpack_from('<Q', elf, s + 0x10)[0]
    o = struct.unpack_from('<Q', elf, s + 0x18)[0]
    z = struct.unpack_from('<Q', elf, s + 0x20)[0]
    if name == '.text': text_addr, text_off, text_size = a, o, z
    elif name == '.dynsym': dynsym_off, dynsym_sz = o, z
    elif name == '.dynstr': dynstr_off = o
    elif name == '.got': got_addr, got_off, got_size = a, o, z
    elif name == '.got.plt': gotp_addr, gotp_off, gotp_size = a, o, z
    elif name == '.rela.plt': relaplt_off, relaplt_size = o, z

# Symbol name lookup
sym_map = {}
if dynsym_sz:
    for i in range(dynsym_sz // 24):
        so = dynsym_off + i * 24
        st_nm = struct.unpack_from('<I', elf, so)[0]
        st_val = struct.unpack_from('<Q', elf, so + 8)[0]
        st_sz = struct.unpack_from('<Q', elf, so + 0x10)[0]
        if st_val and st_sz:
            name = elf[dynstr_off + st_nm:].split(b'\x00')[0].decode(errors='replace')
            sym_map[st_val] = (name, st_sz)

def symof(addr):
    for base, (n, s) in sym_map.items():
        if base <= addr < base + max(s, 1):
            off = addr - base
            return f"{n}+{off}" if off else n
    return ""

# Manual AARCH64 decoder
REG_NAMES = ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9',
             'x10','x11','x12','x13','x14','x15','x16','x17','x18','x19',
             'x20','x21','x22','x23','x24','x25','x26','x27','x28','x29',
             'x30','sp']
WREG = ['w0','w1','w2','w3','w4','w5','w6','w7','w8','w9',
        'w10','w11','w12','w13','w14','w15','w16','w17','w18','w19',
        'w20','w21','w22','w23','w24','w25','w26','w27','w28','w29',
        'w30','wzr']

func_va = 0x407130
func_size = 0xd8
offset = func_va - text_addr
raw = elf[text_off + offset: text_off + offset + func_size]

def decode_adrp(word, pc):
    rd = word & 0x1f
    immlo = (word >> 29) & 3
    immhi = (word >> 5) & 0x7ffff
    imm = (immhi << 2) | immlo
    if imm & 0x80000: imm |= ~0xfffff
    page = (pc & ~0xfff) + (imm << 12)
    return f"adrp {REG_NAMES[rd]}, 0x{page:x}", page

def decode_add_imm(word, pc):
    sf = (word >> 31) & 1
    opc = (word >> 29) & 3
    rd = word & 0x1f
    rn = (word >> 5) & 0x1f
    shift = (word >> 22) & 3
    imm12 = (word >> 10) & 0xfff
    shift_val = shift * 12 if shift else 0
    imm = imm12 << shift_val
    rn_name = REG_NAMES if sf else WREG
    rd_name = REG_NAMES if sf else WREG
    return f"add {rd_name[rd]}, {rn_name[rn]}, #0x{imm:x}"

def decode_ldr_imm(word, pc):
    # LDR Xt, [Xn, #imm12 * 8] (unsigned offset)
    size = word >> 30 & 3
    opc = (word >> 22) & 1
    if size != 3 or opc != 1:  # not 64-bit with opc=11
        return None
    rt = word & 0x1f
    rn = (word >> 5) & 0x1f
    imm12 = (word >> 10) & 0xfff
    shift = imm12 << 3
    return f"ldr {REG_NAMES[rt]}, [{REG_NAMES[rn]}, #0x{shift:x}]"

def decode_ldr_imm32(word, pc):
    size = word >> 30 & 3
    opc = (word >> 24) & 0x1f
    if size == 2 and opc == 0x19:  # 32-bit unsigned offset
        rt = word & 0x1f
        rn = (word >> 5) & 0x1f
        imm12 = (word >> 10) & 0xfff
        shift = imm12 << 2
        return f"ldr {WREG[rt]}, [{REG_NAMES[rn]}, #0x{shift:x}]"
    return None

def decode_strb(word, pc):
    # STRB Wt, [Xn, #imm12]
    size = (word >> 30) & 3
    if size != 0: return None
    opc = (word >> 21) & 0x1f
    # Actually bit pattern for STRB with imm12
    rt = word & 0x1f
    rn = (word >> 5) & 0x1f
    imm12 = (word >> 10) & 0xfff
    return f"strb {WREG[rt]}, [{REG_NAMES[rn]}, #0x{imm12:x}]"

def decode_stp(word, pc):
    # Check for STP post-index or pre-index
    opc = (word >> 30) & 3
    V = (word >> 29) & 1
    L = (word >> 22) & 1
    index = (word >> 23) & 3
    
    if opc == 2 and V == 0:  # STP (store), GP regs
        rt = word & 0x1f
        rn = (word >> 5) & 0x1f
        rt2 = (word >> 10) & 0x1f
        if index == 1:  # signed offset
            imm7 = (word >> 15) & 0x7f
            if imm7 & 0x40: imm7 |= ~0x3f
            off = imm7 << 3 if L == 1 else imm7 << 3
            return f"stp {REG_NAMES[rt]}, {REG_NAMES[rt2]}, [{REG_NAMES[rn]}, #0x{off:x}]" if index == 1 else None
        elif index == 3:  # pre-index
            imm7 = (word >> 15) & 0x7f
            if imm7 & 0x40: imm7 |= ~0x3f
            off = imm7 << 3
            return f"stp {REG_NAMES[rt]}, {REG_NAMES[rt2]}, [{REG_NAMES[rn]}, #-0x{-off:x}]!" if off < 0 else f"stp {REG_NAMES[rt]}, {REG_NAMES[rt2]}, [{REG_NAMES[rn]}, #0x{off:x}]!"
        elif index == 2:  # post-index
            imm7 = (word >> 15) & 0x7f
            if imm7 & 0x40: imm7 |= ~0x3f
            off = imm7 << 3
            return f"stp {REG_NAMES[rt]}, {REG_NAMES[rt2]}, [{REG_NAMES[rn]}], #0x{off:x}"
    elif opc == 3 and V == 0:  # LDP (load), GP regs, signed offset
        rt = word & 0x1f
        rn = (word >> 5) & 0x1f
        rt2 = (word >> 10) & 0x1f
        L = (word >> 22) & 1
        index = (word >> 23) & 3
        if index == 1 or index == 3 or index == 2:
            imm7 = (word >> 15) & 0x7f
            if imm7 & 0x40: imm7 |= ~0x3f
            off = imm7 << 3
            if index == 1: return f"ldp {REG_NAMES[rt]}, {REG_NAMES[rt2]}, [{REG_NAMES[rn]}, #0x{off:x}]"
            elif index == 3: return f"ldp {REG_NAMES[rt]}, {REG_NAMES[rt2]}, [{REG_NAMES[rn]}, #0x{off:x}]!"
            elif index == 2: return f"ldp {REG_NAMES[rt]}, {REG_NAMES[rt2]}, [{REG_NAMES[rn]}], #0x{off:x}"
    return None

print("=" * 80)
print("ENTRY 200 MANUAL DISASSEMBLY")
print("=" * 80)

got_page = None
for i in range(0, func_size, 4):
    word = struct.unpack_from('<I', raw, i)[0]
    va = func_va + i
    
    if word == 0xd503201f:
        line = "nop"
    elif word == 0xd65f03c0:
        line = "ret"
    elif (word >> 26) == 0x25:  # BL
        imm = word & 0x3ffffff
        if imm & 0x2000000: imm |= ~0x3ffffff
        target = va + (imm << 2)
        sym = symof(target)
        line = f"bl      0x{target:x}  ; {sym}" if sym else f"bl      0x{target:x}"
    elif (word >> 26) == 0x05:  # B (uncond)
        imm = word & 0x3ffffff
        if imm & 0x2000000: imm |= ~0x3ffffff
        target = va + (imm << 2)
        line = f"b       0x{target:x}"
    elif (word & 0xfc000000) == 0x54000000:  # B.cond
        cond = word & 0xf
        imm19 = (word >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 |= ~0x7ffff
        target = va + (imm19 << 2)
        cond_names = ['eq','ne','cs/hs','cc/lo','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv']
        cn = cond_names[cond] if cond < 16 else f"?{cond}"
        line = f"b.{cn}    0x{target:x}"
    elif (word & 0x7f000000) == 0x35000000:  # CBNZ (32-bit)
        rt = word & 0x1f
        imm19 = (word >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 |= ~0x7ffff
        target = va + (imm19 << 2)
        line = f"cbnz    {WREG[rt]}, 0x{target:x}"
    elif (word & 0xfc000000) == 0xb0000000 or (word & 0xfc000000) == 0x90000000:  # ADRP
        line, page = decode_adrp(word, va)
        if got_addr and got_addr <= page < got_addr + got_size:
            line += "  ; GOT page"
        elif gotp_addr and gotp_addr <= page < gotp_addr + gotp_size:
            line += "  ; GOT.PLT page"
    elif (word & 0xffc00000) == 0x91000000:  # ADD (immediate, 64-bit)
        line = decode_add_imm(word, va)
    elif (word & 0xffc00000) == 0x11000000:  # ADD (immediate, 32-bit)
        rd = word & 0x1f
        rn = (word >> 5) & 0x1f
        imm12 = (word >> 10) & 0xfff
        shift = (word >> 22) & 3
        imm = imm12 << (shift * 12) if shift else imm12
        line = f"add     {WREG[rd]}, {WREG[rn]}, #0x{imm:x}"
    elif (word & 0x7f000000) == 0x34000000:  # CBZ (32-bit)
        rt = word & 0x1f
        imm19 = (word >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 |= ~0x7ffff
        target = va + (imm19 << 2)
        line = f"cbz     {WREG[rt]}, 0x{target:x}"
    elif (word >> 24) == 0x39 and (word & 0x04000000) == 0:  # STRB/STRH possible
        # Try STRB unsigned offset
        opc = (word >> 21) & 0x1f
        if opc == 0:  # STRB
            rt = word & 0x1f
            rn = (word >> 5) & 0x1f
            imm12 = (word >> 10) & 0xfff
            line = f"strb    {WREG[rt]}, [{REG_NAMES[rn]}, #0x{imm12:x}]"
        else:
            line = f".word   0x{word:08x}"
    elif (word >> 24) == 0xb9:  # STR/STRH (scale check)
        size = word >> 30 & 3
        opc = (word >> 21) & 0x1f
        if opc == 0 and size == 2:  # STR 32-bit
            rt = word & 0x1f
            rn = (word >> 5) & 0x1f
            imm12 = (word >> 10) & 0xfff
            line = f"str     {WREG[rt]}, [{REG_NAMES[rn]}, #0x{imm12 << 2:x}]"
        else:
            line = f".word   0x{word:08x}"
    elif (word >> 24) == 0xf9:  # STR 64-bit or LDR 64-bit
        size = word >> 30 & 3
        V = (word >> 26) & 1
        opc = word >> 22 & 1  # bit 22 in opc field for LDR vs STR:
        # Actually for unsigned offset store: bits[29:22] = 11100101 for STR, 11100101 for LDR
        # Simpler: bit[24]=f9 means STR, bit[24]=f8 means LDR? No...
        # f9 at bits[31:24] = 1111 1001
        # f8 at bits[31:24] = 1111 1000
        
        # Check L bit (bit 22): 0=STR, 1=LDR
        Lbit = (word >> 22) & 1
        rt = word & 0x1f
        rn = (word >> 5) & 0x1f
        imm12 = (word >> 10) & 0xfff
        if Lbit == 0:  # STR
            line = f"str     {REG_NAMES[rt]}, [{REG_NAMES[rn]}, #0x{imm12 << 3:x}]"
        else:  # LDR
            line = f"ldr     {REG_NAMES[rt]}, [{REG_NAMES[rn]}, #0x{imm12 << 3:x}]"
    elif (word >> 25) == 0x08 and word & 0x3f == 0x3f:  # BLR
        rn = (word >> 5) & 0x1f
        line = f"blr     {REG_NAMES[rn]}"
    elif (word >> 25) == 0x08 and word & 0x3f == 0:  # BR
        rn = (word >> 5) & 0x1f
        line = f"br      {REG_NAMES[rn]}"
    elif (word >> 23) == 0x355:  # CBNZ (64-bit)
        rt = word & 0x1f
        imm19 = (word >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 |= ~0x7ffff
        target = va + (imm19 << 2)
        line = f"cbnz    {REG_NAMES[rt]}, 0x{target:x}"
    elif (word & 0x1f000000) == 0x10000000:  # ADR
        rd = word & 0x1f
        immlo = (word >> 29) & 3
        immhi = (word >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & 0x80000: imm |= ~0xfffff
        target = va + imm
        line = f"adr     {REG_NAMES[rd]}, 0x{target:x}"
    elif (word & 0xffe00000) == 0x2a000000:  # MOV (orr, 64-bit) or MOV (register)
        rd = word & 0x1f
        rn = (word >> 16) & 0x1f
        rm = (word >> 8) & 0x1f
        op = (word >> 21) & 3
        if op == 0:  # AND, but check for ORR with imm = 0
            N = (word >> 22) & 1
            immshift = (word >> 10) & 0xfff
            if N == 0 and immshift == 0:
                line = f"mov     {REG_NAMES[rd]}, {REG_NAMES[rm if word & 0x200 else rn]}"
            else:
                line = f".word   0x{word:08x}"
        elif op == 2:  # ORR
            N = (word >> 22) & 1
            immshift = (word >> 10) & 0xfff
            if N == 0 and immshift == 0:
                line = f"orr     {REG_NAMES[rd]}, {REG_NAMES[rn]}, {REG_NAMES[rm]}"
            else:
                line = f".word   0x{word:08x}"
        else:
            line = f".word   0x{word:08x}"
    elif (word & 0x7f000000) == 0x71000000:  # CMP/S/SUBS (immediate, 32-bit)
        rd = word & 0x1f
        rn = (word >> 5) & 0x1f
        imm12 = (word >> 10) & 0xfff
        shift = (word >> 22) & 3
        op = (word >> 29) & 3
        S = (word >> 29) & 1
        if rd == 0x1f and op == 3 and S == 1:  # CMP
            line = f"cmp     {WREG[rn]}, #0x{imm12 << (shift*12) if shift else imm12:x}"
        elif rd == 0x1f and op == 1 and S == 1:  # CMP 64-bit
            line = f"cmp     {REG_NAMES[rn]}, #0x{imm12 << (shift*12) if shift else imm12:x}"
        else:
            line = f".word   0x{word:08x}"
    elif (word >> 24) == 0x52:  # MOVZ/MOVK
        opc = (word >> 29) & 3
        hw = (word >> 21) & 3
        imm16 = (word >> 5) & 0xffff
        rd = word & 0x1f
        if opc == 0:  # MOVN
            imm = imm16 << (hw*16)
            line = f"movn    {REG_NAMES[rd]}, #0x{imm:x}, lsl #{hw*16}"
        elif opc == 2:  # MOVZ  
            imm = imm16 << (hw*16)
            line = f"movz    {REG_NAMES[rd]}, #0x{imm:x}, lsl #{hw*16}"
        elif opc == 3:  # MOVK
            imm = imm16 << (hw*16)
            line = f"movk    {REG_NAMES[rd]}, #0x{imm:x}, lsl #{hw*16}"
        else:
            line = f".word   0x{word:08x}"
    elif (word & 0x1b000000) == 0x0a000000 and (word & 0x2000):  # LSR/LSL etc
        # bit 31=0, 30-29=00, 28=0, 25=1
        # Check for LSR
        opc = (word >> 29) & 3
        if opc == 2:  # LSR (UBFM)
            rd = word & 0x1f
            rn = (word >> 5) & 0x1f
            immr = (word >> 16) & 0x3f
            imms = (word >> 10) & 0x3f
            N = (word >> 22) & 1
            # LSR Xd, Xn, #shift -> UBFM Xd, Xn, #shift, #63
            if imms == 0x3f:
                line = f"lsr     {REG_NAMES[rd]}, {REG_NAMES[rn]}, #0x{immr:x}"
            else:
                line = f"ubfm    {REG_NAMES[rd]}, {REG_NAMES[rn]}, #{immr}, #{imms}"
        else:
            line = f".word   0x{word:08x}"
    elif (word >> 21) == 0x1ac:  # SXTW
        rd = word & 0x1f
        rn = (word >> 5) & 0x1f
        line = f"sxtw    {REG_NAMES[rd]}, {WREG[rn]}"
    elif (word >> 10) == 0x321c0f and (word & 0x1f) != 0x1f:  # MOV w0, #0 (ORR)
        rd = word & 0x1f
        imm16 = (word >> 5) & 0xffff
        line = f"mov     {WREG[rd]}, #0x{imm16:x}"
    elif word == 0xd1006000:  # SUB x0, x0, #0x18
        line = f"sub     x0, x0, #0x18"
    else:
        line = f".word   0x{word:08x}"
    
    print(f"  0x{va:08x}: {line}")
