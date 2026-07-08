import struct

DEX = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\classes.dex'
data = open(DEX, 'rb').read()
END = len(data)

sio = struct.unpack_from('<I', data, 0x3C)[0]
tio = struct.unpack_from('<I', data, 0x44)[0]
mio = struct.unpack_from('<I', data, 0x5C)[0]
fio = struct.unpack_from('<I', data, 0x54)[0]

def uleb(off):
    r = 0; s = 0
    for _ in range(5):
        if off >= END: return -1, off
        b = data[off]; off += 1
        r |= (b & 0x7F) << s; s += 7
        if not (b & 0x80): return r, off
    return -1, off

def raw_str(off):
    sz, p = uleb(off)
    if sz < 0: return b'?'
    return data[p:p+sz]

def type_name(ti):
    s = raw_str(struct.unpack_from('<I', data, tio + ti * 4)[0])
    return s.decode('utf-8', errors='replace')

def mth_sig(mi):
    """Return class.method_name:proto for a method index"""
    off = mio + mi * 8
    class_idx = struct.unpack_from('<H', data, off)[0]
    proto_idx = struct.unpack_from('<H', data, off+2)[0]
    name_idx = struct.unpack_from('<I', data, off+4)[0]
    cls = type_name(class_idx)
    name = raw_str(struct.unpack_from('<I', data, sio + name_idx * 4)[0]).decode('utf-8', errors='replace')
    # proto
    poff = struct.unpack_from('<I', data, 0x48)[0]  # proto_ids_off
    prio = poff + proto_idx * 12
    shorty_idx = struct.unpack_from('<I', data, prio)[0]  # not using
    ret_type_idx = struct.unpack_from('<I', data, prio+4)[0]
    param_off = struct.unpack_from('<I', data, prio+8)[0]
    ret_type = type_name(ret_type_idx)
    params = b''
    if param_off != 0:
        sz, p2 = uleb(param_off)
        params = '('
        for _ in range(sz):
            ti2, p2 = uleb(p2)
            params += type_name(ti2)
        params += ')'
    else:
        params = '()'
    return '%s.%s:%s%s' % (cls, name, params, ret_type)

OPCODES = {
    0x00: 'nop', 0x01: 'move', 0x02: 'move/from16', 0x03: 'move/16',
    0x04: 'move-wide', 0x05: 'move-wide/from16', 0x06: 'move-wide/16',
    0x07: 'move-object', 0x08: 'move-object/from16', 0x09: 'move-object/16',
    0x0a: 'move-result', 0x0b: 'move-result-wide', 0x0c: 'move-result-object',
    0x0d: 'move-exception',
    0x0e: 'return-void', 0x0f: 'return', 0x10: 'return-wide', 0x11: 'return-object',
    0x12: 'const/4', 0x13: 'const/16', 0x14: 'const',
    0x15: 'const/high16', 0x16: 'const-wide/16', 0x17: 'const-wide/32',
    0x18: 'const-wide', 0x19: 'const-wide/high16',
    0x1a: 'const-string', 0x1b: 'const-string-jumbo',
    0x1c: 'const-class', 0x1d: 'monitor-enter', 0x1e: 'monitor-exit',
    0x1f: 'check-cast', 0x20: 'instance-of', 0x21: 'array-length',
    0x22: 'new-instance', 0x23: 'new-array', 0x24: 'filled-new-array',
    0x25: 'filled-new-array/range', 0x26: 'fill-array-data',
    0x27: 'throw', 0x28: 'goto', 0x29: 'goto/16', 0x2a: 'goto/32',
    0x2b: 'packed-switch', 0x2c: 'sparse-switch',
    0x2d: 'cmpl-float', 0x2e: 'cmpg-float', 0x2f: 'cmpl-double',
    0x30: 'cmpg-double', 0x31: 'cmp-long', 0x32: 'if-eq', 0x33: 'if-ne',
    0x34: 'if-lt', 0x35: 'if-ge', 0x36: 'if-gt', 0x37: 'if-le',
    0x38: 'if-eqz', 0x39: 'if-nez', 0x3a: 'if-ltz', 0x3b: 'if-gez',
    0x3c: 'if-gtz', 0x3d: 'if-lez',
    0x3e: 'aget', 0x3f: 'aget-wide', 0x40: 'aget-object', 0x41: 'aget-boolean',
    0x42: 'aget-byte', 0x43: 'aget-char', 0x44: 'aget-short', 0x45: 'aput',
    0x46: 'aput-wide', 0x47: 'aput-object', 0x48: 'aput-boolean', 0x49: 'aput-byte',
    0x4a: 'aput-char', 0x4b: 'aput-short', 0x4c: 'iget', 0x4d: 'iget-wide',
    0x4e: 'iget-object', 0x4f: 'iget-boolean', 0x50: 'iget-byte', 0x51: 'iget-char',
    0x52: 'iget-short', 0x53: 'iput', 0x54: 'iput-wide', 0x55: 'iput-object',
    0x56: 'iput-boolean', 0x57: 'iput-byte', 0x58: 'iput-char', 0x59: 'iput-short',
    0x5a: 'sget', 0x5b: 'sget-wide', 0x5c: 'sget-object', 0x5d: 'sget-boolean',
    0x5e: 'sget-byte', 0x5f: 'sget-char', 0x60: 'sget-short', 0x61: 'sput',
    0x62: 'sput-wide', 0x63: 'sput-object', 0x64: 'sput-boolean', 0x65: 'sput-byte',
    0x66: 'sput-char', 0x67: 'sput-short',
    0x68: 'invoke-virtual', 0x69: 'invoke-super', 0x6a: 'invoke-direct',
    0x6b: 'invoke-static', 0x6c: 'invoke-interface',
    0x6d: 'return-void-barrier', 0x6e: 'invoke-virtual/range',
    0x6f: 'invoke-super/range', 0x70: 'invoke-direct/range',
    0x71: 'invoke-static/range', 0x72: 'invoke-interface/range',
    0x73: 'nop', 0x74: 'nop',
    0x7b: 'neg-int', 0x7c: 'not-int', 0x7d: 'neg-long', 0x7e: 'not-long',
    0x7f: 'neg-float', 0x80: 'neg-double', 0x81: 'int-to-long', 0x82: 'int-to-float',
    0x83: 'int-to-double', 0x84: 'long-to-int', 0x85: 'long-to-float',
    0x86: 'long-to-double', 0x87: 'float-to-int', 0x88: 'float-to-long',
    0x89: 'float-to-double', 0x8a: 'double-to-int', 0x8b: 'double-to-long',
    0x8c: 'double-to-float', 0x8d: 'int-to-byte', 0x8e: 'int-to-char',
    0x8f: 'int-to-short',
    0x90: 'add-int', 0x91: 'sub-int', 0x92: 'mul-int', 0x93: 'div-int',
    0x94: 'rem-int', 0x95: 'and-int', 0x96: 'or-int', 0x97: 'xor-int',
    0x98: 'shl-int', 0x99: 'shr-int', 0x9a: 'ushr-int',
    0x9b: 'add-long', 0x9c: 'sub-long', 0x9d: 'mul-long', 0x9e: 'div-long',
    0x9f: 'rem-long', 0xa0: 'and-long', 0xa1: 'or-long', 0xa2: 'xor-long',
    0xa3: 'shl-long', 0xa4: 'shr-long', 0xa5: 'ushr-long',
    0xa6: 'add-float', 0xa7: 'sub-float', 0xa8: 'mul-float', 0xa9: 'div-float',
    0xaa: 'rem-float', 0xab: 'add-double', 0xac: 'sub-double', 0xad: 'mul-double',
    0xae: 'div-double', 0xaf: 'rem-double',
    0xb0: 'add-int/2addr', 0xb1: 'sub-int/2addr', 0xb2: 'mul-int/2addr',
    0xb3: 'div-int/2addr', 0xb4: 'rem-int/2addr', 0xb5: 'and-int/2addr',
    0xb6: 'or-int/2addr', 0xb7: 'xor-int/2addr', 0xb8: 'shl-int/2addr',
    0xb9: 'shr-int/2addr', 0xba: 'ushr-int/2addr',
    0xbb: 'add-long/2addr', 0xbc: 'sub-long/2addr', 0xbd: 'mul-long/2addr',
    0xbe: 'div-long/2addr', 0xbf: 'rem-long/2addr', 0xc0: 'and-long/2addr',
    0xc1: 'or-long/2addr', 0xc2: 'xor-long/2addr', 0xc3: 'shl-long/2addr',
    0xc4: 'shr-long/2addr', 0xc5: 'ushr-long/2addr',
    0xc6: 'add-float/2addr', 0xc7: 'sub-float/2addr', 0xc8: 'mul-float/2addr',
    0xc9: 'div-float/2addr', 0xca: 'rem-float/2addr', 0xcb: 'add-double/2addr',
    0xcc: 'sub-double/2addr', 0xcd: 'mul-double/2addr', 0xce: 'div-double/2addr',
    0xcf: 'rem-double/2addr', 0xd0: 'add-int/lit16', 0xd1: 'rsub-int',
    0xd2: 'mul-int/lit16', 0xd3: 'div-int/lit16', 0xd4: 'rem-int/lit16',
    0xd5: 'and-int/lit16', 0xd6: 'or-int/lit16', 0xd7: 'xor-int/lit16',
    0xd8: 'add-int/lit8', 0xd9: 'rsub-int/lit8', 0xda: 'mul-int/lit8',
    0xdb: 'div-int/lit8', 0xdc: 'rem-int/lit8', 0xdd: 'and-int/lit8',
    0xde: 'or-int/lit8', 0xdf: 'xor-int/lit8', 0xe0: 'shl-int/lit8',
    0xe1: 'shr-int/lit8', 0xe2: 'ushr-int/lit8',
    0xe3: 'nop', 0xe4: 'nop', 0xe5: 'nop', 0xe6: 'nop',
    0xe7: 'nop', 0xe8: 'nop', 0xe9: 'nop', 0xea: 'nop',
    0xeb: 'nop', 0xec: 'nop', 0xed: 'nop', 0xee: 'nop',
    0xef: 'nop', 0xf0: 'nop', 0xf1: 'nop', 0xf2: 'nop',
    0xf3: 'nop', 0xf4: 'nop', 0xf5: 'nop', 0xf6: 'nop',
    0xf7: 'nop', 0xf8: 'nop', 0xf9: 'nop', 0xfa: 'nop',
    0xfb: 'nop', 0xfc: 'nop', 0xfd: 'nop', 0xfe: 'nop',
    0xff: 'nop',
}

# Let me use a simpler but more accurate approach: just walk instructions at generateKey's code_item
code_off = 0x412684
regs = struct.unpack_from('<H', data, code_off)[0]
ins = struct.unpack_from('<H', data, code_off+2)[0]
outs = struct.unpack_from('<H', data, code_off+4)[0]
tries = struct.unpack_from('<H', data, code_off+6)[0]
debug = struct.unpack_from('<I', data, code_off+8)[0]
insns_size = struct.unpack_from('<I', data, code_off+12)[0]
insns = code_off + 16

print('code_off: 0x%x' % code_off)
print('regs: %d, ins: %d, outs: %d' % (regs, ins, outs))
print('insns_size: %d (bytes: %d)' % (insns_size, insns_size * 2))
print()

pos = insns
end = pos + insns_size * 2
while pos < end:
    op = data[pos]
    name = OPCODES.get(op, 'unknown(0x%02x)' % op)
    
    # Simple instruction length by format
    fmt_21c = {0x22, 0x1c, 0x1f, 0x20, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x1a, 0x1b}
    fmt_35c = {0x68, 0x69, 0x6a, 0x6b, 0x6c}
    fmt_3rc = {0x6e, 0x6f, 0x70, 0x71, 0x72}
    fmt_21t = {0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x28}
    fmt_31t = {0x2b, 0x2c, 0x26}
    fmt_11x = {0x0e, 0x0f, 0x10, 0x11, 0x27, 0x0d, 0x1d, 0x1e}
    fmt_12x = {0x01, 0x04, 0x07, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf}
    fmt_22c = {0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x40, 0x47, 0x3e, 0x3f, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x48, 0x49, 0x4a, 0x4b, 0x23}
    fmt_21h = {0x15, 0x19, 0x18}
    fmt_11n = {0x12}
    fmt_31i = {0x14}
    fmt_51l = {0x18}
    fmt_22t = {0x2d, 0x2e, 0x2f, 0x30, 0x31}
    fmt_22s = {0xd0, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd1}
    fmt_22b = {0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2}
    fmt_10x = {0x00, 0x73, 0x74, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}
    fmt_20t = {0x29}
    fmt_30t = {0x2a}
    fmt_23x = {0x21, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f}
    
    if op == 0x0c:  # move-result-object: format 11x -> 2 bytes
        line = '%04x: %-24s v%d' % (pos, name, data[pos+1])
        pos += 2
    elif op in fmt_10x:
        line = '%04x: %-24s' % (pos, name)
        pos += 2
    elif op in fmt_11x:
        line = '%04x: %-24s v%d' % (pos, name, data[pos+1])
        pos += 2
    elif op in fmt_11n:
        val = (data[pos+1] << 28) >> 28  # sign-extend 4-bit
        line = '%04x: %-24s v%d, #%d' % (pos, name, (data[pos+1] >> 4) & 0xf, val)
        pos += 2
    elif op in fmt_12x:
        vA = data[pos+1] >> 4
        vB = data[pos+1] & 0xf
        line = '%04x: %-24s v%d, v%d' % (pos, name, vA, vB)
        pos += 2
    elif op in fmt_21h:
        vA = data[pos+1]
        val = struct.unpack_from('<I', data, pos)[0] >> 8
        line = '%04x: %-24s v%d, #%d' % (pos, name, vA, val)
        pos += 4
    elif op == 0x13:  # const/16
        vA = data[pos+1]
        val = struct.unpack_from('<h', data, pos+2)[0]
        line = '%04x: %-24s v%d, #%d' % (pos, name, vA, val)
        pos += 4
    elif op in fmt_21c:
        vA = data[pos+1]
        idx = struct.unpack_from('<H', data, pos+2)[0]
        extra = ''
        if op in (0x5c, 0x62, 0x5a, 0x61, 0x5d, 0x5e, 0x5f, 0x60, 0x63, 0x64, 0x65, 0x66, 0x67):
            # field access
            extra = 'field@0x%x' % idx
        elif op == 0x22:
            extra = 'type@%d (%s)' % (idx, type_name(idx))
        elif op == 0x1a:
            s = raw_str(struct.unpack_from('<I', data, sio + idx * 4)[0])
            extra = 'string@%d "%s"' % (idx, s.decode('utf-8', errors='replace'))
        elif op == 0x1c:
            extra = 'type@%d (%s)' % (idx, type_name(idx))
        elif op == 0x1f:
            extra = 'type@%d (%s)' % (idx, type_name(idx))
        line = '%04x: %-24s v%d, %s' % (pos, name, vA, extra)
        pos += 4
    elif op in fmt_22c:
        vA = data[pos+1] >> 4
        vB = data[pos+1] & 0xf
        idx = struct.unpack_from('<H', data, pos+2)[0]
        extra = ''
        if op in (0x4e, 0x55, 0x53, 0x54, 0x4c, 0x4d, 0x4f, 0x50, 0x51, 0x52, 0x56, 0x57, 0x58, 0x59):
            extra = 'field@0x%x' % idx
        elif op in (0x40, 0x47):
            extra = 'type@%d' % idx
        elif op == 0x23:
            extra = 'type@%d (%s)' % (idx, type_name(idx))
        line = '%04x: %-24s v%d, v%d, %s' % (pos, name, vA, vB, extra)
        pos += 4
    elif op in fmt_35c:
        A = (data[pos+1] >> 4) & 0xf
        G = data[pos+1] & 0xf
        ref = struct.unpack_from('<H', data, pos+2)[0]
        C = (data[pos+4] >> 4) & 0xf
        B = data[pos+4] & 0xf
        E = (data[pos+5] >> 4) & 0xf
        D = data[pos+5] & 0xf
        # args: C, D, E, F(=G if A >= 4... actually F is different)
        # Actually the 4th arg register is in pos+5 high nibble? No...
        # Let me try: args are vB, vC, vD, vE, vG (with G at byte1 low nibble)
        args = []
        # Actually for 35c: the definition says "Arguments appear in the order C, D, E, F, G"
        # Where F is encoded... hmm
        # Let me just use: args = B, C, D, E, G
        # Since B=low nibble of byte4, C=high nibble of byte4
        # D=low nibble of byte5, E=high nibble of byte5
        # G=low nibble of byte1
        # Actually I think:
        # C in high nibble of byte4 -> first arg register
        # B in low nibble of byte4...
        # E in high nibble of byte5...
        # D in low nibble of byte5...
        # G in low nibble of byte1
        
        # Let me just use the conventional ordering from AOSP:
        # The format is [op, A, G, ref, C, B, E, D, F]
        # Hmm no. Let me try differently - let me use the disassembly approach from the spec
        # "Arguments appear in the order C, D, E, F, G"
        # Where C is at pos+4 high nibble
        # Where D is at pos+5 low nibble
        # Where E is at pos+5 high nibble
        # Where F is... actually there is no F explicitly, the spec says F is encoded differently
        
        # I think for 35c, the register arguments use:
        # C = pos+4 high nibble (first arg)
        # B = pos+4 low nibble ... actually this doesn't make sense
        
        # OK let me just use the simple approach that I've seen in other disassemblers:
        # The register list is: v[arg5], v[arg4], ..., v[arg0]
        # Where:
        #   arg0 = byte4 high nibble  (vC)
        #   arg1 = byte4 low nibble   (vB - wait, spec says C first)
        #   Hmm, I'm confusing myself.
        
        # Let me just print the raw values and we can figure it out:
        line = '%04x: %-24s {%s}, method@0x%x [A=%d G=%d B=%d C=%d D=%d E=%d]' % (
            pos, name, '', ref, A, G, B, C, D, E)
        try:
            sig = mth_sig(ref)
            line += ' ; %s' % sig
        except:
            pass
        pos += 6
    elif op in fmt_3rc:
        A = data[pos+1]
        C = struct.unpack_from('<H', data, pos+2)[0]
        ref = struct.unpack_from('<H', data, pos+4)[0]
        line = '%04x: %-24s {v%d..v%d}, method@0x%x' % (pos, name, C, C+A-1, ref)
        try:
            sig = mth_sig(ref)
            line += ' ; %s' % sig
        except:
            pass
        pos += 6
    elif op == 0x26:  # fill-array-data
        vA = data[pos+1]
        target = pos + struct.unpack_from('<i', data, pos+2)[0] * 2
        line = '%04x: %-24s v%d, +%d (0x%x)' % (pos, name, vA, struct.unpack_from('<i', data, pos+2)[0]*2, target)
        pos += 6
    elif op in fmt_31i:
        vA = data[pos+1]
        val = struct.unpack_from('<i', data, pos+2)[0]
        line = '%04x: %-24s v%d, #%d (0x%x)' % (pos, name, vA, val, val)
        pos += 6
    elif op in fmt_51l:
        vA = data[pos+1]
        val = struct.unpack_from('<q', data, pos+2)[0]
        line = '%04x: %-24s v%d, #%d (0x%x)' % (pos, name, vA, val, val)
        pos += 10
    elif op in fmt_22t:
        vA = data[pos+1] >> 4
        vB = data[pos+1] & 0xf
        offset = struct.unpack_from('<h', data, pos+2)[0] * 2
        line = '%04x: %-24s v%d, v%d, %+d (0x%x)' % (pos, name, vA, vB, offset, pos + offset)
        pos += 4
    elif op in fmt_22s:
        vA = data[pos+1] >> 4
        vB = data[pos+1] & 0xf
        val = struct.unpack_from('<h', data, pos+2)[0]
        line = '%04x: %-24s v%d, v%d, #%d' % (pos, name, vA, vB, val)
        pos += 4
    elif op in fmt_22b:
        vA = data[pos+1] >> 4
        vB = data[pos+1] & 0xf
        val = struct.unpack_from('<b', data, pos+2)[0]
        line = '%04x: %-24s v%d, v%d, #%d' % (pos, name, vA, vB, val)
        pos += 4
    elif op in fmt_21t:
        vA = data[pos+1]
        offset = struct.unpack_from('<h', data, pos+2)[0] * 2
        line = '%04x: %-24s v%d, %+d (0x%x)' % (pos, name, vA, offset, pos + offset)
        pos += 4
    elif op in fmt_20t:
        offset = struct.unpack_from('<h', data, pos)[0] * 2
        line = '%04x: %-24s %+d (0x%x)' % (pos, name, offset, pos + offset)
        pos += 2
    elif op in fmt_30t:
        offset = struct.unpack_from('<i', data, pos+2)[0] * 2
        line = '%04x: %-24s %+d (0x%x)' % (pos, name, offset, pos + offset)
        pos += 6
    elif op in fmt_23x:
        vA = data[pos+1] >> 4
        vB = data[pos+1] & 0xf
        vC = data[pos+2] >> 4
        # 23x: [op, A, B, C] where A, B, C are 4-bit each
        # But byte2 contains: C(4)|D(4)... actually for 23x:
        # Byte 0: opcode
        # Byte 1: A (high) | B (low) - 4 bits each
        # Byte 2: C (high) | (unused low) - actually for 23x the spec is:
        # op AA BB CC â†’ 12x format
        # Actually 23x is: [op AA, BB, CC] where AA, BB, CC are 8 bits each = 4 bytes
        # For example array-length: vA = op(1) + reg(1), vB = op(2) + reg(1)... no
        # Let me just handle the common ones
        vA = data[pos+1]
        vB = data[pos+2]
        line = '%04x: %-24s v%d, v%d' % (pos, name, vA, vB)
        pos += 4
    elif op == 0x0b:  # move-result-wide
        line = '%04x: %-24s v%d' % (pos, name, data[pos+1])
        pos += 2
    elif op == 0x0a:  # move-result
        line = '%04x: %-24s v%d' % (pos, name, data[pos+1])
        pos += 2
    elif op == 0x24:  # filled-new-array (35c format)
        A = (data[pos+1] >> 4) & 0xf
        G = data[pos+1] & 0xf
        ref = struct.unpack_from('<H', data, pos+2)[0]
        B = data[pos+4] & 0xf
        C = (data[pos+4] >> 4) & 0xf
        D = data[pos+5] & 0xf
        E = (data[pos+5] >> 4) & 0xf
        line = '%04x: %-24s {%s}, type@0x%x' % (pos, name, '', ref)
        try:
            sig = mth_sig(ref)
            extra = ' ; %s' % sig
        except:
            extra = ' ; type: %s' % type_name(ref)
        line += extra
        pos += 6
    elif op == 0x0e:  # return-void
        line = '%04x: %-24s' % (pos, name)
        pos += 2
    else:
        # unknown opcode, skip 2 bytes
        line = '%04x: %-24s ; unknown' % (pos, name)
        pos += 2
    
    print(line)

# Also let's look at what methods are at interesting indices
print('\n=== Methods used in generateKey ===')
# From the instruction stream:
# method@0x9270 and others - let me print them
meth_ids_to_check = [0x9270]
for mid in meth_ids_to_check:
    try:
        print('method@0x%x = %s' % (mid, mth_sig(mid)))
    except Exception as e:
        print('method@0x%x = ERROR: %s' % (mid, e))
