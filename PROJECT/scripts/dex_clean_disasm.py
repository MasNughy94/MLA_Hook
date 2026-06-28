import struct

DEX = r'C:\Users\NGEONG\Videos\MLA\MLADVENTURE2\classes.dex'
data = open(DEX, 'rb').read()
END = len(data)

# DEX header offsets (CORRECT)
sio = struct.unpack_from('<I', data, 0x3C)[0]  # string_ids_off
tio = struct.unpack_from('<I', data, 0x44)[0]  # type_ids_off
pis = struct.unpack_from('<I', data, 0x48)[0]  # proto_ids_size
pio = struct.unpack_from('<I', data, 0x4C)[0]  # proto_ids_off
fis = struct.unpack_from('<I', data, 0x50)[0]  # field_ids_size
fio = struct.unpack_from('<I', data, 0x54)[0]  # field_ids_off
mis = struct.unpack_from('<I', data, 0x58)[0]  # method_ids_size
mio = struct.unpack_from('<I', data, 0x5C)[0]  # method_ids_off
cds = struct.unpack_from('<I', data, 0x60)[0]  # class_defs_size
cdo = struct.unpack_from('<I', data, 0x64)[0]  # class_defs_off

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
    if ti >= struct.unpack_from('<I', data, 0x40)[0]:
        return '?type_%d?' % ti
    si = struct.unpack_from('<I', data, tio + ti * 4)[0]
    return raw_str(struct.unpack_from('<I', data, sio + si * 4)[0]).decode('utf-8', errors='replace')

def mth_sig(mi):
    if mi >= mis: return '?method_%d?' % mi
    off = mio + mi * 8
    mc = struct.unpack_from('<H', data, off)[0]
    mp = struct.unpack_from('<H', data, off+2)[0]
    mn = struct.unpack_from('<I', data, off+4)[0]
    cls = type_name(mc)
    name = raw_str(struct.unpack_from('<I', data, sio + mn * 4)[0]).decode('utf-8', errors='replace')
    if mp >= pis: return '%s.%s' % (cls, name)
    prio = pio + mp * 12
    rt = struct.unpack_from('<I', data, prio+4)[0]
    pm = struct.unpack_from('<I', data, prio+8)[0]
    ret = type_name(rt)
    params = ''
    if pm != 0:
        sz, p2 = uleb(pm)
        params_parts = []
        for _ in range(sz):
            ti2, p2 = uleb(p2)
            params_parts.append(type_name(ti2))
        params = '(%s)' % ','.join(params_parts)
    else:
        params = '()'
    return '%s.%s%s%s' % (cls, name, params, ret)

def fld_info(fi):
    if fi >= fis: return ('?', '?', '?')
    off = fio + fi * 8
    fc = struct.unpack_from('<H', data, off)[0]
    ft = struct.unpack_from('<H', data, off+2)[0]
    fn = struct.unpack_from('<I', data, off+4)[0]
    return (type_name(fc), 
            raw_str(struct.unpack_from('<I', data, sio + fn * 4)[0]).decode('utf-8', errors='replace'),
            type_name(ft))

def str_val(si):
    if si >= struct.unpack_from('<I', data, 0x38)[0]:
        return '?str_%d?' % si
    return raw_str(struct.unpack_from('<I', data, sio + si * 4)[0]).decode('utf-8', errors='replace')

# Disassemble a method given code_off
def disasm(code_off, label=''):
    regs = struct.unpack_from('<H', data, code_off)[0]
    ins = struct.unpack_from('<H', data, code_off+2)[0]
    outs = struct.unpack_from('<H', data, code_off+4)[0]
    tries = struct.unpack_from('<H', data, code_off+6)[0]
    debug = struct.unpack_from('<I', data, code_off+8)[0]
    insns_size = struct.unpack_from('<I', data, code_off+12)[0]
    insns = code_off + 16
    
    print('=== %s ===' % label)
    print('regs=%d ins=%d outs=%d tries=%d insns_size=%d' % (regs, ins, outs, tries, insns_size))
    print()
    
    pos = insns
    end = pos + insns_size * 2
    while pos < end:
        op = data[pos]
        line = '%06x: ' % pos
        
        if op == 0x00: line += 'nop'; pos += 2
        elif op == 0x0e: line += 'return-void'; pos += 2
        elif op == 0x0f: line += 'return v%d' % data[pos+1]; pos += 2
        elif op == 0x10: line += 'return-wide v%d' % data[pos+1]; pos += 2
        elif op == 0x11: line += 'return-object v%d' % data[pos+1]; pos += 2
        elif op == 0x12:  # const/4
            vA = (data[pos+1] >> 4) & 0xf
            vB = data[pos+1] & 0xf
            val = (vB << 28) >> 28
            line += 'const/4 v%d, #%d' % (vA, val); pos += 2
        elif op == 0x13:  # const/16
            vA = data[pos+1]
            val = struct.unpack_from('<h', data, pos+2)[0]
            line += 'const/16 v%d, #%d' % (vA, val); pos += 4
        elif op == 0x14:  # const
            vA = data[pos+1]
            val = struct.unpack_from('<i', data, pos+2)[0]
            line += 'const v%d, #%d' % (vA, val); pos += 6
        elif op == 0x15:  # const/high16
            vA = data[pos+1]
            val = struct.unpack_from('<I', data, pos+2)[0]
            line += 'const/high16 v%d, #0x%x' % (vA, val >> 16); pos += 4
        elif op == 0x1a:  # const-string
            vA = data[pos+1]
            idx = struct.unpack_from('<H', data, pos+2)[0]
            line += 'const-string v%d, "%s"' % (vA, str_val(idx)); pos += 4
        elif op == 0x1c:  # const-class
            vA = data[pos+1]
            idx = struct.unpack_from('<H', data, pos+2)[0]
            line += 'const-class v%d, %s' % (vA, type_name(idx)); pos += 4
        elif op == 0x22:  # new-instance
            vA = data[pos+1]
            idx = struct.unpack_from('<H', data, pos+2)[0]
            line += 'new-instance v%d, %s' % (vA, type_name(idx)); pos += 4
        elif op == 0x23:  # new-array
            vA = data[pos+1] >> 4
            vB = data[pos+1] & 0xf
            idx = struct.unpack_from('<H', data, pos+2)[0]
            line += 'new-array v%d, v%d, %s' % (vA, vB, type_name(idx)); pos += 4
        elif op == 0x26:  # fill-array-data
            vA = data[pos+1]
            off_val = struct.unpack_from('<i', data, pos+2)[0]
            target = pos + off_val * 2
            line += 'fill-array-data v%d, +%d (payload at %06x)' % (vA, off_val * 2, target); pos += 6
        elif op == 0x5c:  # sget-object
            vA = data[pos+1]
            idx = struct.unpack_from('<H', data, pos+2)[0]
            fc, fn, ft = fld_info(idx)
            line += 'sget-object v%d, %s.%s:%s' % (vA, fc, fn, ft); pos += 4
        elif op == 0x62:  # sput-wide
            vA = data[pos+1]
            idx = struct.unpack_from('<H', data, pos+2)[0]
            fc, fn, ft = fld_info(idx)
            line += 'sput-wide v%d, %s.%s:%s' % (vA, fc, fn, ft); pos += 4
        elif op == 0x63:  # sput-object
            vA = data[pos+1]
            idx = struct.unpack_from('<H', data, pos+2)[0]
            fc, fn, ft = fld_info(idx)
            line += 'sput-object v%d, %s.%s:%s' % (vA, fc, fn, ft); pos += 4
        elif op == 0x68:  # invoke-virtual
            A = (data[pos+1] >> 4) & 0xf
            G = data[pos+1] & 0xf
            ref = struct.unpack_from('<H', data, pos+2)[0]
            B = data[pos+4] & 0xf
            C = (data[pos+4] >> 4) & 0xf
            D = data[pos+5] & 0xf
            E = (data[pos+5] >> 4) & 0xf
            args = []
            if A >= 1: args.append('v%d' % C)
            if A >= 2: args.append('v%d' % B)
            if A >= 3: args.append('v%d' % D)
            if A >= 4: args.append('v%d' % E)
            if A >= 5: args.append('v%d' % G)
            line += 'invoke-virtual {%s}, %s' % (', '.join(args[:A]), mth_sig(ref)); pos += 6
        elif op == 0x69:  # invoke-super
            A = (data[pos+1] >> 4) & 0xf
            G = data[pos+1] & 0xf
            ref = struct.unpack_from('<H', data, pos+2)[0]
            B = data[pos+4] & 0xf
            C = (data[pos+4] >> 4) & 0xf
            D = data[pos+5] & 0xf
            E = (data[pos+5] >> 4) & 0xf
            args = []
            if A >= 1: args.append('v%d' % C)
            if A >= 2: args.append('v%d' % B)
            if A >= 3: args.append('v%d' % D)
            if A >= 4: args.append('v%d' % E)
            if A >= 5: args.append('v%d' % G)
            line += 'invoke-super {%s}, %s' % (', '.join(args[:A]), mth_sig(ref)); pos += 6
        elif op == 0x6a:  # invoke-direct
            A = (data[pos+1] >> 4) & 0xf
            G = data[pos+1] & 0xf
            ref = struct.unpack_from('<H', data, pos+2)[0]
            B = data[pos+4] & 0xf
            C = (data[pos+4] >> 4) & 0xf
            D = data[pos+5] & 0xf
            E = (data[pos+5] >> 4) & 0xf
            args = []
            if A >= 1: args.append('v%d' % C)
            if A >= 2: args.append('v%d' % B)
            if A >= 3: args.append('v%d' % D)
            if A >= 4: args.append('v%d' % E)
            if A >= 5: args.append('v%d' % G)
            line += 'invoke-direct {%s}, %s' % (', '.join(args[:A]), mth_sig(ref)); pos += 6
        elif op == 0x6b:  # invoke-static
            A = (data[pos+1] >> 4) & 0xf
            G = data[pos+1] & 0xf
            ref = struct.unpack_from('<H', data, pos+2)[0]
            C = (data[pos+4] >> 4) & 0xf
            B = data[pos+4] & 0xf
            E = (data[pos+5] >> 4) & 0xf
            D = data[pos+5] & 0xf
            args = []
            if A >= 1: args.append('v%d' % C)
            if A >= 2: args.append('v%d' % B)
            if A >= 3: args.append('v%d' % D)
            if A >= 4: args.append('v%d' % E)
            if A >= 5: args.append('v%d' % G)
            line += 'invoke-static {%s}, %s' % (', '.join(args[:A]), mth_sig(ref)); pos += 6
        elif op == 0x6c:  # invoke-interface
            A = (data[pos+1] >> 4) & 0xf
            G = data[pos+1] & 0xf
            ref = struct.unpack_from('<H', data, pos+2)[0]
            B = data[pos+4] & 0xf
            C = (data[pos+4] >> 4) & 0xf
            D = data[pos+5] & 0xf
            E = (data[pos+5] >> 4) & 0xf
            args = []
            if A >= 1: args.append('v%d' % C)
            if A >= 2: args.append('v%d' % B)
            if A >= 3: args.append('v%d' % D)
            if A >= 4: args.append('v%d' % E)
            if A >= 5: args.append('v%d' % G)
            line += 'invoke-interface {%s}, %s' % (', '.join(args[:A]), mth_sig(ref)); pos += 6
        elif op == 0x70:  # invoke-direct/range
            A = data[pos+1]
            C = struct.unpack_from('<H', data, pos+2)[0]
            ref = struct.unpack_from('<H', data, pos+4)[0]
            line += 'invoke-direct/range {v%d..v%d}, %s' % (C, C+A-1, mth_sig(ref)); pos += 6
        elif op == 0x71:  # invoke-static/range
            A = data[pos+1]
            C = struct.unpack_from('<H', data, pos+2)[0]
            ref = struct.unpack_from('<H', data, pos+4)[0]
            line += 'invoke-static/range {v%d..v%d}, %s' % (C, C+A-1, mth_sig(ref)); pos += 6
        elif op == 0x72:  # invoke-interface/range
            A = data[pos+1]
            C = struct.unpack_from('<H', data, pos+2)[0]
            ref = struct.unpack_from('<H', data, pos+4)[0]
            line += 'invoke-interface/range {v%d..v%d}, %s' % (C, C+A-1, mth_sig(ref)); pos += 6
        elif op == 0x0c:  # move-result-object
            line += 'move-result-object v%d' % data[pos+1]; pos += 2
        elif op == 0x0a: line += 'move-result v%d' % data[pos+1]; pos += 2
        elif op == 0x0b: line += 'move-result-wide v%d' % data[pos+1]; pos += 2
        else:
            line += 'unknown opcode 0x%02x at %x' % (op, pos)
            pos += 2
        print(line)
    print()

# === <clinit> at code_off=0x4126a8 ===
disasm(0x4126a8, '<clinit>')

# === generateKey at code_off=0x412684 ===
disasm(0x412684, 'generateKey')

# Resolve the fill-array-data payload for <clinit>
print('=== fill-array-data payload at 0x4126cc ===')
ident = struct.unpack_from('<H', data, 0x4126cc)[0]
elem_w = struct.unpack_from('<H', data, 0x4126ce)[0]
size = struct.unpack_from('<I', data, 0x4126d0)[0]
print('ident=0x%x (should be 0x0003) elem_width=%d size=%d' % (ident, elem_w, size))
if ident == 0x0003 or ident == 0x0300:
    payload_start = 0x4126d4
    payload = data[payload_start:payload_start+size*elem_w]
    print('payload hex: ' + payload.hex(' '))
    print('payload ASCII: ' + ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in payload))
    print('payload string: ' + payload.decode('utf-8', errors='replace'))
