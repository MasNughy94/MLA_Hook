import struct

DEX = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\classes.dex'
data = open(DEX, 'rb').read()
END = len(data)

sio = struct.unpack_from('<I', data, 0x3C)[0]
tio = struct.unpack_from('<I', data, 0x44)[0]
mio = struct.unpack_from('<I', data, 0x5C)[0]
cdo = struct.unpack_from('<I', data, 0x64)[0]
cds = struct.unpack_from('<I', data, 0x60)[0]
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

def cls_name(ti):
    s = raw_str(struct.unpack_from('<I', data, tio + ti * 4)[0])
    return s.decode('utf-8', errors='replace')

def mth_name(mi):
    s = raw_str(struct.unpack_from('<I', data, sio + struct.unpack_from('<I', data, mio + mi * 8 + 4)[0] * 4)[0])
    return s.decode('utf-8', errors='replace')

# Dump context around 0x412698
off = 0x412698
print('Context around 0x412698 (sget-object v1, field@0xa781):')
print('=' * 60)
start = max(0, off - 32)
end = min(END, off + 80)
for i in range(start, end, 16):
    chunk = data[i:i+16]
    seg = ' '.join(f'{b:02x}' for b in chunk)
    asc = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
    marker = '  <-- instruction here' if i <= off < i+16 else ''
    print(f'  0x{i:06x}: {seg:48s} {asc}{marker}')

# Find which code_item header this instruction belongs to
# Scan backward from 0x412698 to find a valid code_item header
# code_item structure: regs(2) ins(2) outs(2) tries(2) debug_off(4) insns_size(4) insns[]
# regs should be plausible (< 256), ins_size <= regs, outs <= regs, insns_size ~ plausible

print('\nSearching backward for code_item header...')
for candidate in range(off - 64, off, 2):  # must be 2-aligned
    if candidate < 0: continue
    regs = struct.unpack_from('<H', data, candidate)[0]
    ins = struct.unpack_from('<H', data, candidate+2)[0]
    outs = struct.unpack_from('<H', data, candidate+4)[0]
    tries = struct.unpack_from('<H', data, candidate+6)[0]
    debug_off = struct.unpack_from('<I', data, candidate+8)[0]
    insns_size = struct.unpack_from('<I', data, candidate+12)[0]
    # Sanity: instruction area should cover our target offset
    insns_start = candidate + 16
    insns_end = insns_start + insns_size * 2
    if regs <= 32 and ins <= regs and outs <= regs and insns_size < 65536:
        if insns_start <= off < insns_end:
            print('  Possible code_item at 0x%x: regs=%d ins=%d outs=%d tries=%d debug=0x%x insns_size=%d' 
                  % (candidate, regs, ins, outs, tries, debug_off, insns_size))
            # Show instructions at this code_item
            print('\n  Instructions from 0x%x:' % insns_start)
            for j in range(0, min(insns_size * 2, 48), 2):
                abs_j = insns_start + j
                if abs_j >= END: break
                op = data[abs_j]
                arg = data[abs_j+1] if abs_j+1 < END else 0
                marker = ' <<<' if abs_j == off else ''
                print('    0x%x: %02x %02x%s' % (abs_j, op, arg, marker))

# Now find the method that contains this instruction
print('\nSearching for method that contains 0x412698...')
for i in range(cds):
    o = cdo + i * 0x20
    ci = struct.unpack_from('<I', data, o)[0]
    cda = struct.unpack_from('<I', data, o + 0x18)[0]
    if cda == 0 or cda >= END: continue
    pos = cda
    sfs, pos = uleb(pos); ifs, pos = uleb(pos); dms, pos = uleb(pos); vms, pos = uleb(pos)
    if any(x < 0 or x > 50000 for x in (sfs, ifs, dms, vms)): continue
    ok = True
    for _ in range(sfs + ifs):
        p1, pos = uleb(pos); p2, pos = uleb(pos)
        if -1 in (p1, p2): ok = False; break
    if not ok: continue
    for mcount in [dms, vms]:
        pm = 0
        for _ in range(mcount):
            df, pos = uleb(pos)
            if df < 0: ok = False; break
            pm += df
            _, pos = uleb(pos)
            co, pos = uleb(pos)
            if co < 0: ok = False; break
            if co == 0: continue
            insns_start = co + 16
            insns_size = struct.unpack_from('<I', data, co + 12)[0]
            insns_end = insns_start + insns_size * 2
            if insns_start <= off < insns_end:
                cn = cls_name(ci)
                mn = mth_name(pm)
                print('  FOUND: Class=%s Method=%s (class_def=%d, method_idx=%d)' % (cn, mn, i, pm))
                print('  code_off=0x%x, insns_start=0x%x, insns_size=%d' % (co, insns_start, insns_size))
                # Dump full instruction context
                ctx_start = max(insns_start, off - 32)
                ctx_end = min(insns_end, off + 32)
                print('\n  Instruction context:')
                for j in range(ctx_start - insns_start, ctx_end - insns_start, 2):
                    abs_j = insns_start + j
                    if abs_j >= END: break
                    op = data[abs_j]
                    arg = data[abs_j+1] if abs_j+1 < END else 0
                    marker = ' <<<' if abs_j == off else ''
                    print('    0x%x: %02x %02x%s' % (abs_j, op, arg, marker))
