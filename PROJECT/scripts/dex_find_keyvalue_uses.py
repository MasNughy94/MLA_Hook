import struct

DEX = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\classes.dex'
data = open(DEX, 'rb').read()
END = len(data)
TARGET_FIELD = 0xa781

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

# Pre-compute string indices for known JNI method names
# Common names that accept byte arrays
JNI_TARGETS = [b'encrypt', b'decrypt', b'encode', b'decode', b'crypt', b'aes', b'xxtea',
               b'jniEncrypt', b'jniDecrypt', b'nativeEncrypt', b'nativeDecrypt',
               b'encryptNative', b'decryptNative', b'Encrypt', b'Decrypt',
               b'stringFromJNI', b'getKey', b'setKey', b'getSecretKey', b'doFinal',
               b'Cipher']

print('Scanning all methods for sget-object field@0xa781 (keyValue)...')
print('=' * 60)

hits = []
for i in range(cds):
    off = cdo + i * 0x20
    ci = struct.unpack_from('<I', data, off)[0]
    cda = struct.unpack_from('<I', data, off + 0x18)[0]
    if cda == 0 or cda >= END: continue
    pos = cda
    sfs, pos = uleb(pos); ifs, pos = uleb(pos); dms, pos = uleb(pos); vms, pos = uleb(pos)
    if any(x < 0 or x > 50000 for x in (sfs, ifs, dms, vms)): continue
    ok = True
    for _ in range(sfs + ifs):
        p1, pos = uleb(pos); p2, pos = uleb(pos)
        if -1 in (p1, p2): ok = False; break
    if not ok: continue
    for mcount, kind in [(dms, 'direct'), (vms, 'virtual')]:
        pm = 0
        for _ in range(mcount):
            df, pos = uleb(pos)
            if df < 0: ok = False; break
            pm += df
            _, pos = uleb(pos)
            co, pos = uleb(pos)
            if co < 0: ok = False; break
            if co == 0: continue
            
            # Read code_item
            insns_size = struct.unpack_from('<I', data, co + 8)[0]
            insns_off = co + 16
            if insns_off + insns_size * 2 > END: continue
            
            # Scan for sget-object (0x62) with field_idx = TARGET_FIELD
            field_bytes = struct.pack('<H', TARGET_FIELD)
            code = data[insns_off:insns_off + insns_size * 2]
            idx = 0
            while idx < len(code) - 3:
                if code[idx] == 0x62 and code[idx+2:idx+4] == field_bytes:
                    reg = code[idx+1]
                    # Read context: up to 8 instructions before/after (each 2 bytes)
                    ctx_start = max(0, idx - 16)
                    ctx_end = min(len(code), idx + 16)
                    ctx = code[ctx_start:ctx_end]
                    
                    cn = cls_name(ci)
                    mn = mth_name(pm)
                    
                    hits.append((cn, mn, kind, i, pm, co, idx, reg, ctx, ctx_start, insns_off))
                    break  # one hit per method is enough for now
                idx += 2  # advance by instruction (2 bytes)
            # end while

print('\nFound %d methods using sget-object keyValue:\n' % len(hits))

for cn, mn, kind, cidx, pmid, co, ins_off, reg, ctx, ctx_start, insns_off_base in hits:
    print('=' * 60)
    print('Class: %s' % cn)
    print('Method: %s (%s)' % (mn, kind))
    print('Context bytes (hex): ' + ctx.hex(' '))
    # Try to disassemble context
    # Note: most instructions are 2 bytes, some are 2-5 bytes
    # Let's print a simple byte-by-byte listing
    print('Instruction bytes around the hit:')
    base = ctx_start
    for bi in range(0, len(ctx), 2):
        if bi + 1 < len(ctx):
            op = ctx[bi]
            arg = ctx[bi+1]
            abs_off = insns_off_base + base + bi
            marker = ' <<<' if base + bi == idx else ''
            print('  0x%x: %02x %02x%s' % (abs_off, op, arg, marker))
    print()

if not hits:
    print('No sget-object uses found for field@0xa781')
    # Try to find it via raw byte scan as fallback
    print('\nTrying raw byte scan for 62 xx 81 a7 pattern...')
    pattern = bytes([0x62]) + b'.\x81\xa7'
    # Actually just search for any 62 ?? 81 a7
    for off in range(END - 3):
        if data[off] == 0x62 and data[off+2] == 0x81 and data[off+3] == 0xa7:
            reg = data[off+1]
            print('  0x%x: sget-object v%d, field@0xa781' % (off, reg))
