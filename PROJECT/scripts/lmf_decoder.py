import struct, math, sys

P = 0x400    # initial probability
PM = 0x800   # probability max
PS = 5       # update shift
RB = 11      # range bit (h>>11)*prob
RT = 0x1000000  # renormalization threshold

def upd(prob, bit):
    return ((prob + ((PM - prob) >> PS)) if bit == 0 else (prob - (prob >> PS))) & 0xFFFF

def decode_lmf(data: bytes) -> bytes:
    # Parse header
    if data[:4] != b'lmF@':
        raise ValueError('Not lmF@ format')

    hdr = data[:14]
    flags = bytearray(5)
    flags[0] = hdr[4]
    flags[1] = hdr[5]
    flags[2] = hdr[6]
    flags[3] = hdr[7] ^ 5
    flags[4] = hdr[8]

    e = flags[0]
    ws = e // 9
    r9 = e % 9

    # prob_shift from ARM UMULL emulation (64-bit result, >>34)
    ps = (ws * 0xCCCCCCCD) >> 34
    r5 = ws - ps * 5
    te = (0x300 << (r5 + r9)) + 0x736
    mk = (1 << ps) - 1

    # Decompressed size
    ds = struct.unpack_from('<I', data, 0x0A)[0] ^ 0x3EA

    # Build compressed data
    cd = bytearray(data)
    for i in range(min(ds, 16)):
        cd[0x0E + i] ^= 0xEC
    cd = bytes(cd[0x0E:])

    ctx = [cd[0], cd[1], cd[2], cd[3], cd[4]]
    si = ctx[0] & 0xF
    dp = 5
    h = 0xFFFFFFFF
    l = (cd[1] << 24) | (cd[2] << 16) | (cd[3] << 8) | cd[4]

    tbl = [P] * te

    def rn():
        nonlocal h, l, dp
        while h < RT:
            h = (h << 8) & 0xFFFFFFFF
            if dp < len(cd):
                l = ((l << 8) | cd[dp]) & 0xFFFFFFFF
                dp += 1
            else:
                l = (l << 8) & 0xFFFFFFFF

    def db(pr):
        nonlocal h, l
        rn()
        m = ((h >> RB) * pr) & 0xFFFFFFFF
        if l < m:
            h = m
            return 0
        else:
            l = (l - m) & 0xFFFFFFFF
            h = (h - m) & 0xFFFFFFFF
            return 1

    bc = 0
    pb = 0
    wm = 4095
    w = bytearray(4096)
    wp = 0
    out = bytearray()

    def shift_ctx(byte):
        nonlocal si
        ctx[0], ctx[1], ctx[2], ctx[3], ctx[4] = ctx[1], ctx[2], ctx[3], ctx[4], byte
        si = ctx[0] & 0xF

    while len(out) < ds:
        ci = (si << 4) + (bc & mk)
        b = db(tbl[ci])
        tbl[ci] = upd(tbl[ci], b)

        if b == 0:  # literal
            ii = 1
            while ii <= 0xFF:
                pr = tbl[0x736 + ii]
                b2 = db(pr)
                tbl[0x736 + ii] = upd(pr, b2)
                ii = (ii << 1) | b2
            v = ii & 0xFF
            out.append(v)
            w[wp & wm] = v
            wp += 1
            pb = v
            shift_ctx(v)
            bc += 1

        else:  # match
            si2 = si + 0xC0
            bs = db(tbl[si2])
            tbl[si2] = upd(tbl[si2], bs)

            if bs == 0:  # short match (repeat)
                ii = 1
                while ii <= 7:
                    pr = tbl[0x332 + ii]
                    b2 = db(pr)
                    tbl[0x332 + ii] = upd(pr, b2)
                    ii = (ii << 1) | b2
                l2 = (ii & 0xFF) + 3
            else:  # long match
                l2 = 0
                for i in range(5):
                    pr = tbl[(si << 4) + 0xCC + i]
                    b2 = db(pr)
                    tbl[(si << 4) + 0xCC + i] = upd(pr, b2)
                    l2 = (l2 << 1) | b2
                    if b2 == 0:
                        break
                l2 += 3

            sc = min(l2 - 3, 3)
            sb = 0x1B0 + sc * 64
            sl = 0
            for i in range(6):
                pr = tbl[sb + i]
                b2 = db(pr)
                tbl[sb + i] = upd(pr, b2)
                sl = (sl << 1) | b2
                if b2 == 0:
                    break

            if sl < 4:
                d2 = sl + 1
            else:
                ex = (sl >> 1) - 1
                d2 = ((2 + (sl & 1)) << ex) + 1
                for i in range(ex):
                    pr = tbl[sb + 6 + i]
                    b2 = db(pr)
                    tbl[sb + 6 + i] = upd(pr, b2)
                    d2 = (d2 << 1) | b2

            bc += 1
            for i in range(l2):
                src = wp - d2
                by = w[(src + i) & wm] if 0 <= src < len(w) else 0
                out.append(by)
                w[wp & wm] = by
                wp += 1
                pb = by
                shift_ctx(by)

    return bytes(out)


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else r'C:\Users\NGEONG\Videos\VSCODE\mt_dump\intermediate\01_aes_output.bin'
    data = open(path, 'rb').read()
    result = decode_lmf(data)
    out_path = path + '.decompressed'
    open(out_path, 'wb').write(result)
    print(f'Decompressed: {len(result)} bytes -> {out_path}')
    print(f'First 48: {result[:48].hex()}')

    # Compare with reference
    ref_path = r'C:\Users\NGEONG\Videos\VSCODE\mt_dump\intermediate\0002_final_decompressed.bin'
    try:
        ref = open(ref_path, 'rb').read()
        m = sum(1 for a, b in zip(result, ref) if a == b)
        print(f'Match with ref: {m}/{min(len(result), len(ref))} bytes')
        if m < min(len(result), len(ref)):
            for i in range(min(len(result), len(ref))):
                if result[i] != ref[i]:
                    print(f'  First diff at [{i}] got={result[i]:02x} ref={ref[i]:02x}')
                    break
    except:
        print('No reference file found')
