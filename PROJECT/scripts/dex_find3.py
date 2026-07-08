import struct, sys

dex_path = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\classes.dex'
with open(dex_path, 'rb') as f:
    data = f.read()

string_ids_off = struct.unpack_from('<I', data, 0x3C)[0]
string_ids_size = struct.unpack_from('<I', data, 0x38)[0]
type_ids_off = struct.unpack_from('<I', data, 0x44)[0]
type_ids_size = struct.unpack_from('<I', data, 0x40)[0]
method_ids_off = struct.unpack_from('<I', data, 0x5C)[0]
class_defs_off = struct.unpack_from('<I', data, 0x64)[0]
class_defs_size = struct.unpack_from('<I', data, 0x60)[0]

def read_uleb128_safe(data, off):
    result = 0
    shift = 0
    start = off
    while off < len(data):
        byte = data[off]
        result |= (byte & 0x7F) << shift
        shift += 7
        off += 1
        if not (byte & 0x80):
            return result, off
    return -1, start

def safe_str(off):
    try:
        s, _ = read_uleb128_safe(data, off)
        return data[off+_:off+_+s].decode('utf-8', errors='replace')
    except:
        return '<err>'

target_instr_off = 0x4126c0
print('Looking for code_item covering offset 0x%x (fill-array-data instruction)...' % target_instr_off)

found = False
for cd_idx in range(class_defs_size):
    if found:
        break
    
    cd_off = class_defs_off + cd_idx * 0x20
    class_data_off = struct.unpack_from('<I', data, cd_off + 0x14)[0]
    if class_data_off == 0:
        continue
    
    pos = class_data_off
    
    sfs, pos = read_uleb128_safe(data, pos)
    if sfs < 0: continue
    ifs, pos = read_uleb128_safe(data, pos)
    if ifs < 0: continue
    dms, pos = read_uleb128_safe(data, pos)
    if dms < 0: continue
    vms, pos = read_uleb128_safe(data, pos)
    if vms < 0: continue
    
    # Skip field defs
    for _ in range(sfs + ifs):
        _, pos = read_uleb128_safe(data, pos)
        _, pos = read_uleb128_safe(data, pos)
    
    # Direct methods
    prev = 0
    for m in range(dms):
        diff, pos = read_uleb128_safe(data, pos)
        if diff < 0: continue
        prev += diff
        _, pos = read_uleb128_safe(data, pos)  # access
        code_off, pos = read_uleb128_safe(data, pos)
        
        if code_off <= 0:
            continue
        
        # Check if target falls within this method's instructions
        try:
            insns_size = struct.unpack_from('<I', data, code_off + 12)[0]
        except:
            continue
        
        cstart = code_off + 16
        cend = cstart + insns_size * 2
        
        if cstart <= target_instr_off < cend:
            cls_idx = struct.unpack_from('<I', data, cd_off)[0]
            cls_name = safe_str(struct.unpack_from('<I', data, type_ids_off + cls_idx * 4)[0])
            
            moff = method_ids_off + prev * 8
            mn_idx = struct.unpack_from('<I', data, moff + 4)[0]
            mname = safe_str(struct.unpack_from('<I', data, string_ids_off + mn_idx * 4)[0])
            
            print('FOUND: %s.%s() [direct]' % (cls_name, mname))
            print('  code_off=0x%x, insns_size=%d' % (code_off, insns_size))
            offset_in_method = target_instr_off - cstart
            print('  fill-array-data at offset %d bytes (code unit %d)' % (offset_in_method, offset_in_method // 2))
            
            # Decode the fill-array-data
            print()
            print('  fill-array-data payload at 0x%x:' % (target_instr_off + 4 + struct.unpack_from('<i', data, target_instr_off + 2)[0] * 2))
            
            # Dump method bytecode
            print()
            print('  Method bytecode:')
            for i in range(0, min(insns_size * 2, 200), 2):
                off = cstart + i
                instr = struct.unpack_from('<H', data, off)[0]
                op = data[off]
                marker = ' <---' if off == target_instr_off else ''
                payload_str = ''
                if op == 0x26:
                    off_val = struct.unpack_from('<i', data, off + 2)[0]
                    payload_str = ' payload_off=%+d' % off_val
                elif op == 0x1a:
                    sid = struct.unpack_from('<H', data, off + 2)[0]
                    payload_str = ' string_id=%d' % sid
                elif op == 0x1b:
                    sid = struct.unpack_from('<I', data, off + 2)[0]
                    payload_str = ' string_id=%d' % sid
                print('    [%d] 0x%04x%s%s' % (i//2, instr, payload_str, marker))
            
            found = True
            break
    
    if found:
        break
    
    # Virtual methods
    prev = 0
    for m in range(vms):
        diff, pos = read_uleb128_safe(data, pos)
        if diff < 0: continue
        prev += diff
        _, pos = read_uleb128_safe(data, pos)
        code_off, pos = read_uleb128_safe(data, pos)
        
        if code_off <= 0:
            continue
        
        try:
            insns_size = struct.unpack_from('<I', data, code_off + 12)[0]
        except:
            continue
        
        cstart = code_off + 16
        cend = cstart + insns_size * 2
        
        if cstart <= target_instr_off < cend:
            cls_idx = struct.unpack_from('<I', data, cd_off)[0]
            cls_name = safe_str(struct.unpack_from('<I', data, type_ids_off + cls_idx * 4)[0])
            
            moff = method_ids_off + prev * 8
            mn_idx = struct.unpack_from('<I', data, moff + 4)[0]
            mname = safe_str(struct.unpack_from('<I', data, string_ids_off + mn_idx * 4)[0])
            
            print('FOUND: %s.%s() [virtual]' % (cls_name, mname))
            print('  code_off=0x%x, insns_size=%d' % (code_off, insns_size))
            offset_in_method = target_instr_off - cstart
            
            print()
            print('  Method bytecode:')
            for i in range(0, min(insns_size * 2, 200), 2):
                off = cstart + i
                instr = struct.unpack_from('<H', data, off)[0]
                op = data[off]
                marker = ' <---' if off == target_instr_off else ''
                payload_str = ''
                if op == 0x26:
                    off_val = struct.unpack_from('<i', data, off + 2)[0]
                    payload_str = ' payload_off=%+d' % off_val
                elif op == 0x1a:
                    sid = struct.unpack_from('<H', data, off + 2)[0]
                    payload_str = ' string_id=%d' % sid
                elif op == 0x1b:
                    sid = struct.unpack_from('<I', data, off + 2)[0]
                    payload_str = ' string_id=%d' % sid
                print('    [%d] 0x%04x%s%s' % (i//2, instr, payload_str, marker))
            
            found = True
            break

if not found:
    print('NOT FOUND in any method')
