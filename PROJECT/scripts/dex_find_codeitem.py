import struct, sys

dex_path = r'C:\Users\NGEONG\Videos\MLA\MLADVENTURE2\classes.dex'
with open(dex_path, 'rb') as f:
    data = f.read()

string_ids_off = struct.unpack_from('<I', data, 0x3C)[0]
string_ids_size = struct.unpack_from('<I', data, 0x38)[0]
type_ids_off = struct.unpack_from('<I', data, 0x44)[0]
type_ids_size = struct.unpack_from('<I', data, 0x40)[0]
method_ids_off = struct.unpack_from('<I', data, 0x5C)[0]
method_ids_size = struct.unpack_from('<I', data, 0x58)[0]
class_defs_off = struct.unpack_from('<I', data, 0x64)[0]
class_defs_size = struct.unpack_from('<I', data, 0x60)[0]

def read_uleb128(data, off):
    result = 0
    shift = 0
    while True:
        byte = data[off]
        result |= (byte & 0x7F) << shift
        shift += 7
        off += 1
        if not (byte & 0x80):
            break
    return result, off

def get_type_name(type_idx):
    off = struct.unpack_from('<I', data, type_ids_off + type_idx * 4)[0]
    s, _ = read_uleb128(data, off)
    return data[off+_:off+_+s].decode('utf-8', errors='replace')

def get_method_info(method_idx):
    off = method_ids_off + method_idx * 8
    class_idx = struct.unpack_from('<H', data, off)[0]
    proto_idx = struct.unpack_from('<H', data, off + 2)[0]
    name_idx = struct.unpack_from('<I', data, off + 4)[0]
    cls = get_type_name(class_idx)
    name_off = struct.unpack_from('<I', data, string_ids_off + name_idx * 4)[0]
    s, _ = read_uleb128(data, name_off)
    method_name = data[name_off+_:name_off+_+s].decode('utf-8', errors='replace')
    return cls, method_name

def get_class_name(cd_off):
    type_idx = struct.unpack_from('<I', data, cd_off)[0]
    return get_type_name(type_idx)

target_offset = 0x4126c0

print('Searching for code_item containing offset 0x%x...' % target_offset)

found = False
for cd_idx in range(class_defs_size):
    if found:
        break
    cd_off = class_defs_off + cd_idx * 0x20
    class_data_off = struct.unpack_from('<I', data, cd_off + 0x14)[0]
    if class_data_off == 0:
        continue
    
    pos = class_data_off
    static_fields_size, pos = read_uleb128(data, pos)
    instance_fields_size, pos = read_uleb128(data, pos)
    direct_methods_size, pos = read_uleb128(data, pos)
    virtual_methods_size, pos = read_uleb128(data, pos)
    
    # Skip field definitions
    for _ in range(static_fields_size + instance_fields_size):
        _, pos = read_uleb128(data, pos)  # field_idx_diff
        _, pos = read_uleb128(data, pos)  # access_flags
    
    # Check direct methods
    prev = 0
    for m in range(direct_methods_size):
        diff, pos = read_uleb128(data, pos)
        prev += diff
        access, pos = read_uleb128(data, pos)
        code_off, pos = read_uleb128(data, pos)
        if code_off == 0:
            continue
        
        regs = struct.unpack_from('<H', data, code_off)[0]
        ins_size = struct.unpack_from('<H', data, code_off + 2)[0]
        outs = struct.unpack_from('<H', data, code_off + 4)[0]
        tries = struct.unpack_from('<H', data, code_off + 6)[0]
        dbg = struct.unpack_from('<I', data, code_off + 8)[0]
        insns_size = struct.unpack_from('<I', data, code_off + 12)[0]
        
        cstart = code_off + 16
        cend = cstart + insns_size * 2
        if cstart <= target_offset < cend:
            cls, mn = get_method_info(prev)
            offset_in_method = target_offset - cstart
            print('DIRECT: %s.%s() (method_idx=%d)' % (cls, mn, prev))
            print('  code_off=0x%x, insns_size=%d, offset_in_method=%d bytes' % (code_off, insns_size, offset_in_method))
            # Show context
            print('  Method bytes at 0x%x:' % target_offset)
            for i in range(-8, 32):
                off = target_offset + i
                if 0 <= off < len(data):
                    marker = ' <--' if i == 0 else ''
                    print('    0x%x: 0x%02x%s' % (off, data[off], marker))
            found = True
            break
    
    if found:
        break
    
    # Check virtual methods
    prev = 0
    for m in range(virtual_methods_size):
        diff, pos = read_uleb128(data, pos)
        prev += diff
        access, pos = read_uleb128(data, pos)
        code_off, pos = read_uleb128(data, pos)
        if code_off == 0:
            continue
        
        regs = struct.unpack_from('<H', data, code_off)[0]
        ins_size = struct.unpack_from('<H', data, code_off + 2)[0]
        outs = struct.unpack_from('<H', data, code_off + 4)[0]
        tries = struct.unpack_from('<H', data, code_off + 6)[0]
        dbg = struct.unpack_from('<I', data, code_off + 8)[0]
        insns_size = struct.unpack_from('<I', data, code_off + 12)[0]
        
        cstart = code_off + 16
        cend = cstart + insns_size * 2
        if cstart <= target_offset < cend:
            cls, mn = get_method_info(prev)
            offset_in_method = target_offset - cstart
            print('VIRTUAL: %s.%s() (method_idx=%d)' % (cls, mn, prev))
            print('  code_off=0x%x, insns_size=%d, offset_in_method=%d bytes' % (code_off, insns_size, offset_in_method))
            print('  Method bytes at 0x%x:' % target_offset)
            for i in range(-8, 32):
                off = target_offset + i
                if 0 <= off < len(data):
                    marker = ' <--' if i == 0 else ''
                    print('    0x%x: 0x%02x%s' % (off, data[off], marker))
            found = True
            break

if not found:
    print('NOT FOUND in any code_item!')
