import struct, sys

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

def read_uleb128p1(data, off):
    val, off = read_uleb128(data, off)
    return val - 1, off

def dex_find_string(dex_path, target_str):
    with open(dex_path, 'rb') as f:
        data = f.read()
    
    header_size = struct.unpack_from('<I', data, 0x24)[0]
    string_ids_size = struct.unpack_from('<I', data, 0x38)[0]
    string_ids_off = struct.unpack_from('<I', data, 0x3C)[0]
    type_ids_size = struct.unpack_from('<I', data, 0x40)[0]
    type_ids_off = struct.unpack_from('<I', data, 0x44)[0]
    proto_ids_size = struct.unpack_from('<I', data, 0x48)[0]
    proto_ids_off = struct.unpack_from('<I', data, 0x4C)[0]
    field_ids_size = struct.unpack_from('<I', data, 0x50)[0]
    field_ids_off = struct.unpack_from('<I', data, 0x54)[0]
    method_ids_size = struct.unpack_from('<I', data, 0x58)[0]
    method_ids_off = struct.unpack_from('<I', data, 0x5C)[0]
    class_defs_size = struct.unpack_from('<I', data, 0x60)[0]
    class_defs_off = struct.unpack_from('<I', data, 0x64)[0]
    
    target_bytes = target_str.encode('latin-1')
    
    # Read all string offsets and decode each string to find the target
    target_id = None
    for i in range(string_ids_size):
        off = struct.unpack_from('<I', data, string_ids_off + i*4)[0]
        # Decode MUTF-8 string
        s, _ = read_uleb128(data, off)
        str_start = _  # past length
        str_end = str_start + s
        str_data = data[str_start:str_end]
        # Convert MUTF-8 (serialize raw, it's ASCII compatible)
        try:
            decoded = str_data.decode('utf-8')
        except:
            continue
        if decoded == target_str:
            target_id = i
            break
    
    return target_id, data, string_ids_size, type_ids_size, proto_ids_size, field_ids_size, method_ids_size, class_defs_off

def find_string_xrefs(data, string_ids_size, target_id):
    """Find all instructions that reference the given string ID."""
    refs = []
    
    # Search through all class data for const-string instructions
    # const-string: 0x1a | string_id@BBBB
    # const-string/jumbo: 0x1b | string_id@AAAAAAAA
    
    # Scan entire DEX for these opcodes
    off = 0
    while off < len(data) - 3:
        opcode = data[off]
        
        # const-string vAA, string@BBBB (format 21c)
        if opcode == 0x1a:
            string_id = struct.unpack_from('<H', data, off + 2)[0]
            if string_id == target_id:
                refs.append(('const-string', off))
        
        # const-string/jumbo vAA, string@AAAAAAAA (format 31c)
        elif opcode == 0x1b:
            string_id = struct.unpack_from('<I', data, off + 2)[0]
            if string_id == target_id:
                refs.append(('const-string/jumbo', off))
        
        off += 1
    
    return refs

def get_method_name(data, method_ids_off, method_idx):
    """Get class_name.method_name for a method ID."""
    off = method_ids_off + method_idx * 8
    class_idx = struct.unpack_from('<H', data, off)[0]
    proto_idx = struct.unpack_from('<H', data, off + 2)[0]
    name_idx = struct.unpack_from('<I', data, off + 4)[0]
    return name_idx  # return string ID for method name

def resolve_method(data, string_ids_size, string_ids_off, type_ids_off, type_ids_size, method_ids_off, method_idx):
    """Resolve method ID to full signature."""
    off = method_ids_off + method_idx * 8
    class_idx = struct.unpack_from('<H', data, off)[0]
    proto_idx = struct.unpack_from('<H', data, off + 2)[0]
    name_idx = struct.unpack_from('<I', data, off + 4)[0]
    
    # Get class name from type_ids[class_idx]
    type_off = struct.unpack_from('<I', data, type_ids_off + class_idx * 4)[0]
    s, _ = read_uleb128(data, type_off)
    cls_name = data[type_off+_:type_off+_+s].decode('utf-8', errors='replace')
    
    # Get method name
    name_str_off = struct.unpack_from('<I', data, string_ids_off + name_idx * 4)[0]
    s, _ = read_uleb128(data, name_str_off)
    method_name = data[name_str_off+_:name_str_off+_+s].decode('utf-8', errors='replace')
    
    return cls_name, method_name

def find_method_containing(data, code_offset):
    """Find which class and method contains a given code offset.
    
    We need to scan class_defs to find the class, then its class_data to find methods.
    This is complex. Instead, let's search backward for method headers.
    """
    # DEX method header format at code_offset:
    # ushort registers_size
    # ushort ins_size (args)
    # ushort outs_size
    # ushort tries_size
    # uint debug_info_off
    # uint insns_size (code units)
    # ushort[] insns
    
    # We'll scan backward from the reference to find the method header
    pass

def main():
    dex_paths = [
        r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\classes.dex',
        r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\classes2.dex',
    ]
    
    target = 'moontonAGame1234'
    
    for dex_path in dex_paths:
        print('=== %s ===' % dex_path)
        result = dex_find_string(dex_path, target)
        target_id = result[0]
        data = result[1]
        
        if target_id is None:
            print('  String not found.')
            continue
        
        print('  String ID: %d (0x%x)' % (target_id, target_id))
        
        # Find all references
        refs = find_string_xrefs(data, result[2], target_id)
        print('  References found: %d' % len(refs))
        
        # For each reference, read context
        for ref_type, ref_off in refs:
            # Read surrounding bytes for context
            start = max(0, ref_off - 16)
            end = min(len(data), ref_off + 16)
            print('    %s at offset 0x%x' % (ref_type, ref_off))
            
            # Convert to file offset if needed
            print('      Raw bytes: %s' % data[ref_off:ref_off+6].hex())

if __name__ == '__main__':
    main()
