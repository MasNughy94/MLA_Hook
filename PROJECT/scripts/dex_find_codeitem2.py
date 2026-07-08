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

def read_uleb128(data, off):
    result = 0
    shift = 0
    while off < len(data):
        byte = data[off]
        result |= (byte & 0x7F) << shift
        shift += 7
        off += 1
        if not (byte & 0x80):
            return result, off
    raise ValueError('Truncated ULEB128 at offset 0x%x' % off)

def get_type_name(type_idx):
    off = struct.unpack_from('<I', data, type_ids_off + type_idx * 4)[0]
    s, _ = read_uleb128(data, off)
    return data[off+_:off+_+s].decode('utf-8', errors='replace')

def get_method_info(method_idx):
    off = method_ids_off + method_idx * 8
    class_idx = struct.unpack_from('<H', data, off)[0]
    name_idx = struct.unpack_from('<I', data, off + 4)[0]
    cls = get_type_name(class_idx)
    name_off = struct.unpack_from('<I', data, string_ids_off + name_idx * 4)[0]
    s, _ = read_uleb128(data, name_off)
    method_name = data[name_off+_:name_off+_+s].decode('utf-8', errors='replace')
    return cls, method_name

target_offset = 0x4126c0

# Instead of parsing class_data which is complex, let me scan ALL code_items
# by looking for code_off references in methods.
# First, collect all code_offs from all methods
# We can find code_offs by scanning method_ids and checking class_data for each class

# Actually, let's be smarter. Just binary search through all possible code_items.
# A code_item starts with registers_size (uint16), which is typically small (<256).
# Then ins_size (uint16), outs_size (uint16), tries_size (uint16).
# Then debug_info_off (uint32), insns_size (uint32).
# Then insns[insns_size].

# The tricky part is tries_size > 0 adds try_items and catch_handlers after insns.
# We need to handle this.

# Let me try a different approach. Scan backwards from the target to find
# what looks like a code_item header. The code_item header is 16 bytes:
# 2+2+2+2+4+4 = 16

# At target 0x4126c0, the code_item header would be at some offset <= 0x4126c0.
# Looking at the data before 0x4126c0:
start_before = max(0, target_offset - 1000)
for header_off in range(target_offset - 16, start_before - 1, -2):
    # Possible header?
    regs = struct.unpack_from('<H', data, header_off)[0]
    ins = struct.unpack_from('<H', data, header_off + 2)[0]
    outs = struct.unpack_from('<H', data, header_off + 4)[0]
    tries = struct.unpack_from('<H', data, header_off + 6)[0]
    dbg = struct.unpack_from('<I', data, header_off + 8)[0]
    insns_size = struct.unpack_from('<I', data, header_off + 12)[0]
    
    code_start = header_off + 16
    code_end = code_start + insns_size * 2
    
    if code_start <= target_offset < code_end:
        # Potential match! Check if it's a valid header
        # regs should be 0-256, tries < 100 probably
        if 0 <= regs <= 256 and 0 <= ins <= regs and 0 <= outs <= regs and insns_size > 0 and insns_size < 100000:
            # Also need to handle try/catch blocks
            if tries > 0:
                # Skip try_items and catch_handlers to verify this is self-consistent
                pass
            
            # Now check if this code_off is referenced by any method
            # Scan class_defs to verify
            print('Candidate code_item at 0x%x: regs=%d, ins=%d, outs=%d, tries=%d, dbg=0x%x, insns=%d' %
                  (header_off, regs, ins, outs, tries, dbg, insns_size))
            print('  Target is at offset +%d in code' % (target_offset - code_start))

# Since scanning all candidates is error-prone, let me directly find 
# which class_def references our code_off
print()
print('=== Direct search by scanning all class_data ===')
print()

# Alternative simpler approach
# Iterate all method_ids and look up code_off from class_data
# Actually each method_id has an index into class_def's method lists

# Let me just iterate all class_defs more carefully
for cd_idx in range(class_defs_size):
    cd_off = class_defs_off + cd_idx * 0x20
    class_data_off = struct.unpack_from('<I', data, cd_off + 0x14)[0]
    if class_data_off == 0:
        continue
    
    try:
        pos = class_data_off
        static_fields_size, pos = read_uleb128(data, pos)
        instance_fields_size, pos = read_uleb128(data, pos)
        direct_methods_size, pos = read_uleb128(data, pos)
        virtual_methods_size, pos = read_uleb128(data, pos)
    except:
        continue
    
    # Static fields
    for _ in range(static_fields_size):
        try:
            _, pos = read_uleb128(data, pos)
            _, pos = read_uleb128(data, pos)
        except:
            break
    
    # Instance fields
    for _ in range(instance_fields_size):
        try:
            _, pos = read_uleb128(data, pos)
            _, pos = read_uleb128(data, pos)
        except:
            break
    
    # Direct methods
    prev = 0
    found_here = False
    for m in range(direct_methods_size):
        try:
            diff, pos = read_uleb128(data, pos)
            prev += diff
            _, pos = read_uleb128(data, pos)  # access_flags
            code_off, pos = read_uleb128(data, pos)
        except:
            break
        
        if code_off == 0:
            continue
        
        try:
            regs = struct.unpack_from('<H', data, code_off)[0]
            ins = struct.unpack_from('<H', data, code_off + 2)[0]
            outs = struct.unpack_from('<H', data, code_off + 4)[0]
            tries = struct.unpack_from('<H', data, code_off + 6)[0]
            dbg = struct.unpack_from('<I', data, code_off + 8)[0]
            insns_size = struct.unpack_from('<I', data, code_off + 12)[0]
        except:
            continue
        
        cstart = code_off + 16
        cend = cstart + insns_size * 2
        if cstart <= target_offset < cend:
            cls_name = get_type_name(struct.unpack_from('<I', data, cd_off)[0])
            cls2, mn = get_method_info(prev)
            print('DIRECT %s.%s() code_off=0x%x insns_size=%d' % (cls_name, mn, code_off, insns_size))
            
            # Show instructions around target
            off_in_method = target_offset - cstart
            instr_addr = off_in_method  # in bytes
            print('  fill-array-data at instruction offset %d' % instr_addr)
            
            # Show the full method disassembly context
            print('  Full method bytes (%d units):' % insns_size)
            for i in range(0, min(insns_size * 2, 200), 2):
                off = cstart + i
                opcode = data[off]
                marker = ' <--- fill-array-data' if off == target_offset else ''
                if marker or i >= instr_addr - 16:
                    print('    +%3d: 0x%04x op=0x%02x%s' % (i, struct.unpack_from('<H', data, off)[0], opcode, marker))
            
            found_here = True
            break
    
    if found_here:
        break
    
    # Virtual methods
    prev = 0
    for m in range(virtual_methods_size):
        try:
            diff, pos = read_uleb128(data, pos)
            prev += diff
            _, pos = read_uleb128(data, pos)  # access_flags
            code_off, pos = read_uleb128(data, pos)
        except:
            break
        
        if code_off == 0:
            continue
        
        try:
            regs = struct.unpack_from('<H', data, code_off)[0]
            ins = struct.unpack_from('<H', data, code_off + 2)[0]
            outs = struct.unpack_from('<H', data, code_off + 4)[0]
            tries = struct.unpack_from('<H', data, code_off + 6)[0]
            dbg = struct.unpack_from('<I', data, code_off + 8)[0]
            insns_size = struct.unpack_from('<I', data, code_off + 12)[0]
        except:
            continue
        
        cstart = code_off + 16
        cend = cstart + insns_size * 2
        if cstart <= target_offset < cend:
            cls_name = get_type_name(struct.unpack_from('<I', data, cd_off)[0])
            cls2, mn = get_method_info(prev)
            print('VIRTUAL %s.%s() code_off=0x%x insns_size=%d' % (cls_name, mn, code_off, insns_size))
            
            off_in_method = target_offset - cstart
            
            print('  Full method bytes (%d units):' % insns_size)
            for i in range(0, min(insns_size * 2, 200), 2):
                off = cstart + i
                opcode = data[off]
                marker = ' <--- fill-array-data' if off == target_offset else ''
                if marker or i >= off_in_method - 16:
                    print('    +%3d: 0x%04x op=0x%02x%s' % (i, struct.unpack_from('<H', data, off)[0], opcode, marker))
            
            found_here = True
            break
    
    if found_here:
        break
