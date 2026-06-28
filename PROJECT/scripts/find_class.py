import mmap, struct, os, sys

TARGET_CODE_OFF = 0x4126a8
TARGET_FIELD_ID = 0xa781
TARGET_DEBUG_OFF = 0x465ecc

dex_path = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\classes.dex'

with open(dex_path, 'rb') as f:
    data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

def uleb(data, off):
    val = 0; sh = 0
    while True:
        b = data[off]; off += 1
        val |= (b & 0x7f) << sh
        sh += 7
        if (b & 0x80) == 0:
            return val, off

def uleb128p1(data, off):
    val = 0; sh = 0
    while True:
        b = data[off]; off += 1
        val |= (b & 0x7f) << sh
        sh += 7
        if (b & 0x80) == 0:
            return val - 1 if val > 0 else 0, off

# Parse header
magic = data[0:8]
assert magic[:4] == b'dex\n', f'Not a dex file: {magic[:4]}'
file_size = struct.unpack_from('<I', data, 0x20)[0]
header_size = struct.unpack_from('<I', data, 0x24)[0]
assert header_size >= 0x70

string_ids_off = struct.unpack_from('<I', data, 0x38)[0]
string_ids_size = struct.unpack_from('<I', data, 0x34)[0]
type_ids_off = struct.unpack_from('<I', data, 0x40)[0]
type_ids_size = struct.unpack_from('<I', data, 0x3C)[0]
field_ids_off = struct.unpack_from('<I', data, 0x4C)[0]
field_ids_size = struct.unpack_from('<I', data, 0x48)[0]
method_ids_off = struct.unpack_from('<I', data, 0x54)[0]
method_ids_size = struct.unpack_from('<I', data, 0x50)[0]
class_defs_off = struct.unpack_from('<I', data, 0x5C)[0]
class_defs_size = struct.unpack_from('<I', data, 0x58)[0]

print(f'classes.dex: {file_size} bytes, {class_defs_size} classes')
print(f'string_ids: {string_ids_size} at 0x{string_ids_off:x}')
print(f'type_ids: {type_ids_size} at 0x{type_ids_off:x}')
print(f'field_ids: {field_ids_size} at 0x{field_ids_off:x}')
print(f'method_ids: {method_ids_size} at 0x{method_ids_off:x}')
print(f'class_defs: {class_defs_size} at 0x{class_defs_off:x}')

# Helper: resolve string by string_idx
def get_string(idx):
    if idx >= string_ids_size:
        return f'<invalid string idx {idx}>'
    str_off = struct.unpack_from('<I', data, string_ids_off + idx * 4)[0]
    # ULEB128 encoded length
    length, pos = uleb128p1(data, str_off)
    # Read inline_insn_bytes
    raw = data[pos:pos + length]
    try:
        return raw.decode('utf-8', errors='replace')
    except:
        return repr(raw)

# Helper: resolve type by type_idx
def get_type(idx):
    if idx >= type_ids_size:
        return f'<invalid type idx {idx}>'
    str_idx = struct.unpack_from('<I', data, type_ids_off + idx * 4)[0]
    return get_string(str_idx)

# Helper: resolve field by field_idx
def get_field(idx):
    if idx >= field_ids_size:
        return f'<invalid field idx {idx}>'
    off = field_ids_off + idx * 8
    class_idx, type_idx, name_idx = struct.unpack_from('<HHI', data, off)
    return f'{get_type(class_idx)}->{get_string(name_idx)}:{get_type(type_idx)}'

# Helper: resolve method by method_idx
def get_method(idx):
    if idx >= method_ids_size:
        return f'<invalid method idx {idx}>'
    off = method_ids_off + idx * 8
    class_idx, proto_idx, name_idx = struct.unpack_from('<HHI', data, off)
    return f'{get_type(class_idx)}->{get_string(name_idx)}'

print('\n=== Scanning class_data for code_off=0x4126a8 ===')
print(f'TARGET: code_off=0x{TARGET_CODE_OFF:x}, field_id=0x{TARGET_FIELD_ID:x}')
print()

found = []
errors = []

for cidx in range(class_defs_size):
    off = class_defs_off + cidx * 32
    (class_idx, access_flags, superclass_idx, interfaces_off,
     source_file_idx, annotations_off, class_data_off, static_values_off) = \
        struct.unpack_from('<IIIIIIII', data, off)

    if class_data_off == 0:
        continue

    if cidx % 1000 == 0 and cidx > 0:
        print(f'  scanned {cidx}/{class_defs_size} classes...')

    pos = class_data_off
    try:
        static_fields_size, pos = uleb(data, pos)
        instance_fields_size, pos = uleb(data, pos)
        direct_methods_size, pos = uleb(data, pos)
        virtual_methods_size, pos = uleb(data, pos)

        # Skip static fields
        for _ in range(static_fields_size):
            _, pos = uleb(data, pos)  # field_idx_diff
            _, pos = uleb(data, pos)  # access_flags

        # Skip instance fields
        for _ in range(instance_fields_size):
            _, pos = uleb(data, pos)  # field_idx_diff
            _, pos = uleb(data, pos)  # access_flags

        # Check direct methods
        for mi in range(direct_methods_size):
            m_idx_diff, pos = uleb(data, pos)
            acc_flags, pos = uleb(data, pos)
            code_off, pos = uleb(data, pos)
            if code_off == TARGET_CODE_OFF:
                cls_type = get_type(class_idx)
                found.append({
                    'class_idx': class_idx,
                    'class_name': cls_type,
                    'method_idx': mi,
                    'kind': 'direct',
                    'access_flags': acc_flags,
                })
                print(f'  FOUND in class {cls_type} (idx={class_idx}), direct method #{mi}')

        # Check virtual methods
        for mi in range(virtual_methods_size):
            m_idx_diff, pos = uleb(data, pos)
            acc_flags, pos = uleb(data, pos)
            code_off, pos = uleb(data, pos)
            if code_off == TARGET_CODE_OFF:
                cls_type = get_type(class_idx)
                found.append({
                    'class_idx': class_idx,
                    'class_name': cls_type,
                    'method_idx': mi,
                    'kind': 'virtual',
                    'access_flags': acc_flags,
                })
                print(f'  FOUND in class {cls_type} (idx={class_idx}), virtual method #{mi}')
    except Exception as e:
        errors.append((cidx, class_idx, class_data_off, str(e)))
        if len(errors) <= 5:
            print(f'  ERROR class_def #{cidx} (class_idx={class_idx}) at 0x{class_data_off:x}: {e}')

if errors:
    print(f'\n=== PARSING ERRORS: {len(errors)} ===')
    for c, ci, cdo, e in errors[:10]:
        class_name = get_type(ci) if ci < type_ids_size else '?'
        print(f'  class_def #{c} class_idx={ci} ({class_name}) at 0x{cdo:x}: {e}')
    if len(errors) > 10:
        print(f'  ... and {len(errors)-10} more')

print(f'\n=== RESULTS ===')
if found:
    for f_entry in found:
        print(f'Class: {f_entry["class_name"]} (class_idx={f_entry["class_idx"]})')
        print(f'  Kind: {f_entry["kind"]} method #{f_entry["method_idx"]}')
        print(f'  Access: 0x{f_entry["access_flags"]:04x}')
else:
    print('No class found with code_off=0x%x' % TARGET_CODE_OFF)

# Also trace field@0xa781
print(f'\n=== Field Trace: field@0x{TARGET_FIELD_ID:x} ===')
print(f'Field: {get_field(TARGET_FIELD_ID)}')

# Now find all methods that reference this field
print(f'\n=== Searching for sput-object / sget-object referencing field@0x{TARGET_FIELD_ID:x} ===')

# Scan all code_items for sput-object (0x6a) with field@0xa781
# sput-object opcode = 0x6a, format: op(1), vAA(1), field_idx(4) = 6 bytes total

# Also look for sput-object opcode in the code we found
if found:
    f_entry = found[0]
    cls = f_entry['class_name']
    print(f'\nClass owning static initializer: {cls}')
    print(f'\nNext steps: search other methods that reference field@0x{TARGET_FIELD_ID:x} or class {cls}')
