import struct
from capstone import *

SO = r'C:\Users\NGEONG\Videos\MLA\libagame.so'
with open(SO, 'rb') as f:
    data = f.read()
END = len(data)

target = 0xceca74  # CCCrypto::setKey
target2 = 0xcecb5c  # CCCrypto::setKey2

# --- Parse ELF segments ---
ehdr = struct.unpack_from('<16sHHIQQQIHHH', data[:64])
phoff = ehdr[5]
phnum = ehdr[8]

segments = []
for i in range(phnum):
    ph = struct.unpack_from('<IIQQQQQQ', data, phoff + i * 56)
    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = ph
    if p_type == 1:  # LOAD
        segments.append((p_vaddr, p_offset, p_filesz, p_flags, p_vaddr + p_filesz))

def va_to_offset(va):
    for sv, soff, ssz, _, send in segments:
        if sv <= va < send:
            return soff + (va - sv)
    return None

def offset_to_va(off):
    for sv, soff, ssz, _, _ in segments:
        if soff <= off < soff + ssz:
            return sv + (off - soff)
    return None

# --- 1. Scan .text for BL instructions ---
print('=' * 70)
print('SCAN 1: Direct BL calls to CCCrypto::setKey (0xceca74)')
print('=' * 70)

# Find text segment (RX)
text_seg = None
for sv, soff, ssz, flags, send in segments:
    if flags == 5:  # RX
        text_seg = (sv, soff, ssz)
        break

if text_seg:
    sv, soff, ssz = text_seg
    text_start = soff
    text_end = soff + ssz
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    
    print('Text segment: vaddr=0x%x, file=0x%x, size=0x%x' % (sv, soff, ssz))
    
    # Scan in chunks for performance
    chunk_size = 0x10000
    calls = []  # (caller_va, caller_offset)
    for chunk_start in range(text_start, text_end, chunk_size):
        chunk_end = min(text_start + ssz, chunk_start + chunk_size)
        code = data[chunk_start:chunk_end]
        base_va = sv + (chunk_start - soff)
        
        for insn in md.disasm(code, base_va):
            if insn.mnemonic == 'bl' and insn.operands[0].type == 1:  # IMM
                bl_target = insn.operands[0].imm
                if bl_target == target or bl_target == target2:
                    name = 'setKey' if bl_target == target else 'setKey2'
                    caller_va = insn.address
                    caller_off = chunk_start + (insn.address - base_va)
                    calls.append((caller_va, caller_off, name, bl_target))
                    print('  BL %s at 0x%x (file: 0x%x)' % (name, caller_va, caller_off))
    
    if not calls:
        print('  NO DIRECT BL CALLS FOUND')
    
    # For each caller, disassemble surrounding context
    if calls:
        print()
        print('--- Caller Context ---')
        for caller_va, caller_off, name, bl_target in calls:
            print()
            print('Caller 0x%x -> %s (0x%x):' % (caller_va, name, bl_target))
            # Show 20 instructions before the call
            ctx_start = max(text_start, caller_off - 80)
            ctx_code = data[ctx_start:caller_off + 4]
            ctx_base = sv + (ctx_start - soff)
            for insn in md.disasm(ctx_code, ctx_base):
                marker = ' <--- CALL' if insn.address == caller_va else ''
                print('  0x%x: %s %s%s' % (insn.address, insn.mnemonic, insn.op_str, marker))

# --- 2. Search for function pointers in data sections ---
print()
print('=' * 70)
print('SCAN 2: Function pointers to setKey in data sections')
print('=' * 70)

target_bytes = struct.pack('<Q', target)
target2_bytes = struct.pack('<Q', target2)

found_data = []
for sv, soff, ssz, flags, send in segments:
    if flags == 6:  # RW data
        print('Scanning RW segment at vaddr=0x%x, file=0x%x, size=0x%x' % (sv, soff, ssz))
        seg_data = data[soff:soff+ssz]
        for ptr_name, ptr_bytes in [('setKey', target_bytes), ('setKey2', target2_bytes)]:
            off = 0
            while True:
                off = seg_data.find(ptr_bytes, off)
                if off == -1: break
                file_off = soff + off
                va = sv + off
                found_data.append((file_off, va, ptr_name))
                print('  %s pointer at file 0x%x (vaddr 0x%x)' % (ptr_name, file_off, va))
                off += 8

if not found_data:
    print('  NO function pointers found')

# --- 3. Search .data.rel.ro and .got ---
print()
print('=' * 70)
print('SCAN 3: GOT / RELRO references')
print('=' * 70)

# Search for 4-byte relative references (ADRP + ADD sequences)
# Common in vtables/static initializers
for sv, soff, ssz, flags, send in segments:
    seg_start = soff
    seg_end = soff + ssz
    # Look for the 32-bit lower portion of the target address in data sections
    target_lower = target & 0xFFFFFFFF
    target2_lower = target2 & 0xFFFFFFFF
    target_lower_bytes = struct.pack('<I', target_lower)
    target2_lower_bytes = struct.pack('<I', target2_lower)
    
    for ptr_name, pt_bytes in [('setKey', target_lower_bytes), ('setKey2', target2_lower_bytes)]:
        off = 0
        seg_data = data[soff:soff+ssz]
        while True:
            off = seg_data.find(pt_bytes, off)
            if off == -1: break
            file_off = soff + off
            va = sv + off
            # Check if this looks like a pointer (aligned to 4 or 8)
            if off % 4 == 0:
                print('  %s (32-bit) at file 0x%x (vaddr 0x%x)' % (ptr_name, file_off, va))
            off += 4

# --- 4. Use Ghidra-style relocation search ---
print()
print('=' * 70)
print('SCAN 4: Relocation entries (RELA)')
print('=' * 70)

# Parse .rela.dyn / .rela.plt
# Find RELA section via segment headers (DYNAMIC segment)
for i in range(phnum):
    ph = struct.unpack_from('<IIQQQQQQ', data, phoff + i * 56)
    p_type = ph[0]
    if p_type == 2:  # DYNAMIC
        dyn_off = ph[2]  # p_offset
        dyn_size = ph[5]  # p_filesz
        print('DYNAMIC segment at file 0x%x, size 0x%x' % (dyn_off, dyn_size))
        
        # Parse .dynamic entries to find RELA
        j = 0
        rela_addr = None
        rela_size = None
        rela_ent = None
        while j < dyn_size:
            d_tag, d_val = struct.unpack_from('<QQ', data, dyn_off + j)
            if d_tag == 0:  # DT_NULL
                break
            elif d_tag == 7:  # DT_RELA
                rela_addr = d_val
            elif d_tag == 8:  # DT_RELASZ
                rela_size = d_val
            elif d_tag == 9:  # DT_RELAENT
                rela_ent = d_val
            j += 16
        
        if rela_addr and rela_size and rela_ent:
            rela_off = va_to_offset(rela_addr)
            print('RELA table: vaddr=0x%x, file=0x%x, size=0x%x, ent_size=%d' % (rela_addr, rela_off, rela_size, rela_ent))
            
            count = rela_size // rela_ent
            for k in range(count):
                entry_off = rela_off + k * rela_ent
                r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, entry_off)
                r_type = r_info & 0xFFFFFFFF
                r_sym = r_info >> 32
                
                # R_AARCH64_ABS64 = 0x101, R_AARCH64_GLOB_DAT = 0x102, R_AARCH64_JUMP_SLOT = 0x103
                # For ABS64: the addend or symbol value equals the target
                if r_type in (0x101, 0x102, 0x103):
                    if r_addend == target or r_addend == target2:
                        name = 'setKey' if r_addend == target else 'setKey2'
                        print('  RELA: %s at vaddr 0x%x (file 0x%x), type=0x%x, sym=%d' % (name, r_offset, va_to_offset(r_offset), r_type, r_sym))
        break

print()
print('=' * 70)
if not calls and not found_data:
    print('RESULT: NO callers found for CCCrypto::setKey(0xceca74) or setKey2(0xcecb5c)')
    print('Both functions have zero direct references in the binary.')
else:
    print('SUMMARY:')
    if calls:
        for cv, co, name, bt in calls:
            print('  BL %s from 0x%x' % (name, cv))
    if found_data:
        for fo, va, name in found_data:
            print('  Data ref %s at 0x%x (file 0x%x)' % (name, va, fo))
print('=' * 70)
