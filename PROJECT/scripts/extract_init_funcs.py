"""
Extract and analyze all 53 .init_array constructor functions from libagame.so.
Target: identify which function potentially initializes CCCrypto::m_sKey.
"""
import struct
import subprocess
import json
import re
import sys
from pathlib import Path

LIBAGAME = r"C:\Users\NGEONG\Videos\MLA\libagame.so"
CAPSTONE = r"C:\Users\NGEONG\AppData\Local\Programs\Python\Python312\Lib\site-packages\capstone\lib\x64\capstone.dll"

import capstone

def read_u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]

def read_u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]

def read_u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]

def read_s32(data, offset):
    return struct.unpack_from("<i", data, offset)[0]

def read_u8(data, offset):
    return struct.unpack_from("<B", data, offset)[0]

def read_s64(data, offset):
    return struct.unpack_from("<q", data, offset)[0]

def read_cstr(data, offset, maxlen=256):
    end = data.find(b'\x00', offset, offset + maxlen)
    return data[offset:end].decode('ascii', errors='replace') if end > offset else ""

# ── Load ELF ────────────────────────────────────────────────
print("Loading libagame.so...")
with open(LIBAGAME, "rb") as f:
    elf = f.read()

# ── Parse ELF header ────────────────────────────────────────
e_ident = elf[:16]
ei_class = e_ident[4]  # 2 = 64-bit
ei_data = e_ident[5]   # 1 = LE
if ei_class != 2 or ei_data != 1:
    print("ERROR: Not 64-bit LE")
    sys.exit(1)

e_phoff = read_u64(elf, 0x20)  # Program header offset
e_shoff = read_u64(elf, 0x28)  # Section header offset
e_phentsize = read_u16(elf, 0x36)
e_phnum = read_u16(elf, 0x38)
e_shentsize = read_u16(elf, 0x3a)
e_shnum = read_u16(elf, 0x3c)
e_shstrndx = read_u16(elf, 0x3e)

print(f"  PHDR: offset=0x{e_phoff:x}, num={e_phnum}, entsize={e_phentsize}")
print(f"  SHDR: offset=0x{e_shoff:x}, num={e_shnum}, entsize={e_shentsize}")
print(f"  Section string table index: {e_shstrndx}")

# ── Parse section headers ───────────────────────────────────
sections = []
shstrtab_off = e_shoff + e_shstrndx * e_shentsize
shstrtab_sh_offset = read_u64(elf, shstrtab_off + 0x18)
shstrtab_sh_size = read_u64(elf, shstrtab_off + 0x20)

for i in range(e_shnum):
    sh_off = e_shoff + i * e_shentsize
    sh_name = read_u32(elf, sh_off)
    sh_type = read_u32(elf, sh_off + 4)
    sh_flags = read_u64(elf, sh_off + 8)
    sh_addr = read_u64(elf, sh_off + 0x10)
    sh_offset = read_u64(elf, sh_off + 0x18)
    sh_size = read_u64(elf, sh_off + 0x20)
    sh_link = read_u32(elf, sh_off + 0x28)
    sh_info = read_u32(elf, sh_off + 0x2c)
    sh_addralign = read_u64(elf, sh_off + 0x30)
    sh_entsize = read_u64(elf, sh_off + 0x38)
    
    name = read_cstr(elf, shstrtab_sh_offset + sh_name)
    sections.append({
        'name': name,
        'type': sh_type,
        'flags': sh_flags,
        'addr': sh_addr,
        'offset': sh_offset,
        'size': sh_size,
        'link': sh_link,
        'info': sh_info,
        'addralign': sh_addralign,
        'entsize': sh_entsize,
    })

for s in sections:
    print(f"  [{s['name']:20s}] addr=0x{s['addr']:08x} offset=0x{s['offset']:08x} size=0x{s['size']:x}")

# ── Find .init_array section ────────────────────────────────
init_array = next((s for s in sections if s['name'] == '.init_array'), None)
if not init_array:
    print("ERROR: .init_array not found")
    sys.exit(1)

print(f"\n.init_array: addr=0x{init_array['addr']:x} offset=0x{init_array['offset']:x} size=0x{init_array['size']:x}")
init_array_start = init_array['addr']
init_array_end = init_array['addr'] + init_array['size']
init_array_offset = init_array['offset']

# ── Find .rela.dyn section ──────────────────────────────────
rela_dyn = next((s for s in sections if s['name'] == '.rela.dyn'), None)
if not rela_dyn:
    print("ERROR: .rela.dyn not found")
    sys.exit(1)

print(f".rela.dyn: offset=0x{rela_dyn['offset']:x} size=0x{rela_dyn['size']:x} entsize={rela_dyn['entsize']}")

# ── Extract RELA entries targeting .init_array ──────────────
rela_entries = []
rela_end = rela_dyn['offset'] + rela_dyn['size']
r = rela_dyn['offset']
R_AARCH64_RELATIVE = 1027

while r + 24 <= rela_end:
    r_offset = read_u64(elf, r)
    r_info = read_u64(elf, r + 8)
    r_addend = read_s64(elf, r + 16)
    r_type = r_info & 0xffffffff
    r_sym = r_info >> 32
    
    if init_array_start <= r_offset < init_array_end:
        rela_entries.append({
            'r_offset': r_offset,
            'r_info': r_info,
            'r_addend': r_addend,
            'r_type': r_type,
            'r_sym': r_sym,
        })
    r += 24

print(f"\nFound {len(rela_entries)} RELA entries targeting .init_array range [0x{init_array_start:x}, 0x{init_array_end:x})")

# ── Verify ordering ─────────────────────────────────────────
rela_entries.sort(key=lambda e: e['r_offset'])
# Check for gaps and non-function addends
text_start_candidates = []
for i, e in enumerate(rela_entries):
    expected_offset = init_array_start + i * 8
    if e['r_offset'] != expected_offset:
        print(f"  GAP: expected offset 0x{expected_offset:x}, got 0x{e['r_offset']:x}")
    addend = e['r_addend'] & 0xffffffff
    status = ""
    if 0x3fc000 <= addend < 0xdf61ec:
        status = " (in .text)"
        text_start_candidates.append(e)
    elif addend < 0x100:
        status = f" (small: 0x{addend:x})"
    elif addend == 0:
        status = " (ZERO)"
    print(f"  entry[{i:3d}]: r_offset=0x{e['r_offset']:08x} addend=0x{e['r_addend']:016x} type={e['r_type']}{status}")

print(f"\nOf {len(rela_entries)} entries, {len(text_start_candidates)} have addends in .text range (0x3fc000-0xdf61ec)")

# ── Build function list (only entries with addends in .text or meaningful range) ──
funcs = []
for i, e in enumerate(rela_entries):
    addend_lo = e['r_addend'] & 0xffffffff
    # Only include entries that point to executable code
    # (addends in .text range or very small positive offsets)
    if 0x3fc000 <= addend_lo < 0xdf61ec:
        funcs.append({
            'index': i,
            'addr': addend_lo,
            'r_offset': e['r_offset'],
            'r_addend': e['r_addend'],
        })
    elif addend_lo == 0:
        # Zero addend = no function (empty slot)
        print(f"  Skipping entry[{i}] addend=0 (empty slot)")
    else:
        print(f"  Skipping entry[{i}] addend=0x{addend_lo:x} (not in .text range)")

# ── Determine function sizes ────────────────────────────────
# Sort by address
funcs.sort(key=lambda f: f['addr'])

# Find .text bounds
text_section = next((s for s in sections if s['name'] == '.text'), None)
if text_section:
    text_start = text_section['addr']
    text_end = text_section['addr'] + text_section['size']
else:
    text_start = funcs[0]['addr']
    text_end = funcs[-1]['addr'] + 0x1000

for i in range(len(funcs)):
    if i + 1 < len(funcs):
        # Size = next function addr - current addr
        size = funcs[i+1]['addr'] - funcs[i]['addr']
    else:
        # Last function: look for next function after it or use default
        size = 0x200  # default guess for last
    # Cap size at reasonable bounds
    if size > 0x1000:
        size = 0x200
    funcs[i]['size'] = size

# Restore original order
funcs.sort(key=lambda f: f['index'])

# ── Try to find symbol names ─────────────────────────────────
# Check .symtab (if not stripped) or .dynsym
symtab = next((s for s in sections if s['name'] == '.symtab'), None)
strtab = next((s for s in sections if s['name'] == '.strtab'), None)

symbol_map = {}

if symtab and strtab:
    print(f"\n.symtab found: offset=0x{symtab['offset']:x} size=0x{symtab['size']:x}")
    sym_end = symtab['offset'] + symtab['size']
    s = symtab['offset']
    while s + 24 <= sym_end:
        st_name = read_u32(elf, s)
        st_info = read_u8(elf, s + 4)
        st_other = read_u8(elf, s + 5)
        st_shndx = read_u16(elf, s + 6)
        st_value = read_u64(elf, s + 8)
        st_size = read_u64(elf, s + 0x10)
        
        st_type = st_info & 0xf
        st_bind = st_info >> 4
        
        if st_type == 2:  # STT_FUNC
            name = read_cstr(elf, strtab['offset'] + st_name)
            if name:
                symbol_map[st_value] = {
                    'name': name,
                    'size': st_size,
                    'bind': st_bind,
                }
        s += 24

# Also check dynamic symbols
dynsym = next((s for s in sections if s['name'] == '.dynsym'), None)
dynstr = next((s for s in sections if s['name'] == '.dynstr'), None)

if dynsym and dynstr:
    print(f".dynsym found: offset=0x{dynsym['offset']:x} size=0x{dynsym['size']:x}")
    sym_end = dynsym['offset'] + dynsym['size']
    s = dynsym['offset']
    while s + 24 <= sym_end:
        st_name = read_u32(elf, s)
        st_info = read_u8(elf, s + 4)
        st_value = read_u64(elf, s + 8)
        st_size = read_u64(elf, s + 0x10)
        
        st_type = st_info & 0xf
        if st_type == 2 and st_value != 0:  # STT_FUNC
            name = read_cstr(elf, dynstr['offset'] + st_name)
            if name and st_value not in symbol_map:
                symbol_map[st_value] = {
                    'name': name,
                    'size': st_size,
                    'bind': st_info >> 4,
                }
        s += 24

print(f"Total symbols mapped: {len(symbol_map)}")

# ── Resolve names for our functions ─────────────────────────
for f in funcs:
    addr = f['addr']
    if addr in symbol_map:
        f['name'] = symbol_map[addr]['name']
        if symbol_map[addr]['size'] > 0 and symbol_map[addr]['size'] < 0x1000:
            f['size'] = symbol_map[addr]['size']
    else:
        # Look for closest preceding symbol
        close = None
        for sym_addr, sym_info in symbol_map.items():
            if sym_addr <= addr and (close is None or sym_addr > close[0]):
                close = (sym_addr, sym_info)
        if close and addr - close[0] < 0x100:
            f['name'] = f"{close[1]['name']}+{addr - close[0]}"
        else:
            f['name'] = "sub_" + format(addr, 'x')

print(f"\n{'='*120}")
print(f"{'Idx':4s} {'Addr':12s} {'Size':6s} {'Name':50s}")
print(f"{'='*120}")
for f in funcs:
    print(f"{f['index']:4d} 0x{f['addr']:08x} {f['size']:6d} {f['name'][:50]}")

# ── Disassemble each function ────────────────────────────────
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

def is_ret(insn):
    return insn.mnemonic in ('ret', 'br')

def is_bl(insn):
    return insn.mnemonic == 'bl'

def is_b(insn):
    return insn.mnemonic == 'b'

def is_adrp(insn):
    return insn.mnemonic == 'adrp'

def is_adr(insn):
    return insn.mnemonic in ('adr', 'adrl')

def is_ldr(insn):
    return insn.mnemonic == 'ldr'

def is_str(insn):
    return insn.mnemonic == 'str'

def is_branch(insn):
    return insn.mnemonic in ('b', 'bl', 'b.eq', 'b.ne', 'b.lt', 'b.gt', 'b.le', 'b.ge',
                             'b.lo', 'b.hs', 'b.hi', 'b.ls', 'cbz', 'cbnz', 'tbz', 'tbnz')

def insn_to_string(insn):
    """Convert instruction to readable string."""
    op_str = insn.op_str
    # Simplify address references
    op_str = re.sub(r'#0x[0-9a-f]+', lambda m: m.group(0), op_str)
    return f"{insn.mnemonic:8s} {op_str}"

def resolve_adrp_target(insn, all_insns, current_offset):
    """Resolve ADRP + LDR/ADD pair to compute page-aligned address."""
    adrp_addr = insn.address
    # adrp Xd, #imm -> Xd = (PC & ~0xFFF) + imm
    pg = adrp_addr & ~0xFFF
    
    # Extract immediate from adrp instruction
    raw = insn.bytes
    imm = 0
    imm_low = (raw[1] >> 5) | ((raw[2] & 0x60) << 3)  # bits 5:4 of byte1 repr
    imm_high = (raw[3] & 0x7f) | ((raw[2] & 0x1f) << 7)  # hi 21 bits
    # adrp encoding: 
    # 1 0 0 1 0 0 0 0 | imm_hi | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | Rd
    # Actually let me use capstone to get the target
    # Capstone already provides op_str with the target address
    m = re.search(r'#0x([0-9a-f]+)', insn.op_str)
    if m:
        return int(m.group(1), 16)
    return 0

def analyze_function(md, elf_data, addr, size, func_idx, all_funcs):
    """Disassemble a function and extract key information."""
    result = {
        'index': func_idx,
        'addr': addr,
        'size': size,
        'name': '',
        'calls': [],
        'globals': [],
        'categories': set(),
        'pseudocode': [],
        'has_ret': False,
        'is_thunk': False,
        'is_trampoline': False,
        'confidence': 0,
    }
    
    # Read function bytes
    # Check if addr is in a valid file range
    text_range_start = None
    text_range_end = None
    for s in sections:
        if s['addr'] <= addr < s['addr'] + s['size']:
            file_offset = s['offset'] + (addr - s['addr'])
            file_size = min(size, s['addr'] + s['size'] - addr)
            text_range_start = file_offset
            text_range_end = file_offset + file_size
            break
    
    if text_range_start is None:
        result['pseudocode'].append(f"// INVALID ADDRESS: 0x{addr:x} not in any section")
        return result
    
    code = elf_data[text_range_start:text_range_end]
    
    # Check for all-zero (data, not code)
    if all(b == 0 for b in code):
        result['pseudocode'].append("// ZERO DATA (not code)")
        return result
    
    # Check for import table pattern (indirect branches through GOT)
    if code[:4] == b'\xf0\x7f\x00\xa9' or len(code) < 4:
        pass  # May be a stub
    
    try:
        insns = list(md.disasm(code, addr))
    except Exception as e:
        result['pseudocode'].append(f"// DISASM ERROR: {e}")
        return result
    
    if not insns:
        result['pseudocode'].append("// NO INSTRUCTIONS (data table?)")
        return result
    
    # Analyze instructions
    for insn in insns:
        line = f"  0x{insn.address:x}: {insn_to_string(insn)}"
        
        # Check for branch calls
        if insn.mnemonic == 'bl':
            target_match = re.search(r'#0x([0-9a-f]+)', insn.op_str)
            if target_match:
                target = int(target_match.group(1), 16)
                result['calls'].append({
                    'type': 'direct',
                    'target': target,
                    'target_name': symbol_map.get(target, {}).get('name', f'sub_{target:x}'),
                })
                # Check if this is a call to setKey (0xceca74)
                if target == 0xceca74:
                    result['categories'].add('CRYPTO_SETKEY')
                # Check for hex decoder
                if target == 0xcec900:
                    result['categories'].add('HEX_DECODE')
                # Check for known crypto functions
                if 0xc82000 <= target < 0xc83000:
                    result['categories'].add('CRYPTO_REGION')
        
        elif insn.mnemonic == 'b':
            target_match = re.search(r'#0x([0-9a-f]+)', insn.op_str)
            if target_match:
                target = int(target_match.group(1), 16)
                # Tail call
                result['calls'].append({
                    'type': 'tail',
                    'target': target,
                    'target_name': symbol_map.get(target, {}).get('name', f'sub_{target:x}'),
                })
        
        # Check for ADRP (page address loading — usually for global access)
        elif insn.mnemonic == 'adrp':
            target_match = re.search(r'#0x([0-9a-f]+)', insn.op_str)
            if target_match:
                target = int(target_match.group(1), 16)
                # Check if this page is near our known data regions
                if 0x11e4000 <= target < 0x11e5000:
                    result['categories'].add('ACCESSES_m_sKey_PAGE')
                    result['globals'].append({
                        'page': f"0x{target:x}",
                        'region': 'm_sKey GOT region (0x11e4000)',
                    })
                elif 0x124eb00 <= target < 0x124ec00:
                    result['categories'].add('ACCESSES_m_sKey_BSS')
                    result['globals'].append({
                        'page': f"0x{target:x}",
                        'region': 'm_sKey BSS (0x124eb50)',
                    })
                elif 0x118c000 <= target < 0x11d4000:
                    result['categories'].add('ACCESSES_GOT')
                elif 0x11d4000 <= target < 0x11e7000:
                    result['categories'].add('ACCESSES_DATA_RO')
                elif 0x115c000 <= target < 0x118c000:
                    result['categories'].add('ACCESSES_INIT_DATA')
                elif 0x3fc000 <= target < 0x115b514:
                    pass  # Accessing code pages is normal
        
        if insn.mnemonic == 'ret':
            result['has_ret'] = True
        
        result['pseudocode'].append(line)
    
    # Detect thunk patterns (very short function that just jumps to another)
    if len(insns) <= 2 and any(c['type'] == 'tail' for c in result['calls']):
        result['is_thunk'] = True
    
    # Detect trampoline (ADRP + LDR + BR)
    if len(insns) == 3 and insns[0].mnemonic == 'adrp' and insns[1].mnemonic == 'ldr' and insns[2].mnemonic == 'br':
        result['is_trampoline'] = True
        result['categories'].add('TRAMPOLINE')
    
    # Categorize based on calls
    for call in result['calls']:
        t = call['target']
        name = call['target_name'].lower()
        
        if 'lua' in name or 'lua' in call.get('target_name', '').lower() or 'tolua' in name:
            result['categories'].add('LUA')
        if 'crypto' in name or 'aes' in name or 'decrypt' in name or 'encrypt' in name:
            result['categories'].add('ENCRYPTION')
        if 'compress' in name or 'zlib' in name or 'inflate' in name or 'deflate' in name:
            result['categories'].add('COMPRESSION')
        if 'jni' in name or 'java' in name:
            result['categories'].add('JNI')
        if 'asset' in name:
            result['categories'].add('ASSET')
        if 'fileutils' in name or 'file' in name:
            result['categories'].add('FILEUTILS')
        if 'moonton' in name or 'unpack' in name or 'protect' in name:
            result['categories'].add('MOONTON_PROTECT')
        if 'std::string' in name or 'string' in name or 'basic_string' in name:
            result['categories'].add('STRING_INIT')
        if 'static_initialization' in name or '_GLOBAL_' in name:
            result['categories'].add('STATIC_INIT')
    
    return result

# ── Analyze all 53 functions ─────────────────────────────────
print(f"\n{'='*120}")
print(f"DISASSEMBLING {len(funcs)} INIT FUNCTIONS...")
print(f"{'='*120}")

results = []
for f in funcs:
    result = analyze_function(md, elf, f['addr'], f['size'], f['index'], funcs)
    result['name'] = f['name']
    result['size'] = f['size']
    results.append(result)
    
    # Print brief summary
    cats = ', '.join(result['categories']) if result['categories'] else '(none)'
    calls_str = ', '.join(f"0x{c['target']:x}({c['target_name'][:20]})" for c in result['calls'][:3])
    if len(result['calls']) > 3:
        calls_str += f" ... (+{len(result['calls'])-3})"
    print(f"  [{f['index']:2d}] 0x{f['addr']:08x}: {cats[:80]:80s} | {calls_str[:50]}")

# ── Scoring / Ranking ───────────────────────────────────────
print(f"\n{'='*120}")
print("RANKING BY LIKELIHOOD OF SETKEY INITIALIZATION")
print(f"{'='*120}")

def score_function(result):
    """Score function based on how likely it is to init crypto."""
    score = 0
    reasons = []
    
    # Direct evidence
    if 'CRYPTO_SETKEY' in result['categories']:
        score += 100
        reasons.append("DIRECT CALL TO setKey")
    if 'HEX_DECODE' in result['categories']:
        score += 50
        reasons.append("CALLS HEX DECODER")
    if 'CRYPTO_REGION' in result['categories']:
        score += 40
        reasons.append("CALLS INTO CRYPTO REGION (0xc82000-0xc83000)")
    
    # Data access patterns
    if 'ACCESSES_m_sKey_PAGE' in result['categories']:
        score += 80
        reasons.append("ACCESSES m_sKey GOT PAGE (0x11E4000)")
    if 'ACCESSES_m_sKey_BSS' in result['categories']:
        score += 75
        reasons.append("ACCESSES m_sKey BSS (0x124eb50)")
    
    # Category hints
    if 'ENCRYPTION' in result['categories']:
        score += 30
        reasons.append("ENCRYPTION RELATED")
    if 'STRING_INIT' in result['categories']:
        score += 15
        reasons.append("STRING INIT")
    if 'STATIC_INIT' in result['categories']:
        score += 10
        reasons.append("STATIC INIT")
    if 'MOONTON_PROTECT' in result['categories']:
        score += 5
        reasons.append("MOONTON PROTECT RELATED")
    if 'ASSET' in result['categories']:
        score += 5
        reasons.append("ASSET RELATED")
    if 'FILEUTILS' in result['categories']:
        score += 3
        reasons.append("FILEUTILS")
    if 'JNI' in result['categories']:
        score += 2
        reasons.append("JNI")
    
    # Has many calls (likely complex init)
    if len(result['calls']) > 5:
        score += 10
        reasons.append(f"MANY CALLS ({len(result['calls'])})")
    elif len(result['calls']) > 2:
        score += 5
    
    # Size matters (bigger = more complex init)
    if result['size'] > 500:
        score += 5
    elif result['size'] > 100:
        score += 3
    
    # Is a thunk? Unlikely to be setKey caller
    if result['is_thunk']:
        score -= 20
        reasons.append("IS THUNK")
    if result['is_trampoline']:
        score -= 20
        reasons.append("IS TRAMPOLINE")
    
    # Zero instructions or data
    if result['pseudocode'] and 'ZERO DATA' in result['pseudocode'][0]:
        score -= 50
        reasons.append("ZERO DATA")
    if result['pseudocode'] and 'NO INSTRUCTIONS' in result['pseudocode'][0]:
        score -= 30
    
    return score, reasons

# Score and rank
for r in results:
    score, reasons = score_function(r)
    r['score'] = score
    r['reasons'] = reasons

# Sort by score descending
ranked = sorted(results, key=lambda r: r['score'], reverse=True)

print(f"\n{'Rank':4s} {'Idx':4s} {'Addr':10s} {'Score':6s} {'Name':50s} {'Key Reasons'}")
print(f"{'-'*120}")
for rank, r in enumerate(ranked, 1):
    reasons = '; '.join(r['reasons'][:3])
    print(f"{rank:4d} [{r['index']:2d}] 0x{r['addr']:08x} {r['score']:4d}  {r['name'][:48]:48s} {reasons[:50]}")

# ── Find functions with SCCrypto/m_sKey page access ──────
print(f"\n{'='*120}")
print("FUNCTIONS ACCESSING m_sKey GOT PAGE (0x11E4000)")
print(f"{'='*120}")
found_mskey = [r for r in results if 'ACCESSES_m_sKey_PAGE' in r['categories']]
if found_mskey:
    for r in found_mskey:
        print(f"  [{r['index']:2d}] 0x{r['addr']:08x} score={r['score']:3d}: {r['name']}")
else:
    print("  NONE FOUND — setKey page not statically referenced from .init_array functions")

# ── Find functions calling into crypto region ──────────
print(f"\n{'='*120}")
print("FUNCTIONS CALLING INTO CRYPTO REGION (0xc82000-0xc83000)")
print(f"{'='*120}")
found_crypto = [r for r in results if 'CRYPTO_REGION' in r['categories']]
if found_crypto:
    for r in found_crypto:
        print(f"  [{r['index']:2d}] 0x{r['addr']:08x} score={r['score']:3d}: {r['name']}")
else:
    print("  NONE FOUND — no direct calls to crypto region")

# ── Output detailed table ────────────────────────────────────
print(f"\n{'='*120}")
print("DETAILED ANALYSIS TABLE (sorted by index)")
print(f"{'='*120}")

cat_cols = ['LUA', 'CRYPTO_SETKEY', 'HEX_DECODE', 'CRYPTO_REGION', 'ACCESSES_m_sKey_PAGE',
            'ACCESSES_m_sKey_BSS', 'ENCRYPTION', 'COMPRESSION', 'ASSET', 'FILEUTILS',
            'JNI', 'MOONTON_PROTECT', 'STRING_INIT', 'STATIC_INIT', 'TRAMPOLINE']

header = f"{'Idx':4s} {'Addr':10s} {'Size':6s} {'Score':5s} {'Name':45s}"
for c in cat_cols:
    header += f" {c[:3]}"
print(header)
print("-" * (len(header)))

for r in results:
    line = f"{r['index']:4d} 0x{r['addr']:08x} {r['size']:5d} {r['score']:4d}  {r['name'][:43]:43s}"
    for c in cat_cols:
        if c in r['categories']:
            line += "  X "
        else:
            line += "    "
    print(line)

# ── Save detailed output to JSON ────────────────────────────
total_init_array_entries = len(rela_entries)
output = {
    'summary': {
        'total_rela_entries_in_init_array': total_init_array_entries,
        'total_functions_in_text_range': len(funcs),
        'direct_setkey_callers': len([r for r in results if 'CRYPTO_SETKEY' in r['categories']]),
        'mskey_page_accessors': len([r for r in results if 'ACCESSES_m_sKey_PAGE' in r['categories']]),
        'crypto_region_callers': len([r for r in results if 'CRYPTO_REGION' in r['categories']]),
        'hex_decode_callers': len([r for r in results if 'HEX_DECODE' in r['categories']]),
        'ranked': [{
            'rank': i+1,
            'index': r['index'],
            'addr': f"0x{r['addr']:x}",
            'score': r['score'],
            'name': r['name'],
            'reasons': r['reasons'][:5],
        } for i, r in enumerate(ranked)],
    },
    'functions': [{
        'index': r['index'],
        'addr': f"0x{r['addr']:x}",
        'size': r['size'],
        'name': r['name'],
        'score': r['score'],
        'categories': list(r['categories']),
        'reasons': r['reasons'][:5],
        'calls': [f"0x{c['target']:x}({c['target_name'][:30]})" for c in r['calls'][:5]],
        'is_thunk': r['is_thunk'],
        'is_trampoline': r['is_trampoline'],
    } for r in results]
}

with open(r"C:\Users\NGEONG\AppData\Local\Temp\opencode\init_funcs_analysis.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"\n\nDetailed analysis saved to init_funcs_analysis.json")
print("Done.")
