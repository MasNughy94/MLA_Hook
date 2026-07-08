"""
Build multi-level call graph from CCCrypto::setKey() backward/forward through 5+ levels.
"""
import struct
import capstone
import re, json, sys
from collections import defaultdict, Counter

LIBAGAME = r"C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so"

def read_u64(d, o): return struct.unpack_from("<Q", d, o)[0]
def read_u32(d, o): return struct.unpack_from("<I", d, o)[0]
def read_u16(d, o): return struct.unpack_from("<H", d, o)[0]
def read_u8(d, o):  return struct.unpack_from("<B", d, o)[0]

print("Loading ELF...")
with open(LIBAGAME, "rb") as f:
    elf = f.read()

# â”€â”€ Parse ELF â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
e_shoff = read_u64(elf, 0x28)
e_shentsize = read_u16(elf, 0x3a)
e_shnum = read_u16(elf, 0x3c)
e_shstrndx = read_u16(elf, 0x3e)
shstrtab_hdr = e_shoff + e_shstrndx * e_shentsize
shstrtab_off = read_u64(elf, shstrtab_hdr + 0x18)

def section_name(idx):
    s = e_shoff + idx * e_shentsize
    no = read_u32(elf, s)
    end = elf.find(b'\x00', shstrtab_off + no, shstrtab_off + no + 128)
    return elf[shstrtab_off+no:end].decode()

sections = {}
for i in range(e_shnum):
    s = e_shoff + i * e_shentsize
    name = section_name(i)
    sections[name] = {
        'addr': read_u64(elf, s + 0x10),
        'offset': read_u64(elf, s + 0x18),
        'size': read_u64(elf, s + 0x20),
    }

# .dynsym + .dynstr
dynsym_s = sections.get('.dynsym', {})
dynstr_s = sections.get('.dynstr', {})
TOTAL_SYMS = dynsym_s['size'] // 24 if dynsym_s else 0

symbols_forward = {}
for i in range(TOTAL_SYMS):
    so = dynsym_s['offset'] + i * 24
    st_value = read_u64(elf, so + 8)
    st_info = read_u8(elf, so + 4)
    st_size = read_u64(elf, so + 0x10)
    if (st_info & 0xf) == 2 and st_value != 0:
        name = elf[dynstr_s['offset'] + read_u32(elf, so):elf.find(b'\x00', dynstr_s['offset'] + read_u32(elf, so))].decode(errors='replace')
        symbols_forward[st_value] = (name, st_size)

def sym_name(addr):
    best = None
    for sa, (n, sz) in symbols_forward.items():
        if sa <= addr < sa + max(sz, 1):
            offset = addr - sa
            return f"{n}+{offset}" if offset else n
    return f"sub_{addr:x}"

# â”€â”€ Section helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def get_bytes(addr, size):
    for sn, s in sections.items():
        if s['addr'] <= addr < s['addr'] + s['size']:
            off = s['offset'] + (addr - s['addr'])
            end = min(off + size, s['offset'] + s['size'])
            return elf[off:end]
    return b''

# â”€â”€ Capstone â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

def disasm_func(addr, size=0x800):
    code = get_bytes(addr, size)
    if not code or len(code) < 4:
        return []
    try:
        return list(md.disasm(code, addr))
    except:
        return []

def get_calls_and_globals(insns):
    """Extract direct calls (BL), indirect calls (BLR), and ADRP global refs."""
    calls = []
    indirect_calls = []
    globals_found = set()  # set of pages accessed
    for i, insn in enumerate(insns):
        # Direct BL
        if insn.mnemonic == 'bl':
            m = re.search(r'#0x([0-9a-f]+)', insn.op_str)
            if m:
                target = int(m.group(1), 16)
                calls.append(('call', target))
        # Indirect call BLR
        elif insn.mnemonic == 'blr':
            indirect_calls.append(('blr', insn.address, insn.op_str))
        # Tail call via B
        elif insn.mnemonic == 'b':
            m = re.search(r'#0x([0-9a-f]+)', insn.op_str)
            if m:
                target = int(m.group(1), 16)
                calls.append(('tail', target))
        # ADRP for global access
        elif insn.mnemonic == 'adrp':
            m = re.search(r'#0x([0-9a-f]+)', insn.op_str)
            if m:
                globals_found.add(int(m.group(1), 16))
        # ret
        elif insn.mnemonic == 'ret':
            break  # End of function
    return calls, indirect_calls, globals_found

# =====================================================================
# LEVEL 0: setKey analysis
# =====================================================================
print("\n=== LEVEL 0: CCCrypto::setKey (0xceca74) ===")
setkey_insns = disasm_func(0xceca74, 0x200)
setkey_calls, setkey_blr, setkey_globals = get_calls_and_globals(setkey_insns)
print(f"  Direct calls from setKey: {[hex(t) for _, t in setkey_calls]}")
print(f"  Pages accessed: {[hex(p) for p in setkey_globals]}")

# Functions called BY setKey (callees)
setkey_callees = set(t for _, t in setkey_calls)

# =====================================================================
# LEVEL 1: Find all direct callers of setKey (0xceca74)
# =====================================================================
print("\n=== LEVEL 1: Direct callers of setKey ===")

# Search the entire .text section for BL to 0xceca74
text_s = sections.get('.text', {})
TEXT_START = text_s['addr']
TEXT_SIZE = text_s['size']
TEXT_END = TEXT_START + TEXT_SIZE

print(f"  .text range: 0x{TEXT_START:x} - 0x{TEXT_END:x}")
print(f"  Scanning {TEXT_SIZE} bytes for BL to 0xceca74...")

# Efficient scan: search for the 4-byte encoding of "bl 0xceca74"
# BL encoding: 0x14000000 | (imm26 & 0x3ffffff) where imm26 = (target - pc) >> 2
# For BL from any address 'pc' to target 0xceca74:
# We need to search for BL instructions where the immediate encodes to 0xceca74
# But it's easier to just disassemble and check

# Instead of full disassembly of entire .text, do a smarter search
# BL encoding: opcode=0x25 (bits[31:26]=100101), imm26=branch offset / 4
# We need to scan every 4-byte aligned word, decode as BL, check if target == 0xceca74

direct_callers = []
addr = TEXT_START
while addr + 4 <= TEXT_END:
    word = read_u32(elf, text_s['offset'] + (addr - TEXT_START))
    # Check if it's a BL instruction (bits[31:26] = 0b100101 = 0x25)
    if (word >> 26) == 0x25:
        imm = word & 0x3ffffff
        # Sign extend 26-bit
        if imm & 0x2000000:
            imm |= ~0x3ffffff
        target = addr + (imm << 2)
        if target == 0xceca74:
            direct_callers.append(addr)
    addr += 4

print(f"  Found {len(direct_callers)} direct callers of setKey:")
for ca in direct_callers:
    print(f"    {hex(ca)} ({sym_name(ca)})")

# Also search .plt section for PLT stubs pointing to setKey
plt_s = sections.get('.plt', {})
if plt_s:
    plt_code = elf[plt_s['offset']:plt_s['offset']+plt_s['size']]
    plt_addr = plt_s['addr']
    # Check if any PLT entry references setKey
    md2 = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    for insn in md2.disasm(plt_code, plt_addr):
        if insn.mnemonic == 'bl' and f'#0xceca74' in insn.op_str:
            print(f"  PLT caller at {hex(insn.address)}")

# Check .rela.plt for setKey as imported symbol
print("\n  Checking .rela.plt for setKey as dynamic symbol...")
rela_plt = sections.get('.rela.plt', {})
if rela_plt:
    num_plt = rela_plt['size'] // 24
    for j in range(num_plt):
        eo = rela_plt['offset'] + j * 24
        r_offset = read_u64(elf, eo)
        r_info = read_u64(elf, eo + 8)
        r_sym = r_info >> 32
        r_type = r_info & 0xffffffff
        if r_sym < TOTAL_SYMS:
            so = dynsym_s['offset'] + r_sym * 24
            st_value = read_u64(elf, so + 8)
            if st_value == 0xceca74:
                print(f"    Found setKey in PLT at GOT 0x{r_offset:x}")

# =====================================================================
# LEVEL 1b: Search for setKey address in data sections (function pointer)
# =====================================================================
print("\n=== LEVEL 0x: setKey address in data sections ===")
target_bytes = struct.pack("<Q", 0xceca74)
for sn in ['.data', '.data.rel.ro', '.got', '.got.plt', '.rodata', '.eh_frame']:
    s = sections.get(sn)
    if s and s['size'] > 0:
        data = elf[s['offset']:s['offset'] + s['size']]
        pos = 0
        count = 0
        while True:
            pos = data.find(target_bytes, pos)
            if pos < 0:
                break
            addr_in_section = s['addr'] + pos
            count += 1
            # Determine what section this is in
            section_hint = ""
            for sn2, s2 in sections.items():
                if s2['addr'] <= addr_in_section < s2['addr'] + s2['size']:
                    section_hint = sn2
                    break
            print(f"  Found 8-byte ptr 0xceca74 at {hex(addr_in_section)} (in {section_hint})")
            pos += 8
        if count == 0:
            pass  # print(f"  No refs in {sn}")

# Also search for 4-byte truncated reference
target32 = struct.pack("<I", 0xceca74)
for sn in ['.rodata', '.data']:
    s = sections.get(sn)
    if s and s['size'] > 0:
        data = elf[s['offset']:s['offset'] + s['size']]
        if target32 in data:
            pos = data.find(target32)
            addr = s['addr'] + pos
            print(f"  Found 4-byte ref 0xceca74 at {hex(addr)} (in {sn})")

# =====================================================================
# LEVEL 2: Functions that call fromHex (0xcec900) â€” called by setKey
# =====================================================================
print("\n=== LEVEL 2: Callers of fromHex (0xcec900) ===")
# fromHex is: CCCrypto::fromHex(RKSs) = 0xcec900

fromHex_callers = []
addr = TEXT_START
while addr + 4 <= TEXT_END:
    word = read_u32(elf, text_s['offset'] + (addr - TEXT_START))
    if (word >> 26) == 0x25:
        imm = word & 0x3ffffff
        if imm & 0x2000000:
            imm |= ~0x3ffffff
        target = addr + (imm << 2)
        if target == 0xcec900:
            fromHex_callers.append(addr)
    addr += 4

print(f"  Found {len(fromHex_callers)} callers of fromHex:")
seen = set()
for ca in fromHex_callers:
    print(f"    {hex(ca)} ({sym_name(ca)})")
    seen.add(ca)

# Check: do any of these callers also access m_sKey page?
print("\n  Checking which fromHex callers also access m_sKey page (0x11E4000)...")
for ca in fromHex_callers:
    insns = disasm_func(ca, 0x200)
    _, _, globs = get_calls_and_globals(insns)
    if 0x11e4000 in globs:
        # Check if it accesses specific offset 0x670 (m_sKey)
        code = get_bytes(ca, 0x200)
        if b'\x00' + struct.pack("<I", 0x11e4670 & 0xfffff)[:3] in code[:0x100]:
            print(f"    *** {hex(ca)} ({sym_name(ca)}) accesses m_sKey GOT! ***")
        else:
            print(f"    ** {hex(ca)} ({sym_name(ca)}) accesses 0x11E4000 page **")

# =====================================================================
# LEVEL 2b: Functions calling sub_9aeb8c (string assign, called by setKey)
# =====================================================================
print("\n=== LEVEL 2b: Callers of sub_9aeb8c (0x9aeb8c, string=) ===")
callees_9aeb8c = []
addr = TEXT_START
while addr + 4 <= TEXT_END:
    word = read_u32(elf, text_s['offset'] + (addr - TEXT_START))
    if (word >> 26) == 0x25:
        imm = word & 0x3ffffff
        if imm & 0x2000000:
            imm |= ~0x3ffffff
        target = addr + (imm << 2)
        if target == 0x9aeb8c:
            callees_9aeb8c.append(addr)
    addr += 4

print(f"  Found {len(callees_9aeb8c)} callers of sub_9aeb8c:")
for ca in callees_9aeb8c:
    print(f"    {hex(ca)} ({sym_name(ca)})")

# Cross-reference: functions that call BOTH fromHex AND sub_9aeb8c
fromHex_set = set(fromHex_callers)
both = [c for c in callees_9aeb8c if c in fromHex_set]
print(f"\n  Functions calling BOTH fromHex and sub_9aeb8c: {[hex(c) for c in both]}")
for c in both:
    print(f"    *** {hex(c)} ({sym_name(c)}) replicates setKey behavior! ***")

# =====================================================================
# LEVEL 3: Callers of functions called BY setKey 
# (trace forward from setKey's callees: fromHex and sub_9aeb8c)
# =====================================================================
print("\n=== LEVEL 3: Forward expansion from setKey's callees ===")

# For each function called by setKey, find THEIR callers
# This creates a reverse graph
def find_all_callers(target_addr, max_depth=3):
    """Find all functions that eventually call target_addr."""
    # Already have level 1 (direct callers)
    level_results = {0: {target_addr}}
    
    for depth in range(1, max_depth + 1):
        current_level = set()
        # For each function in previous level, find its callers
        for func in level_results[depth - 1]:
            if func < TEXT_START or func >= TEXT_END:
                continue
            callers = []
            addr = TEXT_START
            while addr + 4 <= TEXT_END:
                word = read_u32(elf, text_s['offset'] + (addr - TEXT_START))
                if (word >> 26) == 0x25:
                    imm = word & 0x3ffffff
                    if imm & 0x2000000:
                        imm |= ~0x3ffffff
                    target = addr + (imm << 2)
                    if target == func:
                        callers.append(addr)
                addr += 4
            current_level.update(callers)
        
        if not current_level:
            break
        level_results[depth] = current_level
        print(f"    Level {depth}: {len(current_level)} callers")
        for ca in sorted(current_level)[:10]:
            print(f"      {hex(ca)} ({sym_name(ca)})")
        if len(current_level) > 10:
            print(f"      ... and {len(current_level)-10} more")
    
    return level_results

print("\n  Tracing callers of fromHex (0xcec900) 3 levels deep...")
fromhex_callers_tree = find_all_callers(0xcec900, 3)

print("\n  Tracing callers of sub_9aeb8c (0x9aeb8c) 3 levels deep...")
_ = find_all_callers(0x9aeb8c, 3)

# =====================================================================
# LEVEL 3b: .init_array forward call graph (3 levels deep)
# =====================================================================
print("\n=== .init_array FORWARD CALL GRAPH (3 levels) ===")

# First get the 203 init function addresses from .init_array
init_array_s = sections.get('.init_array', {})
INIT_START = init_array_s['addr']
INIT_SIZE = init_array_s['size']

init_funcs = []
for idx in range(INIT_SIZE // 8):
    offset = init_array_s['offset'] + idx * 8
    val = read_u64(elf, offset)
    if val != 0:  # Only non-zero entries (RELA-filled)
        init_funcs.append((idx, val))

print(f"  {len(init_funcs)} .init_array entries with non-zero values")

# For each init function, trace its call chain 3 levels
# looking for path to setKey (0xceca74), fromHex, or m_sKey access

def trace_func_calls(func_addr, target_addrs, max_depth, current_depth=0, visited=None):
    """DFS trace from func_addr to see if it reaches any target."""
    if visited is None:
        visited = set()
    if func_addr in visited or current_depth > max_depth:
        return None
    visited.add(func_addr)
    
    insns = disasm_func(func_addr, 0x200)
    calls, blrs, globs = get_calls_and_globals(insns)
    
    # Check direct calls
    for ctype, target in calls:
        if target in target_addrs:
            return [{
                'func': func_addr,
                'call_to': target,
                'type': ctype,
                'depth': current_depth + 1,
            }]
    
    # Recurse into callees
    for ctype, target in calls:
        if TEXT_START <= target < TEXT_END:
            path = trace_func_calls(target, target_addrs, max_depth, current_depth + 1, visited)
            if path:
                path.insert(0, {
                    'func': func_addr,
                    'call_to': target,
                    'type': ctype,
                    'depth': current_depth + 1,
                })
                return path
    
    return None

TARGETS = {0xceca74, 0xcec900, 0x11e4670}  # setKey, fromHex, m_sKey page

print("  Tracing init functions for paths to targets...")
paths_found = []
for idx, func_addr in init_funcs:
    path = trace_func_calls(func_addr, TARGETS, 3)
    if path:
        paths_found.append((idx, func_addr, path))
        print(f"\n    PATH from init[{idx}] ({hex(func_addr)}):")
        for step in path:
            print(f"      {step['depth']}: {hex(step['func'])} -> {step['type']} {hex(step['call_to'])} ({sym_name(step['call_to'])})")

if not paths_found:
    print("  NO paths found to targets within 3 levels!")

# =====================================================================
# LEVEL 4: BLR indirect calls â€” find all BLR in .text
# =====================================================================
print("\n=== LEVEL 4: BLR (indirect call) analysis ===")

# Scan for BLR instructions â€” these could dispatch to setKey
blr_sites = []
addr = TEXT_START
while addr + 4 <= TEXT_END:
    word = read_u32(elf, text_s['offset'] + (addr - TEXT_START))
    # BLR encoding: bits[31:24] = 11010110_0_000_0000_0_0_0000_0_00000
    # Simplified: 0xD63FXXXX where X = register
    # BLR Xn = 0xD63F0000 | (n << 5)
    if (word & 0xFFFFFC00) == 0xD63F0000:  # BLR any register
        rn = (word >> 5) & 0x1F
        blr_sites.append((addr, rn))
    addr += 4

print(f"  Found {len(blr_sites)} BLR sites in .text")
# Group by function
blr_by_func = defaultdict(list)
for site, rn in blr_sites:
    # Find containing function
    containing_func = site
    for idx, func_addr in init_funcs:
        if func_addr <= site < func_addr + 0x800:
            containing_func = func_addr
            break
    blr_by_func[containing_func].append((site, rn))

# Show BLR sites grouped by function
for func, sites in sorted(blr_by_func.items()):
    sym = sym_name(func)
    if len(sites) <= 3:  # Only show with few BLRs (more manageable)
        for site, rn in sites:
            print(f"    {hex(site)} BLR x{rn} in {hex(func)} ({sym})")

# =====================================================================
# LEVEL 5: Check if setKey is in any vtable or function pointer table
# =====================================================================
print("\n=== LEVEL 5: Vtable / function pointer table scan ===")

# Search for 0xceca74 in .data.rel.ro (where vtables typically live)
data_rel_ro = sections.get('.data.rel.ro', {})
if data_rel_ro:
    data = elf[data_rel_ro['offset']:data_rel_ro['offset'] + data_rel_ro['size']]
    count_8 = 0
    pos = 0
    while True:
        pos = data.find(struct.pack("<Q", 0xceca74), pos)
        if pos < 0:
            break
        vaddr = data_rel_ro['addr'] + pos
        count_8 += 1
        print(f"  8-byte vtable ptr at {hex(vaddr)}")
        pos += 8
    if count_8 == 0:
        print("  No 8-byte references to setKey in .data.rel.ro")
    
    # Also check for align-4 references
    count_4 = 0
    pos = 0
    target32 = struct.pack("<I", 0xceca74)
    while True:
        pos = data.find(target32, pos)
        if pos < 0:
            break
        vaddr = data_rel_ro['addr'] + pos
        # Only count if at least 4-byte aligned
        if vaddr % 4 == 0:
            count_4 += 1
            print(f"  4-byte vtable ptr at {hex(vaddr)}")
        pos += 4
    if count_4 == 0:
        print("  No 4-byte references to setKey in .data.rel.ro")

# =====================================================================
# FINAL EXPANSION: Try to trace caller chain 5 levels from all known entry points
# =====================================================================
print("\n=== FINAL EXPANSION: 5-level recursive trace ===")

# Entry points: all .init_array functions + JNI_OnLoad
entry_points = [v for _, v in init_funcs] + [0x7d3600, 0x7e484c, 0x7856d0]

def trace_multi_level(start, target, max_depth=5):
    """BFS from start to see if it reaches target within max_depth jumps."""
    queue = [(start, 0, [start])]
    visited_full = set()
    
    while queue:
        func, depth, path = queue.pop(0)
        
        if func in visited_full or depth > max_depth:
            continue
        visited_full.add(func)
        
        insns = disasm_func(func, 0x200)
        calls, _, _ = get_calls_and_globals(insns)
        
        for ctype, callee in calls:
            if callee == target:
                return path + [callee]
            if TEXT_START <= callee < TEXT_END and callee not in visited_full and depth < max_depth:
                queue.append((callee, depth + 1, path + [callee]))
    
    return None

# Try to trace from each entry point to setKey
print("  Tracing from all entry points to setKey (5 levels)...")
found_any = False
for ep in entry_points:
    if ep < TEXT_START or ep >= TEXT_END:
        continue
    path = trace_multi_level(ep, 0xceca74, 5)
    if path:
        found_any = True
        print(f"\n  *** PATH FOUND from {hex(ep)} ({sym_name(ep)}) ***")
        for i, step in enumerate(path):
            if i + 1 < len(path):
                print(f"      Level {i}: {hex(step)} ({sym_name(step)}) -> {hex(path[i+1])}")
            else:
                print(f"      Level {i}: {hex(step)} ({sym_name(step)}) -> CCCrypto::setKey!")

if not found_any:
    print("  NO path from any entry point to setKey within 5 levels!")

# =====================================================================
# Extra: Expand init[200] (most relevant) 5 levels forward
# =====================================================================
print("\n=== FOCUS: Forward expansion from init[200] (0x407130) 5 levels ===")

def expand_forward(func, max_depth=5, visited=None, depth=0):
    """DFS expand showing all paths."""
    if visited is None:
        visited = set()
    if func in visited or depth > max_depth:
        return {}
    visited.add(func)
    
    insns = disasm_func(func, 0x200)
    calls, _, _ = get_calls_and_globals(insns)
    
    result = {}
    for ctype, callee in calls:
        if TEXT_START <= callee < TEXT_END:
            sub = expand_forward(callee, max_depth, visited, depth + 1)
            if callee == 0xceca74:
                sub['_LEADS_TO_SETKEY'] = True
            result[callee] = {
                'type': ctype,
                'name': sym_name(callee),
                'calls': sub,
            }
    return result

tree = expand_forward(0x407130, 4)

def print_tree(tree, indent=2):
    for addr, info in tree.items():
        marker = " *** SETKEY ***" if info.get('_LEADS_TO_SETKEY') else ""
        print(f"{' ' * indent}{hex(addr)} ({info['name']}){marker}")
        if info['calls']:
            print_tree(info['calls'], indent + 4)

print_tree(tree)

# =====================================================================
# SUMMARY
# =====================================================================
print("\n=== SUMMARY ===")
print(f"  Direct callers of setKey: {len(direct_callers)}")
print(f"  Functions calling fromHex: {len(fromHex_callers)}")
print(f"  Functions calling fromHex AND sub_9aeb8c: {len(both)}")
print(f"  BLR sites: {len(blr_sites)}")
print(f"  Paths from .init_array to targets: {len(paths_found)}")
print(f"  Paths from all entry points to setKey: {'FOUND' if found_any else 'NONE'}")

# Check for COMBINED pattern: functions that call all 3 of setKey's sub-operations
print("\n=== CROSS-REFERENCE: Functions replicating setKey ===")
print("  SetKey does: fromHex + m_sKey page access + sub_9aeb8c string assign")
fromHex_set = set(fromHex_callers)
m_sKey_funcs = set()
for idx, func_addr in init_funcs:
    insns = disasm_func(func_addr, 0x200)
    _, _, globs = get_calls_and_globals(insns)
    if 0x11e4000 in globs:
        m_sKey_funcs.add(func_addr)

candidates = fromHex_set & m_sKey_funcs
print(f"  Functions doing BOTH fromHex AND accessing 0x11E4000 page: {len(candidates)}")
for c in candidates:
    print(f"    {hex(c)} ({sym_name(c)})")

print("\nDone.")
