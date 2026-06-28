import struct
from capstone import *

SO = r'C:\Users\NGEONG\Videos\MLA\libagame.so'
with open(SO, 'rb') as f:
    data = f.read()
END = len(data)

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

text_end = 0x115b514
chunk_size = 0x40000

# ============================================================
# CONFIRMED: m_sKey is at 0x11E4670 (pointer to BSS std::string)
# getKey(0xcec678):  ADRP x1, #0x11E4000; LDR x1, [x1, #0x670]
# setKey(0xceca74):  ADRP x0, #0x11E4000; LDR x0, [x0, #0x670]
# Pointer value at 0x11E4670: 0x124eb50 (BSS - zero-initialized at startup)
# ============================================================

# 1. Find all ADRP referencing page 0x11E4000 (m_sKey)
print('=== References to page 0x11E4000 (m_sKey pointer) ===')
for chunk_start in range(0, text_end, chunk_size):
    chunk_end = min(text_end, chunk_start + chunk_size)
    code = data[chunk_start:chunk_end]
    for insn in md.disasm(code, chunk_start):
        if insn.mnemonic == 'adrp':
            try:
                tp = insn.operands[1].imm
                if tp == 0x11E4000:
                    print(f'  0x{insn.address:x}: ADRP x{insn.operands[0].reg}')
            except:
                pass

# 2. Find callers of getKey (0xcec678) - used by Data::decryptData
print()
print('=== Callers of getKey (0xcec678) ===')
for chunk_start in range(0, text_end, chunk_size):
    chunk_end = min(text_end, chunk_start + chunk_size)
    code = data[chunk_start:chunk_end]
    for insn in md.disasm(code, chunk_start):
        if insn.mnemonic == 'bl':
            try:
                tgt = insn.operands[0].imm
                if tgt == 0xcec678:
                    print(f'  0x{insn.address:x}: BL getKey')
            except:
                pass

# 3. Find callers of setKey (0xceca74) - EXPECTED: ZERO (packed by Moonton Protect)
print()
print('=== Callers of setKey (0xceca74) - EXPECTED: NONE ===')
for chunk_start in range(0, text_end, chunk_size):
    chunk_end = min(text_end, chunk_start + chunk_size)
    code = data[chunk_start:chunk_end]
    for insn in md.disasm(code, chunk_start):
        if insn.mnemonic == 'bl':
            try:
                tgt = insn.operands[0].imm
                if tgt == 0xceca74:
                    print(f'  0x{insn.address:x}: BL setKey')
            except:
                pass
print('  (no output = no callers found)')
