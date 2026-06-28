import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open(r'C:\Users\NGEONG\Videos\MLA\libagame.so', 'rb') as f:
    elf = f.read()

TEXT_ADDR = 0x3fc000
TEXT_OFF = 0x3fc000

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# Disassemble aes_set_key at 0xcee4ec to verify key size
print("=== aes_set_key (0xcee4ec) - FIRST 10 instructions ===")
raw = elf[TEXT_OFF + (0xcee4ec - TEXT_ADDR) : TEXT_OFF + (0xcee4ec - TEXT_ADDR) + 0x200]
for insn in md.disasm(raw, 0xcee4ec):
    print(f"  0x{insn.address:08x}: {insn.mnemonic:8s} {insn.op_str}")
    if insn.address >= 0xcee4ec + 0xa0:
        break

print()

# Check the custom aes_decrypt at 0xcefa44 (the actual block decrypt callback)
print("=== aes_decrypt block function (0xcefa44) - FIRST 10 instructions ===")
raw = elf[TEXT_OFF + (0xcefa44 - TEXT_ADDR) : TEXT_OFF + (0xcefa44 - TEXT_ADDR) + 0x100]
for insn in md.disasm(raw, 0xcefa44):
    print(f"  0x{insn.address:08x}: {insn.mnemonic:8s} {insn.op_str}")
    if insn.address >= 0xcefa44 + 0x80:
        break

print()

# Check xor_decrypt (0xceccec) to understand the pre-processing
print("=== CCCrypto::xor_decrypt (0xceccec) ===")
raw = elf[TEXT_OFF + (0xceccec - TEXT_ADDR) : TEXT_OFF + (0xceccec - TEXT_ADDR) + 0x38]
for insn in md.disasm(raw, 0xceccec):
    print(f"  0x{insn.address:08x}: {insn.mnemonic:8s} {insn.op_str}")

print()

# Check the whole Data::decryptData flow more carefully
# Show all BL calls with context (nearby ADRP for key page access)
print("=== Data::decryptData (0xc82ab0) - FULL ===")
raw = elf[TEXT_OFF + (0xc82ab0 - TEXT_ADDR) : TEXT_OFF + (0xc82ab0 - TEXT_ADDR) + 0x32c]
for insn in md.disasm(raw, 0xc82ab0):
    addr = insn.address
    op_str = insn.op_str
    
    # Check for m_sKey page access
    extra = ""
    if 'adrp' in insn.mnemonic:
        try:
            page = int(op_str.split(',')[1].strip(), 16)
            if page in [0x11e4000, 0x11e2000, 0x11e5000, 0x11de000]:
                extra = "  ; *** m_sKey/CRYPTO GOT PAGE ***"
        except: pass
    
    if insn.mnemonic == 'bl':
        try: target = int(op_str, 16)
        except: target = 0
        labels = ''
        if target == 0xcec678: labels = ' ; CCCrypto::getKey() -> returns m_sKey'
        elif target == 0xcec5c0: labels = ' ; CCCrypto::aes_decrypt(buf, len, key, iv, mode)'
        elif target == 0xceccec: labels = ' ; CCCrypto::xor_decrypt(p, len)'
        elif target == 0xcecd24: labels = ' ; CCCrypto::uncompressData()'
        elif target == 0xca41c4: labels = ' ; ZipUtils::inflateMemory()'
        elif target == 0xca4638: labels = ' ; ZipUtils::ccInflateMemory()'
        elif target == 0xc828f8: labels = ' ; Data::clear()'
        elif target == 0x3faf50: labels = ' ; free'
        elif target == 0x3fa240: labels = ' ; malloc'
        elif target == 0x9b135c: labels = ' ; operator delete'
        extra = labels
    elif insn.mnemonic == 'b':
        try: target = int(op_str, 16)
        except: target = 0
        if target == 0xc82afc: extra = ' ; loop/retry'
    
    print(f"  0x{addr:08x}: {insn.mnemonic:8s} {op_str:30s}{extra}")
