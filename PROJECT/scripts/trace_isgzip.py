from capstone import *
with open(r'C:\Users\NGEONG\Videos\MLA\libagame.so', 'rb') as f:
    code = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# 1. Full isGzip at 0xca4638
func = code[0xca4638:0xca4678]
print("=== isGzip (0xca4638) ===")
for insn in md.disasm(func, 0xca4638):
    a = insn.address
    line = "0x%x: %-10s %s" % (a, insn.mnemonic, insn.op_str)
    if a == 0xca4648:
        line += "  ; check if byte[0] == 0x1F"
    if a == 0xca465c:
        line += "  ; check if byte[1] == 0x8B"
    if a == 0xca4660:
        line += "  ; return 1 if both magic bytes match"
    print(line)

# 2. Show the exact data flow for isGzip call in Type-1
# At 0xc82c50: mov x0, x24  -> x0 = AES-CBC output buffer
# At 0xc82c54: str x1, [x20, #8] -> x1 = real_size (from w21)
# At 0xc82c60: bl #0xca4638 -> isGzip(x0, x1)
# At 0xc82c68: cbz w0, #0xc82d40 -> if FALSE, go to uncompressData

func2 = code[0xc82c30:0xc82c7c]
print("\n=== Type-1 path after decompress_worker (0xc82c30-0xc82c7c) ===")
for insn in md.disasm(func2, 0xc82c30):
    a = insn.address
    line = "0x%x: %-10s %s" % (a, insn.mnemonic, insn.op_str)
    if a == 0xc82c48:
        line += "  ; this._ptr = x24 (AES-CBC output buffer)"
    if a == 0xc82c54:
        line += "  ; this._size = real_size"
    if a == 0xc82c60:
        line += "  ; CALL isGzip(x24, real_size)"
    if a == 0xc82c68:
        line += "  ; isGzip returned w0 -> if FALSE goto uncompressData"
    if a == 0xc82c78:
        line += "  ; CALL gunzip(this._ptr, size, &new_out)"
    print(line)

# 3. Show the not-gzip branch target
func3 = code[0xc82d40:0xc82d5c]
print("\n=== Type-1 NOT gzip path (0xc82d40-0xc82d5c) ===")
for insn in md.disasm(func3, 0xc82d40):
    a = insn.address
    line = "0x%x: %-10s %s" % (a, insn.mnemonic, insn.op_str)
    if a == 0xc82d50:
        line += "  ; CALL uncompressData(this._ptr, size, &new_out, status)"
    if a == 0xc82d58:
        line += "  ; if uncompressData returns 0 (FAIL), skip update"
    if a == 0xc82d5c:
        line += "  ; else -> update this._ptr with decompressed output"
    print(line)

# 4. Show what happens when uncompressData succeeds
func4 = code[0xc82cf8:0xc82d14]
print("\n=== uncompressData success: update this._ptr (0xc82cf8-0xc82d14) ===")
for insn in md.disasm(func4, 0xc82cf8):
    a = insn.address
    line = "0x%x: %-10s %s" % (a, insn.mnemonic, insn.op_str)
    if a == 0xc82d04:
        line += "  ; this._ptr = decompressed Lua script"
    if a == 0xc82d0c:
        line += "  ; this._size = decompressed size"
    print(line)
