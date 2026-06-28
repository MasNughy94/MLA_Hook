from capstone import *
with open(r'C:\Users\NGEONG\Videos\MLA\libagame.so', 'rb') as f:
    code = f.read()

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

func = code[0xcecd24:0xcecfe4]
for insn in md.disasm(func, 0xcecd24):
    a = insn.address
    m = insn.mnemonic
    line = "0x%x: %-10s %s" % (a, m, insn.op_str)
    if a == 0xcecd64:
        line += "  ; w0 = 0x6D6C ('lm')"
    if a == 0xcecd6c:
        line += "  ; w0 = 0x40466D6C ('lmF@')"
    if a == 0xcecd70:
        line += "  ; cmp first 4 bytes with 'lmF@'"
    if a == 0xcecd74:
        line += "  ; MATCH -> process lmF@"
    if a == 0xcecd78:
        line += "  ; RETURN (w0=w2)"
    if a == 0xcecfc0:
        line += "  ; lmf returns 0 (success) -> RET with w2 non-zero"
    if a == 0xcecfd8:
        line += "  ; FAIL: w2=0 -> RET w0=0"
    if a == 0xcecfbc:
        line += "  ; CALL lmf_decompress_wrapper"
    print(line)
