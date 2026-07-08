"""
Unicorn ARM64 emulation of CCCrypto::uncompressData inner call (0xcf2b2c).
"""
import struct, os, sys
from unicorn import *
from unicorn.arm64_const import *

BINARY = r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so'
with open(BINARY, 'rb') as f:
    so = bytearray(f.read())

# â”€â”€ ELF â”€â”€
e_phoff = struct.unpack('<Q', so[0x20:0x28])[0]
e_phentsize = struct.unpack('<H', so[0x36:0x38])[0]
e_phnum = struct.unpack('<H', so[0x38:0x3a])[0]
segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    t = struct.unpack('<I', so[off:off+4])[0]
    if t != 1: continue
    f_off = struct.unpack('<Q', so[off+8:off+16])[0]
    vaddr = struct.unpack('<Q', so[off+16:off+24])[0]
    f_sz  = struct.unpack('<Q', so[off+32:off+40])[0]
    m_sz  = struct.unpack('<Q', so[off+40:off+48])[0]
    fl    = struct.unpack('<I', so[off+4:off+8])[0]
    segs.append((f_off, vaddr, f_sz, m_sz, fl))

def w64(mu, a, v): mu.mem_write(a, struct.pack('<Q', v))
def r64(mu, a): return struct.unpack('<Q', mu.mem_read(a, 8))[0]

# â”€â”€ Test file â”€â”€
sys.path.insert(0, r'C:\Users\ADMIN SERVICE\Videos\MLA')
from mt_tool import decrypt_layer1

mt_dir = r'C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump\assets'
for root, dirs, files in os.walk(mt_dir):
    for f in files:
        if not f.endswith('.mt'): continue
        fp = os.path.join(root, f)
        with open(fp, 'rb') as fh:
            raw = fh.read()
        dec = decrypt_layer1(raw)
        if dec[:4] == b'lmF@':
            sz = struct.unpack('<I', dec[10:14])[0] ^ 0x3EA
            if 1000 < sz < 50000:
                break
    else: continue
    break

# Build XOR-ed payload (already modifies dec in-place-like)
payload = bytearray(dec[14:])
for i in range(min(16, len(payload))): payload[i] ^= 0xEC
payload = bytes(payload)
comp_size = len(payload)
uncomp_size = sz
key5 = bytes([dec[4], dec[5], dec[6], dec[7] ^ 5, dec[8]])
print(f"File: {f}  key={key5.hex()}  comp={comp_size}  uncomp={uncomp_size}")

# â”€â”€ Setup unicorn â”€â”€
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# Map binary
for f_off, vaddr, f_sz, m_sz, fl in segs:
    start = vaddr & ~0xFFF
    end = ((vaddr + m_sz + 0xFFF) & ~0xFFF)
    prot = UC_PROT_READ | UC_PROT_EXEC
    if fl & 2: prot |= UC_PROT_WRITE
    mu.mem_map(start, end - start, prot)
    mu.mem_write(vaddr, bytes(so[f_off:f_off+min(f_sz, m_sz)]))
    if m_sz > f_sz:
        mu.mem_write(vaddr + f_sz, b'\x00' * (m_sz - f_sz))

# Map stack + heap
mu.mem_map(0x7FF00000, 0x40000, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(0x80000000, 0x400000, UC_PROT_READ | UC_PROT_WRITE)
heap_ptr = 0x80010000

def alloc(sz):
    global heap_ptr
    p = heap_ptr; heap_ptr += (sz + 15) & ~15; return p

# â”€â”€ TLS canary â”€â”€
CANARY_ADDR = alloc(64); CANARY_VAL = 0x1234567890ABCDEF
w64(mu, CANARY_ADDR, CANARY_VAL)
w64(mu, 0x11de3e0, CANARY_ADDR)

# â”€â”€ Interface at 0x11fed98 â”€â”€
ALLOC_FAKE = 0x30000000; FREE_FAKE = 0x30000008
w64(mu, 0x11fed98, ALLOC_FAKE); w64(mu, 0x11fed98+8, FREE_FAKE)

# â”€â”€ Setup call frame â”€â”€
FRAME = 0x7FF30000
sp = FRAME + 0x7F00

# Stack layout mimicking uncompressData's frame:
# [FRAME + 0x58] = compressed data size (arg1 - 0xe)
# [FRAME + 0x54] = scratch
# [FRAME + 0x60] = key bytes (5 bytes)
# [FRAME + 0x48] = saved arg1 (original input total size)

total_size = comp_size + 0xe  # including header
w64(mu, FRAME + 0x58, comp_size)   # x3 -> &comp_size
w64(mu, FRAME + 0x54, 0)           # x7 -> scratch

# Key layout at 0x60-0x64
mu.mem_write(FRAME + 0x60, bytes([dec[4], dec[5], dec[6], dec[7] ^ 5, dec[8]]))

# Allocate output buffer
output_buf = alloc(uncomp_size + 0x100)
mu.mem_write(output_buf, b'\x00' * (uncomp_size + 0x100))

# Input data buffer (after header)
input_buf = alloc(comp_size + 16)
mu.mem_write(input_buf, payload)

# Size pointer struct (for x1=x21)
SIZE_PTR = alloc(16)
w64(mu, SIZE_PTR, uncomp_size)
w64(mu, SIZE_PTR + 8, 0)

print(f"input={input_buf:#x} output={output_buf:#x} frame={FRAME:#x}")
print(f"comp_size={comp_size:#x} key_layout at {FRAME+0x60:#x}")

# â”€â”€ Registers â”€â”€
mu.reg_write(UC_ARM64_REG_SP, sp)
mu.reg_write(UC_ARM64_REG_X29, FRAME)
mu.reg_write(UC_ARM64_REG_X30, 0xDEAD)
mu.reg_write(UC_ARM64_REG_X0, output_buf)       # output buffer
mu.reg_write(UC_ARM64_REG_X1, SIZE_PTR)         # context / size ptr
mu.reg_write(UC_ARM64_REG_X2, input_buf)        # compressed data after header
mu.reg_write(UC_ARM64_REG_X3, FRAME + 0x58)     # &comp_size
mu.reg_write(UC_ARM64_REG_X4, FRAME + 0x60)     # &key layout
mu.reg_write(UC_ARM64_REG_X5, 5)
mu.reg_write(UC_ARM64_REG_X6, 1)
mu.reg_write(UC_ARM64_REG_X7, FRAME + 0x54)     # scratch

# Push interface on stack as 8th arg
sp -= 8; w64(mu, sp, 0x11fed98)
mu.reg_write(UC_ARM64_REG_SP, sp)

print(f"\nStarting emulation at 0xcf2b2c...")

# â”€â”€ BLR hook â”€â”€
def hook_blr(uc, addr, size, ud):
    code = uc.mem_read(addr, 4)
    insn = struct.unpack('<I', code)[0]
    if (insn >> 10) != 0x36BFC: return
    rn = (insn >> 5) & 0x1F
    target = uc.reg_read(getattr(UC_ARM64_REG, f'X{rn}'))
    if target == ALLOC_FAKE:
        sz = uc.reg_read(UC_ARM64_REG_X1)
        ptr = alloc(sz)
        print(f"  [ALLOC] size={sz:#x} -> {ptr:#x}", flush=True)
        uc.reg_write(UC_ARM64_REG_X0, ptr)
    elif target == FREE_FAKE:
        ptr = uc.reg_read(UC_ARM64_REG_X1)
        # print(f"  [FREE] ptr={ptr:#x}", flush=True)
        uc.reg_write(UC_ARM64_REG_X0, 0)
    else:
        print(f"  BLR unknown: target={target:#x} at {addr:#x}", flush=True)
        raise UcError(UC_ERR_INSN_INVALID)
mu.hook_add(UC_HOOK_CODE, hook_blr)

# â”€â”€ Code trace hook â”€â”€
def hook_code(uc, addr, size, ud):
    # Trace key function entry/exit
    if addr in [0xcf292c, 0xcf2100, 0xcf2110]:
        print(f"  -> entering fn at {addr:#x}", flush=True)
mu.hook_add(UC_HOOK_CODE, hook_code)

# â”€â”€ Error hook â”€â”€
def hook_err(uc, access, addr, size, value, ud):
    print(f"MEM: access={access} addr={addr:#x} size={size}", flush=True)
    return False
mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_err)

# â”€â”€ Run â”€â”€
try:
    mu.emu_start(0xcf2b2c, 0xcf2bb4, timeout=2000000)
    ret = mu.reg_read(UC_ARM64_REG_X0)
    print(f"Return: {ret:#x}")
    
    # Read output
    out = mu.mem_read(output_buf, min(uncomp_size, 5000))
    printable = sum(1 for b in out[:200] if 32 <= b < 127)
    print(f"Output: {len(out)} bytes, {printable}/200 printable")
    if printable > 80:
        print(repr(out[:300]))
    else:
        # Show first bytes as hex
        print('Hex:', out[:64].hex())
    
    # Try zlib on output
    import zlib
    try:
        res = zlib.decompress(out)
        print(f"zlib: {len(res)} bytes - decompressed!")
        print(repr(res[:300]))
    except:
        print("zlib: failed")
    
except UcError as e:
    print(f"Error: {e}")
    pc = mu.reg_read(UC_ARM64_REG_PC)
    print(f"PC={pc:#x}")
    for r in ['X0','X1','X2','X3','X4','X5','X6','X7','X19','X20','X21','X22',
              'X23','X24','X25','X26','X27','X28','X29','X30','SP']:
        v = mu.reg_read(getattr(UC_ARM64_REG, r))
        print(f"  {r} = {v:#018x}")
