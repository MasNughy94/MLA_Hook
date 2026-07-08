import struct, os
from unicorn import *
from unicorn.arm64_const import *

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    so = bytearray(f.read())
from Crypto.Cipher import AES
def dl(d):
    p=d[16:]; pad=(16-len(p)%16)%16; pp=p+b'\x00'*pad if pad else p
    c=AES.new(bytes.fromhex('f5a193d50ade553e9835595f5cd75ddd'), AES.MODE_ECB)
    return c.decrypt(pp)[:len(p)]

mt = r'C:\Users\ADMIN SERVICE\Videos\MLA\MLADVENTURE2\assets\0\0000488d2f64199aca0cc7d54e7d11c0.mt'
with open(mt, 'rb') as f:
    raw = f.read()
dec = dl(raw)
payload = bytearray(dec[0xe:])
for i in range(min(16, len(payload))):
    payload[i] ^= 0xec
payload = bytes(payload)
xor_uncomp = struct.unpack('<I', dec[10:14])[0]
uncomp_size = xor_uncomp ^ 0x3ea
comp_size = len(payload)
print(f'Comp size: {comp_size}, Uncomp size: {uncomp_size:#x}')

mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
HEAP_BASE = 0x31000000
STATE_ADDR = 0x7FF30070
OUTPUT_BUF = 0x80010000
COMP_BUF = 0x90000000
COMP_SIZE_ADDR = 0x7FF30058
SCRATCH = 0x7FF30054

BIN_SIZE = (len(so) + 0xFFF) & ~0xFFF
mu.mem_map(0, BIN_SIZE + 0x1000000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
mu.mem_write(0, bytes(so[:BIN_SIZE]))
mu.mem_map(0x30000000, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
mu.mem_write(0x30000000, b'\xc0\x03\x5f\xd6')
mu.mem_write(0x30000008, b'\xc0\x03\x5f\xd6')
mu.mem_map(HEAP_BASE, 0x100000, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(0x7FF00000, 0x40000, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(0x80000000, 0x40000, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(0x90000000, 0x40000, UC_PROT_READ | UC_PROT_WRITE)

def w64(a,v): mu.mem_write(a, struct.pack('<Q', v))
def w32(a,v): mu.mem_write(a, struct.pack('<I', v))

w64(0x11fed98, 0x30000000)
w64(0x11fed98+8, 0x30000008)

# Setup state frame (0x7FF30070-0x7FF300??)
# state layout:
# +0x00: key[0]=3
# +0x04: key[1]=0
# +0x08: key[2]=2
# +0x0c: key[3]=0x40000
# +0x10: heap (alloc buffer)
# +0x18: output buffer ptr
# +0x20: compressed data ptr
# +0x28: range (-1)
# +0x2c: code (from 5 raw bytes)
# +0x30: output_pos (0)
# +0x40: state0 (0)
# +0x44: state1 (0)
# +0x48/4c/50/54/58: tree state fields
# +0x5c: ...
# +0x60: flag init (1 means do raw byte first)
# +0x64: tree init flag (1)
# +0x6c: raw_byte_count (0)
# +0x70-0x84: buffer for raw bytes / refill data

w32(STATE_ADDR + 0x00, 3)
w32(STATE_ADDR + 0x04, 0)
w32(STATE_ADDR + 0x08, 2)
w32(STATE_ADDR + 0x0c, 0x40000)
w64(STATE_ADDR + 0x10, HEAP_BASE)
w64(STATE_ADDR + 0x18, OUTPUT_BUF)
w64(STATE_ADDR + 0x20, COMP_BUF)
w32(STATE_ADDR + 0x28, 0xFFFFFFFF)
w32(STATE_ADDR + 0x2c, 0)  # code will be set by raw byte processing
w64(STATE_ADDR + 0x30, 0)
w32(STATE_ADDR + 0x40, 0)
w32(STATE_ADDR + 0x44, 0)
w32(STATE_ADDR + 0x48, 0)
w32(STATE_ADDR + 0x4c, 0)
w32(STATE_ADDR + 0x50, 0)
w32(STATE_ADDR + 0x54, 0)
w32(STATE_ADDR + 0x58, 0)
w32(STATE_ADDR + 0x5c, 0)
w32(STATE_ADDR + 0x60, 1)
w32(STATE_ADDR + 0x64, 1)
w32(STATE_ADDR + 0x6c, 0)

w64(COMP_SIZE_ADDR, comp_size)
mu.mem_write(COMP_BUF, payload)
w32(SCRATCH, 0)

# Store comp_size in the state frame after 0x7FF30070
# The outer function uses comp_size pointer at x3

inctr = [0]
last_pc = [0]

def hook(uc, address, size, user_data):
    inctr[0] += 1
    if inctr[0] > 200000:
        uc.emu_stop()
        return
    if address == 0x30000000:
        uc.reg_write(UC_ARM64_REG_X0, HEAP_BASE)
        return
    elif address == 0x30000008:
        return

    # Trace key calls
    if address == 0xcf0b04:
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        out_pos = struct.unpack("<Q", mu.mem_read(STATE_ADDR+0x30, 8))[0]
        state28 = struct.unpack("<I", mu.mem_read(STATE_ADDR+0x28, 4))[0]
        state2c = struct.unpack("<I", mu.mem_read(STATE_ADDR+0x2c, 4))[0]
        state40 = struct.unpack("<I", mu.mem_read(STATE_ADDR+0x40, 4))[0]
        state44 = struct.unpack("<I", mu.mem_read(STATE_ADDR+0x44, 4))[0]
        state60 = struct.unpack("<I", mu.mem_read(STATE_ADDR+0x60, 4))[0]
        state64 = struct.unpack("<I", mu.mem_read(STATE_ADDR+0x64, 4))[0]
        state6c = struct.unpack("<I", mu.mem_read(STATE_ADDR+0x6c, 4))[0]
        state48 = struct.unpack("<I", mu.mem_read(STATE_ADDR+0x48, 4))[0]
        print(f'\n=== sub_CF0B04 CALL #{inctr[0]} ===')
        print(f'  x0={x0:#x} x1={x1:#x} x2={x2:#x}')
        print(f'  state28={state28:#x} state2c={state2c:#x} out={out_pos:#x}')
        print(f'  state40={state40:#x} state44={state44:#x} state60={state60:#x} state64={state64:#x} state6c={state6c:#x} state48={state48:#x}')
        print(f'  state20={struct.unpack("<Q", mu.mem_read(STATE_ADDR+0x20, 8))[0]:#x} state18={struct.unpack("<Q", mu.mem_read(STATE_ADDR+0x18, 8))[0]:#x}')
    elif address == 0xcf1a44:
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        out_pos = struct.unpack("<Q", mu.mem_read(STATE_ADDR+0x30, 8))[0]
        state20 = struct.unpack("<Q", mu.mem_read(STATE_ADDR+0x20, 8))[0]
        print(f'  [{inctr[0]}] sub_CF1A44 CALL x0={x0:#x} x1={x1:#x} x2={x2:#x} out={out_pos:#x} st20={state20:#x}')
    elif address == 0xcf24e4:
        w0 = uc.reg_read(UC_ARM64_REG_W0)
        print(f'  [{inctr[0]}] sub_CF0B04 RET w0={w0:#x}')
    elif address == 0xcf24e8:
        w0 = uc.reg_read(UC_ARM64_REG_W0)
        out_pos = struct.unpack("<Q", mu.mem_read(STATE_ADDR+0x30, 8))[0]
        print(f'  [{inctr[0]}] sub_CF0B04 SUCCESS at 0xcf24e8 out={out_pos:#x}')
    elif address == 0xcf253c:
        w0 = uc.reg_read(UC_ARM64_REG_W0)
        out_pos = struct.unpack("<Q", mu.mem_read(STATE_ADDR+0x30, 8))[0]
        print(f'  [{inctr[0]}] sub_CF0B04 RET !=0 handled at 0xcf253c out={out_pos:#x} w0={w0:#x}')
    elif address == 0xcf2680:
        print(f'  [{inctr[0]}] sub_CF1A44 RET 0 at 0xcf2680')
    elif address == 0xcf235c:
        w0 = uc.reg_read(UC_ARM64_REG_W0)
        print(f'  [{inctr[0]}] SECOND sub_CF0B04 RET w0={w0:#x}')
    elif address == 0xcf25a0:
        out_pos = struct.unpack("<Q", mu.mem_read(STATE_ADDR+0x30, 8))[0]
        state40 = struct.unpack("<I", mu.mem_read(STATE_ADDR+0x40, 4))[0]
        state44 = struct.unpack("<I", mu.mem_read(STATE_ADDR+0x44, 4))[0]
        print(f'  [{inctr[0]}] SECOND sub_CF0B04 ERROR at 0xcf25a0 out={out_pos:#x} st40={state40:#x} st44={state44:#x}')
    elif address == 0xcf1788:
        w0 = uc.reg_read(UC_ARM64_REG_W0)
        out_pos = struct.unpack("<Q", mu.mem_read(STATE_ADDR+0x30, 8))[0]
        print(f'  [{inctr[0]}] sub_CF0B04 RET w0={w0:#x} out={out_pos:#x}')
    elif address == 0xcf1790:
        w0 = uc.reg_read(UC_ARM64_REG_W0)
        print(f'  [{inctr[0]}] sub_CF0B04 RET at 0xcf1790 w0={w0:#x}')

mu.hook_add(UC_HOOK_CODE, hook)

# Call sub_CF2110 as it would be called from the outer function:
# x0 = state, x1 = uncomp_bytes_left, x2 = comp_data, x3 = comp_size_ptr, x4 = flag, x5 = scratch
mu.reg_write(UC_ARM64_REG_X0, STATE_ADDR)
mu.reg_write(UC_ARM64_REG_X1, uncomp_size)
mu.reg_write(UC_ARM64_REG_X2, COMP_BUF)
mu.reg_write(UC_ARM64_REG_X3, COMP_SIZE_ADDR)
mu.reg_write(UC_ARM64_REG_X4, 1)
mu.reg_write(UC_ARM64_REG_X5, SCRATCH)
mu.reg_write(UC_ARM64_REG_X29, 0x7FF30010)
mu.reg_write(UC_ARM64_REG_X30, 0xDEAD)
mu.reg_write(UC_ARM64_REG_SP, 0x7FF2FFF0)

print('Starting sub_CF2110 emulation...')
try:
    mu.emu_start(0xcf2110, 0xDEAD, timeout=120000000)
except UcError as e:
    print(f'Error: {e} PC={mu.reg_read(UC_ARM64_REG_PC):#x}')
except Exception as e:
    print(f'Exception: {e}')

x0 = mu.reg_read(UC_ARM64_REG_X0)
pc = mu.reg_read(UC_ARM64_REG_PC)
out_pos = struct.unpack("<Q", mu.mem_read(STATE_ADDR+0x30, 8))[0]
state40 = struct.unpack("<I", mu.mem_read(STATE_ADDR+0x40, 4))[0]
state44 = struct.unpack("<I", mu.mem_read(STATE_ADDR+0x44, 4))[0]
state48 = struct.unpack("<I", mu.mem_read(STATE_ADDR+0x48, 4))[0]
state20 = struct.unpack("<Q", mu.mem_read(STATE_ADDR+0x20, 8))[0]
print(f'\nFinal PC={pc:#x} X0={x0:#x} total={inctr[0]}')
print(f'Output pos={out_pos:#x} state40={state40:#x} state44={state44:#x} state48={state48:#x}')
print(f'state20={state20:#x}')

# Check output
if out_pos > 0 and out_pos < 0x100000:
    out = mu.mem_read(OUTPUT_BUF, min(out_pos, 64))
    print(f'First {min(out_pos, 64)} output bytes: {out.hex()}')
