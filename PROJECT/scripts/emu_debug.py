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

w32(STATE_ADDR + 0x00, 3)
w32(STATE_ADDR + 0x04, 0)
w32(STATE_ADDR + 0x08, 2)
w32(STATE_ADDR + 0x0c, 0x40000)
w64(STATE_ADDR + 0x10, HEAP_BASE)
w64(STATE_ADDR + 0x18, OUTPUT_BUF)
w64(STATE_ADDR + 0x20, COMP_BUF)
w32(STATE_ADDR + 0x28, 0xFFFFFFFF)
w32(STATE_ADDR + 0x2c, 0)
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

inctr = [0]
trace_on = [False]

def hook(uc, address, size, user_data):
    inctr[0] += 1
    
    if address == 0xcf1a44:
        print(f'  [{inctr[0]}] 0xcf1a44 ENTER sub_CF1A44')
        trace_on[0] = True
    
    if address == 0x30000000:
        uc.reg_write(UC_ARM64_REG_X0, HEAP_BASE)
        return
    elif address == 0x30000008:
        return
    
    if trace_on[0] and inctr[0] < 50000:
        if address >= 0xcf1a44 and address <= 0xcf1c00:
            w0 = uc.reg_read(UC_ARM64_REG_W0)
            print(f'  [{inctr[0]}] 0x{address:#x} w0={w0:#x}')
        elif address == 0xcf2554:
            w0 = uc.reg_read(UC_ARM64_REG_W0)
            print(f'  [{inctr[0]}] 0xcf2554 cbz w0={w0:#x}')
        elif address == 0xcf2348:
            print(f'  [{inctr[0]}] 0xcf2348 SECOND CALL PATH')
        elif address == 0xcf0b04:
            print(f'  [{inctr[0]}] 0xcf0b04 SECOND sub_CF0B04 ENTRY')
        elif address == 0xcf25a0:
            print(f'  [{inctr[0]}] 0xcf25a0 ERROR')
            trace_on[0] = False

mu.hook_add(UC_HOOK_CODE, hook)

print('Starting sub_CF2110...')
mu.reg_write(UC_ARM64_REG_X0, STATE_ADDR)
mu.reg_write(UC_ARM64_REG_X1, uncomp_size)
mu.reg_write(UC_ARM64_REG_X2, COMP_BUF)
mu.reg_write(UC_ARM64_REG_X3, COMP_SIZE_ADDR)
mu.reg_write(UC_ARM64_REG_X4, 1)
mu.reg_write(UC_ARM64_REG_X5, SCRATCH)
mu.reg_write(UC_ARM64_REG_X29, 0x7FF30010)
mu.reg_write(UC_ARM64_REG_X30, 0xDEAD)
mu.reg_write(UC_ARM64_REG_SP, 0x7FF2FFF0)

try:
    mu.emu_start(0xcf2110, 0xDEAD, timeout=120000000)
except UcError as e:
    print(f'Error: {e} PC={mu.reg_read(UC_ARM64_REG_PC):#x}')

print(f'\nTotal instructions: {inctr[0]}')
