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

mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
HEAP_BASE = 0x31000000
STATE_ADDR = 0x7FF30070
OUTPUT_BUF = 0x80010000
COMP_BUF = 0x90000000  # separate from output!
COMP_SIZE_ADDR = 0x7FF30058
SCRATCH = 0x7FF30054

BIN_SIZE = (len(so) + 0xFFF) & ~0xFFF
mu.mem_map(0, BIN_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
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

# Compute the state[0x2c] value from the 5 raw header bytes
raw5 = payload[:5]  # first 5 bytes of XOR'd compressed data
# At 0xcf22ac: w0 = big-endian combination of bytes 1,2,3,4
# byte[0]=0x00 (checked), byte[1]=w4, byte[2]=w0, byte[4]=w2, byte[3]=w1
b1, b2, b3, b4, b5 = raw5[0], raw5[1], raw5[2], raw5[3], raw5[4]
# w0 = (b2 << 24) | (b3 << 16) | (b5) | (b4 << 8)  [from 0xcf229c-0xcf22ac]
combined = (b2 << 24) | (b3 << 16) | (b5) | (b4 << 8)
print(f'Raw bytes: {raw5.hex()}')
print(f'Combined state[0x2c] = {combined:#010x}')

w32(STATE_ADDR + 0x00, 3)
w32(STATE_ADDR + 0x04, 0)
w32(STATE_ADDR + 0x08, 2)
w32(STATE_ADDR + 0x0c, 0x40000)
w64(STATE_ADDR + 0x10, HEAP_BASE)
w64(STATE_ADDR + 0x18, OUTPUT_BUF)
w32(STATE_ADDR + 0x28, 0xFFFFFFFF)  # -1, set by raw byte processing
w32(STATE_ADDR + 0x2c, combined)     # from 5 raw bytes
w64(STATE_ADDR + 0x30, 0)
w32(STATE_ADDR + 0x40, 0)
w32(STATE_ADDR + 0x44, 0)
w32(STATE_ADDR + 0x5c, 0)
w32(STATE_ADDR + 0x60, 1)            # initialized flag
w32(STATE_ADDR + 0x64, 1)            # tree init flag
w32(STATE_ADDR + 0x6c, 0)
w64(COMP_SIZE_ADDR, len(payload))
mu.mem_write(COMP_BUF, payload)
w32(SCRATCH, 0)

print(f'Before: output[0x00]={mu.mem_read(OUTPUT_BUF,4).hex()}')

count = [0]
sub_count = [0]
def hook(uc, address, size, user_data):
    count[0] += 1
    if count[0] > 30000000:
        uc.emu_stop()
        return
    if address == 0x30000000:
        uc.reg_write(UC_ARM64_REG_X0, HEAP_BASE)
    elif address == 0x30000008:
        pass
    # Trace sub_CF0B04
    if address in (0xcf24e0, 0xcf2358):
        sub_count[0] += 1
        s30 = struct.unpack('<Q', mu.mem_read(STATE_ADDR+0x30, 8))[0]
        print(f'  Call #{sub_count[0]} sub_CF0B04 out_pos={s30:#x}')
    elif address == 0xcf0dcc:
        print(f'  sub_CF0B04 SUCCESS call #{sub_count[0]}')
    elif address == 0xcf141c:
        w4 = uc.reg_read(UC_ARM64_REG_W4)
        if w4 == 0:
            print(f'  sub_CF0B04 FAIL cbz w4 call #{sub_count[0]}')
    elif address == 0xcf1788:
        s40 = struct.unpack('<I', mu.mem_read(STATE_ADDR+0x40, 4))[0]
        s44 = struct.unpack('<I', mu.mem_read(STATE_ADDR+0x44, 4))[0]
        print(f'  sub_CF0B04 ERROR ret w0=1 call #{sub_count[0]} state40={s40:#x} 44={s44:#x}')

mu.hook_add(UC_HOOK_CODE, hook)

mu.reg_write(UC_ARM64_REG_X0, STATE_ADDR)
mu.reg_write(UC_ARM64_REG_X1, uncomp_size)
mu.reg_write(UC_ARM64_REG_X2, COMP_BUF)
mu.reg_write(UC_ARM64_REG_X3, COMP_SIZE_ADDR)
mu.reg_write(UC_ARM64_REG_X4, 1)
mu.reg_write(UC_ARM64_REG_X5, SCRATCH)
mu.reg_write(UC_ARM64_REG_X29, 0x7FF30010)
mu.reg_write(UC_ARM64_REG_X30, 0xDEAD)
mu.reg_write(UC_ARM64_REG_SP, 0x7FF30000)

try:
    mu.emu_start(0xcf2110, 0, timeout=120000000)
except UcError as e:
    print(f'Error: {e} PC={mu.reg_read(UC_ARM64_REG_PC):#x}')

x0 = mu.reg_read(UC_ARM64_REG_X0)
print(f'\nFinal PC={mu.reg_read(UC_ARM64_REG_PC):#x} X0={x0:#x} total_insns={count[0]}')
print(f'Total sub_CF0B04 calls: {sub_count[0]}')
print(f'Return {"SUCCESS" if x0 == 0 else f"ERROR code {x0}"}')

out_buf = bytes(mu.mem_read(OUTPUT_BUF, uncomp_size))
print(f'Output size: {len(out_buf)} bytes')
print(f'First 128 hex: {out_buf[:128].hex()}')
printable = sum(1 for b in out_buf if 32 <= b < 127)
print(f'Printable: {printable}/{len(out_buf)}')

if x0 == 0:
    with open(r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\output.bin', 'wb') as f:
        f.write(out_buf)
    print('SUCCESS! Saved to output.bin')
