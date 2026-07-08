import struct
from unicorn import *
from unicorn.arm64_const import *

with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb') as f:
    so = bytearray(f.read())

mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
BIN_SIZE = (len(so) + 0xFFF) & ~0xFFF
mu.mem_map(0, BIN_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
mu.mem_write(0, bytes(so[:BIN_SIZE]))
mu.mem_map(0x30000000, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
mu.mem_write(0x30000000, b'\xc0\x03\x5f\xd6')
mu.mem_write(0x30000008, b'\xc0\x03\x5f\xd6')
HEAP_BASE = 0x31000000
mu.mem_map(HEAP_BASE, 0x100000, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(0x7FF00000, 0x40000, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(0x80000000, 0x40000, UC_PROT_READ | UC_PROT_WRITE)

def w64(a,v): mu.mem_write(a, struct.pack('<Q', v))
def w32(a,v): mu.mem_write(a, struct.pack('<I', v))
w64(0x11de3e0, 0x11dee00)
w64(0x11dee00, 0x1234567890ABCDEF)
w64(0x11fed98, 0x30000000)
w64(0x11fed98+8, 0x30000008)
FRAME = 0x7FF30000
w64(FRAME + 0x100, 0x11fed98)
w32(FRAME + 0x54, 0)
w64(FRAME + 0x58, 9747)
key_5 = bytes.fromhex('5d00000400')
mu.mem_write(FRAME + 0x60, key_5)
mu.mem_write(FRAME + 0x65, b'\x00' * 3)
w64(0x80010050, 32553)

alloc_ptr = [HEAP_BASE]

catch_addr = FRAME + 0x60  # 0x7FF30060

def write_hook(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    if address <= catch_addr + 7 and address + size > catch_addr:
        print(f'WRITE @ pc={pc:#x} addr={address:#x} size={size} value={value:#x}')
    return True

mu.hook_add(UC_HOOK_MEM_WRITE, write_hook)

print('Checking key memory BEFORE emulation:')
print(f'  [0x7ff30060]: {bytes(mu.mem_read(0x7ff30060, 8)).hex()}')

sp = FRAME + 0x100
mu.reg_write(UC_ARM64_REG_X0, 0x80010000)
mu.reg_write(UC_ARM64_REG_X1, 0x80010050)
mu.reg_write(UC_ARM64_REG_X2, 0x80010080)
mu.reg_write(UC_ARM64_REG_X3, FRAME + 0x58)
mu.reg_write(UC_ARM64_REG_X4, FRAME + 0x60)
mu.reg_write(UC_ARM64_REG_X5, 5)
mu.reg_write(UC_ARM64_REG_X6, 1)
mu.reg_write(UC_ARM64_REG_X7, FRAME + 0x54)
mu.reg_write(UC_ARM64_REG_X29, FRAME)
mu.reg_write(UC_ARM64_REG_X30, 0xDEAD)
mu.reg_write(UC_ARM64_REG_SP, sp)

try:
    mu.emu_start(0xcf2b2c, 0, timeout=10000000)
except UcError as e:
    pass

print(f'AFTER emulation - [0x7ff30060]: {bytes(mu.mem_read(0x7ff30060, 8)).hex()}')
