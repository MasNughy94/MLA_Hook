"""Debug: minimal trace of fn at 0xcf2b2c - v3"""
import struct
from unicorn import *
from unicorn.arm64_const import *

with open(r'C:\Users\NGEONG\Videos\MLA\libagame.so', 'rb') as f:
    so = bytearray(f.read())

mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# Map full binary (VA == file offset, PIE)
BIN_SIZE = (len(so) + 0xFFF) & ~0xFFF
mu.mem_map(0, BIN_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
mu.mem_write(0, bytes(so[:BIN_SIZE]))

# Fake alloc/free at 0x30000000 - write real ret instructions
# ret = 0xD65F03C0
mu.mem_map(0x30000000, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
mu.mem_write(0x30000000, b'\xc0\x03\x5f\xd6')  # ret
mu.mem_write(0x30000008, b'\xc0\x03\x5f\xd6')  # ret

HEAP_BASE = 0x31000000
HEAP_SIZE = 0x100000
mu.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE)

# Stack
mu.mem_map(0x7FF00000, 0x40000, UC_PROT_READ | UC_PROT_WRITE)

# Heap for output/input buffers
mu.mem_map(0x80000000, 0x20000, UC_PROT_READ | UC_PROT_WRITE)

# TLS canary
def w64(a,v): mu.mem_write(a, struct.pack('<Q', v))
def w32(a,v): mu.mem_write(a, struct.pack('<I', v))

w64(0x11de3e0, 0x11dee00)
w64(0x11dee00, 0x1234567890ABCDEF)

# Interface struct at 0x11fed98
w64(0x11fed98, 0x30000000)
w64(0x11fed98+8, 0x30000008)

# Stack frame for main function (0xcf2b2c allocates 0x100 bytes)
# At entry: sp = caller's sp. After stp x29,x30,[sp,#-0x100]!:
#   x29 = sp - 0x100
# Saved regs: x19,x20 at x29+0x10, x21,x22 at x29+0x20, x23,x24 at x29+0x30,
#             x25,x26 at x29+0x40, x27 at x29+0x50
# Stack arg (interface ptr) at x29+0x100

FRAME = 0x7FF30000  # main's x29 (after stp [sp,#-0x100]!)
sp = FRAME + 0x100  # original SP before prologue

# The interface ptr is passed as the 9th arg, at [sp] before main's prologue
# After prologue, it's at x29 + 0x100
w64(FRAME + 0x100, 0x11fed98)

# Registers - match what the CALLER (0xCECD24) sets
mu.reg_write(UC_ARM64_REG_X0, 0x80010000)    # output buf
mu.reg_write(UC_ARM64_REG_X1, 0x80010050)    # size ptr struct
mu.reg_write(UC_ARM64_REG_X2, 0x80010080)    # input buf
mu.reg_write(UC_ARM64_REG_X3, FRAME + 0x58)  # &comp_size
mu.reg_write(UC_ARM64_REG_X4, FRAME + 0x60)  # &key
mu.reg_write(UC_ARM64_REG_X5, 5)
mu.reg_write(UC_ARM64_REG_X6, 1)
mu.reg_write(UC_ARM64_REG_X7, FRAME + 0x54)  # scratch
mu.reg_write(UC_ARM64_REG_X29, FRAME)
mu.reg_write(UC_ARM64_REG_X30, 0xDEAD)
mu.reg_write(UC_ARM64_REG_SP, sp)

# Frame data at FRAME (main's x29):
# [0x54]: scratch (32-bit)
# [0x58]: comp_size (64-bit)
# [0x60]: key[0..4] (5 bytes)
w32(FRAME + 0x54, 0)
w64(FRAME + 0x58, 9747)
mu.mem_write(FRAME + 0x60, bytes([0x5d, 0x00, 0x00, 0x04, 0x00]))

# Size ptr struct at 0x80010050
w64(0x80010050, 32553)

# Alloc state
alloc_ptr = [HEAP_BASE]

print("Starting trace v3...")
count = [0]
def hook(uc, address, size, user_data):
    if count[0] >= 150:
        return
    sp_val = uc.reg_read(UC_ARM64_REG_SP)
    x29 = uc.reg_read(UC_ARM64_REG_X29)
    x30 = uc.reg_read(UC_ARM64_REG_X30)
    
    extra = ""
    if address == 0x30000000:
        size_arg = uc.reg_read(UC_ARM64_REG_X0)
        ptr = alloc_ptr[0]
        alloc_ptr[0] += (size_arg + 15) & ~15
        uc.reg_write(UC_ARM64_REG_X0, ptr)
        extra = f" <-- ALLOC(size={size_arg:#x}) -> {ptr:#x}"
    elif address == 0x30000008:
        ptr_arg = uc.reg_read(UC_ARM64_REG_X0)
        extra = f" <-- FREE(ptr={ptr_arg:#x})"
    elif address in (0xcf2b2c, 0xcf292c, 0xcf2878, 0xcf2100, 0xcf2110, 0xcf2810):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        extra = f" X0={x0:#x} X1={x1:#x} X2={x2:#x}"
    
    print(f"  PC={address:#x} SP={sp_val:#x} X29={x29:#x} X30={x30:#x}{extra}")
    count[0] += 1
mu.hook_add(UC_HOOK_CODE, hook)

try:
    mu.emu_start(0xcf2b2c, 0, timeout=5000000)
except UcError as e:
    print(f"Error: {e}")
    print(f"PC={mu.reg_read(UC_ARM64_REG_PC):#x}")
    print(f"SP={mu.reg_read(UC_ARM64_REG_SP):#x}")

print(f"\nFinal PC={mu.reg_read(UC_ARM64_REG_PC):#x} X0={mu.reg_read(UC_ARM64_REG_X0):#x}")
