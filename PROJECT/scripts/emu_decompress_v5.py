"""Emulate decompression starting from sub_CF2110 with manually prepped state"""
import struct, os
from unicorn import *
from unicorn.arm64_const import *

with open(r'C:\Users\NGEONG\Videos\MLA\libagame.so', 'rb') as f:
    so = bytearray(f.read())

# Pre-computed state values for key = 5d 00 00 04 00
STATE0 = 3    # key[0] % 9
STATE4 = 0    # (key[0]/9) % 5
STATE8 = 2    # division result
STATEC = 0x00040000  # built key

HEAP_BASE = 0x31000000
ALLOC_SIZE = 0x3E6C
OUTPUT_BUF = 0x80010000
COMP_BUF = 0x80010080
COMP_SIZE_ADDR = 0x7FF30058
STATE_ADDR = 0x7FF30070

# Load compressed data
from Crypto.Cipher import AES
def decrypt_layer1(data):
    payload = data[16:]
    pad = (16 - len(payload) % 16) % 16
    pp = payload + b'\x00' * pad if pad else payload
    c = AES.new(bytes.fromhex('f5a193d50ade553e9835595f5cd75ddd'), AES.MODE_ECB)
    dec = c.decrypt(pp)
    return dec[:len(payload)]

root = r'C:\Users\NGEONG\Videos\MLA'
mt_path = os.path.join(root, r'MLADVENTURE2\assets\0\0000488d2f64199aca0cc7d54e7d11c0.mt')
with open(mt_path, 'rb') as f:
    raw_file = f.read()
dec = decrypt_layer1(raw_file)
comp_size = len(dec) - 0xe
payload = bytearray(dec[0xe:])
for i in range(min(16, len(payload))):
    payload[i] ^= 0xec
payload = bytes(payload)
uncomp_size = struct.unpack('<I', dec[0xa:0xa+4])[0] ^ 0x3ea

print(f"uncomp_size={uncomp_size} comp_size={comp_size}")

mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

BIN_SIZE = (len(so) + 0xFFF) & ~0xFFF
mu.mem_map(0, BIN_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
mu.mem_write(0, bytes(so[:BIN_SIZE]))

mu.mem_map(0x30000000, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
mu.mem_write(0x30000000, b'\xc0\x03\x5f\xd6')  # ret (alloc stub)
mu.mem_write(0x30000008, b'\xc0\x03\x5f\xd6')  # ret (free stub)

mu.mem_map(HEAP_BASE, 0x100000, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(0x7FF00000, 0x40000, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(0x80000000, 0x40000, UC_PROT_READ | UC_PROT_WRITE)

def w64(a,v): mu.mem_write(a, struct.pack('<Q', v))
def w32(a,v): mu.mem_write(a, struct.pack('<I', v))

# Interface struct
w64(0x11fed98, 0x30000000)
w64(0x11fed98+8, 0x30000008)

# Init state at STATE_ADDR
# State struct layout (word offsets, from CF2B2C analysis):
# 0x00: state[0], 0x04: state[4], 0x08: state[8], 0x0c: state[12]
# 0x10: alloc_buf ptr, 0x18: output buf ptr
# 0x20: compressed data ptr (set during decomp)
# 0x30: output position counter (set during decomp)
# 0x38-0x5c: various decompression parameters
# 0x60: flag/data, 0x64: flag, 0x68: block_size, 0x6c: byte counter

w32(STATE_ADDR + 0x00, STATE0)
w32(STATE_ADDR + 0x04, STATE4)
w32(STATE_ADDR + 0x08, STATE8)
w32(STATE_ADDR + 0x0c, STATEC)
w64(STATE_ADDR + 0x10, HEAP_BASE)    # alloc buffer
w64(STATE_ADDR + 0x18, OUTPUT_BUF)   # output buffer
# offset 0x20 = compressed data ptr (set dynamically)
w64(STATE_ADDR + 0x30, 0)            # state[6] = output position
w32(STATE_ADDR + 0x68, 0x1F36)       # block size
# All other fields are 0 (fresh memory)

# Set comp_size at its address
w64(COMP_SIZE_ADDR, comp_size)

# Write compressed data at COMP_BUF
mu.mem_write(COMP_BUF, bytes(payload))

# Scratch value at scratch ptr
SCRATCH = 0x7FF30054
w32(SCRATCH, 0)

# uncomp_size at its struct
w64(OUTPUT_BUF + 0x50, uncomp_size)

print("Starting emulation from sub_CF2110...")
count = [0]
ret_seen = [False]

def hook(uc, address, size, user_data):
    count[0] += 1
    # Stop if we've been running too many instructions
    if count[0] > 20000000:
        uc.emu_stop()
        print("INSTRUCTION LIMIT")
        return

    if address == 0x30000000:
        sz = uc.reg_read(UC_ARM64_REG_X1)
        ptr = HEAP_BASE  # just return same base for simplicity
        uc.reg_write(UC_ARM64_REG_X0, ptr)
    elif address == 0x30000008:
        pass  # free is a no-op

    # Trace sub_CF0B04 key points
    if address == 0xcf0b04:
        x28v = uc.reg_read(UC_ARM64_REG_X28)
        print(f"  ENTER sub_CF0B04 x28={x28v:#x}")
    elif address == 0xcf0dcc:
        print(f"  sub_CF0B04 SUCCESS (mov w0, #0) after {count[0]} insns")
    elif address == 0xcf0df4:
        w0v = uc.reg_read(UC_ARM64_REG_W0)
        print(f"  sub_CF0B04 RET w0={w0v:#x} after {count[0]} insns")
    elif address == 0xcf0c58:
        x26v = uc.reg_read(UC_ARM64_REG_X26)
        x28v = uc.reg_read(UC_ARM64_REG_X28)
        print(f"  cbnz x26 -> 0xcf1630 (x26={x26v:#x} x28={x28v:#x})")
    elif address == 0xcf2504:
        x28v = uc.reg_read(UC_ARM64_REG_X28)
        print(f"  LOOP BACK x28={x28v:#x}")
    elif address == 0xcf25b4:
        print(f"  ERROR PATH at 0xcf25b4")
    elif address == 0xcf2524:
        print(f"  ERROR PATH at 0xcf2524")

mu.hook_add(UC_HOOK_CODE, hook)

# Registers for sub_CF2110(local_state, uncomp_size, comp_data, &comp_size, flag=1, scratch)
mu.reg_write(UC_ARM64_REG_X0, STATE_ADDR)     # state
mu.reg_write(UC_ARM64_REG_X1, uncomp_size)     # uncomp_size
mu.reg_write(UC_ARM64_REG_X2, COMP_BUF)        # compressed data
mu.reg_write(UC_ARM64_REG_X3, COMP_SIZE_ADDR)  # &comp_size
mu.reg_write(UC_ARM64_REG_X4, 1)               # flag
mu.reg_write(UC_ARM64_REG_X5, SCRATCH)         # scratch ptr
mu.reg_write(UC_ARM64_REG_X29, 0x7FF30010)
mu.reg_write(UC_ARM64_REG_X30, 0xDEAD)
mu.reg_write(UC_ARM64_REG_SP, 0x7FF30000)

try:
    mu.emu_start(0xcf2110, 0, timeout=120000000)
except UcError as e:
    print(f"Error: {e} PC={mu.reg_read(UC_ARM64_REG_PC):#x}")

print(f"\nFinal PC={mu.reg_read(UC_ARM64_REG_PC):#x} X0={mu.reg_read(UC_ARM64_REG_X0):#x} count={count[0]}")

out_buf = bytes(mu.mem_read(OUTPUT_BUF, uncomp_size))
print(f"Output first 64: {out_buf[:64].hex()}")
printable = sum(1 for b in out_buf[:200] if 32 <= b < 127)
print(f"Printable: {printable}/200")
if printable > 50:
    with open(r'C:\Users\NGEONG\AppData\Local\Temp\opencode\output.bin', 'wb') as f:
        f.write(out_buf)
    print("Saved to output.bin")
