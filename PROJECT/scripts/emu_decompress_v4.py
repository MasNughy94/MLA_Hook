"""Emulate decompression with real compressed data - v4"""
import struct, os
from unicorn import *
from unicorn.arm64_const import *
from Crypto.Cipher import AES

# Load binary
with open(r'C:\Users\NGEONG\Videos\MLA\libagame.so', 'rb') as f:
    so = bytearray(f.read())

# Load and decrypt a real .mt file
def decrypt_layer1(data):
    payload = data[16:]
    pad = (16 - len(payload) % 16) % 16
    if pad:
        payload_padded = payload + b'\x00' * pad
    else:
        payload_padded = payload
    cipher = AES.new(bytes.fromhex('f5a193d50ade553e9835595f5cd75ddd'), AES.MODE_ECB)
    dec = cipher.decrypt(payload_padded)
    return dec[:len(payload)]

root = r'C:\Users\NGEONG\Videos\MLA'
mt_path = os.path.join(root, r'MLADVENTURE2\assets\0\0000488d2f64199aca0cc7d54e7d11c0.mt')
with open(mt_path, 'rb') as f:
    raw_file = f.read()

dec = decrypt_layer1(raw_file)
assert dec[:4] == b'lmF@', "Expected lmF@ magic"
key_5 = dec[4:9]          # 5-byte key at offset 4-8
# Compressed data starts at offset 0xe (14), NOT 16!
# CALLER passes lmF@+0xe as input; comp_size = total_size - 0xe
comp_size = len(dec) - 0xe  # = 9761 - 14 = 9747
payload = dec[0xe:]         # data starting at offset 14
# CALLER XORs first 16 bytes of compressed payload with 0xec
payload = bytearray(payload)
for i in range(min(16, len(payload))):
    payload[i] ^= 0xec
payload = bytes(payload)
# Uncompressed size: [lmF@ + 0xa] ^ 0x3ea
uncomp_size = (struct.unpack('<I', dec[0xa:0xa+4])[0]) ^ 0x3ea

print(f"Key: {key_5.hex()}")
print(f"lmF@ total: {len(dec)} bytes")
print(f"Compressed (offset 0xe): {comp_size} bytes")
print(f"Uncompressed: {uncomp_size} bytes")

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
SAFE_KEY = 0x7FF20000
w64(FRAME + 0x100, 0x11fed98)
w32(FRAME + 0x54, 0)
w64(FRAME + 0x58, comp_size)
mu.mem_write(SAFE_KEY, key_5 + b'\x00' * 3)
w64(0x80010050, uncomp_size)
mu.mem_write(0x80010080, bytes(payload))

alloc_ptr = [HEAP_BASE]

print("Starting emulation...")
count = [0]
trace_ret = {}  # { address: description }

# Trace return-1 points in sub_CF2110 (block_process)
trace_ret[0xcf2524] = 'ret 1 from 0xcf2524 (w5 != 0 path)'
trace_ret[0xcf25b4] = 'ret 1 from 0xcf25b4 (sub_CF0B04 failed)'

# Trace sub_CF0B04 key points
trace_ret[0xcf0b04] = 'sub_CF0B04 ENTRY'
trace_ret[0xcf0b60] = 'sub_CF0B04: b.ls taken (init path)'
trace_ret[0xcf0c58] = 'sub_CF0B04: cbnz x26 to 0xcf1630 (x26 != 0)'
trace_ret[0xcf0da0] = 'sub_CF0B04 calling sub_CF0A44'
trace_ret[0xcf0dcc] = 'sub_CF0B04: mov w0, #0 SUCCESS'

iter_count = [0]
last_print = [0]

def hook(uc, address, size, user_data):
    count[0] += 1
    iter_count[0] += 1
    
    if address in trace_ret:
        w0 = uc.reg_read(UC_ARM64_REG_W0)
        x26 = uc.reg_read(UC_ARM64_REG_X26)
        x28 = uc.reg_read(UC_ARM64_REG_X28)
        print(f"  TRACE {trace_ret[address]} (w0={w0:#x} x26={x26:#x} x28={x28:#x})")
        if address == 0xcf0c58:
            # Also print the x26 value
            print(f"    -> x26={x26:#x}")
    
    # Progress indicator for long loops
    if count[0] % 500000 == 0 and count[0] != last_print[0]:
        last_print[0] = count[0]
        x28 = uc.reg_read(UC_ARM64_REG_X28)
        x26 = uc.reg_read(UC_ARM64_REG_X26)
        print(f"  [progress] count={count[0]} x28={x28:#x} x26={x26:#x}")
    
    if address == 0x30000000:
        size_arg = uc.reg_read(UC_ARM64_REG_X1)
        ptr = alloc_ptr[0]
        alloc_ptr[0] += (size_arg + 15) & ~15
        uc.reg_write(UC_ARM64_REG_X0, ptr)
        print(f"    ALLOC(size={size_arg:#x}) -> {ptr:#x}")
    elif address == 0x30000008:
        ptr_arg = uc.reg_read(UC_ARM64_REG_X0)
        print(f"    FREE(ptr={ptr_arg:#x})")
    # Trace the loop count in sub_CF2110
    elif address == 0xcf2504:
        x28 = uc.reg_read(UC_ARM64_REG_X28)
        print(f"  LOOP BACK remaining={x28:#x}")

mu.hook_add(UC_HOOK_CODE, hook)

sp = FRAME + 0x100
mu.reg_write(UC_ARM64_REG_X0, 0x80010000)
mu.reg_write(UC_ARM64_REG_X1, 0x80010050)
mu.reg_write(UC_ARM64_REG_X2, 0x80010080)
mu.reg_write(UC_ARM64_REG_X3, FRAME + 0x58)
mu.reg_write(UC_ARM64_REG_X4, SAFE_KEY)
mu.reg_write(UC_ARM64_REG_X5, 5)
mu.reg_write(UC_ARM64_REG_X6, 1)
mu.reg_write(UC_ARM64_REG_X7, FRAME + 0x54)
mu.reg_write(UC_ARM64_REG_X29, FRAME)
mu.reg_write(UC_ARM64_REG_X30, 0xDEAD)
mu.reg_write(UC_ARM64_REG_SP, sp)

try:
    mu.emu_start(0xcf2b2c, 0, timeout=60000000)
except UcError as e:
    print(f"Error: {e}")
    print(f"PC={mu.reg_read(UC_ARM64_REG_PC):#x}")

final_pc = mu.reg_read(UC_ARM64_REG_PC)
final_x0 = mu.reg_read(UC_ARM64_REG_X0)
print(f"\nFinal PC={final_pc:#x} X0={final_x0:#x}")

# Read output - check both the buffer and the size ptr struct
READ_SIZE = min(uncomp_size, 262144)
out_buf = bytes(mu.mem_read(0x80010000, READ_SIZE))
print(f"Output first 64: {out_buf[:64].hex()}")
printable = sum(1 for b in out_buf[:200] if 32 <= b < 127)
print(f"Printable chars in first 200: {printable}/200")
if printable > 50:
    text = "".join(chr(b) if 32 <= b < 127 else '.' for b in out_buf[:500])
    print(f"Preview: {text[:200]}")
    with open(r'C:\Users\NGEONG\AppData\Local\Temp\opencode\output.bin', 'wb') as f:
        f.write(out_buf)
    print("Saved to output.bin")

final_uncomp = struct.unpack('<Q', mu.mem_read(0x80010050, 8))[0]
print(f"Uncomp size at ptr: {final_uncomp}")

# Also check the state struct area for written data
state_bytes = bytes(mu.mem_read(FRAME + 0x70, 0x100))
print(f"State struct at FRAME+0x70 first 64: {state_bytes[:64].hex()}")

# Check alloc buffer for written data
alloc_buf = bytes(mu.mem_read(0x31000000, min(4096, alloc_ptr[0] - HEAP_BASE)))
print(f"Alloc buffer first 64: {alloc_buf[:64].hex()}")
