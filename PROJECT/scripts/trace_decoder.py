import struct, os

WORK = r"C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump"
IN_FILE = os.path.join(WORK, "sample.mt")
aes_file = os.path.join(WORK, "intermediate", "01_aes_output.bin")
aes = open(aes_file, 'rb').read()
ref = open(os.path.join(WORK, "sample.mt.lua"), 'rb').read()

PROB_INIT = 0x400
PROB_MAX = 0x800
PROB_SHIFT = 5
RANGE_BITS = 11
RENORM_THRESH = 0x1000000

def update_prob(prob, bit):
    if bit == 0:
        prob += (PROB_MAX - prob) >> PROB_SHIFT
    else:
        prob -= prob >> PROB_SHIFT
    return prob & 0xFFFF

def parse_lmf_header(data):
    assert data[:4] == b"lmF@"
    flags = bytearray(5)
    flags[0] = data[4]
    flags[1] = data[5]
    flags[2] = data[6]
    flags[3] = data[7] ^ 5
    flags[4] = data[8]
    encoded = struct.unpack_from('<I', data, 0x0A)[0]
    decompressed_size = encoded ^ 0x3EA
    buf = bytearray(data)
    limit = min(decompressed_size, 16)
    for i in range(limit):
        buf[0x0E + i] ^= 0xEC
    compressed_data = bytes(buf[0x0E:])
    return decompressed_size, bytes(flags), compressed_data

decomp_size, flags, comp_data = parse_lmf_header(aes)

# Manual range decoder trace
class BitDecoder:
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.end = len(data)
        self.high = 0xFFFFFFFF
        self.low = 0

    def init_from_ctx(self, seed):
        self.high = 0xFFFFFFFF
        self.low = seed & 0xFFFFFFFF

    def renorm(self):
        while self.high < RENORM_THRESH:
            self.high = (self.high << 8) & 0xFFFFFFFF
            if self.pos < self.end:
                self.low = ((self.low << 8) | self.data[self.pos]) & 0xFFFFFFFF
                self.pos += 1
            else:
                self.low = (self.low << 8) & 0xFFFFFFFF

    def decode_bit(self, prob, label=""):
        self.renorm()
        mid = ((self.high >> RANGE_BITS) * prob) & 0xFFFFFFFF
        if self.low < mid:
            self.high = mid
            return 0
        else:
            self.low = (self.low - mid) & 0xFFFFFFFF
            self.high = (self.high - mid) & 0xFFFFFFFF
            return 1

    def decode_tree(self, tbl, base_idx, max_idx, label=""):
        idx = 1
        bits = []
        while idx <= max_idx:
            p = tbl[base_idx + idx]
            bit = self.decode_bit(p)
            tbl[base_idx + idx] = update_prob(p, bit)
            bits.append(str(bit))
            idx = (idx << 1) | bit
        val = idx & 0xFF
        return val

# Set up context
exponent = flags[0]
window_shift = exponent // 9
remainder_9 = exponent % 9
prob_shift = (window_shift * 0xCCCCCCCD) >> 34
remainder_5 = window_shift - prob_shift * 5
field_00 = remainder_9
field_04 = remainder_5
prob_shift = prob_shift
table_entries = (0x300 << (field_04 + field_00)) + 0x736

print(f"flags: {flags.hex()}")
print(f"exponent={exponent}, window_shift={window_shift}, prob_shift={prob_shift}")
print(f"field_00={field_00}, field_04={field_04}")
print(f"table_entries={table_entries}")

table = [PROB_INIT] * table_entries
bd = BitDecoder(comp_data)

# Simulate the first 5-byte seed read (like the decompressor does)
# bd.pos starts at 0 and we read 5 bytes for the seed
seed_bytes = comp_data[:5]
print(f"\nFirst 5 bytes of compressed: {seed_bytes.hex()}")
ctx0 = seed_bytes[0]
ctx_seed = (seed_bytes[1] << 24) | (seed_bytes[2] << 16) | (seed_bytes[3] << 8) | seed_bytes[4]
print(f"ctx0={ctx0:#04x}, ctx_seed={ctx_seed:#010x}")
bd.init_from_ctx(ctx_seed)
# After reading 5 bytes for seed, bd.pos should be 5
bd.pos = 5  # The decompressor advances pos by 5 after reading the seed

print(f"\nRange decoder initial state:")
print(f"  high={bd.high:#010x}, low={bd.low:#010x}")
print(f"  pos={bd.pos}, end={bd.end}")
print()

# Decode first symbol step by step
mask = (1 << prob_shift) - 1
state_idx = 0
block_cnt = 0
ctx_idx = (state_idx << 4) + (block_cnt & mask)
p0 = table[ctx_idx]
print(f"Symbol 1: ctx_idx={ctx_idx:#06x}, p={p0:#06x}")
bit0 = bd.decode_bit(p0, "sym1")
table[ctx_idx] = update_prob(p0, bit0)
print(f"  First bit: {bit0} (0=literal, 1=match)")

if bit0 == 0:
    tree_val = bd.decode_tree(table, 0x736, 0xFF, "literal")
    print(f"  Literal tree result: {tree_val} (0x{tree_val:02x})")
    block_cnt += 1
    print(f"  Literal byte: {tree_val} ({chr(tree_val) if 32<=tree_val<127 else '?'})")
