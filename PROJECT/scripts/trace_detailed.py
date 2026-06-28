import struct, os

WORK = r"C:\Users\NGEONG\Videos\VSCODE\mt_dump"
aes = open(os.path.join(WORK, "intermediate", "01_aes_output.bin"), 'rb').read()

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
    return decompressed_size, bytes(flags), bytes(buf[0x0E:])

decomp_size, flags, comp_data = parse_lmf_header(aes)

class BitDecoder:
    def __init__(self, data):
        self.data = data
        self.pos = 5  # start after 5-byte seed
        self.end = len(data)
        self.high = 0xFFFFFFFF
        self.low = 0
        self.bit_count = 0

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

    def decode_bit(self, prob, ctx=None):
        self.renorm()
        mid = ((self.high >> RANGE_BITS) * prob) & 0xFFFFFFFF
        self.bit_count += 1
        if self.low < mid:
            self.high = mid
            if ctx:
                print(f"  bit {self.bit_count}: low={self.low:#010x} < mid={mid:#010x} => 0 (ctx={ctx})")
            return 0
        else:
            self.low = (self.low - mid) & 0xFFFFFFFF
            self.high = (self.high - mid) & 0xFFFFFFFF
            if ctx:
                print(f"  bit {self.bit_count}: low >= mid={mid:#010x} => 1 (ctx={ctx})  [new low={self.low:#010x} high={self.high:#010x}]")
            return 1

    def decode_tree(self, tbl, base_idx, max_idx, label=""):
        idx = 1
        level = 0
        while idx <= max_idx:
            p = tbl[base_idx + idx]
            bit = self.decode_bit(p, f"{label}:idx={idx}")
            tbl[base_idx + idx] = update_prob(p, bit)
            idx = (idx << 1) | bit
            level += 1
        val = idx & 0xFF
        return val

exponent = flags[0]
window_shift = exponent // 9
remainder_9 = exponent % 9
prob_shift = (window_shift * 0xCCCCCCCD) >> 34
remainder_5 = window_shift - prob_shift * 5
field_00 = remainder_9
field_04 = remainder_5
table_entries = (0x300 << (field_04 + field_00)) + 0x736

table = [PROB_INIT] * table_entries
bd = BitDecoder(comp_data)

seed = comp_data[:5]
ctx0 = seed[0]
ctx_seed = (seed[1] << 24) | (seed[2] << 16) | (seed[3] << 8) | seed[4]
print(f"Seed: {seed.hex()}, ctx0={ctx0:#04x}, ctx_seed={ctx_seed:#010x}")
bd.init_from_ctx(ctx_seed)

mask = (1 << prob_shift) - 1
state_idx = 0
block_cnt = 0

print(f"\n{'='*60}")
print(f"Symbol 0 - LITERAL/MATCH decision")
bit0 = bd.decode_bit(table[(state_idx << 4) + (block_cnt & mask)], f"sym0_ctx={(state_idx<<4)+(block_cnt&mask):#x}")
if bit0 == 0:
    print(f"  => LITERAL, decoding literal tree:")
    val = bd.decode_tree(table, 0x736, 0xFF, "sym0_lit")
    print(f"  => Literal value: {val} ({val:#04x})")
