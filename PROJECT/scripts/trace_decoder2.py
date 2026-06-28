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
    compressed_data = bytes(buf[0x0E:])
    return decompressed_size, bytes(flags), compressed_data

decomp_size, flags, comp_data = parse_lmf_header(aes)

class BitDecoder:
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.end = len(data)
        self.high = 0xFFFFFFFF
        self.low = 0
        self.bits_decoded = 0

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

    def decode_bit(self, prob):
        self.renorm()
        self.bits_decoded += 1
        mid = ((self.high >> RANGE_BITS) * prob) & 0xFFFFFFFF
        if self.low < mid:
            self.high = mid
            return 0
        else:
            self.low = (self.low - mid) & 0xFFFFFFFF
            self.high = (self.high - mid) & 0xFFFFFFFF
            return 1

    def decode_tree(self, tbl, base_idx, max_idx):
        idx = 1
        while idx <= max_idx:
            p = tbl[base_idx + idx]
            bit = self.decode_bit(p)
            tbl[base_idx + idx] = update_prob(p, bit)
            idx = (idx << 1) | bit
        return idx & 0xFF

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

# Read seed
ctx0 = comp_data[0]
ctx_seed = (comp_data[1] << 24) | (comp_data[2] << 16) | (comp_data[3] << 8) | comp_data[4]
bd.init_from_ctx(ctx_seed)
bd.pos = 5

mask = (1 << prob_shift) - 1
state_idx = 0
block_cnt = 0

# Lua bytecode expected header
expected = bytes([0x1B, 0x4C, 0x75, 0x61, 0x53, 0x00, 0x01, 0x04, 0x08, 0x04, 0x08, 0x00, 0x19, 0x93, 0x0D, 0x0A])
output = bytearray()

for sym_num in range(20):
    ctx_idx = (state_idx << 4) + (block_cnt & mask)
    p = table[ctx_idx]
    bit = bd.decode_bit(p)
    table[ctx_idx] = update_prob(p, bit)
    
    if bit == 0:  # literal
        tree_val = bd.decode_tree(table, 0x736, 0xFF)
        output.append(tree_val)
        state_idx = tree_val & 0xF
        block_cnt += 1
        expected_byte = expected[len(output)-1] if len(output)-1 < len(expected) else None
        match = "[OK]" if expected_byte is not None and tree_val == expected_byte else f"(expected {expected_byte:#04x})" if expected_byte is not None else "(past expected)"
        print(f"Sym {sym_num}: LITERAL byte={tree_val:#04x} ('{chr(tree_val) if 32<=tree_val<127 else '?'}') {match}")
    else:  # match
        sub_idx = state_idx + 0xC0
        b_sub = bd.decode_bit(table[sub_idx])
        table[sub_idx] = update_prob(table[sub_idx], b_sub)
        
        if b_sub == 0:  # short match
            length = bd.decode_tree(table, 0x332, 7)
            match_len = length + 3
        else:  # long match
            length = 0
            for i in range(5):
                p = table[(state_idx << 4) + 0xCC + i]
                b = bd.decode_bit(p)
                table[(state_idx << 4) + 0xCC + i] = update_prob(p, b)
                length = (length << 1) | b
                if b == 0:
                    break
            match_len = length + 3
        
        # distance
        slot_ctx = min(match_len - 3, 3)
        slot_base = 0x1B0 + slot_ctx * 64
        slot = 0
        for i in range(6):
            p = table[slot_base + i]
            b = bd.decode_bit(p)
            table[slot_base + i] = update_prob(p, b)
            slot = (slot << 1) | b
            if b == 0:
                break
        if slot < 4:
            dist = slot + 1
        else:
            extra = (slot >> 1) - 1
            dist = ((2 + (slot & 1)) << extra) + 1
            for i in range(extra):
                p = table[slot_base + 6 + i]
                b = bd.decode_bit(p)
                table[slot_base + 6 + i] = update_prob(p, b)
                dist = (dist << 1) | b
        
        block_cnt += 1
        print(f"Sym {sym_num}: MATCH len={match_len} dist={dist}")
        # We can't produce the match bytes without a window, just record
        for i in range(match_len):
            output.append(0xFF)  # placeholder

print(f"\nFirst {len(output)} bytes of output: {output[:20].hex()}")
print(f"Expected first 20 bytes:           {expected[:20].hex()}")
