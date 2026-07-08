import struct, os

WORK = r"C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump"
aes = open(os.path.join(WORK, "intermediate", "01_aes_output.bin"), 'rb').read()

PROB_INIT = 0x400; PROB_MAX = 0x800; PROB_SHIFT = 5; RANGE_BITS = 11; RENORM_THRESH = 0x1000000

def update_prob(prob, bit):
    if bit == 0: prob += (PROB_MAX - prob) >> PROB_SHIFT
    else: prob -= prob >> PROB_SHIFT
    return prob & 0xFFFF

def parse_lmf_header(data):
    flags = bytearray(5)
    flags[0], flags[1], flags[2] = data[4], data[5], data[6]
    flags[3] = data[7] ^ 5
    flags[4] = data[8]
    encoded = struct.unpack_from('<I', data, 0x0A)[0]
    decompressed_size = encoded ^ 0x3EA
    buf = bytearray(data)
    for i in range(min(decompressed_size, 16)):
        buf[0x0E + i] ^= 0xEC
    return decompressed_size, bytes(flags), bytes(buf[0x0E:])

decomp_size, flags, comp_data = parse_lmf_header(aes)

class BitDecoder:
    def __init__(self, data):
        self.data = data; self.pos = 5; self.end = len(data)
        self.high = 0xFFFFFFFF; self.low = 0
    def init_from_ctx(self, seed):
        self.high = 0xFFFFFFFF; self.low = seed & 0xFFFFFFFF
    def renorm(self):
        while self.high < RENORM_THRESH:
            self.high = (self.high << 8) & 0xFFFFFFFF
            if self.pos < self.end:
                self.low = ((self.low << 8) | self.data[self.pos]) & 0xFFFFFFFF; self.pos += 1
            else: self.low = (self.low << 8) & 0xFFFFFFFF
    def decode_bit(self, prob):
        self.renorm()
        mid = ((self.high >> RANGE_BITS) * prob) & 0xFFFFFFFF
        if self.low < mid: self.high = mid; return 0
        else: self.low = (self.low - mid) & 0xFFFFFFFF; self.high = (self.high - mid) & 0xFFFFFFFF; return 1
    def decode_tree(self, tbl, base_idx, max_idx):
        idx = 1
        while idx <= max_idx:
            p = tbl[base_idx + idx]; bit = self.decode_bit(p)
            tbl[base_idx + idx] = update_prob(p, bit)
            idx = (idx << 1) | bit
        return idx & 0xFF

exponent = flags[0]; window_shift = exponent // 9; remainder_9 = exponent % 9
prob_shift = (window_shift * 0xCCCCCCCD) >> 34
field_04 = window_shift - prob_shift * 5; field_00 = remainder_9
table_entries = (0x300 << (field_04 + field_00)) + 0x736
mask = (1 << prob_shift) - 1

# Test with different literal tree base offsets
for lit_shift in [0, 5, 6, 7, 8]:
    table = [PROB_INIT] * table_entries
    bd = BitDecoder(comp_data)
    seed = comp_data[:5]; ctx_seed = (seed[1]<<24)|(seed[2]<<16)|(seed[3]<<8)|seed[4]
    bd.init_from_ctx(ctx_seed)
    state_idx = 0; block_cnt = 0
    output = bytearray()
    
    # Prev byte for context-based tree selection
    prev_byte = 0
    
    for sym_num in range(16):
        p = table[(state_idx << 4) + (block_cnt & mask)]
        bit = bd.decode_bit(p)
        table[(state_idx << 4) + (block_cnt & mask)] = update_prob(p, bit)
        
        if bit == 0:
            if lit_shift == 0:
                tree_base = 0x736  # fixed
            else:
                tree_base = 0x736 + (prev_byte >> (8 - lit_shift)) * 256
            val = bd.decode_tree(table, tree_base, 0xFF)
            output.append(val)
            prev_byte = val
            state_idx = val & 0xF
            block_cnt += 1
        else:
            # match - skip
            sub_idx = state_idx + 0xC0
            b_sub = bd.decode_bit(table[sub_idx])
            table[sub_idx] = update_prob(table[sub_idx], b_sub)
            if b_sub == 0:
                length = bd.decode_tree(table, 0x332, 7) + 3
            else:
                length = 0
                for i in range(5):
                    pp = table[(state_idx << 4) + 0xCC + i]
                    bb = bd.decode_bit(pp)
                    table[(state_idx << 4) + 0xCC + i] = update_prob(pp, bb)
                    length = (length << 1) | bb
                    if bb == 0: break
                length += 3
            slot_ctx = min(length - 3, 3)
            slot_base = 0x1B0 + slot_ctx * 64
            slot = 0
            for i in range(6):
                pp = table[slot_base + i]
                bb = bd.decode_bit(pp)
                table[slot_base + i] = update_prob(pp, bb)
                slot = (slot << 1) | bb
                if bb == 0: break
            if slot < 4: dist = slot + 1
            else:
                extra = (slot >> 1) - 1
                dist = ((2 + (slot & 1)) << extra) + 1
                for i in range(extra):
                    pp = table[slot_base + 6 + i]
                    bb = bd.decode_bit(pp)
                    table[slot_base + 6 + i] = update_prob(pp, bb)
                    dist = (dist << 1) | bb
            block_cnt += 1
            # generate match bytes using window (but we don't have window here)
            for i in range(length):
                output.append(0xFF)
    
    expected = bytes([0x1B, 0x4C, 0x75, 0x61, 0x53, 0x00, 0x01, 0x04, 0x08, 0x04, 0x08, 0x00, 0x19, 0x93, 0x0D, 0x0A])
    match = sum(1 for a,b in zip(output[:16], expected) if a==b)
    print(f"lit_shift={lit_shift}: output={output[:16].hex()} matches={match}/16")
