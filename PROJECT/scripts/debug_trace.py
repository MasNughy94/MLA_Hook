#!/usr/bin/env python3
"""Debug trace for the first 30 decode bits."""
import struct, sys, os
os.chdir(r'C:\Users\NGEONG\AppData\Local\Temp\opencode')
sys.path.insert(0, '.')

bit_trace = []

# Monkey-patch BitDecoder to trace
import mt_decoder as dec
orig_decode_bit = dec.BitDecoder.decode_bit
orig_decode_tree = dec.BitDecoder.decode_tree
orig_init = dec.BitDecoder.init_from_ctx

def traced_init(self, ctx_seed):
    orig_init(self, ctx_seed)
    bit_trace.append(('INIT', self.high, self.low, ctx_seed))

def traced_decode_bit(self, prob):
    result = orig_decode_bit(self, prob)
    if len(bit_trace) < 35:
        bit_trace.append(('BIT', result, prob, self.high, self.low))
    return result

def traced_decode_tree(self, tbl, base_idx, max_idx):
    if len(bit_trace) < 35:
        bit_trace.append(('TREE_START', base_idx, max_idx))
    result = orig_decode_tree(self, tbl, base_idx, max_idx)
    if len(bit_trace) < 35:
        bit_trace.append(('TREE_END', result))
    return result

dec.BitDecoder.init_from_ctx = traced_init
dec.BitDecoder.decode_bit = traced_decode_bit
dec.BitDecoder.decode_tree = traced_decode_tree

result = dec.decrypt_mt_file(r'C:\Users\NGEONG\Videos\VSCODE\mt_dump\sample.mt')

for i, entry in enumerate(bit_trace):
    print(f'{i}: {entry}')
