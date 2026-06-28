"""
Deep structural analysis of the .mt binary body.
"""

import struct
from collections import Counter

# Read all three files
f1 = open(r'C:\Users\NGEONG\AppData\Local\Temp\opencode\0000488d2f64199aca0cc7d54e7d11c0.mt.dec', 'rb').read()
f2 = open(r'C:\Users\NGEONG\AppData\Local\Temp\opencode\00378c64fbd63011a81dccef6bf6e2bd.mt.dec', 'rb').read()
f3 = open(r'C:\Users\NGEONG\AppData\Local\Temp\opencode\008fea3143557d628ac845a13a254e8a.mt.dec', 'rb').read()

bodies = {
    'f1': f1[69:],
    'f2': f2[69:],
    'f3': f3[69:],
}

# 1. Byte value distribution
print('=== Byte Value Distribution (Body Only, ignores zeros) ===')
for name, body in bodies.items():
    non_zero = [b for b in body if b != 0]
    c = Counter(non_zero)
    top = c.most_common(20)
    print('{} ({} non-zero bytes):'.format(name, len(non_zero)))
    for val, cnt in top:
        print('  0x{:02x} ({}): {} times, {}% of non-zero'.format(val, val, cnt, 100*cnt/len(non_zero)))

print()

# 2. Zero density
print('=== Zero Density ===')
for name, body in bodies.items():
    zeros = body.count(0)
    print('{}: {} zeros out of {} ({}%)'.format(name, zeros, len(body), 100*zeros/len(body)))

print()

# 3. Byte pair frequencies in 2-byte runs
print('=== Byte Pair Analysis ===')
for name, body in bodies.items():
    pairs = {}
    for i in range(0, len(body)-1):
        if body[i] != 0 and body[i+1] != 0:
            pair = (body[i], body[i+1])
            pairs[pair] = pairs.get(pair, 0) + 1
    top = sorted(pairs.items(), key=lambda x: -x[1])[:15]
    print('{}:'.format(name))
    for (a, b), cnt in top:
        print('  [{:02x} {:02x}] : {} times'.format(a, b, cnt))

print()

# 4. Repeated byte analysis (XX XX in 2-byte runs)
print('=== Repeated Byte Pairs (XX XX) ===')
for name, body in bodies.items():
    same_pairs = []
    for i in range(0, len(body)-1):
        if body[i] != 0 and body[i] == body[i+1]:
            same_pairs.append(body[i])
    c = Counter(same_pairs)
    print('{}: {} total same-byte pairs'.format(name, len(same_pairs)))
    for val, cnt in c.most_common(10):
        print('  0x{:02x}: {} times'.format(val, cnt))

print()

# 5. Common triple pattern analysis (XX YY YY - tag + repeated value)
print('=== Tag-Value-Repeat (XX YY YY) ===')
for name, body in bodies.items():
    triples = []
    for i in range(0, len(body)-2):
        if body[i] != 0 and body[i+1] != 0 and body[i+1] == body[i+2]:
            triples.append((body[i], body[i+1]))
    c = Counter(triples)
    print('{}: {} total tag-repeat triples'.format(name, len(triples)))
    for (tag, val), cnt in c.most_common(10):
        print('  tag={:02x} val={:02x}: {} times'.format(tag, val, cnt))

print()

# 6. Analyze the FIRST DIFFERENCES between f1 and f2
# Find where they differ, and classify the type of difference
print('=== Cross-file Differences (f1 vs f2) ===')
min_len = min(len(bodies['f1']), len(bodies['f2']))
diffs = []
for i in range(min_len):
    if bodies['f1'][i] != bodies['f2'][i]:
        diffs.append(i)

print('Total differing bytes: {}'.format(len(diffs)))

# Find contiguous differing segments
diff_segments = []
if diffs:
    start = diffs[0]
    end = diffs[0]
    for d in diffs[1:]:
        if d == end + 1:
            end = d
        else:
            diff_segments.append((start, end, end-start+1))
            start = d
            end = d
    diff_segments.append((start, end, end-start+1))

print('Number of diff segments: {}'.format(len(diff_segments)))
seg_lens = [s[2] for s in diff_segments]
len_counter = Counter(seg_lens)
print('Diff segment length distribution:')
for length, cnt in len_counter.most_common():
    print('  {} byte(s): {} segments'.format(length, cnt))

# Show pattern: what do the differing bytes look like in context?
print('\nFirst 20 diff segments with context:')
seg_idx = 0
for start, end, length in diff_segments[:20]:
    offset = start + 69  # absolute offset
    ctx_before = f1[max(0,start-3):start]
    ctx_after1 = f1[end+1:end+4]
    diff_bytes_f1 = f1[start:end+1]
    diff_bytes_f2 = f2[start:end+1]
    ctx_str = ' '.join('{:02x}'.format(b) if b != 0 else '..' for b in ctx_before) if ctx_before else ''
    ctx_str += ' [{}] '.format(' '.join('{:02x}'.format(b) for b in diff_bytes_f1))
    ctx_str += 'vs f2: [{}] '.format(' '.join('{:02x}'.format(b) for b in diff_bytes_f2))
    ctx_str += ' '.join('{:02x}'.format(b) if b != 0 else '..' for b in ctx_after1) if ctx_after1 else ''
    print('  seg#{}: abs_offset={}, len={}  {}'.format(seg_idx, offset, length, ctx_str))
    seg_idx += 1
