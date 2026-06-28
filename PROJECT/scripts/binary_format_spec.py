"""
Binary format specification for decompressed MLA .mt files.
Based on structural analysis of 3 different .mt files.

Header (69 bytes, identical across all files of type "Roo"):
  [0-3]   4 bytes: Magic       = 1B 4C 6D 00
  [4-5]   2 bytes: Flags/Ver   = 00 00
  [6-9]   4 bytes: Type        = "Roo\0"
  [10-11] 2 bytes: Reserved    = 00 00
  [12-20] 9 bytes: Zero/padding
  [21-22] 2 bytes: Value       = D1 D1 (uint16 = 53713, constant)
  [23-36] 14 bytes: Zeros/padding
  [37]    1 byte:  Value       = D1 (constant)
  [38-42] 5 bytes: Zeros/padding  
  [43-44] 2 bytes: Zero
  [45]    1 byte:  Zero
  [46-47] 2 bytes: Zero
  [48-54] 7 bytes: Zeros
  [55-56] 2 bytes: Value       = D1 00 (uint16 = 209)
  [57]    1 byte:  Zero
  [58-59] 2 bytes: Zero
  [60-68] 9 bytes: Zeros

Body (starting at offset 69):
  Sparse tagged serialization format.
  Fields are stored as non-zero runs separated by zero bytes.
  
  Observation: ~70% of bytes are identical across different .mt files of same type,
  indicating a TEMPLATE structure where most field positions have the same values
  and only ~30% vary as instance data.
"""

import struct
from collections import Counter

class MTBinaryReader:
    def __init__(self, data):
        self.data = data
        self.size = len(data)
        
    def read_header(self):
        """Parse the 69-byte header."""
        h = {}
        h['magic'] = self.data[0:4]
        h['flags'] = struct.unpack('<H', self.data[4:6])[0]
        h['type'] = self.data[6:9].decode('ascii', errors='replace')
        h['reserved'] = self.data[10:12]
        h['field_d1d1'] = struct.unpack('<H', self.data[21:23])[0]
        h['field_d1'] = self.data[37]
        h['field_d1_00'] = struct.unpack('<H', self.data[55:57])[0]
        return h
    
    def get_body(self):
        """Return body starting at offset 69."""
        return self.data[69:]
    
    def extract_runs(self, body=None):
        """Extract all non-zero runs with their offsets."""
        if body is None:
            body = self.get_body()
        runs = []
        i = 0
        while i < len(body):
            if body[i] != 0:
                start = i
                run = []
                while i < len(body) and body[i] != 0:
                    run.append(body[i])
                    i += 1
                runs.append((start + 69, list(run)))
            else:
                i += 1
        return runs
    
    def parse_body_as_fields(self):
        """Parse body as a flat field sequence."""
        body = self.get_body()
        runs = self.extract_runs(body)
        
        fields = []
        for offset, run in runs:
            fields.append({
                'offset': offset,
                'data': bytes(run),
                'len': len(run),
                'values': [struct.unpack('<H', bytes(run[i:i+2]))[0] if i+1 < len(run) else run[i] 
                          for i in range(0, len(run))]
            })
        return fields
    
    def run_type_summary(self, run):
        """Classify the type of a non-zero run."""
        if len(run) == 0:
            return 'empty'
        if len(run) == 1:
            return 'single_byte'
        if len(run) == 2:
            if run[0] == run[1]:
                return 'byte_pair_same'
            else:
                return 'byte_pair_diff'
        if len(run) == 3:
            if run[0] == run[1] == run[2]:
                return 'triple_same'
            elif run[1] == run[2]:
                return 'tag_value_dup'
            else:
                return 'triple_diff'
        # longer runs
        return 'multi({})'.format(len(run))


def analyze_file(path, name):
    f = open(path, 'rb').read()
    reader = MTBinaryReader(f)
    header = reader.read_header()
    
    print('=== {} ==='.format(name))
    print('File size: {} bytes'.format(len(f)))
    print('Header:')
    for k, v in header.items():
        print('  {}: {}'.format(k, v.hex() if isinstance(v, bytes) else v if isinstance(v, str) else hex(v)))
    
    body = reader.get_body()
    runs = reader.extract_runs(body)
    
    print('Body: {} bytes, {} non-zero runs'.format(len(body), len(runs)))
    
    if runs:
        type_counts = Counter(reader.run_type_summary(r) for _, r in runs)
        print('Run type distribution:')
        for t, c in type_counts.most_common():
            print('  {}: {}'.format(t, c))
    
    print()

# Analyze all three files
analyze_file(r'C:\Users\NGEONG\AppData\Local\Temp\opencode\0000488d2f64199aca0cc7d54e7d11c0.mt.dec', 'File 1')
analyze_file(r'C:\Users\NGEONG\AppData\Local\Temp\opencode\00378c64fbd63011a81dccef6bf6e2bd.mt.dec', 'File 2')
analyze_file(r'C:\Users\NGEONG\AppData\Local\Temp\opencode\008fea3143557d628ac845a13a254e8a.mt.dec', 'File 3')
