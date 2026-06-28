"""
Roo binary format parser.
Understands the format as a sparse-tagged dictionary.
Each record: TAG [value_bytes...] followed by 0x00 padding to next record.
"""

import struct, os, json
from collections import defaultdict

class RooParser:
    def __init__(self, data, name=''):
        self.data = data
        self.name = name
        self.HDR_SZ = 69
        self.header = data[:self.HDR_SZ]
        self.body = data[self.HDR_SZ:]
        self.fields = []
        self.tag_values = {}
        self._parse()
    
    def _parse(self):
        """Parse body into tag-value records."""
        i = 0
        while i < len(self.body):
            if self.body[i] == 0:
                i += 1
                continue
            tag = self.body[i]
            i += 1
            
            # Collect value bytes until next zero or EOF
            value_start = i
            while i < len(self.body) and self.body[i] != 0:
                i += 1
            value_bytes = self.body[value_start:i]
            
            self.fields.append((tag, value_bytes))
            
            if tag not in self.tag_values:
                self.tag_values[tag] = []
            if len(self.tag_values[tag]) < 5:
                self.tag_values[tag].append(value_bytes)
    
    def analyze_tag(self, tag):
        """Get all records for a given tag."""
        return [(offset, vb) for offset, (t, vb) in enumerate(self.fields) if t == tag]
    
    def dump_json(self, output_path):
        """Export parsed data as JSON."""
        # By default, convert to list of records
        records = []
        for tag, value_bytes in self.fields:
            val_str = value_bytes.hex()
            # Try to decode as various types
            val = None
            if len(value_bytes) == 0:
                val = None
            elif len(value_bytes) == 1:
                val = value_bytes[0]
            elif len(value_bytes) == 2:
                val = struct.unpack_from('<H', value_bytes)[0]
            elif len(value_bytes) == 4:
                val = struct.unpack_from('<I', value_bytes)[0]
            elif len(value_bytes) == 8:
                val = struct.unpack_from('<Q', value_bytes)[0]
            else:
                val = value_bytes.hex()
            
            records.append({
                'tag': tag,
                'tag_hex': f'0x{tag:02x}',
                'tag_char': chr(tag) if 32 <= tag < 127 else None,
                'value_len': len(value_bytes),
                'value': val,
                'value_raw': value_bytes.hex() if len(value_bytes) > 0 else None
            })
        
        result = {
            'name': self.name,
            'file_size': len(self.data),
            'body_size': len(self.body),
            'num_fields': len(self.fields),
            'fields': records,
            # Also try to group by tag
            'tag_groups': {}
        }
        
        # Group records by tag
        for tag in sorted(set(r['tag'] for r in records)):
            tag_records = [r for r in records if r['tag'] == tag]
            values = [r['value'] for r in tag_records]
            result['tag_groups'][f'0x{tag:02x}'] = {
                'count': len(tag_records),
                'char': chr(tag) if 32 <= tag < 127 else None,
                'values': values
            }
        
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2)
        print(f'Exported {len(records)} records to {output_path}')
        return result
    
    def print_summary(self):
        """Print a summary of the parsed data."""
        nz_count = sum(1 for b in self.body if b != 0)
        print(f'=== {self.name} ===')
        print(f'  File size: {len(self.data)} bytes')
        print(f'  Body size: {len(self.body)} bytes ({len(self.body)/len(self.data)*100:.1f}%)')
        print(f'  Non-zero bytes in body: {nz_count} ({nz_count/len(self.body)*100:.1f}%)')
        print(f'  Records found: {len(self.fields)}')
        
        # Count unique tags
        unique_tags = len(set(t for t, _ in self.fields))
        print(f'  Unique tags: {unique_tags}')
        
        # Top tags by frequency
        tag_counts = defaultdict(int)
        for tag, _ in self.fields:
            tag_counts[tag] += 1
        
        print(f'\n  Top 20 tags by frequency:')
        for tag, count in sorted(tag_counts.items(), key=lambda x: -x[1])[:20]:
            ch = chr(tag) if 32 <= tag < 127 else '.'
            print(f'    0x{tag:02x} ({ch}): {count:4d} occurrences')
        
        # Value length distribution
        print(f'\n  Value byte lengths:')
        len_counts = defaultdict(int)
        for _, vb in self.fields:
            len_counts[len(vb)] += 1
        for l, c in sorted(len_counts.items()):
            print(f'    len={l}: {c} fields')
    
    def try_struct_sections(self):
        """Try to identify section boundaries in the body."""
        # Look at runs of non-zero bytes (clusters of activity)
        i = 0
        clusters = []
        while i < len(self.body):
            if self.body[i] == 0:
                i += 1
                continue
            start = i
            nz_count = 0
            while i < len(self.body) and self.body[i] != 0:
                # Count consecutive nz bytes
                nz_count += 1
                i += 1
            zero_run = 0
            while i < len(self.body) and self.body[i] == 0:
                zero_run += 1
                i += 1
            clusters.append((start, nz_count, zero_run))
        
        print(f'\n  Data clusters (offset, non-zero bytes, trailing zeros):')
        significant = [c for c in clusters if c[1] > 0]
        for start, nz, zeros in significant[:30]:
            print(f'    body+0x{start:04x}: {nz:3d} nz bytes, {zeros:3d} zeros after')
        if len(significant) > 30:
            print(f'    ... and {len(significant)-30} more clusters')

def analyze_all():
    samples_dir = r'C:\Users\NGEONG\AppData\Local\Temp\opencode'
    files = [
        '0000488d2f64199aca0cc7d54e7d11c0.mt.dec',
        '008fea3143557d628ac845a13a254e8a.mt.dec',
    ]
    
    for fname in files:
        fpath = os.path.join(samples_dir, fname)
        with open(fpath, 'rb') as f:
            data = f.read()
        
        parser = RooParser(data, fname)
        parser.print_summary()
        parser.try_struct_sections()
        print()
        
        # Export JSON
        json_path = fpath + '.json'
        parser.dump_json(json_path)
        print()

if __name__ == '__main__':
    analyze_all()
