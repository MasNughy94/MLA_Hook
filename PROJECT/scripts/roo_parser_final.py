"""
Roo Binary Format Parser
=========================
Parses decompressed .mt files (Roo format) into human-readable JSON.

Format:
- 69-byte shared header (template, identical across all files)
- Body: sequence of 3-byte records [tag, value1, value2]
- tag=0x00: template/empty record (82% of body)
- tag!=0x00: data override record
- V1:V2 encode values as u16 (little-endian)
- Override records cluster into entries separated by gaps
- No entry count or fixed entry size - entries are variable-length

Usage:
    python roo_parser.py <input.mt.dec> [output.json]
"""

import os, sys
import json
from collections import defaultdict
from itertools import groupby

HDR_SIZE = 69

class RooBinaryFormat:
    """Parse the Roo binary format from decompressed data."""
    
    def __init__(self, data, source=''):
        self.data = data
        self.source = source
        self.header = data[:HDR_SIZE]
        self.body = data[HDR_SIZE:]
        self.records = []         # list of (offset, tag, v1, v2)
        self.override_records = []  # records with tag != 0
        self.template_records = []  # records with tag == 0 but v1/v2 != 0
        self.empty_records = []     # records with all zeros
        self.entries = []           # clustered groups of override records
        self._parse()
    
    def _parse(self):
        """Parse body into 3-byte records."""
        body = self.body
        for i in range(0, len(body) - 2, 3):
            tag, v1, v2 = body[i], body[i+1], body[i+2]
            rec = (i, tag, v1, v2)
            self.records.append(rec)
            if tag == 0 and v1 == 0 and v2 == 0:
                self.empty_records.append(rec)
            elif tag == 0:
                self.template_records.append(rec)
            else:
                self.override_records.append(rec)
    
    def cluster_entries(self, gap_threshold=30):
        """Group override records into entries based on gap threshold (in bytes)."""
        if not self.override_records:
            return []
        
        sorted_overrides = sorted(self.override_records, key=lambda x: x[0])
        
        entries = []
        current_entry = [sorted_overrides[0]]
        
        for rec in sorted_overrides[1:]:
            gap = rec[0] - current_entry[-1][0]
            if gap > gap_threshold:
                entries.append(current_entry)
                current_entry = [rec]
            else:
                current_entry.append(rec)
        
        if current_entry:
            entries.append(current_entry)
        
        self.entries = entries
        return entries
    
    def decode_value(self, v1, v2):
        """Decode V1:V2 as appropriate type.
        
        Returns a dict with value interpretations.
        """
        u16 = v1 | (v2 << 8)
        result = {
            'v1': v1,
            'v2': v2,
            'u16': u16,
            'u16_signed': u16 if u16 < 0x8000 else u16 - 0x10000,
        }
        
        # Try interpreting as two separate bytes
        if v1 != 0 and v2 != 0:
            result['bytes'] = f'0x{v1:02x} 0x{v2:02x}'
        
        # Try ASCII interpretation
        if 32 <= v1 < 127:
            result['v1_char'] = chr(v1)
        if 32 <= v2 < 127:
            result['v2_char'] = chr(v2)
        
        return result
    
    def to_json_dict(self, gap_threshold=30):
        """Convert entire file to a JSON-serializable dict."""
        self.cluster_entries(gap_threshold)
        
        # Build record list
        result = {
            'format': 'Roo',
            'source': self.source,
            'file_size': len(self.data),
            'header_size': HDR_SIZE,
            'body_size': len(self.body),
            'num_records': len(self.records),
            'num_records_total': len(self.records),
            'num_empty': len(self.empty_records),
            'num_template': len(self.template_records),
            'num_override': len(self.override_records),
            'header_bytes': self.header.hex(),
            'header_ascii': ''.join(chr(b) if 32 <= b < 127 else '.' for b in self.header),
        }
        
        # Tag statistics
        tag_counts = defaultdict(int)
        tag_values = defaultdict(list)
        for offset, tag, v1, v2 in self.override_records:
            tag_counts[tag] += 1
            tag_values[tag].append(self.decode_value(v1, v2))
        
        result['tags'] = {}
        for tag in sorted(tag_counts.keys()):
            ch = chr(tag) if 32 <= tag < 127 else '.'
            vals = tag_values[tag]
            u16_values = [v['u16'] for v in vals]
            result['tags'][f'0x{tag:02x}'] = {
                'char': ch,
                'count': tag_counts[tag],
                'min_value': min(u16_values),
                'max_value': max(u16_values),
                'unique_values': len(set(u16_values)),
                'values': [v for v in vals[:20]]  # first 20 values
            }
        
        # Entries
        result['entries'] = []
        for e_idx, entry in enumerate(self.entries):
            entry_records = []
            for offset, tag, v1, v2 in entry:
                rec = {
                    'record_index': offset // 3,
                    'body_offset': offset,
                    'tag': tag,
                    'tag_hex': f'0x{tag:02x}',
                    'tag_char': chr(tag) if 32 <= tag < 127 else None,
                    'value': self.decode_value(v1, v2),
                }
                entry_records.append(rec)
            
            result['entries'].append({
                'entry_index': e_idx,
                'num_records': len(entry_records),
                'body_offset_start': entry[0][0],
                'body_offset_end': entry[-1][0] + 3,
                'records': entry_records,
            })
        
        # Template defaults (shared skeleton across files of same type)
        result['template_defaults'] = []
        for offset, tag, v1, v2 in self.template_records:
            result['template_defaults'].append({
                'record_index': offset // 3,
                'body_offset': offset,
                'v1': v1,
                'v2': v2,
                'value': self.decode_value(v1, v2),
            })
        
        return result
    
    def export_json(self, output_path, gap_threshold=30, pretty=True):
        """Export parsed data as JSON file."""
        data = self.to_json_dict(gap_threshold)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2 if pretty else None, ensure_ascii=False)
        print(f"Exported {len(data['entries'])} entries, {data['num_override']} override records to {output_path}")
        return data


def decompress_all_mt():
    """Decompress all .mt files in the assets directory (placeholder)."""
    # This would use the LMF decompressor
    pass


def main_batch(samples_dir, output_dir):
    """Process all decompressed .mt files."""
    os.makedirs(output_dir, exist_ok=True)
    
    for fname in os.listdir(samples_dir):
        if fname.endswith('.mt.dec'):
            fpath = os.path.join(samples_dir, fname)
            with open(fpath, 'rb') as f:
                data = f.read()
            
            parser = RooBinaryFormat(data, fname)
            
            # Export JSON
            json_path = os.path.join(output_dir, fname + '.json')
            parser.export_json(json_path)
            
            # Print summary
            print(f"\n{fname}:")
            print(f"  Body: {len(parser.body)} bytes = {len(parser.records)} records")
            print(f"  Tags: {len(parser.override_records)} override, {len(parser.template_records)} template, {len(parser.empty_records)} empty")
            print(f"  Entries: {len(parser.entries)} (gap threshold 30)")
            
            # Top 10 tags
            tag_counts = defaultdict(int)
            for _, tag, _, _ in parser.override_records:
                tag_counts[tag] += 1
            print(f"  Top 5 tags: ", end='')
            for tag, cnt in sorted(tag_counts.items(), key=lambda x: -x[1])[:5]:
                ch = chr(tag) if 32 <= tag < 127 else '.'
                print(f"0x{tag:02x}('{ch}'):{cnt}", end=' ')
            print()


def analyze_perfect_row_size(body):
    """Try to find the entry size by looking for repeating patterns."""
    # Convert body to numpy-style analysis
    # Look for the most common record-to-record difference
    nz_positions = [i for i, b in enumerate(body) if b != 0]
    if len(nz_positions) < 10:
        return None
    
    gaps = [nz_positions[j+1] - nz_positions[j] for j in range(len(nz_positions)-1)]
    from collections import Counter
    gap_freq = Counter(gaps)
    return gap_freq.most_common(5)


if __name__ == '__main__':
    samples_dir = r'C:\Users\NGEONG\AppData\Local\Temp\opencode'
    output_dir = os.path.join(samples_dir, 'json_output')
    
    main_batch(samples_dir, output_dir)
