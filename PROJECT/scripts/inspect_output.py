"""
Inspect the JSON output from the Roo parser.
"""
import json

with open(r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\json_output\0000488d2f64199aca0cc7d54e7d11c0.mt.dec.json', 'r') as f:
    d = json.load(f)

print('File metadata:')
for k in ['format','source','file_size','body_size','num_records_total','num_override','num_template','num_empty']:
    print(f'  {k}: {d[k]}')

print(f'\nEntries: {len(d["entries"])}')
print(f'Templates: {len(d["template_defaults"])}')
print(f'Tags: {len(d["tags"])}')

print('\nFirst 5 entries:')
for e in d['entries'][:5]:
    tags = [(r['tag_hex'], r['tag_char'], r['value']['u16']) for r in e['records']]
    print(f'  Entry {e["entry_index"]}: {e["num_records"]} records, offset={e["body_offset_start"]}')
    for tag_hex, tag_char, val in tags:
        print(f'    {tag_hex} ({tag_char}): {val}')

print('\nFirst 10 template defaults:')
for t in d['template_defaults'][:10]:
    print(f'  Record {t["record_index"]}: v1=0x{t["v1"]:02x} v2=0x{t["v2"]:02x} u16={t["value"]["u16"]}')

print(f'\nTop 10 tags:')
for tag_hex, info in sorted(d['tags'].items(), key=lambda x: -x[1]['count'])[:10]:
    print(f'  {tag_hex} ({info["char"]}): {info["count"]} occ, values {info["min_value"]}-{info["max_value"]}')
