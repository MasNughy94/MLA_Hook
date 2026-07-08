import json
with open(r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\semantic\hero_db_schema.json', 'r') as f:
    data = json.load(f)
# Search for tags 0x1b, 0x20, 0x70 explanations
if 'tags' in data:
    for tag_key, tag_info in data['tags'].items():
        if tag_key.lower() in ['0x1b', '0x20', '0x70', '0x6f', '0x50', '0x51']:
            print(f'Tag {tag_key}: {json.dumps(tag_info, indent=2)[:500]}')
            print()
