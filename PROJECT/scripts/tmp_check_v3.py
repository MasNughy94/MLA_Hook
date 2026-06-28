import json

s = json.load(open(r'semantic_v3/semantic_db_v3.json'))
et = s['entity_types']

for name, data in et.items():
    print(f"\n=== {name} ===")
    if isinstance(data, dict):
        print(f"  Keys: {list(data.keys())}")
        if 'fields' in data:
            f = data['fields']
            print(f"  Fields type: {type(f).__name__}, length: {len(f)}")
            if isinstance(f, list):
                print(f"  First 3 fields:")
                for fi in f[:3]:
                    print(f"    {json.dumps(fi)}")
            elif isinstance(f, dict):
                print(f"  First 3 field keys: {list(f.keys())[:3]}")
                for k in list(f.keys())[:3]:
                    print(f"    {k}: {json.dumps(f[k])}")
        if 'tables' in data:
            print(f"  Tables: {list(data['tables'].keys())}")
        if 'entries' in data:
            entry_keys = list(data['entries'].keys())
            print(f"  Entry keys: {entry_keys[:5]}")
            if entry_keys:
                ek = entry_keys[0]
                entry = data['entries'][ek]
                print(f"  First entry type: {type(entry).__name__}")
                if isinstance(entry, dict):
                    print(f"  First entry keys: {list(entry.keys())[:10]}")

print()
print("All entity types that use 'fields':")
for name, data in et.items():
    if 'fields' in data:
        f = data['fields']
        if isinstance(f, list):
            print(f"  {name}: list of {len(f)} fields")
        elif isinstance(f, dict):
            print(f"  {name}: dict of {len(f)} fields")
