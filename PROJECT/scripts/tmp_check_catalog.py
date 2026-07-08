import json
with open(r'C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\analysis\roo_file_catalog.json') as f:
    cat = json.load(f)
# Find hero-related files
hero_files = [(h, info) for h, info in cat.items() if info.get('classification','') in ('MASTER_HERO_DB','MASTER_GAME_DB','GAME_SYSTEM_DB')]
for h, info in hero_files:
    print(f'{h}: entries={info["num_entries"]} tags={info["tag_count"]} cls={info.get("classification","?")}')
print('---')
# Find files by entry count
for h, info in sorted(cat.items(), key=lambda x: -x[1]['num_entries'])[:10]:
    print(f'{h}: entries={info["num_entries"]} tags={info["tag_count"]} cls={info.get("classification","?")}')
