"""Merge hero_db into the main semantic_db_v3.json."""
import json

# Load main DB
with open('semantic/semantic_db_v3.json', 'r') as f:
    main_db = json.load(f)

# Load hero DB
with open('semantic/hero_db_schema.json', 'r') as f:
    hero_db = json.load(f)

# Add hero_db entity type
main_db['entity_types']['hero_db'] = hero_db['entity_types']['hero_db']

# Update metadata to reflect new total
main_db['metadata']['description'] = (
    "Complete semantic reconstruction of Roo binary format data "
    "(includes hero_db schema from 55-file cluster analysis)"
)

# Write back
with open('semantic/semantic_db_v3.json', 'w') as f:
    json.dump(main_db, f, indent=2)

# Verify
d = json.load(open('semantic/semantic_db_v3.json'))
print(f"Entity types now: {list(d['entity_types'].keys())}")
print(f"Total: {len(d['entity_types'])} entity types")
