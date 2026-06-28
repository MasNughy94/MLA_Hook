"""Build Entity Relationship model from 55-file cluster analysis."""
import json, os
from collections import defaultdict

# Load cluster analysis  
with open('analysis/55file_cluster_analysis.json') as f:
    cluster_data = json.load(f)

# Load corpus summary for additional file info
with open('analysis/corpus_summary.json') as f:
    corpus = json.load(f)
corpus_by_file = {}

for e in corpus:
    fname = e.get('file', '')
    if fname:
        corpus_by_file[fname] = e

# Load the detailed hero_db_schema_analysis for tag-level analysis
with open('analysis/hero_db_schema_analysis.json') as f:
    tag_analysis = json.load(f)

fa = tag_analysis.get('field_analysis', {})

# Entity type definitions based on cluster evidence
ENTITY_DEFS = {
    '1c7efa501c5305fb7062cdcbf148c4a9.mt.dec': {
        'name': 'EquipDB',
        'type': 'Equipment_Item_Database',
        'desc': 'Master equipment and item definitions. Contains all game items, equipment sets, and their properties.',
        'top_tag_meaning': 'Item type discriminator',
    },
    '17f4dd5419fdea6aff836f46154d274a.mt.dec': {
        'name': 'SkillDB',
        'type': 'Skill_Ability_Database',
        'desc': 'Complete skill and ability definitions. Contains active skills, passives, ultimates, and talent tree nodes.',
        'top_tag_meaning': 'Skill type discriminator',
    },
    '12eb65e862c413254ae49d2eba76eea2.mt.dec': {
        'name': 'HeroStatDB',
        'type': 'Hero_StatBlock_Database',
        'desc': 'Hero stat blocks with base stats, growth rates, and attribute scaling per hero level.',
        'top_tag_meaning': 'Stat type discriminator',
    },
    '07b5cc5ea4a8d86273be8170720a4587.mt.dec': {
        'name': 'HeroRosterDB',
        'type': 'Hero_Roster_Database',
        'desc': 'Hero registry with class/faction assignments, evolution paths, and basic attributes.',
        'top_tag_meaning': 'Hero type discriminator',
    },
    '1c1ac35710f3a4276a942a776e911a85.mt.dec': {
        'name': 'StageDB',
        'type': 'Stage_Mission_Database',
        'desc': 'Campaign stage, mission, and level definitions including enemy spawns and rewards.',
        'top_tag_meaning': 'Stage type discriminator',
    },
    '1c4ed1eebdb4b8af5c2658f4151aa529.mt.dec': {
        'name': 'MonsterDB',
        'type': 'Monster_NPC_Database',
        'desc': 'Monster and NPC definitions including enemy stats, AI behavior, and spawn groups.',
        'top_tag_meaning': 'Monster type discriminator',
    },
    '18f286461b12e92d9e16b27c07854a7c.mt.dec': {
        'name': 'AnimDB',
        'type': 'Animation_Visual_Database',
        'desc': 'Animation, visual effect, and skeletal mesh references for heroes and monsters.',
        'top_tag_meaning': 'Animation type discriminator',
    },
    '0217cbdae530696836de83aa3c162e1a.mt.dec': {
        'name': 'MasterDB',
        'type': 'Master_Index_Registry',
        'desc': 'Central entity registry. Maps every game object to its attributes across all other databases in the cluster.',
        'top_tag_meaning': 'Entity type discriminator',
    },
    '1a4fb9f36cd34d0eb0ca22000e54f8a5.mt.dec': {
        'name': 'ConfigDB',
        'type': 'System_Config_Database',
        'desc': 'Game system configuration parameters, constants, and global settings.',
        'top_tag_meaning': 'Config parameter type',
    },
    '0e3bbac67f12505f7dfe45d4e6aba1ea.mt.dec': {
        'name': 'AchieveDB',
        'type': 'Achievement_Progress_Database',
        'desc': 'Achievement definitions, progress tracking, and reward configuration.',
        'top_tag_meaning': 'Achievement type discriminator',
    },
}

# Relationships to detect
# For each file, analyze its ID tags and enum tags to find cross-references
print("=== ENTITY DEFINITIONS ===")
for fhash, info in sorted(cluster_data['files'].items(), key=lambda x: -x[1]['entry_count']):
    edef = ENTITY_DEFS.get(fhash, {'name': 'Unknown', 'type': 'Unknown'})
    fi = info
    print(f"\n{edef['name']:12s} ({fi['entry_count']:5d} entries, {fi['max_fields']:3d} max fields)")
    print(f"  Type: {edef['type']}")
    print(f"  Top tag: {fi['top_tag']} ({edef.get('top_tag_meaning', 'Unknown')})")
    
    # Primary key candidates
    if fi['primary_key_candidates']:
        pk_tags = [pk['tag'] for pk in fi['primary_key_candidates'][:3]]
        print(f"  PK candidates: {', '.join(pk_tags)}")
    
    # Enum tags (classification fields)
    if fi['enum_tags']:
        enum_sample = list(fi['enum_tags'].keys())[:5]
        print(f"  Enum tags: {', '.join(enum_sample)}")
    
    # Large ref tags (foreign key candidates)
    if fi['large_ref_tags']:
        lr_tags = list(fi['large_ref_tags'].keys())[:5]
        print(f"  FK candidates (large refs): {', '.join(lr_tags)}")

# Build cross-file reference map
print("\n\n=== CROSS-FILE REFERENCE ANALYSIS ===")
# Map: which tags serve as IDs in each file
file_id_tags = {}
for fhash, fi in cluster_data['files'].items():
    pk_tags = set()
    for pk in fi['primary_key_candidates']:
        pk_tags.add(pk['tag'])
    file_id_tags[fhash] = pk_tags

# Check for shared enum values between files (potential FK relationships)
print("\nShared enum values indicate FK relationships:")
for fhash1 in cluster_data['files']:
    for fhash2 in cluster_data['files']:
        if fhash1 >= fhash2:
            continue
        fi1 = cluster_data['files'][fhash1]
        fi2 = cluster_data['files'][fhash2]
        
        # Check shared enum tags
        enums1 = set(fi1.get('enum_tags', {}).keys())
        enums2 = set(fi2.get('enum_tags', {}).keys())
        shared_enum_tags = enums1 & enums2
        if shared_enum_tags:
            for tag in shared_enum_tags:
                v1 = set(fi1['enum_tags'][tag])
                v2 = set(fi2['enum_tags'][tag])
                shared_vals = v1 & v2
                if shared_vals:
                    e1 = ENTITY_DEFS.get(fhash1, {}).get('name', fhash1[:8])
                    e2 = ENTITY_DEFS.get(fhash2, {}).get('name', fhash2[:8])
                    print(f"  {e1} <-> {e2}: tag {tag}, shared enum values: {sorted(shared_vals)}")

# Generate ERD
print("\n\n=== ENTITY RELATIONSHIP DIAGRAM ===")
parent_child = {
    'MasterDB': ['HeroRosterDB', 'SkillDB', 'EquipDB', 'StageDB', 'MonsterDB', 'AnimDB', 'ConfigDB', 'AchieveDB', 'HeroStatDB'],
    'HeroRosterDB': ['HeroStatDB', 'AnimDB'],
    'SkillDB': ['HeroRosterDB'],
    'EquipDB': ['HeroRosterDB'],
    'StageDB': ['MonsterDB'],
}

print("\nMasterDB (Central Registry)")
print("  |-- references --|")
for child in parent_child['MasterDB']:
    print(f"  |     {child}")
print()

for parent, children in parent_child.items():
    if parent == 'MasterDB':
        continue
    for child in children:
        print(f"{parent} --{'>'} {child}")

# Save schema definitions
schema_output = {
    'entities': {},
    'relationships': []
}

for fhash, fi in sorted(cluster_data['files'].items(), key=lambda x: -x[1]['entry_count']):
    edef = ENTITY_DEFS.get(fhash, {'name': fhash[:16], 'type': 'Unknown'})
    
    # Build field schema from tag analysis
    fields = {}
    for tag_str, tag_info in sorted(fa.items(), key=lambda x: int(x[0])):
        tag_num = int(tag_str)
        tag_hex = f"0x{tag_num:02x}"
        
        # These are from the Master DB's perspective - need file-specific mapping
        field_def = {
            'tag': tag_hex,
            'presence_global': tag_info.get('presence', 0),
            'unique_vals_global': tag_info.get('unique_vals', 0),
            'range_global': [tag_info.get('min', 0), tag_info.get('max', 0)],
        }
        fields[tag_hex] = field_def
    
    schema_output['entities'][edef['name']] = {
        'file': fhash,
        'name': edef['name'],
        'type': edef['type'],
        'description': edef['desc'],
        'entry_count': fi['entry_count'],
        'max_fields': fi['max_fields'],
        'avg_fields': fi['avg_fields'],
        'single_tag_entries': fi['single_tag_entries'],
        'multi_tag_entries': fi['multi_tag_entries'],
        'top_tag': fi['top_tag'],
        'top_tag_meaning': edef.get('top_tag_meaning', ''),
        'primary_key_candidates': fi['primary_key_candidates'],
        'enum_tags': fi['enum_tags'],
        'fields': fields,
    }

with open('semantic/entity_schemas.json', 'w') as f:
    json.dump(schema_output, f, indent=2)

print(f"\nSaved entity schemas to semantic/entity_schemas.json")
