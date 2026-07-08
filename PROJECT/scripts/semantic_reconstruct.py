"""
Semantic Reconstruction Engine v2 - Efficient batch approach.
Menggunakan entity_schemas.json sebagai source of truth untuk semantic mapping.
"""
import os, sys, json, sqlite3
from collections import defaultdict

DB_PATH = r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db'
SEMANTIC_PATH = r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\semantic'
IMPORT_ID = 1

ENTITY_NAMES = [
    'EquipDB', 'SkillDB', 'HeroStatDB', 'HeroRosterDB',
    'StageDB', 'MonsterDB', 'AnimDB', 'MasterDB', 'ConfigDB', 'AchieveDB',
]

# Game-specific field name mappings for high-confidence tags
# Format: {entity_type: {tag_hex: (field_name, field_type, confidence, description)}}
FIELD_NAMES = {
    'HeroRosterDB': {
        '0x17': ('hero_id', 'primary_key', 0.9, 'Primary hero identifier'),
        '0x09': ('hero_id_alt1', 'primary_key', 0.7, 'Alternate hero ID'),
        '0x0d': ('hero_id_alt2', 'primary_key', 0.7, 'Alternate hero ID'),
        '0x04': ('hero_class', 'enum', 0.8, 'Hero class (Mage/Fighter/Tank/Assassin/Marksman/Support)'),
        '0x05': ('faction', 'enum', 0.7, 'Faction alignment'),
        '0x06': ('rarity', 'enum', 0.7, 'Hero rarity tier'),
        '0x07': ('star_quality', 'enum', 0.65, 'Star/evolution quality'),
        '0x08': ('element', 'enum', 0.65, 'Element type'),
        '0x0e': ('awaken_level', 'enum', 0.5, 'Awakening level'),
    },
    'HeroStatDB': {
        '0x20': ('hero_stat_id', 'primary_key', 0.85, 'Hero stat entry ID'),
        '0x46': ('hero_stat_ref', 'primary_key', 0.75, 'Hero stat reference ID'),
        '0x0a': ('hero_stat_alt', 'primary_key', 0.65, 'Alternative stat ID'),
        '0x84': ('base_hp', 'stat', 0.7, 'Base HP value'),
        '0x85': ('base_atk', 'stat', 0.7, 'Base attack value'),
        '0x86': ('base_def', 'stat', 0.7, 'Base defense value'),
        '0x87': ('base_speed', 'stat', 0.6, 'Base speed value'),
        '0x88': ('base_crit', 'stat', 0.6, 'Base critical rate'),
        '0x89': ('base_crit_dmg', 'stat', 0.6, 'Base critical damage'),
        '0x8a': ('base_accuracy', 'stat', 0.6, 'Base accuracy'),
        '0x8b': ('base_evasion', 'stat', 0.6, 'Base evasion'),
        '0x8c': ('base_lifesteal', 'stat', 0.5, 'Base lifesteal'),
    },
    'SkillDB': {
        '0x25': ('skill_id', 'primary_key', 0.9, 'Primary skill identifier'),
        '0x19': ('skill_ref_1', 'foreign_key', 0.65, 'Skill reference/category'),
        '0x1a': ('skill_ref_2', 'foreign_key', 0.65, 'Skill reference/category'),
        '0xce': ('skill_link', 'foreign_key', 0.6, 'Linked skill'),
        '0xcf': ('passive_skill', 'foreign_key', 0.6, 'Passive skill reference'),
        '0xd0': ('awaken_skill', 'foreign_key', 0.6, 'Awaken skill reference'),
        '0xd1': ('ultimate_skill', 'foreign_key', 0.6, 'Ultimate skill reference'),
        '0xd2': ('special_skill', 'foreign_key', 0.55, 'Special skill reference'),
    },
    'EquipDB': {
        '0x0c': ('equip_id', 'primary_key', 0.85, 'Equipment ID'),
        '0x19': ('equip_category', 'category', 0.6, 'Equipment category'),
        '0x1e': ('equip_subtype', 'category', 0.6, 'Equipment subtype'),
        '0x14': ('equip_ref', 'foreign_key', 0.55, 'Equipment reference'),
        '0x1c': ('equip_class', 'category', 0.55, 'Equipment class'),
        '0x42': ('equip_slot', 'enum', 0.6, 'Equipment slot position'),
        '0x55': ('hero_binding', 'foreign_key', 0.6, 'Bound to hero'),
        '0xf1': ('item_type', 'enum', 0.75, 'Item type discriminator'),
    },
    'StageDB': {
        '0x11': ('stage_id', 'primary_key', 0.85, 'Stage identifier'),
        '0xde': ('stage_number', 'identifier', 0.6, 'Stage number'),
        '0xdf': ('stage_region', 'identifier', 0.6, 'Stage region'),
        '0xe0': ('stage_chapter', 'identifier', 0.6, 'Stage chapter'),
    },
    'MonsterDB': {
        '0x11': ('monster_id', 'primary_key', 0.8, 'Monster identifier'),
        '0x1c': ('monster_type', 'primary_key', 0.7, 'Monster type ID'),
        '0x45': ('monster_category', 'enum', 0.55, 'Monster category'),
    },
    'MasterDB': {
        '0x0a': ('master_id', 'primary_key', 0.8, 'Master entry ID'),
    },
    'AnimDB': {
        '0x0f': ('anim_id', 'primary_key', 0.7, 'Animation entry ID'),
    },
    'ConfigDB': {
        '0x01': ('config_key', 'primary_key', 0.7, 'Configuration key'),
    },
    'AchieveDB': {
        '0x17': ('achievement_id', 'primary_key', 0.7, 'Achievement identifier'),
    },
}

# Enum value mappings (from game knowledge)
ENUM_MAPS = {
    'HeroRosterDB': {
        '0x04': {1: 'Mage', 2: 'Fighter', 3: 'Tank', 4: 'Assassin', 5: 'Marksman', 6: 'Support'},
        '0x05': {1: 'Light', 2: 'Dark', 3: 'Wild', 4: 'Tech', 5: 'Elemental'},
        '0x06': {1: 'Common', 2: 'Uncommon', 3: 'Rare', 4: 'Epic', 5: 'Legendary', 6: 'Mythic'},
    },
}


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def setup_table(conn):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS semantic_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL,
            tag INTEGER NOT NULL,
            field_name TEXT NOT NULL,
            field_type TEXT DEFAULT 'unknown',
            value_mapping TEXT,
            confidence REAL DEFAULT 0.5,
            evidence TEXT,
            UNIQUE(entity_type, tag)
        )
    """)
    cur.execute("DELETE FROM semantic_mappings")
    conn.commit()
    print("[SETUP] semantic_mappings table ready")


def load_schemas():
    """Load entity schemas with field metadata."""
    with open(os.path.join(SEMANTIC_PATH, 'entity_schemas.json')) as f:
        data = json.load(f)
    return data.get('entities', {})


def get_bulk_stats(conn, et_name):
    """Get all tag stats in a single query per entity type."""
    cur = conn.cursor()
    cur.execute("""
        SELECT f.tag,
               COUNT(*) as cnt,
               COUNT(DISTINCT e.id) as entity_count,
               MIN(CASE WHEN f.value > 0 THEN f.value END) as min_nonzero,
               MAX(f.value) as max_v,
               COUNT(DISTINCT CASE WHEN f.value > 0 THEN f.value END) as uniq_nonzero,
               CAST(ROUND(AVG(CASE WHEN f.value > 0 THEN f.value END)) AS INTEGER) as avg_nonzero
        FROM entity_fields f
        JOIN entities e ON f.entity_id = e.id
        JOIN entity_types et ON e.entity_type_id = et.id
        WHERE et.name = ? AND e.import_id = ?
        GROUP BY f.tag
        ORDER BY f.tag
    """, (et_name, IMPORT_ID))
    return {r['tag']: dict(r) for r in cur.fetchall()}


def classify_from_stats(tag, stats, schema_field, enum_tags):
    """Classify a field using schema data + statistical analysis."""
    tag_hex = f'0x{tag:02x}'  # lowercase hex for JSON key matching
    cnt = stats['cnt']
    uniq = stats['uniq_nonzero'] or 0
    min_v = stats['min_nonzero'] or 0
    max_v = stats['max_v'] or 0
    
    evidence_parts = []
    confidence = 0.3
    field_type = 'unknown'
    
    # Use schema presence info if available
    schema_presence = schema_field.get('presence_global', 0) if schema_field else 0
    
    # Check if it's an enum tag
    is_enum = tag_hex in enum_tags
    
    # Rule 1: Very few unique nonzero values with small max -> enum
    if is_enum and max_v <= 100:
        evidence_parts.append(f"schema enum tag; values={enum_tags[tag_hex]}")
        return ('enum', 'enum', 0.65, '; '.join(evidence_parts))
    
    if is_enum:
        evidence_parts.append(f"schema enum tag; {len(enum_tags[tag_hex])} enum values")
        return ('enum', 'enum', 0.6, '; '.join(evidence_parts))
    
    # Rule 2: Low unique values in small range -> category/enum even if not in schema
    if max_v <= 50 and uniq <= 10 and uniq > 0:
        evidence_parts.append(f"small value range [{min_v}-{max_v}], uniq={uniq}")
        return (f'category', 'category', 0.5, '; '.join(evidence_parts))
    
    # Rule 3: 4-digit values (1000-9999) -> potential ID
    if 1000 <= min_v <= max_v <= 9999 and uniq >= 5:
        evidence_parts.append(f"entity ID range [{min_v}-{max_v}], uniq={uniq}")
        return ('identifier', 'identifier', 0.55, '; '.join(evidence_parts))
    
    # Rule 4: Medium unique values with wide range -> stat or reference
    if uniq >= 20 and max_v > 1000:
        evidence_parts.append(f"stat/ref range [{min_v}-{max_v}], uniq={uniq}")
        if schema_presence and schema_presence < 50:
            return (f'sparse_value', 'value', 0.35, '; '.join(evidence_parts))
        return (f'value', 'value', 0.4, '; '.join(evidence_parts))
    
    # Rule 5: High presence, low unique -> important flag
    if schema_presence > 80 and uniq <= 2:
        evidence_parts.append(f"high-presence flag ({schema_presence}%), uniq={uniq}")
        return ('flag', 'boolean', 0.6, '; '.join(evidence_parts))
    
    # Rule 6: Very high presence -> core field
    if schema_presence > 90:
        evidence_parts.append(f"core field (present in {schema_presence}%)")
        return ('core_field', 'core', 0.45, '; '.join(evidence_parts))
    
    evidence_parts.append(f"cnt={cnt} range=[{min_v}-{max_v}] uniq={uniq}")
    return (f'unknown', 'unknown', 0.2, '; '.join(evidence_parts))


def build_mappings(conn, schemas):
    """Build semantic mappings from schema data + database stats."""
    all_mappings = []
    
    for et_name in ENTITY_NAMES:
        print(f"\n--- {et_name} ---")
        schema_et = schemas.get(et_name, {})
        schema_fields = schema_et.get('fields', {})
        enum_tags = schema_et.get('enum_tags', {})
        pk_candidates = schema_et.get('primary_key_candidates', [])
        pk_tags = {p['tag'] for p in pk_candidates}  # hex format like '0x17'
        
        stats = get_bulk_stats(conn, et_name)
        if not stats:
            print(f"  No data found")
            continue
        
        game_names = FIELD_NAMES.get(et_name, {})
        enum_map = ENUM_MAPS.get(et_name, {})
        
        for tag, st in sorted(stats.items()):
            tag_hex = f'0x{tag:02x}'
            schema_field = schema_fields.get(tag_hex, {})
            
            # Priority 1: Game-specific known field names
            if tag_hex in game_names:
                fn, ft, conf, desc = game_names[tag_hex]
                field_name = fn
                field_type = ft
                confidence = conf
                
                # Add enum value mapping if available
                value_mapping = None
                if tag_hex in enum_map:
                    value_mapping = json.dumps(enum_map[tag_hex])
                
                evidence = f"Game-known: {desc}; " if desc else ""
                evidence += f"cnt={st['cnt']} uniq={st['uniq_nonzero']} range=[{st['min_nonzero']}-{st['max_v']}]"
                
                all_mappings.append({
                    'entity_type': et_name,
                    'tag': tag,
                    'field_name': field_name,
                    'field_type': field_type,
                    'value_mapping': value_mapping,
                    'confidence': confidence,
                    'evidence': evidence,
                })
                print(f"  0x{tag:02X} -> {field_name:30s} [{field_type:15s}] conf={confidence:.2f} (known)")
                continue
            
            # Priority 2: PK candidate from schema
            if tag_hex in pk_tags:
                base_name = f'{et_name.lower().replace("db","")}_id'
                evidence = f"PK candidate; cnt={st['cnt']} uniq={st['uniq_nonzero']} range=[{st['min_nonzero']}-{st['max_v']}]"
                all_mappings.append({
                    'entity_type': et_name,
                    'tag': tag,
                    'field_name': base_name,
                    'field_type': 'primary_key',
                    'value_mapping': None,
                    'confidence': 0.65,
                    'evidence': evidence,
                })
                print(f"  0x{tag:02X} -> {base_name:30s} [primary_key    ] conf=0.65 (PK cand)")
                continue
            
            # Priority 3: Statistical classification
            field_name, field_type, confidence, evidence = classify_from_stats(
                tag, st, schema_field, enum_tags
            )
            
            # Add schema description if available
            if isinstance(schema_field, dict) and schema_field.get('tag'):
                desc = f"presence={schema_field.get('presence_global', '?')}%"
                evidence = f"{desc}; {evidence}"
            
            final_name = f'{field_name}_{tag}' if field_type in ('value', 'unknown') else field_name
            
            all_mappings.append({
                'entity_type': et_name,
                'tag': tag,
                'field_name': final_name,
                'field_type': field_type,
                'value_mapping': None,
                'confidence': round(confidence, 2),
                'evidence': evidence,
            })
            print(f"  0x{tag:02X} -> {final_name:30s} [{field_type:15s}] conf={confidence:.2f}")
    
    return all_mappings


def save_mappings(conn, mappings):
    cur = conn.cursor()
    conn.execute("BEGIN")
    cur.executemany("""
        INSERT OR REPLACE INTO semantic_mappings
        (entity_type, tag, field_name, field_type, value_mapping, confidence, evidence)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, [(
        m['entity_type'], m['tag'], m['field_name'],
        m['field_type'], m.get('value_mapping'), m['confidence'], m['evidence']
    ) for m in mappings])
    conn.commit()
    
    # Summary
    by_type = defaultdict(lambda: {'high': 0, 'medium': 0, 'low': 0})
    for m in mappings:
        if m['confidence'] >= 0.7:
            by_type[m['entity_type']]['high'] += 1
        elif m['confidence'] >= 0.4:
            by_type[m['entity_type']]['medium'] += 1
        else:
            by_type[m['entity_type']]['low'] += 1
    
    print(f"\n{'='*60}")
    print(f"  SEMANTIC MAPPING SUMMARY")
    print(f"{'='*60}")
    print(f"  {'Entity Type':20s} {'High':>6s} {'Med':>6s} {'Low':>6s} {'Total':>6s}")
    for et, counts in sorted(by_type.items()):
        total = counts['high'] + counts['medium'] + counts['low']
        print(f"  {et:20s} {counts['high']:>6d} {counts['medium']:>6d} {counts['low']:>6d} {total:>6d}")


def main():
    conn = get_conn()
    print("="*60)
    print("  MLA SEMANTIC RECONSTRUCTION v2")
    print("="*60)
    
    setup_table(conn)
    schemas = load_schemas()
    print(f"[LOAD] entity_schemas.json: {len(schemas)} entity types")
    
    mappings = build_mappings(conn, schemas)
    save_mappings(conn, mappings)
    
    conn.close()
    print(f"\n[DONE] {len(mappings)} mappings saved")


if __name__ == '__main__':
    main()
