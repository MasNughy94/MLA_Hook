"""
Build the complete MLA relational database (SQLite).
Creates schema, imports all parsed entities, builds indexes.
"""
import os, json, sqlite3, hashlib, time, sys
from collections import defaultdict

DB_PATH = r'C:\Users\NGEONG\Videos\MLA\PROJECT\cache\mla_database.db'
DEC_BATCH = r'C:\Users\NGEONG\Videos\MLA\PROJECT\decrypted\dec_batch'
HDR_SIZE = 69

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def create_schema(conn):
    """Create the complete database schema."""
    cur = conn.executescript("""
        -- Version tracking
        CREATE TABLE IF NOT EXISTS version_imports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version_id TEXT NOT NULL UNIQUE,
            version_label TEXT,
            import_date TEXT NOT NULL DEFAULT (datetime('now')),
            source_path TEXT,
            file_count INTEGER DEFAULT 0,
            entry_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            checksum TEXT,
            notes TEXT
        );

        -- Entity types (static catalog)
        CREATE TABLE IF NOT EXISTS entity_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            short_name TEXT,
            full_type TEXT,
            description TEXT,
            source_file TEXT,
            entry_count INTEGER DEFAULT 0,
            max_fields INTEGER DEFAULT 0,
            top_tag TEXT,
            created_in_import INTEGER REFERENCES version_imports(id)
        );

        -- Master entity table (all entries across all files)
        CREATE TABLE IF NOT EXISTS entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stable_id TEXT NOT NULL UNIQUE,
            entity_type_id INTEGER REFERENCES entity_types(id),
            import_id INTEGER REFERENCES version_imports(id),
            source_file TEXT NOT NULL,
            entry_index INTEGER NOT NULL,
            field_count INTEGER DEFAULT 0,
            tag_count INTEGER DEFAULT 0,
            tag_signature TEXT,
            hash_hex TEXT,
            UNIQUE(source_file, entry_index, import_id)
        );

        -- Entity field values (tag-value pairs)
        CREATE TABLE IF NOT EXISTS entity_fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_id INTEGER REFERENCES entities(id) ON DELETE CASCADE,
            import_id INTEGER REFERENCES version_imports(id),
            tag INTEGER NOT NULL,
            tag_hex TEXT NOT NULL,
            tag_char TEXT,
            value INTEGER NOT NULL,
            field_index INTEGER NOT NULL,
            role TEXT DEFAULT 'unknown',
            UNIQUE(entity_id, field_index, import_id)
        );

        -- Known game IDs (HeroID, SkillID, etc.)
        CREATE TABLE IF NOT EXISTS known_ids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            id_value INTEGER NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER REFERENCES entities(id),
            label TEXT,
            confidence REAL DEFAULT 0.5,
            source_tag INTEGER,
            source_file TEXT,
            import_id INTEGER REFERENCES version_imports(id),
            UNIQUE(id_value, entity_type, import_id)
        );

        -- Entity relationships
        CREATE TABLE IF NOT EXISTS relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_entity_id INTEGER REFERENCES entities(id),
            target_entity_id INTEGER REFERENCES entities(id),
            source_entity_type TEXT,
            target_entity_type TEXT,
            relationship_type TEXT NOT NULL,
            confidence REAL DEFAULT 0.5,
            evidence TEXT,
            shared_tags TEXT,
            discovered_in_import INTEGER REFERENCES version_imports(id)
        );

        -- Version diffs
        CREATE TABLE IF NOT EXISTS version_diffs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            base_import_id INTEGER REFERENCES version_imports(id),
            compare_import_id INTEGER REFERENCES version_imports(id),
            diff_type TEXT NOT NULL,
            entity_type TEXT,
            entity_stable_id TEXT,
            field_tag INTEGER,
            old_value INTEGER,
            new_value INTEGER,
            notes TEXT,
            detected_at TEXT DEFAULT (datetime('now'))
        );

        -- Tag definitions per file
        CREATE TABLE IF NOT EXISTS tag_definitions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag_hex TEXT NOT NULL,
            source_file TEXT,
            role TEXT DEFAULT 'unknown',
            value_range_min INTEGER DEFAULT 0,
            value_range_max INTEGER DEFAULT 65535,
            unique_values INTEGER DEFAULT 0,
            presence_count INTEGER DEFAULT 0,
            description TEXT,
            UNIQUE(tag_hex, source_file)
        );

        -- Search indexes
        CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type_id);
        CREATE INDEX IF NOT EXISTS idx_entities_stable ON entities(stable_id);
        CREATE INDEX IF NOT EXISTS idx_entities_source ON entities(source_file, entry_index);
        CREATE INDEX IF NOT EXISTS idx_fields_entity ON entity_fields(entity_id);
        CREATE INDEX IF NOT EXISTS idx_fields_tag ON entity_fields(tag_hex);
        CREATE INDEX IF NOT EXISTS idx_fields_value ON entity_fields(value);
        CREATE INDEX IF NOT EXISTS idx_known_ids_val ON known_ids(id_value);
        CREATE INDEX IF NOT EXISTS idx_known_ids_type ON known_ids(entity_type);
        CREATE INDEX IF NOT EXISTS idx_relationships_src ON relationships(source_entity_id);
        CREATE INDEX IF NOT EXISTS idx_relationships_tgt ON relationships(target_entity_id);
        CREATE INDEX IF NOT EXISTS idx_diffs_base ON version_diffs(base_import_id);
        CREATE INDEX IF NOT EXISTS idx_diffs_comp ON version_diffs(compare_import_id);
    """)
    conn.commit()
    print("Schema created successfully")

def stable_id(source_file, entry_index, import_id=1):
    """Generate a stable, deterministic entity ID."""
    raw = f"{source_file}:{entry_index}:v{import_id}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"MLA-{import_id}-{h}"

def parse_entries(path):
    """Parse entries from a decrypted Roo file."""
    with open(path, 'rb') as f:
        data = f.read()
    body = data[HDR_SIZE:]
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        if tag != 0:
            val = v1 | (v2 << 8)
            records.append({'offset': i, 'tag': tag, 'val': val})
    entries = []
    if records:
        gap = 30
        cur = [records[0]]
        for r in records[1:]:
            if r['offset'] - cur[-1]['offset'] > gap:
                entries.append(cur)
                cur = [r]
            else:
                cur.append(r)
        if cur:
            entries.append(cur)
    return entries

# ============================================================
# ENTITY TYPE DEFINITIONS
# ============================================================
ENTITY_TYPES = [
    {'name': 'EquipDB', 'short': 'equip', 'type': 'Equipment_Item_Database',
     'file': '1c7efa501c5305fb7062cdcbf148c4a9.mt.dec',
     'desc': 'Equipment and item definitions'},
    {'name': 'SkillDB', 'short': 'skill', 'type': 'Skill_Ability_Database',
     'file': '17f4dd5419fdea6aff836f46154d274a.mt.dec',
     'desc': 'Skill and ability definitions'},
    {'name': 'HeroStatDB', 'short': 'hero_stat', 'type': 'Hero_StatBlock_Database',
     'file': '12eb65e862c413254ae49d2eba76eea2.mt.dec',
     'desc': 'Hero stat blocks and attribute scaling'},
    {'name': 'HeroRosterDB', 'short': 'hero_roster', 'type': 'Hero_Roster_Database',
     'file': '07b5cc5ea4a8d86273be8170720a4587.mt.dec',
     'desc': 'Hero registry with class/faction assignments'},
    {'name': 'StageDB', 'short': 'stage', 'type': 'Stage_Mission_Database',
     'file': '1c1ac35710f3a4276a942a776e911a85.mt.dec',
     'desc': 'Campaign stage and mission definitions'},
    {'name': 'MonsterDB', 'short': 'monster', 'type': 'Monster_NPC_Database',
     'file': '1c4ed1eebdb4b8af5c2658f4151aa529.mt.dec',
     'desc': 'Monster and NPC definitions'},
    {'name': 'AnimDB', 'short': 'anim', 'type': 'Animation_Visual_Database',
     'file': '18f286461b12e92d9e16b27c07854a7c.mt.dec',
     'desc': 'Animation and visual effect references'},
    {'name': 'MasterDB', 'short': 'master', 'type': 'Master_Index_Registry',
     'file': '0217cbdae530696836de83aa3c162e1a.mt.dec',
     'desc': 'Central entity registry'},
    {'name': 'ConfigDB', 'short': 'config', 'type': 'System_Config_Database',
     'file': '1a4fb9f36cd34d0eb0ca22000e54f8a5.mt.dec',
     'desc': 'System configuration parameters'},
    {'name': 'AchieveDB', 'short': 'achieve', 'type': 'Achievement_Progress_Database',
     'file': '0e3bbac67f12505f7dfe45d4e6aba1ea.mt.dec',
     'desc': 'Achievement definitions and progress tracking'},
]

# Known game IDs (manually identified)
KNOWN_GAME_IDS = [
    (2111, 'Hero', 'HeroRosterDB', 'Hero 2111', 0.85, 0x09),
    (2112, 'Hero', 'HeroStatDB', 'Hero 2112', 0.80, 0x83),
    (5970, 'Hero', 'EquipDB', 'Hero 5970', 0.70, 0x55),
    (3019, 'Entity', 'HeroRosterDB', 'Entity 3019', 0.50, 0x7A),
    (6089, 'Entity', 'HeroRosterDB', 'Entity 6089', 0.50, 0xB7),
    (4303, 'Entity', 'HeroStatDB', 'Entity 4303', 0.50, 0xF4),
    (5380, 'Entity', 'MasterDB', 'Entity 5380', 0.50, 0xFA),
    (4076, 'Entity', 'MasterDB', 'Entity 4076', 0.50, 0xEC),
    (6854, 'Entity', 'MasterDB', 'Entity 6854', 0.50, 0xB5),
]

def import_all(conn, import_id=1):
    """Import all parsed entities into the database."""
    cur = conn.cursor()
    
    # 1. Populate entity types
    type_map = {}
    for et in ENTITY_TYPES:
        cur.execute("""
            INSERT OR IGNORE INTO entity_types (name, short_name, full_type, description, source_file)
            VALUES (?, ?, ?, ?, ?)
        """, (et['name'], et['short'], et['type'], et['desc'], et['file']))
        cur.execute("SELECT id FROM entity_types WHERE name = ?", (et['name'],))
        type_map[et['name']] = cur.fetchone()[0]
    
    total_entities = 0
    
    # 2. Process each entity type file
    for et in ENTITY_TYPES:
        fname = et['file']
        path = os.path.join(DEC_BATCH, fname)
        if not os.path.exists(path):
            print(f"  SKIP {fname} (not found)")
            continue
        
        print(f"  Importing {et['name']} ({fname})...")
        entries = parse_entries(path)
        type_id = type_map[et['name']]
        
        for eidx, entry in enumerate(entries):
            # Generate stable ID
            sid = stable_id(fname, eidx, import_id)
            
            # Compute tag signature
            tags = sorted(set(r['tag'] for r in entry))
            sig = ' '.join(f"0x{t:02x}" for t in tags)
            sig_hash = hashlib.md5(sig.encode()).hexdigest()[:12]
            
            # Insert entity
            cur.execute("""
                INSERT OR IGNORE INTO entities 
                (stable_id, entity_type_id, import_id, source_file, entry_index, 
                 field_count, tag_count, tag_signature, hash_hex)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (sid, type_id, import_id, fname, eidx,
                  len(entry), len(tags), sig, sig_hash))
            
            cur.execute("SELECT id FROM entities WHERE stable_id = ?", (sid,))
            entity_db_id = cur.fetchone()[0]
            
            # Insert field values
            for fi, r in enumerate(entry):
                tc = chr(r['tag']) if 32 <= r['tag'] < 127 else None
                role = 'unknown'
                if 50000 <= r['val'] <= 65535:
                    role = 'cross_file_ref'
                elif 2000 <= r['val'] <= 9999:
                    role = 'entity_id'
                elif 1 <= r['val'] <= 8 and r['val'] != 0:
                    role = 'enum'
                elif r['val'] == 0:
                    role = 'zero_flag'
                
                cur.execute("""
                    INSERT OR IGNORE INTO entity_fields
                    (entity_id, import_id, tag, tag_hex, tag_char, value, field_index, role)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (entity_db_id, import_id, r['tag'], f"0x{r['tag']:02x}",
                      tc, r['val'], fi, role))
            
            total_entities += 1
        
        # Update entity type stats
        cur.execute("""
            UPDATE entity_types SET entry_count = ?, max_fields = (
                SELECT MAX(field_count) FROM entities WHERE entity_type_id = ?
            ) WHERE id = ?
        """, (len(entries), type_id, type_id))
        
        print(f"    -> {len(entries)} entries, {total_entities} total so far")
    
    # 3. Import known game IDs
    for id_val, ent_type, src_file, label, conf, tag in KNOWN_GAME_IDS:
        # Find entity that has this ID
        cur.execute("""
            SELECT e.id FROM entities e
            JOIN entity_fields f ON e.id = f.entity_id
            WHERE e.source_file = ? AND f.value = ? AND f.tag = ?
            LIMIT 1
        """, (src_file, id_val, tag))
        row = cur.fetchone()
        entity_db_id = row[0] if row else None
        
        cur.execute("""
            INSERT OR IGNORE INTO known_ids 
            (id_value, entity_type, entity_id, label, confidence, source_tag, source_file, import_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (id_val, ent_type, entity_db_id, label, conf, tag, src_file, import_id))
    
    # 4. Build relationships
    print("\n  Building relationships...")
    # Find entities sharing the same 4-digit ID values (indicates they are the same game object)
    cur.execute("""
        SELECT f1.entity_id, f2.entity_id, f1.value, e1.entity_type_id, e2.entity_type_id
        FROM entity_fields f1
        JOIN entity_fields f2 ON f1.value = f2.value AND f1.entity_id < f2.entity_id
        JOIN entities e1 ON f1.entity_id = e1.id
        JOIN entities e2 ON f2.entity_id = e2.id
        WHERE f1.role = 'entity_id' AND f2.role = 'entity_id'
          AND f1.import_id = ? AND f2.import_id = ?
        GROUP BY f1.entity_id, f2.entity_id
    """, (import_id, import_id))
    
    rel_count = 0
    for src_id, tgt_id, val, src_type, tgt_type in cur.fetchall():
        et1 = ENTITY_TYPES[src_type - 1]['name'] if 0 < src_type <= len(ENTITY_TYPES) else 'Unknown'
        et2 = ENTITY_TYPES[tgt_type - 1]['name'] if 0 < tgt_type <= len(ENTITY_TYPES) else 'Unknown'
        
        cur.execute("""
            INSERT OR IGNORE INTO relationships
            (source_entity_id, target_entity_id, source_entity_type, target_entity_type,
             relationship_type, confidence, evidence, shared_tags, discovered_in_import)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (src_id, tgt_id, et1, et2,
              'same_entity', 0.7, f"Shared ID value {val}", f"value={val}", import_id))
        rel_count += 1
    
    print(f"    -> {rel_count} relationships built")
    
    conn.commit()
    print(f"\n  Total entities imported: {total_entities}")
    print(f"  Total relationships: {rel_count}")
    return total_entities

def main():
    print("="*60)
    print("MLA DATABASE BUILDER")
    print("="*60)
    
    # Remove existing DB if present
    if os.path.exists(DB_PATH):
        print(f"Removing existing database: {DB_PATH}")
        os.remove(DB_PATH)
    
    conn = get_conn()
    
    # Create schema
    print("\n[1/3] Creating schema...")
    create_schema(conn)
    
    # Register import
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO version_imports (version_id, version_label, source_path, status)
        VALUES (?, ?, ?, ?)
    """, ('MLA_v1.0', 'Initial Release (reconstructed)', DEC_BATCH, 'running'))
    import_id = cur.lastrowid
    conn.commit()
    
    # Import all data
    print("\n[2/3] Importing entity data...")
    total = import_all(conn, import_id)
    
    # Update import metadata
    cur.execute("""
        UPDATE version_imports 
        SET file_count = (SELECT COUNT(DISTINCT source_file) FROM entities WHERE import_id = ?),
            entry_count = ?,
            status = 'complete'
        WHERE id = ?
    """, (import_id, total, import_id))
    conn.commit()
    
    # Verify
    print("\n[3/3] Verifying database...")
    cur.execute("SELECT COUNT(*) FROM entities")
    e_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM entity_fields")
    f_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM known_ids")
    k_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM relationships")
    r_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM entity_types")
    t_count = cur.fetchone()[0]
    
    conn.close()
    
    print(f"\n{'='*60}")
    print(f"DATABASE BUILD COMPLETE")
    print(f"{'='*60}")
    print(f"  Database: {DB_PATH}")
    print(f"  Tables: 9")
    print(f"  Entity types: {t_count}")
    print(f"  Total entities: {e_count}")
    print(f"  Total field values: {f_count}")
    print(f"  Known game IDs: {k_count}")
    print(f"  Relationships: {r_count}")
    print(f"  File size: {os.path.getsize(DB_PATH) / 1024:.0f} KB")
    print(f"{'='*60}")

if __name__ == '__main__':
    main()
