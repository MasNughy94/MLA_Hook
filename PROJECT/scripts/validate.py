"""
Validation Suite for MLA Database.
Menjalankan seluruh validasi untuk memastikan database stabil.
"""
import os, sys, json, sqlite3
from collections import defaultdict

DB_PATH = r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db'
PASS = 0
FAIL = 0
ERRORS = []

def check(condition, message):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {message}")
    else:
        FAIL += 1
        print(f"  [FAIL] {message}")
        ERRORS.append(message)

def section(name):
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")

def test_relationship_validity():
    section("1. Relationship Validity")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # No same_entity across different types
    cur.execute("""
        SELECT COUNT(*) FROM relationships
        WHERE relationship_type = 'same_entity'
          AND source_entity_type != target_entity_type
    """)
    bad_same = cur.fetchone()[0]
    check(bad_same == 0, f"same_entity across different types: {bad_same}")
    
    # All relationships have valid entity references
    cur.execute("""
        SELECT COUNT(*) FROM relationships r
        LEFT JOIN entities s ON r.source_entity_id = s.id
        LEFT JOIN entities t ON r.target_entity_id = t.id
        WHERE s.id IS NULL OR t.id IS NULL
    """)
    orphaned = cur.fetchone()[0]
    check(orphaned == 0, f"Orphaned relationship references: {orphaned}")
    
    # Relationship distribution makes sense
    cur.execute("""
        SELECT relationship_type, COUNT(*) as cnt
        FROM relationships
        GROUP BY relationship_type
        ORDER BY cnt DESC
    """)
    dist = {r[0]: r[1] for r in cur.fetchall()}
    for rtype, cnt in sorted(dist.items()):
        print(f"    {rtype}: {cnt:,}")
    
    conn.close()

def test_primary_key_validity():
    section("2. Primary Key Validity")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # PK candidate tags should carry values in 1000-9999 range PER ENTITY TYPE
    # Tags are file-specific: same tag means different things in different files
    pk_config = {
        'EquipDB':      [0x0C, 0x19, 0x1E], 'SkillDB':      [0x25, 0x19],
        'HeroRosterDB': [0x17, 0x09],        'HeroStatDB':   [0x20, 0x46],
        'StageDB':      [0x11, 0x71],        'MonsterDB':    [0x11, 0x1C],
        'MasterDB':     [0x27, 0x22],        'AchieveDB':    [0x10, 0xBF],
    }
    for et_name, tags in pk_config.items():
        for tag in tags:
            cur.execute("""
                SELECT MIN(f.value), MAX(f.value), COUNT(DISTINCT f.value)
                FROM entity_fields f
                JOIN entities e ON f.entity_id = e.id
                JOIN entity_types et ON e.entity_type_id = et.id
                WHERE f.tag = ? AND et.name = ? AND e.import_id = 1
            """, (tag, et_name))
            r = cur.fetchone()
            min_v, max_v, uniq = r
            in_range = (1000 <= min_v <= 9999) if min_v else True
            check(in_range, f"PK tag 0x{tag:02X} in {et_name}: range=[{min_v}-{max_v}] unique={uniq}")
    
    conn.close()

def test_foreign_key_validity():
    section("3. Foreign Key / Cross-Reference Validity")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # cross_file_ref should reference entities in different entity types
    cur.execute("""
        SELECT COUNT(*) FROM relationships
        WHERE relationship_type = 'cross_file_ref'
          AND source_entity_type = target_entity_type
    """)
    bad_cross = cur.fetchone()[0]
    check(bad_cross == 0, f"cross_file_ref between same types: {bad_cross}")
    
    # cross_file_ref count should be > 0
    cur.execute("SELECT COUNT(*) FROM relationships WHERE relationship_type = 'cross_file_ref'")
    cross_cnt = cur.fetchone()[0]
    check(cross_cnt > 0, f"Total cross_file_ref relationships: {cross_cnt:,}")
    
    conn.close()

def test_diff_validity():
    section("4. Version Diff Validity")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # v1 and v2 should have identical entity counts
    cur.execute("""
        SELECT e.import_id, et.name, COUNT(*) as cnt
        FROM entities e
        JOIN entity_types et ON e.entity_type_id = et.id
        GROUP BY e.import_id, et.name
        ORDER BY e.import_id, et.name
    """)
    rows = cur.fetchall()
    v1 = {r[1]: r[2] for r in rows if r[0] == 1}
    v2 = {r[1]: r[2] for r in rows if r[0] == 2}
    check(v1 == v2, f"Entity counts match across versions: v1={sum(v1.values()):,} v2={sum(v2.values()):,}")
    
    # v1 and v2 should have identical relationship counts
    cur.execute("""
        SELECT discovered_in_import, relationship_type, COUNT(*) as cnt
        FROM relationships
        GROUP BY discovered_in_import, relationship_type
        ORDER BY discovered_in_import, relationship_type
    """)
    rows = cur.fetchall()
    v1_rel = {(r[1]): r[2] for r in rows if r[0] == 1}
    v2_rel = {(r[1]): r[2] for r in rows if r[0] == 2}
    check(v1_rel == v2_rel, f"Relationship counts match: v1={v1_rel} v2={v2_rel}")
    
    # Field counts should match
    cur.execute("SELECT import_id, COUNT(*) FROM entity_fields GROUP BY import_id ORDER BY import_id")
    v1_fields = cur.fetchone()[1]
    v2_fields = cur.fetchone()[1]
    check(v1_fields == v2_fields, f"Field counts match: v1={v1_fields:,} v2={v2_fields:,}")
    
    conn.close()

def test_entity_count_validity():
    section("5. Entity Count Validity")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    expected = {
        'EquipDB': 27836, 'SkillDB': 27647, 'HeroStatDB': 18793,
        'HeroRosterDB': 13133, 'StageDB': 8772, 'MonsterDB': 4857,
        'AnimDB': 3209, 'MasterDB': 2980, 'ConfigDB': 2539, 'AchieveDB': 1035,
    }
    
    cur.execute("""
        SELECT et.name, COUNT(*) as cnt
        FROM entities e
        JOIN entity_types et ON e.entity_type_id = et.id
        WHERE e.import_id = 1
        GROUP BY et.name
    """)
    actual = {r[0]: r[1] for r in cur.fetchall()}
    
    for name, exp_cnt in expected.items():
        act_cnt = actual.get(name, 0)
        check(act_cnt == exp_cnt, f"{name}: expected {exp_cnt:,}, got {act_cnt:,}")
    
    total_expected = sum(expected.values())
    total_actual = sum(actual.values())
    check(total_actual == total_expected, f"Total entities: expected {total_expected:,}, got {total_actual:,}")
    
    # Entity_types table should have matching counts
    cur.execute("SELECT name, entry_count FROM entity_types")
    for r in cur.fetchall():
        name, db_cnt = r
        act_cnt = actual.get(name, 0)
        check(db_cnt == act_cnt or db_cnt == 0, 
              f"entity_types.{name}.entry_count: expected {act_cnt}, got {db_cnt}")
    
    conn.close()

def test_tag_definitions_validity():
    section("6. Tag Definitions Validity")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # tag_definitions should not be empty
    cur.execute("SELECT COUNT(*) FROM tag_definitions")
    cnt = cur.fetchone()[0]
    check(cnt > 0, f"Tag definitions populated: {cnt:,} rows")
    
    # Every entity type should have tag definitions
    cur.execute("""
        SELECT et.name, COUNT(td.id) as tag_cnt
        FROM entity_types et
        LEFT JOIN tag_definitions td ON td.source_file LIKE '%' || et.name || '%'
            OR td.source_file = et.source_file
            OR td.source_file LIKE '%' || SUBSTR(et.source_file, 1, 6) || '%'
        GROUP BY et.name
        ORDER BY tag_cnt DESC
    """)
    for r in cur.fetchall():
        check(r[1] > 0, f"Tag definitions for {r[0]}: {r[1]} tags")
    
    conn.close()

def test_known_ids_validity():
    section("7. Known IDs Validity")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    cur.execute("SELECT COUNT(*) FROM known_ids")
    cnt = cur.fetchone()[0]
    check(cnt > 1000, f"Known IDs count: {cnt:,} (was 9 before fix)")
    
    # Distinct entity types in known_ids
    cur.execute("SELECT DISTINCT entity_type FROM known_ids")
    types = [r[0] for r in cur.fetchall()]
    check(len(types) >= 5, f"Entity types covered: {len(types)} ({', '.join(types[:6])})")
    
    # Check for duplicates
    cur.execute("""
        SELECT id_value, entity_type, COUNT(*) as cnt
        FROM known_ids
        GROUP BY id_value, entity_type
        HAVING cnt > 1
    """)
    dupes = cur.fetchall()
    check(len(dupes) == 0, f"Duplicate known IDs: {len(dupes)}")
    
    conn.close()

def test_schema_integrity():
    section("8. Schema Integrity")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # All tables exist
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [r[0] for r in cur.fetchall() if not r[0].startswith('sqlite_')]
    expected_tables = {'version_imports', 'entity_types', 'entities', 'entity_fields', 
                       'relationships', 'known_ids', 'tag_definitions', 'version_diffs'}
    for t in expected_tables:
        check(t in tables, f"Table exists: {t}")
    
    # Foreign key integrity
    cur.execute("PRAGMA foreign_key_check")
    fk_issues = cur.fetchall()
    check(len(fk_issues) == 0, f"Foreign key violations: {len(fk_issues)}")
    if fk_issues:
        for issue in fk_issues[:5]:
            print(f"    FK issue: {issue}")
    
    conn.close()

def test_query_layer():
    section("9. Query Layer Smoke Test")
    # Test that mla_query.py can be imported and basic functions work
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))
    try:
        import mla_query as mq
        # Test basic functions
        stats = mq.db_stats()
        check(stats['total_entities'] > 0, f"db_stats() returns {stats['total_entities']:,} entities")
        check(stats['total_fields'] > 0, f"db_stats() returns {stats['total_fields']:,} fields")
        check(stats['total_relationships'] > 0, f"db_stats() returns {stats['total_relationships']:,} relationships")
        check(stats['known_ids'] > 1000, f"db_stats() known_ids: {stats['known_ids']}")
        
        # Test tag role lookup
        role = mq.get_tag_role(0x09, 'HeroRosterDB')
        check('id' in role, f"get_tag_role(0x09, HeroRosterDB) = '{role}'")
        
        # Test entity lookup
        entity = mq.get_entity('MLA-1-aec1555b40b2991d')
        check(entity is not None, f"get_entity('MLA-1-aec1555b40b2991d') found")
        if entity:
            check(len(entity.get('fields', [])) > 0, f"Entity has {len(entity.get('fields', []))} fields")
        
        # Test search
        results = mq.search_by_id(2111)
        check(len(results) > 0, f"search_by_id(2111) returns {len(results)} results")
        
        # Test ID types
        id_types = mq.list_id_types()
        check(len(id_types) > 0, f"list_id_types() returns {len(id_types)} types")
        
    except Exception as e:
        check(False, f"Query layer import/execution: {e}")

def run_all():
    global PASS, FAIL, ERRORS
    
    print("="*60)
    print("  MLA DATABASE VALIDATION SUITE")
    print("="*60)
    
    test_relationship_validity()
    test_primary_key_validity()
    test_foreign_key_validity()
    test_diff_validity()
    test_entity_count_validity()
    test_tag_definitions_validity()
    test_known_ids_validity()
    test_schema_integrity()
    test_query_layer()
    
    print(f"\n{'='*60}")
    print(f"  RESULTS: {PASS} passed, {FAIL} failed")
    print(f"{'='*60}")
    
    if ERRORS:
        print(f"\nFailed checks:")
        for e in ERRORS:
            print(f"  - {e}")
    
    return FAIL == 0

if __name__ == '__main__':
    success = run_all()
    sys.exit(0 if success else 1)
