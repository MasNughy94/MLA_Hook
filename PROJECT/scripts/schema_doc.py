"""Extract complete schema documentation from mla_database.db."""
import sqlite3, os, sys

DB_PATH = r'C:\Users\NGEONG\Videos\MLA\PROJECT\cache\mla_database.db'

TABLE_PURPOSE = {
    'version_imports': 'Tracks every import of a game version (ID, label, date, entity/file counts). Enables version comparison.',
    'entity_types': 'Static catalog of the 10 known entity types (EquipDB, SkillDB, HeroStatDB, etc.). Name-to-ID mapping.',
    'entities': 'Master entity table. Every parsed entry across all files and versions gets a stable ID.',
    'entity_fields': 'Tag-value pairs for each entity. The raw payload of every entry, linked back to the entity.',
    'known_ids': 'Known game IDs (HeroID 2111, 2112, etc.) with confidence scores and source tags.',
    'relationships': 'Cross-file entity relationships. Entities in different files that share the same value (same game object).',
    'version_diffs': 'Stored diff results between version pairs. Each row is one atomic change (added/removed/modified entity or schema change).',
    'tag_definitions': 'Per-file tag definitions with role, value range, and presence statistics.',
}

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# Get all tables
cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = [r['name'] for r in cur.fetchall()]

for tname in tables:
    print('=' * 72)
    print('TABLE: {}'.format(tname))
    print('Purpose: {}'.format(TABLE_PURPOSE.get(tname, 'N/A')))
    print('=' * 72)
    
    # CREATE TABLE statement
    cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (tname,))
    create_sql = cur.fetchone()[0]
    print(create_sql)
    print()
    
    # Row count
    cur.execute("SELECT COUNT(*) FROM \"{}\"".format(tname))
    count = cur.fetchone()[0]
    print('Row count: {}'.format(count))
    
    # Primary key columns (from schema parse)
    pk_cols = []
    for line in create_sql.split('\n'):
        line = line.strip().strip(',')
        if 'PRIMARY KEY' in line.upper():
            # Extract column names
            pk_match = line.split('(')[1].split(')')[0] if '(' in line else line.split()[0]
            pk_cols.append(pk_match)
    if pk_cols:
        print('Primary key: {}'.format(', '.join(pk_cols)))
    else:
        # sqlite rowid
        print('Primary key: implicit rowid')
    
    # Foreign keys
    fk_count = 0
    for line in create_sql.split('\n'):
        if 'REFERENCES' in line.upper():
            parts = line.strip().strip(',').split()
            col = parts[0]
            ref_info = ' '.join(parts[2:])
            print('Foreign key: {} -> {}'.format(col, ref_info))
            fk_count += 1
    if fk_count == 0:
        print('Foreign keys: none')
    
    # Indexes
    cur.execute("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL", (tname,))
    indexes = cur.fetchall()
    if indexes:
        print('Indexes:')
        for idx in indexes:
            print('  {}'.format(idx['sql']))
    else:
        print('Indexes: none')
    
    # Sample rows
    print()
    print('Sample rows (first 10):')
    try:
        cur.execute("SELECT * FROM \"{}\" LIMIT 10".format(tname))
        rows = cur.fetchall()
        if not rows:
            print('  (no rows)')
        else:
            col_names = [desc[0] for desc in cur.description]
            # Column widths
            widths = {}
            for c in col_names:
                widths[c] = max(len(str(c)), 6)
            for r in rows:
                for c in col_names:
                    val = r[c]
                    if val is None:
                        val = 'NULL'
                    elif isinstance(val, str) and len(val) > 40:
                        val = val[:37] + '...'
                    widths[c] = max(widths[c], len(str(val)))
            
            # Header
            header = '  '
            sep = '  '
            for c in col_names:
                w = widths[c]
                header += c.ljust(w) + ' | '
                sep += '-' * w + '-+-'
            print(header)
            print(sep)
            for r in rows:
                line = '  '
                for c in col_names:
                    val = r[c]
                    if val is None:
                        val = 'NULL'
                    elif isinstance(val, str) and len(val) > 40:
                        val = val[:37] + '...'
                    line += str(val).ljust(widths[c]) + ' | '
                print(line)
    except Exception as e:
        print('  Error: {}'.format(e))
    
    print()

conn.close()
