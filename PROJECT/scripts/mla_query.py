"""
MLA Database Query Layer.
Search by ID, Name, Type, Relationship, Referenced Entity.
Tag roles are file-specific â€” read from tag_definitions table, NOT hardcoded.
"""
import os, sys, json, sqlite3, textwrap
from collections import defaultdict

DB_PATH = r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db'

ENTITY_TYPE_NAMES = [
    'EquipDB', 'SkillDB', 'HeroStatDB', 'HeroRosterDB',
    'StageDB', 'MonsterDB', 'AnimDB', 'MasterDB', 'ConfigDB', 'AchieveDB',
]

# Cache untuk tag roles (file-specific)
_tag_role_cache = None

def load_tag_roles():
    """Load per-file tag roles from tag_definitions table.
    Keys include both filenames and entity type names."""
    global _tag_role_cache
    if _tag_role_cache is not None:
        return _tag_role_cache
    _tag_role_cache = {}
    conn = get_conn()
    cur = conn.cursor()
    
    # Build filename -> entity type name mapping
    cur.execute("SELECT name, source_file FROM entity_types WHERE source_file IS NOT NULL")
    file_to_type = {}
    for r in cur.fetchall():
        ename, fname = r
        if fname:
            file_to_type[fname] = ename
            # Short hash prefix mapping
            short = fname[:6]
            file_to_type[short] = ename
    
    # Load tag roles from tag_definitions
    cur.execute("""
        SELECT t.tag_hex, t.source_file, t.role
        FROM tag_definitions t
        WHERE t.role != 'unknown'
    """)
    for r in cur.fetchall():
        tag = int(r[0], 16) if r[0].startswith('0x') else int(r[0])
        fname = r[1]
        role = r[2]
        if fname not in _tag_role_cache:
            _tag_role_cache[fname] = {}
        _tag_role_cache[fname][tag] = role
        
        # Also index by entity type name
        ename = file_to_type.get(fname)
        if ename:
            if ename not in _tag_role_cache:
                _tag_role_cache[ename] = {}
            _tag_role_cache[ename][tag] = role
    
    conn.close()
    return _tag_role_cache

def get_tag_role(tag, source_file):
    """Get role for a tag in a specific file context. File-specific."""
    roles = load_tag_roles()
    if not source_file:
        return 'unknown'
    
    # Try exact match (by filename or entity type name)
    if source_file in roles and tag in roles[source_file]:
        return roles[source_file][tag]
    
    # Try partial match on entity type name (e.g. "HeroRosterDB" in "07b5cc...")
    for key in roles:
        src_clean = source_file.replace('.mt.dec', '').lower()
        key_clean = key.replace('.mt.dec', '').lower()
        if src_clean in key_clean or key_clean in src_clean:
            if tag in roles[key]:
                return roles[key][tag]
    
    if tag == 0: return 'terminator'
    return 'unknown'

def get_id_tags_for_type(entity_type):
    """Get tags that likely carry entity IDs for a given entity type."""
    roles = load_tag_roles()
    id_tags = []
    for fname, tags in roles.items():
        for tag, role in tags.items():
            if 'id' in role or 'ref' in role:
                id_tags.append(tag)
    return sorted(set(id_tags))

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def search_by_id(id_value, id_type=None, limit=50):
    """Search for entities by their game ID value.
    If id_type given (e.g. 'HeroID'), filter by known ID-carrying tags.
    Tag roles are read from tag_definitions table (file-specific)."""
    conn = get_conn()
    cur = conn.cursor()
    
    if id_type:
        # Find tags with role containing this type hint
        cur.execute("""
            SELECT DISTINCT t.tag_hex FROM tag_definitions t
            WHERE t.role LIKE ? OR t.role LIKE ?
        """, (f'%{id_type}%', f'%{id_type.lower()}%'))
        tag_rows = cur.fetchall()
        tags = [int(r[0], 16) for r in tag_rows if r[0]]
        
        if tags:
            placeholders = ','.join('?' for _ in tags)
            cur.execute(f"""
                SELECT e.stable_id, e.source_file, e.entry_index, et.name as entity_type,
                       f.tag_hex, f.value, f.role
                FROM entity_fields f
                JOIN entities e ON f.entity_id = e.id
                JOIN entity_types et ON e.entity_type_id = et.id
                WHERE f.value = ? AND f.tag IN ({placeholders})
                LIMIT ?
            """, (id_value, *tags, limit))
            rows = cur.fetchall()
            conn.close()
            return [dict(r) for r in rows]
    
    # Fallback: search all fields for this value
    cur.execute("""
        SELECT e.stable_id, e.source_file, e.entry_index, et.name as entity_type,
               f.tag_hex, f.value, f.role
        FROM entity_fields f
        JOIN entities e ON f.entity_id = e.id
        JOIN entity_types et ON e.entity_type_id = et.id
        WHERE f.value = ?
        LIMIT ?
    """, (id_value, limit))
    
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def search_by_type(entity_type, limit=50, offset=0):
    """Get all entities of a given type."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT e.stable_id, e.source_file, e.entry_index, 
               e.field_count, e.tag_count, e.tag_signature, et.name as entity_type
        FROM entities e
        JOIN entity_types et ON e.entity_type_id = et.id
        WHERE et.name = ?
        ORDER BY e.entry_index
        LIMIT ? OFFSET ?
    """, (entity_type, limit, offset))
    rows = cur.fetchall()
    cur.execute("SELECT COUNT(*) FROM entities e JOIN entity_types et ON e.entity_type_id = et.id WHERE et.name = ?",
                (entity_type,))
    total = cur.fetchone()[0]
    conn.close()
    return {'total': total, 'offset': offset, 'limit': limit, 'entries': [dict(r) for r in rows]}

def get_entity(stable_id):
    """Get detailed information about a specific entity by stable_id."""
    conn = get_conn()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT e.*, et.name as entity_type, et.short_name, iv.version_label
        FROM entities e
        JOIN entity_types et ON e.entity_type_id = et.id
        JOIN version_imports iv ON e.import_id = iv.id
        WHERE e.stable_id = ?
    """, (stable_id,))
    entity = cur.fetchone()
    if not entity:
        conn.close()
        return None
    
    result = dict(entity)
    
    cur.execute("""
        SELECT * FROM entity_fields 
        WHERE entity_id = ?
        ORDER BY field_index
    """, (entity['id'],))
    fields = [dict(r) for r in cur.fetchall()]
    for f in fields:
        f['interpreted_role'] = get_tag_role(f['tag'], result.get('source_file', ''))
    
    result['fields'] = fields
    result['field_count'] = len(fields)
    
    # Get relationships
    cur.execute("""
        SELECT * FROM relationships 
        WHERE source_entity_id = ? OR target_entity_id = ?
    """, (entity['id'], entity['id']))
    result['relationships'] = [dict(r) for r in cur.fetchall()]
    
    conn.close()
    return result

def search_relationships(entity_type=None, relationship_type='same_entity', limit=50):
    """Search for relationships between entities."""
    conn = get_conn()
    cur = conn.cursor()
    
    sql = """
        SELECT r.*, s.stable_id as src_stable, t.stable_id as tgt_stable,
               s.source_file as src_file, t.source_file as tgt_file,
               s.entry_index as src_entry, t.entry_index as tgt_entry
        FROM relationships r
        JOIN entities s ON r.source_entity_id = s.id
        JOIN entities t ON r.target_entity_id = t.id
        WHERE r.relationship_type = ?
    """
    params = [relationship_type]
    
    if entity_type:
        sql += " AND (r.source_entity_type = ? OR r.target_entity_type = ?)"
        params.extend([entity_type, entity_type])
    
    sql += " LIMIT ?"
    params.append(limit)
    
    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def search_by_field(tag, value, limit=50):
    """Search for entities with a specific tag-value pair."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT e.stable_id, e.source_file, e.entry_index, et.name as entity_type,
               f.tag_hex, f.value, f.role
        FROM entity_fields f
        JOIN entities e ON f.entity_id = e.id
        JOIN entity_types et ON e.entity_type_id = et.id
        WHERE f.tag = ? AND f.value = ?
        LIMIT ?
    """, (tag, value, limit))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def list_id_types():
    """List all known ID-carrying tags grouped by role from tag_definitions."""
    conn = get_conn()
    cur = conn.cursor()
    
    # Get distinct roles that contain 'id' or 'ref'
    cur.execute("""
        SELECT t.role, COUNT(DISTINCT t.tag_hex) as tag_count,
               GROUP_CONCAT(DISTINCT t.source_file) as sources
        FROM tag_definitions t
        WHERE (t.role LIKE '%id%' OR t.role LIKE '%ref%')
          AND t.role != 'unknown'
        GROUP BY t.role
        ORDER BY COUNT(*) DESC
    """)
    return [dict(r) for r in cur.fetchall()]

def get_entity_fields(entity):
    """Return a dict of tag->value for an entity's fields."""
    if isinstance(entity, str):
        entity = get_entity(entity)
    if not entity:
        return {}
    return {f['tag']: f['value'] for f in entity['fields']}

def find_cross_references(id_value, limit=50):
    """Find all entities referencing a given game ID across all files.
    Tag roles are read dynamically from tag_definitions table."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT e.stable_id, e.source_file, e.entry_index, et.name as entity_type,
               f.tag_hex, f.value, f.role,
               COALESCE(td.role, 'Reference') as ref_type
        FROM entity_fields f
        JOIN entities e ON f.entity_id = e.id
        JOIN entity_types et ON e.entity_type_id = et.id
        LEFT JOIN tag_definitions td ON td.tag_hex = f.tag_hex 
            AND (td.source_file = e.source_file OR td.source_file = et.name)
        WHERE f.value = ?
        LIMIT ?
    """, (id_value, limit))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_entity_names(limit=100):
    """
    Attempt to discover entity names by finding tag-value pairs 
    where values look like encoded character data (sequential small ints).
    """
    conn = get_conn()
    cur = conn.cursor()
    # Look for tags that carry short strings (small values in repeating patterns)
    cur.execute("""
        SELECT f.tag_hex, f.tag, COUNT(*) as cnt, 
               COUNT(DISTINCT f.value) as unique_vals,
               MIN(f.value) as min_val, MAX(f.value) as max_val
        FROM entity_fields f
        WHERE f.value BETWEEN 1 AND 999
        GROUP BY f.tag
        HAVING cnt > 100 AND unique_vals > 50
        ORDER BY unique_vals DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def query(sql, params=None):
    """Direct SQL access for advanced queries."""
    conn = get_conn()
    cur = conn.cursor()
    if params:
        cur.execute(sql, params)
    else:
        cur.execute(sql)
    rows = cur.fetchall()
    cols = [desc[0] for desc in cur.description]
    conn.close()
    return [dict(zip(cols, r)) for r in rows]

def db_stats():
    """Get database statistics."""
    conn = get_conn()
    cur = conn.cursor()
    
    stats = {}
    cur.execute("SELECT COUNT(*) FROM entities")
    stats['total_entities'] = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM entity_fields")
    stats['total_fields'] = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM relationships")
    stats['total_relationships'] = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM known_ids")
    stats['known_ids'] = cur.fetchone()[0]
    
    cur.execute("""
        SELECT et.name, COUNT(*) as cnt FROM entities e
        JOIN entity_types et ON e.entity_type_id = et.id
        GROUP BY et.name ORDER BY cnt DESC
    """)
    stats['entities_per_type'] = [dict(r) for r in cur.fetchall()]
    
    cur.execute("""
        SELECT f.tag_hex, f.tag, COUNT(DISTINCT f.value) as unique_vals,
               MIN(f.value) as min_val, MAX(f.value) as max_val
        FROM entity_fields f
        GROUP BY f.tag
        ORDER BY unique_vals DESC
        LIMIT 20
    """)
    stats['top_tags'] = [dict(r) for r in cur.fetchall()]
    
    conn.close()
    return stats

def format_entity(entity, verbose=False):
    """Pretty-print an entity and its fields."""
    if not entity:
        return "Entity not found"
    
    lines = []
    lines.append(f"Entity: {entity['stable_id']}")
    lines.append(f"  Type:      {entity['entity_type']}")
    lines.append(f"  Source:    {entity['source_file']}:{entity['entry_index']}")
    lines.append(f"  Fields:    {entity['field_count']}")
    lines.append(f"  Import:    {entity.get('version_label', 'unknown')}")
    
    if entity.get('fields'):
        lines.append(f"  Field Data:")
        for f in entity['fields']:
            role = f.get('interpreted_role') or get_tag_role(f['tag'], entity.get('source_file', ''))
            tc = '' if not (32 <= f['tag'] < 127) else f'tag_char={chr(f["tag"])}'
            lines.append(f"    [{f['field_index']:3d}] tag=0x{f['tag']:02X}  val={f['value']:>5d}  role={role}")
    
    if entity.get('relationships'):
        lines.append(f"  Relationships ({len(entity['relationships'])}):")
        for r in entity['relationships'][:10]:
            lines.append(f"    {r['relationship_type']} (conf={r['confidence']})")
            if len(entity['relationships']) > 10:
                lines.append(f"    ... and {len(entity['relationships']) - 10} more")
    
    return '\n'.join(lines)

def format_search_results(results, title="Search Results"):
    """Pretty-print search results."""
    if not results:
        return "No results found"
    
    lines = [f"{title}: ({len(results)} matches)"]
    for r in results[:30]:
        lines.append(f"  {r.get('stable_id','?'):20s}  {r.get('entity_type','?'):15s}  "
                     f"{r.get('source_file','?'):50s}  entry={r.get('entry_index','?'):<5d}  "
                     f"tag={r.get('tag_hex','?'):4s}  val={r.get('value','?'):<5d}")
    if len(results) > 30:
        lines.append(f"  ... and {len(results) - 30} more")
    return '\n'.join(lines)

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("MLA Database Query Tool")
        print("Usage:")
        print("  python mla_query.py stats                          - DB statistics")
        print("  python mla_query.py id <value> [type]              - search by ID")
        print("  python mla_query.py type <entity_type> [limit]     - list entities of type")
        print("  python mla_query.py entity <stable_id>             - get full entity")
        print("  python mla_query.py ref <id_value>                 - find cross-references")
        print("  python mla_query.py field <tag_hex> <value>        - search by field")
        print("  python mla_query.py idtypes                        - list known ID types")
        print("  python mla_query.py sql <query>                    - run raw SQL")
        print("  python mla_query.py discover                       - discover tag patterns")
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    if cmd == 'stats':
        s = db_stats()
        print(f"Database Statistics:")
        print(f"  Total entities:     {s['total_entities']:,}")
        print(f"  Total fields:       {s['total_fields']:,}")
        print(f"  Total relationships:{s['total_relationships']:,}")
        print(f"  Known IDs:          {s['known_ids']}")
        print(f"\nEntities per type:")
        for et in s['entities_per_type']:
            print(f"  {et['name']:15s}: {et['cnt']:>6,}")
        print(f"\nTop tags by unique values:")
        for t in s['top_tags'][:10]:
            print(f"  tag=0x{t['tag']:02X} ({t['tag_hex']:4s}): {t['unique_vals']:>4d} unique vals [{t['min_val']}-{t['max_val']}]")
    
    elif cmd == 'discover':
        names = get_entity_names()
        for r in names:
            print(f"  tag=0x{r['tag']:02X} ({r['tag_hex']:4s}): {r['cnt']:>6d} entries, {r['unique_vals']:>4d} unique vals [{r['min_val']}-{r['max_val']}]")
    
    elif cmd == 'id':
        id_val = int(sys.argv[2])
        id_type = sys.argv[3] if len(sys.argv) > 3 else None
        results = search_by_id(id_val, id_type)
        if not results:
            print(f"No results for ID {id_val}")
        else:
            print(f"Found {len(results)} references to ID {id_val}:")
            for r in results[:50]:
                print(f"  {r['stable_id']:20s}  {r['entity_type']:15s}  "
                      f"{r['source_file'][:30]:30s}  tag={r['tag_hex']:4s}  val={r['value']:<5d}")
    
    elif cmd == 'type':
        etype = sys.argv[2]
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 20
        results = search_by_type(etype, limit)
        print(f"{results['total']} entities of type '{etype}':")
        for r in results['entries'][:limit]:
            print(f"  {r['stable_id']:20s}  entry={r['entry_index']:<5d}  "
                  f"fields={r['field_count']:<3d}  tags={r['tag_count']:<3d}")
        if results['total'] > limit:
            print(f"  ... {results['total'] - limit} more")
    
    elif cmd == 'entity':
        sid = sys.argv[2]
        entity = get_entity(sid)
        print(format_entity(entity))
    
    elif cmd == 'ref':
        id_val = int(sys.argv[2])
        results = find_cross_references(id_val)
        print(f"Cross-references to ID {id_val}:")
        for r in results[:30]:
            print(f"  {r['entity_type']:15s}  {r['stable_id']:20s}  "
                  f"tag={r['tag_hex']:4s}  val={r['value']:<5d}  [{r['ref_type']}]")
    
    elif cmd == 'field':
        tag = int(sys.argv[2], 16) if sys.argv[2].startswith('0x') else int(sys.argv[2])
        value = int(sys.argv[3])
        results = search_by_field(tag, value)
        print(f"Entities with tag={hex(tag)} value={value}:")
        for r in results[:30]:
            print(f"  {r['stable_id']:20s}  {r['entity_type']:15s}  "
                  f"{r['source_file'][:30]:30s}")
    
    elif cmd == 'idtypes':
        types = list_id_types()
        print(f"{'Role':25s} {'Tags':10s} {'Sources'}")
        print(f"{'-'*25} {'-'*10} {'-'*40}")
        for t in types:
            print(f"{t['role']:25s} {t['tag_count']:>4d} tags   {t.get('sources','')[:50]}")
    
    elif cmd == 'sql':
        sql = ' '.join(sys.argv[2:])
        results = query(sql)
        for r in results:
            print(r)
