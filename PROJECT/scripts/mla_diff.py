"""
MLA Version Import & Diff System.
Supports importing new game versions and comparing them against previous versions.
Detects: added/removed/modified entities, schema changes, relationship changes.
"""
import os, sys, json, sqlite3, hashlib, shutil
from datetime import datetime
from collections import defaultdict

DB_PATH = r'C:\Users\NGEONG\Videos\MLA\PROJECT\cache\mla_database.db'
DEC_BATCH = r'C:\Users\NGEONG\Videos\MLA\PROJECT\decrypted\dec_batch'
REPORTS_DIR = r'C:\Users\NGEONG\Videos\MLA\PROJECT\reports'
HDR_SIZE = 69

ENTITY_TYPES = [
    'EquipDB', 'SkillDB', 'HeroStatDB', 'HeroRosterDB',
    'StageDB', 'MonsterDB', 'AnimDB', 'MasterDB', 'ConfigDB', 'AchieveDB',
]

ENTITY_TYPE_NAMES = {
    1: 'EquipDB', 2: 'SkillDB', 3: 'HeroStatDB', 4: 'HeroRosterDB',
    5: 'StageDB', 6: 'MonsterDB', 7: 'AnimDB', 8: 'MasterDB',
    9: 'ConfigDB', 10: 'AchieveDB',
}

ENTITY_TYPE_FILES = {
    'EquipDB': '1c7efa501c5305fb7062cdcbf148c4a9.mt.dec',
    'SkillDB': '17f4dd5419fdea6aff836f46154d274a.mt.dec',
    'HeroStatDB': '12eb65e862c413254ae49d2eba76eea2.mt.dec',
    'HeroRosterDB': '07b5cc5ea4a8d86273be8170720a4587.mt.dec',
    'StageDB': '1c1ac35710f3a4276a942a776e911a85.mt.dec',
    'MonsterDB': '1c4ed1eebdb4b8af5c2658f4151aa529.mt.dec',
    'AnimDB': '18f286461b12e92d9e16b27c07854a7c.mt.dec',
    'MasterDB': '0217cbdae530696836de83aa3c162e1a.mt.dec',
    'ConfigDB': '1a4fb9f36cd34d0eb0ca22000e54f8a5.mt.dec',
    'AchieveDB': '0e3bbac67f12505f7dfe45d4e6aba1ea.mt.dec',
}

# ====================================================================
# PARSING
# ====================================================================

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

def compute_file_signature(entries):
    """Compute a signature for the file structure (entry count, tag sets)."""
    tag_sets = []
    for e in entries:
        tags = sorted(set(r['tag'] for r in e))
        tag_sets.append(tags)
    all_tags = sorted(set(t for ts in tag_sets for t in ts))
    return {
        'num_entries': len(entries),
        'num_tags': len(all_tags),
        'tag_sets': tag_sets[:100],
        'num_tag_sets': len(set(str(ts) for ts in tag_sets)),
        'all_tags': all_tags,
    }

def stable_id(source_file, entry_index, import_id):
    h = hashlib.sha256(f"{source_file}:{entry_index}:v{import_id}".encode()).hexdigest()[:16]
    return f"MLA-{import_id}-{h}"

# ====================================================================
# VERSION TRACKING
# ====================================================================

def latest_import_id(conn):
    """Get the ID of the most recent import."""
    cur = conn.cursor()
    cur.execute("SELECT id FROM version_imports ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    return row[0] if row else None

def register_import(conn, version_id, version_label, source_path):
    """Register a new version import. Returns (import_id, is_first)."""
    cur = conn.cursor()
    existing = cur.execute("SELECT id FROM version_imports WHERE version_id = ?", (version_id,)).fetchone()
    if existing:
        print(f"  Import '{version_id}' already exists (id={existing[0]}), reusing.")
        return existing[0], False
    
    cur.execute("""
        INSERT INTO version_imports (version_id, version_label, source_path, status, import_date)
        VALUES (?, ?, ?, 'running', ?)
    """, (version_id, version_label, source_path, datetime.now().isoformat()))
    import_id = cur.lastrowid
    conn.commit()
    
    is_first = (import_id == 1)
    print(f"  Registered import #{import_id}: {version_id} ({version_label})")
    return import_id, is_first

# ====================================================================
# SCHEMA DETECTION
# ====================================================================

def detect_schema(conn, import_id):
    """
    Detect which tags are present in each entity type for this import.
    Returns dict entity_type -> {tags: set, roles: dict, value_ranges: dict}
    """
    cur = conn.cursor()
    schema = {}
    
    cur.execute("""
        SELECT et.name, f.tag, MIN(f.value), MAX(f.value), 
               COUNT(DISTINCT f.value), COUNT(*)
        FROM entity_fields f
        JOIN entities e ON f.entity_id = e.id
        JOIN entity_types et ON e.entity_type_id = et.id
        WHERE e.import_id = ?
        GROUP BY et.name, f.tag
        ORDER BY et.name, f.tag
    """, (import_id,))
    
    for row in cur.fetchall():
        et_name, tag, min_val, max_val, unique_vals, presence = row
        if et_name not in schema:
            schema[et_name] = {'tags': set(), 'tag_details': {}}
        schema[et_name]['tags'].add(tag)
        schema[et_name]['tag_details'][tag] = {
            'min': min_val, 'max': max_val,
            'unique': unique_vals, 'presence': presence,
        }
    
    for et_name in schema:
        schema[et_name]['tags'] = sorted(schema[et_name]['tags'])
    
    return schema

# ====================================================================
# DIFF ENGINE
# ====================================================================

def diff_imports(conn, base_id, compare_id):
    """
    Compare two imports and detect all changes.
    Returns dict with structured diff results.
    """
    cur = conn.cursor()
    base_version = cur.execute("SELECT version_id FROM version_imports WHERE id = ?", (base_id,)).fetchone()[0]
    compare_version = cur.execute("SELECT version_id FROM version_imports WHERE id = ?", (compare_id,)).fetchone()[0]
    
    print(f"\n  Diffing: {base_version} (v{base_id}) -> {compare_version} (v{compare_id})")
    
    diff = {
        'base_id': base_id,
        'compare_id': compare_id,
        'base_version': base_version,
        'compare_version': compare_version,
        'added_entities': [],
        'removed_entities': [],
        'modified_entities': [],
        'schema_changes': [],
        'relationship_changes': [],
        'summary': {},
    }
    
    # --- ADDED / REMOVED ENTITIES ---
    # Entities are identified by their stable ID structure: source_file:entry_index
    cur.execute("""
        SELECT e.id, e.stable_id, e.source_file, e.entry_index, et.name as entity_type
        FROM entities e JOIN entity_types et ON e.entity_type_id = et.id
        WHERE e.import_id = ?
    """, (base_id,))
    base_entities = {(r['source_file'], r['entry_index']): dict(r) for r in cur.fetchall()}
    
    cur.execute("""
        SELECT e.id, e.stable_id, e.source_file, e.entry_index, et.name as entity_type
        FROM entities e JOIN entity_types et ON e.entity_type_id = et.id
        WHERE e.import_id = ?
    """, (compare_id,))
    compare_entities = {(r['source_file'], r['entry_index']): dict(r) for r in cur.fetchall()}
    
    base_keys = set(base_entities.keys())
    compare_keys = set(compare_entities.keys())
    
    removed_keys = base_keys - compare_keys
    added_keys = compare_keys - base_keys
    common_keys = base_keys & compare_keys
    
    for key in sorted(removed_keys):
        ent = base_entities[key]
        diff['removed_entities'].append({
            'stable_id': ent['stable_id'],
            'entity_type': ent['entity_type'],
            'source_file': ent['source_file'],
            'entry_index': ent['entry_index'],
        })
    
    for key in sorted(added_keys):
        ent = compare_entities[key]
        diff['added_entities'].append({
            'stable_id': ent['stable_id'],
            'entity_type': ent['entity_type'],
            'source_file': ent['source_file'],
            'entry_index': ent['entry_index'],
        })
    
    # --- MODIFIED ENTITIES ---
    for key in sorted(common_keys):
        base_ent = base_entities[key]
        comp_ent = compare_entities[key]
        base_id_db = base_ent['id']
        comp_id_db = comp_ent['id']
        
        # Compare field values
        cur.execute("""
            SELECT tag, tag_hex, value, field_index FROM entity_fields 
            WHERE entity_id = ? ORDER BY field_index
        """, (base_id_db,))
        base_fields = {(r['tag'], r['field_index']): r['value'] for r in cur.fetchall()}
        
        cur.execute("""
            SELECT tag, tag_hex, value, field_index FROM entity_fields 
            WHERE entity_id = ? ORDER BY field_index
        """, (comp_id_db,))
        comp_fields = {(r['tag'], r['field_index']): r['value'] for r in cur.fetchall()}
        
        modifications = []
        
        # Changed values
        for key_f in base_fields:
            if key_f in comp_fields and base_fields[key_f] != comp_fields[key_f]:
                tag, fi = key_f
                modifications.append({
                    'field_index': fi,
                    'tag': tag,
                    'tag_hex': f"0x{tag:02X}",
                    'old_value': base_fields[key_f],
                    'new_value': comp_fields[key_f],
                })
        
        # Added fields (in compare but not base)
        for key_f in comp_fields:
            if key_f not in base_fields:
                tag, fi = key_f
                modifications.append({
                    'field_index': fi,
                    'tag': tag,
                    'tag_hex': f"0x{tag:02X}",
                    'old_value': None,
                    'new_value': comp_fields[key_f],
                    'change': 'field_added',
                })
        
        # Removed fields (in base but not compare)
        for key_f in base_fields:
            if key_f not in comp_fields:
                tag, fi = key_f
                modifications.append({
                    'field_index': fi,
                    'tag': tag,
                    'tag_hex': f"0x{tag:02X}",
                    'old_value': base_fields[key_f],
                    'new_value': None,
                    'change': 'field_removed',
                })
        
        if modifications:
            diff['modified_entities'].append({
                'stable_id': base_ent['stable_id'],
                'entity_type': base_ent['entity_type'],
                'source_file': base_ent['source_file'],
                'entry_index': base_ent['entry_index'],
                'modifications': modifications,
                'modification_count': len(modifications),
            })
    
    # --- SCHEMA CHANGES ---
    base_schema = detect_schema(conn, base_id)
    comp_schema = detect_schema(conn, compare_id)
    
    for et_name in sorted(set(list(base_schema.keys()) + list(comp_schema.keys()))):
        base_tags = set(base_schema.get(et_name, {}).get('tags', []))
        comp_tags = set(comp_schema.get(et_name, {}).get('tags', []))
        
        added_tags = comp_tags - base_tags
        removed_tags = base_tags - comp_tags
        
        if added_tags:
            diff['schema_changes'].append({
                'entity_type': et_name,
                'change_type': 'tags_added',
                'tags': sorted(added_tags),
                'tag_hexes': [f"0x{t:02X}" for t in sorted(added_tags)],
            })
        
        if removed_tags:
            diff['schema_changes'].append({
                'entity_type': et_name,
                'change_type': 'tags_removed',
                'tags': sorted(removed_tags),
                'tag_hexes': [f"0x{t:02X}" for t in sorted(removed_tags)],
            })
    
    # --- RELATIONSHIP CHANGES ---
    cur.execute("""
        SELECT source_entity_id, target_entity_id, relationship_type, confidence
        FROM relationships WHERE discovered_in_import = ?
    """, (base_id,))
    base_rels = {(r['source_entity_id'], r['target_entity_id'], r['relationship_type']): r for r in cur.fetchall()}
    
    cur.execute("""
        SELECT source_entity_id, target_entity_id, relationship_type, confidence
        FROM relationships WHERE discovered_in_import = ?
    """, (compare_id,))
    comp_rels = {(r['source_entity_id'], r['target_entity_id'], r['relationship_type']): r for r in cur.fetchall()}
    
    added_rels = set(comp_rels.keys()) - set(base_rels.keys())
    removed_rels = set(base_rels.keys()) - set(comp_rels.keys())
    
    diff['relationship_changes'] = {
        'added': len(added_rels),
        'removed': len(removed_rels),
        'total_base': len(base_rels),
        'total_compare': len(comp_rels),
    }
    
    # --- SUMMARY ---
    diff['summary'] = {
        'entities_added': len(diff['added_entities']),
        'entities_removed': len(diff['removed_entities']),
        'entities_modified': len(diff['modified_entities']),
        'schema_changes': len(diff['schema_changes']),
        'relationship_changes_added': diff['relationship_changes']['added'],
        'relationship_changes_removed': diff['relationship_changes']['removed'],
        'total_entities_base': len(base_entities),
        'total_entities_compare': len(compare_entities),
    }
    
    return diff

def store_diff(conn, diff):
    """Store diff results in the version_diffs table."""
    cur = conn.cursor()
    base_id = diff['base_id']
    compare_id = diff['compare_id']
    
    # Remove any previous diff for this pair
    cur.execute("DELETE FROM version_diffs WHERE base_import_id = ? AND compare_import_id = ?",
                (base_id, compare_id))
    
    count = 0
    for ent in diff['added_entities']:
        cur.execute("""
            INSERT INTO version_diffs 
            (base_import_id, compare_import_id, diff_type, entity_type, entity_stable_id)
            VALUES (?, ?, 'added', ?, ?)
        """, (base_id, compare_id, ent['entity_type'], ent['stable_id']))
        count += 1
    
    for ent in diff['removed_entities']:
        cur.execute("""
            INSERT INTO version_diffs 
            (base_import_id, compare_import_id, diff_type, entity_type, entity_stable_id)
            VALUES (?, ?, 'removed', ?, ?)
        """, (base_id, compare_id, ent['entity_type'], ent['stable_id']))
        count += 1
    
    for ent in diff['modified_entities']:
        for mod in ent['modifications'][:20]:  # Store up to 20 changes per entity
            cur.execute("""
                INSERT INTO version_diffs 
                (base_import_id, compare_import_id, diff_type, entity_type, entity_stable_id,
                 field_tag, old_value, new_value, notes)
                VALUES (?, ?, 'modified', ?, ?, ?, ?, ?, ?)
            """, (base_id, compare_id, ent['entity_type'], ent['stable_id'],
                  mod.get('tag'), mod.get('old_value'), mod.get('new_value'),
                  f"idx={mod.get('field_index')}"))
            count += 1
    
    for sc in diff['schema_changes']:
        cur.execute("""
            INSERT INTO version_diffs 
            (base_import_id, compare_import_id, diff_type, entity_type, notes)
            VALUES (?, ?, 'schema_change', ?, ?)
        """, (base_id, compare_id, sc['entity_type'],
              f"{sc['change_type']}: {', '.join(sc['tag_hexes'])}"))
        count += 1
    
    conn.commit()
    print(f"  Stored {count} diff rows in database")
    return count

def generate_diff_report(diff):
    """Generate a human-readable diff report."""
    s = diff['summary']
    
    lines = []
    lines.append(f"{'='*70}")
    lines.append(f"VERSION DIFF REPORT")
    lines.append(f"{'='*70}")
    lines.append(f"  Base:    {diff['base_version']} (import #{diff['base_id']})")
    lines.append(f"  Compare: {diff['compare_version']} (import #{diff['compare_id']})")
    lines.append(f"{'='*70}")
    lines.append(f"")
    lines.append(f"SUMMARY")
    lines.append(f"  Entities added:    {s['entities_added']:>6,}")
    lines.append(f"  Entities removed:  {s['entities_removed']:>6,}")
    lines.append(f"  Entities modified: {s['entities_modified']:>6,}")
    lines.append(f"  Schema changes:    {s['schema_changes']:>6,}")
    lines.append(f"  Relationship +:    {s['relationship_changes_added']:>6,}")
    lines.append(f"  Relationship -:    {s['relationship_changes_removed']:>6,}")
    lines.append(f"  Total (base):      {s['total_entities_base']:>6,}")
    lines.append(f"  Total (compare):   {s['total_entities_compare']:>6,}")
    lines.append(f"")
    
    if s['entities_added'] > 0:
        lines.append(f"ADDED ENTITIES ({s['entities_added']})")
        by_type = defaultdict(int)
        for e in diff['added_entities'][:100]:
            by_type[e['entity_type']] += 1
        for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
            lines.append(f"  {t:15s}: {c:>6,}")
        if s['entities_added'] > 100:
            lines.append(f"  (showing first 100, total {s['entities_added']})")
        lines.append(f"")
    
    if s['entities_removed'] > 0:
        lines.append(f"REMOVED ENTITIES ({s['entities_removed']})")
        by_type = defaultdict(int)
        for e in diff['removed_entities'][:100]:
            by_type[e['entity_type']] += 1
        for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
            lines.append(f"  {t:15s}: {c:>6,}")
        if s['entities_removed'] > 100:
            lines.append(f"  (showing first 100, total {s['entities_removed']})")
        lines.append(f"")
    
    if s['entities_modified'] > 0:
        lines.append(f"MODIFIED ENTITIES ({s['entities_modified']})")
        for ent in diff['modified_entities'][:20]:
            lines.append(f"  {ent['stable_id'][:20]:20s}  {ent['entity_type']:15s}  "
                         f"{ent['modification_count']:>3d} changes")
            for mod in ent['modifications'][:5]:
                lines.append(f"    tag={mod['tag_hex']:4s} idx={mod['field_index']:3d}  "
                             f"{mod.get('old_value','---'):>5s} -> {mod.get('new_value','---'):>5s}")
        if s['entities_modified'] > 20:
            lines.append(f"  ... and {s['entities_modified'] - 20} more")
        lines.append(f"")
    
    if s['schema_changes'] > 0:
        lines.append(f"SCHEMA CHANGES ({s['schema_changes']})")
        for sc in diff['schema_changes']:
            lines.append(f"  {sc['entity_type']:15s}  {sc['change_type']:15s}  {', '.join(sc['tag_hexes'])}")
        lines.append(f"")
    
    if diff['relationship_changes']['added'] > 0 or diff['relationship_changes']['removed'] > 0:
        lines.append(f"RELATIONSHIP CHANGES")
        lines.append(f"  Added:   {diff['relationship_changes']['added']}")
        lines.append(f"  Removed: {diff['relationship_changes']['removed']}")
        lines.append(f"")
    
    lines.append(f"{'='*70}")
    return '\n'.join(lines)

# ====================================================================
# REPORT SAVING
# ====================================================================

def save_diff_report(diff):
    """Save diff report to disk (both TXT and JSON)."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    base_id = diff['base_id']
    compare_id = diff['compare_id']
    
    report_path = os.path.join(REPORTS_DIR, f"diff_v{base_id}_v{compare_id}.txt")
    report = generate_diff_report(diff)
    with open(report_path, 'w') as f:
        f.write(report)
    print(f"  Diff report saved: {report_path}")
    
    json_path = os.path.join(REPORTS_DIR, f"diff_v{base_id}_v{compare_id}.json")
    with open(json_path, 'w') as f:
        json.dump(diff, f, indent=2, default=str)
    print(f"  Diff JSON saved: {json_path}")

# ====================================================================
# IMPORT ENGINE
# ====================================================================

def import_version(conn, version_id, version_label, source_path, run_diff=True):
    """
    Import a new game version and optionally diff against the previous version.
    """
    cur = conn.cursor()
    
    # Register the import
    import_id, is_first = register_import(conn, version_id, version_label, source_path)
    
    # Check if entities already exist for this import
    existing = cur.execute("""
        SELECT COUNT(*) FROM entities WHERE import_id = ?
    """, (import_id,)).fetchone()[0]
    
    if existing > 0:
        if run_diff:
            print(f"  Import #{import_id} already has {existing} entities, skipping re-import.")
            # Just run diff against previous
            if not is_first:
                base_id = import_id - 1
                diff = diff_imports(conn, base_id, import_id)
                store_diff(conn, diff)
                save_diff_report(diff)
            return import_id
        else:
            print(f"  Import #{import_id} already has {existing} entities, re-importing...")
            cur.execute("""
                DELETE FROM entity_fields WHERE entity_id IN 
                (SELECT id FROM entities WHERE import_id = ?)
            """, (import_id,))
            cur.execute("DELETE FROM entities WHERE import_id = ?", (import_id,))
            cur.execute("DELETE FROM known_ids WHERE import_id = ?", (import_id,))
            conn.commit()
    
    # Map entity type names to IDs
    cur.execute("SELECT id, name FROM entity_types")
    type_map = {r['name']: r['id'] for r in cur.fetchall()}
    
    # Import each entity type
    total_entities = 0
    file_count = 0
    
    conn.execute("PRAGMA synchronous = OFF")
    conn.execute("PRAGMA cache_size = -80000")
    
    for et_name, fname in ENTITY_TYPE_FILES.items():
        path = os.path.join(source_path, fname)
        if not os.path.exists(path):
            print(f"  SKIP {fname} (not found)")
            continue
        
        entries = parse_entries(path)
        type_id = type_map.get(et_name)
        if not type_id:
            print(f"  SKIP {et_name} (not in entity_types table)")
            continue
        
        # Batch insert entities
        entity_batch = []
        for eidx, entry in enumerate(entries):
            tags = sorted(set(r['tag'] for r in entry))
            sig = ' '.join(f"0x{t:02x}" for t in tags)
            sig_hash = hashlib.md5(sig.encode()).hexdigest()[:12]
            sid = stable_id(fname, eidx, import_id)
            entity_batch.append((sid, type_id, import_id, fname, eidx,
                                 len(entry), len(tags), sig, sig_hash))
        
        cur.executemany("""
            INSERT OR IGNORE INTO entities 
            (stable_id, entity_type_id, import_id, source_file, entry_index,
             field_count, tag_count, tag_signature, hash_hex)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, entity_batch)
        conn.commit()
        
        # Batch insert fields
        field_batch = []
        for eidx, entry in enumerate(entries):
            sid = stable_id(fname, eidx, import_id)
            cur.execute("SELECT id FROM entities WHERE stable_id = ? AND import_id = ?",
                        (sid, import_id))
            row = cur.fetchone()
            if not row:
                continue
            entity_db_id = row[0]
            for fi, r in enumerate(entry):
                field_batch.append((
                    entity_db_id, import_id, r['tag'], f"0x{r['tag']:02x}",
                    r['val'], fi
                ))
        
        cur.executemany("""
            INSERT OR IGNORE INTO entity_fields
            (entity_id, import_id, tag, tag_hex, value, field_index)
            VALUES (?, ?, ?, ?, ?, ?)
        """, field_batch)
        conn.commit()
        
        file_count += 1
        total_entities += len(entries)
        print(f"    {et_name:15s}: {len(entries):>6,} entries ({len(field_batch):>8,} fields)")
    
    conn.execute("PRAGMA synchronous = FULL")
    
    # Update import metadata
    cur.execute("""
        UPDATE version_imports 
        SET file_count = ?, entry_count = ?, status = 'complete'
        WHERE id = ?
    """, (file_count, total_entities, import_id))
    conn.commit()
    
    print(f"\n  Import complete: {total_entities:,} entities from {file_count} files")
    
    # Build relationships for this import
    build_relationships_for_import(conn, import_id)
    
    # Run diff if not the first import
    if run_diff and not is_first:
        base_id = import_id - 1
        print(f"\n  Running diff against import #{base_id}...")
        diff = diff_imports(conn, base_id, import_id)
        store_diff(conn, diff)
        save_diff_report(diff)
        
        print(f"\n  Diff summary: +{diff['summary']['entities_added']} / "
              f"-{diff['summary']['entities_removed']} / "
              f"~{diff['summary']['entities_modified']} entities, "
              f"{diff['summary']['schema_changes']} schema changes")
    
    return import_id

def build_relationships_for_import(conn, import_id):
    """Auto-detect relationships for a specific import using Python grouping."""
    cur = conn.cursor()
    print(f"\n  Building relationships for import #{import_id}...")
    
    # Get all candidate field values grouped by value
    cur.execute("""
        SELECT f.value, f.entity_id, e.entity_type_id
        FROM entity_fields f
        JOIN entities e ON f.entity_id = e.id
        WHERE f.import_id = ? AND f.value BETWEEN 1000 AND 65535
        ORDER BY f.value
    """, (import_id,))
    
    rows = cur.fetchall()
    if not rows:
        print("    -> No candidate values found")
        return 0
    
    # Group by value in Python (avoids dangerous SQL self-join)
    value_groups = {}
    for r in rows:
        val = r['value']
        if val not in value_groups:
            value_groups[val] = []
        value_groups[val].append((r['entity_id'], r['entity_type_id']))
    
    # Build relationships for each shared value
    rel_count = 0
    rel_batch = []
    
    for val, entities in value_groups.items():
        if len(entities) < 2:
            continue
        # Create relationships between entities of different types sharing this value
        for i in range(len(entities)):
            for j in range(i + 1, len(entities)):
                src_id, src_type = entities[i]
                tgt_id, tgt_type = entities[j]
                if src_type == tgt_type:
                    continue  # Skip same-type relationships
                et1 = ENTITY_TYPE_NAMES.get(src_type, 'Unknown')
                et2 = ENTITY_TYPE_NAMES.get(tgt_type, 'Unknown')
                rel_batch.append((
                    src_id, tgt_id, et1, et2,
                    'cross_file_ref', 0.6, f"Shared value {val}", f"value={val}", import_id
                ))
                rel_count += 1
                if rel_count % 5000 == 0:
                    print(f"    ... {rel_count} relationships so far")
    
    if rel_batch:
        conn.execute("BEGIN TRANSACTION")
        cur.executemany("""
            INSERT OR IGNORE INTO relationships
            (source_entity_id, target_entity_id, source_entity_type, target_entity_type,
             relationship_type, confidence, evidence, shared_tags, discovered_in_import)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rel_batch)
        conn.commit()
    
    print(f"    -> {rel_count} relationships built")
    return rel_count

# ====================================================================
# LIST IMPORTS
# ====================================================================

def list_imports(conn):
    """List all registered imports."""
    cur = conn.cursor()
    cur.execute("""
        SELECT id, version_id, version_label, import_date, 
               file_count, entry_count, status
        FROM version_imports
        ORDER BY id
    """)
    rows = cur.fetchall()
    if not rows:
        print("  No imports registered.")
        return
    
    print(f"  {'ID':3s} {'Version ID':25s} {'Label':20s} {'Date':20s} {'Files':6s} {'Entries':>8s} {'Status'}")
    print(f"  {'-'*3} {'-'*25} {'-'*20} {'-'*20} {'-'*6} {'-'*8} {'-'*10}")
    for r in rows:
        print(f"  {r['id']:<3d} {r['version_id']:25s} {str(r['version_label'] or ''):20s} "
              f"{r['import_date'][:19]:20s} {r['file_count'] or 0:<6d} {r['entry_count'] or 0:>8,d} {r['status']}")

# ====================================================================
# DIFF REPORT TOOL
# ====================================================================

def get_diff(conn, base_id, compare_id):
    """Get stored diff between two imports, or compute if not stored."""
    cur = conn.cursor()
    # Check if diff exists
    cur.execute("""
        SELECT COUNT(*) FROM version_diffs 
        WHERE base_import_id = ? AND compare_import_id = ? AND diff_type = 'added'
    """, (base_id, compare_id))
    count = cur.fetchone()[0]
    
    if count == 0:
        print("  Computing fresh diff...")
        diff = diff_imports(conn, base_id, compare_id)
        store_diff(conn, diff)
    else:
        print(f"  Found {count}+ stored diff rows")
        diff = diff_imports(conn, base_id, compare_id)
    
    return diff

# ====================================================================
# CLI
# ====================================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description='MLA Version Import & Diff System')
    parser.add_argument('action', choices=['import', 'diff', 'list', 'schema'],
                       help='Action to perform')
    parser.add_argument('--version-id', help='Version identifier (e.g. MLA_v2.0)')
    parser.add_argument('--version-label', help='Human-readable version label')
    parser.add_argument('--source', default=DEC_BATCH, help='Source directory of decrypted files')
    parser.add_argument('--base', type=int, help='Base import ID for diff')
    parser.add_argument('--compare', type=int, help='Compare import ID for diff')
    parser.add_argument('--no-diff', action='store_true', help='Skip diff after import')
    
    args = parser.parse_args()
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    if args.action == 'list':
        list_imports(conn)
    
    elif args.action == 'diff':
        if not args.base or not args.compare:
            print("Error: --base and --compare required for diff action")
            sys.exit(1)
        diff = get_diff(conn, args.base, args.compare)
        report = generate_diff_report(diff)
        print(report)
        save_diff_report(diff)
    
    elif args.action == 'import':
        if not args.version_id:
            print("Error: --version-id required for import action")
            sys.exit(1)
        import_version(conn, args.version_id, args.version_label or args.version_id,
                       args.source, run_diff=not args.no_diff)
    
    elif args.action == 'schema':
        imp_id = args.base or 1
        schema = detect_schema(conn, imp_id)
        for et_name, info in sorted(schema.items()):
            tags = info['tags']
            print(f"\n{et_name} ({len(tags)} tags):")
            for t in tags[:20]:
                d = info['tag_details'][t]
                print(f"  0x{t:02X}: range=[{d['min']}-{d['max']}] unique={d['unique']} presence={d['presence']}")
            if len(tags) > 20:
                print(f"  ... and {len(tags) - 20} more tags")
    
    conn.close()

if __name__ == '__main__':
    main()
