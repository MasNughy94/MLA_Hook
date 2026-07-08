"""Full import test - all 10 entity types, with relationship building."""
import sqlite3, os, sys, time, hashlib
sys.path.insert(0, 'scripts')
from mla_diff import parse_entries, stable_id, ENTITY_TYPE_FILES, build_relationships_for_import

DB_PATH = r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db'
DEC_BATCH = r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\decrypted\dec_batch'

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# Clean test imports
cur.execute("DELETE FROM version_diffs WHERE compare_import_id >= 2 OR base_import_id >= 2")
cur.execute("DELETE FROM entity_fields WHERE import_id >= 2")
cur.execute("DELETE FROM entities WHERE import_id >= 2")
cur.execute("DELETE FROM known_ids WHERE import_id >= 2")
cur.execute("DELETE FROM relationships WHERE discovered_in_import >= 2")
cur.execute("DELETE FROM version_imports WHERE id >= 2")
conn.commit()

cur.execute("INSERT INTO version_imports (version_id, version_label, source_path, status, import_date) VALUES (?, ?, ?, ?, ?)",
    ("MLA_v2_test", "Test full import", DEC_BATCH, "running", "2026-06-28T10:00:00"))
import_id = 2
conn.commit()
print("Import #2 registered")

cur.execute("SELECT id, name FROM entity_types")
type_map = {r["name"]: r["id"] for r in cur.fetchall()}

conn.execute("PRAGMA synchronous = OFF")
conn.execute("PRAGMA cache_size = -120000")
conn.execute("PRAGMA temp_store = MEMORY")

t_start = time.time()
total_entities = 0
total_fields = 0

for et_name, fname in ENTITY_TYPE_FILES.items():
    path = os.path.join(DEC_BATCH, fname)
    if not os.path.exists(path):
        print("  SKIP {} (not found)".format(fname))
        continue
    
    t0 = time.time()
    entries = parse_entries(path)
    type_id = type_map.get(et_name)
    if not type_id:
        print("  SKIP {} (no type_id)".format(et_name))
        continue
    
    # Batch entity INSERT
    entity_batch = []
    for eidx, entry in enumerate(entries):
        tags = sorted(set(r["tag"] for r in entry))
        sig = " ".join("0x{:02x}".format(t) for t in tags)
        sig_hash = hashlib.md5(sig.encode()).hexdigest()[:12]
        sid = stable_id(fname, eidx, import_id)
        entity_batch.append((sid, type_id, import_id, fname, eidx, len(entry), len(tags), sig, sig_hash))
    
    conn.execute("BEGIN TRANSACTION")
    cur.executemany("INSERT INTO entities (stable_id, entity_type_id, import_id, source_file, entry_index, field_count, tag_count, tag_signature, hash_hex) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", entity_batch)
    conn.commit()
    
    # Batch field INSERT
    field_batch = []
    for eidx, entry in enumerate(entries):
        sid = stable_id(fname, eidx, import_id)
        cur.execute("SELECT id FROM entities WHERE stable_id = ? AND import_id = ?", (sid, import_id))
        row = cur.fetchone()
        if not row:
            continue
        entity_db_id = row[0]
        for fi, r in enumerate(entry):
            field_batch.append((entity_db_id, import_id, r["tag"], "0x{:02x}".format(r["tag"]), r["val"], fi))
    
    conn.execute("BEGIN TRANSACTION")
    cur.executemany("INSERT INTO entity_fields (entity_id, import_id, tag, tag_hex, value, field_index) VALUES (?, ?, ?, ?, ?, ?)", field_batch)
    conn.commit()
    
    total_entities += len(entries)
    total_fields += len(field_batch)
    print("  {:15s}: {:>6,} entries ({:>8,} fields) in {:.1f}s".format(et_name, len(entries), len(field_batch), time.time() - t0))

# Update import metadata
cur.execute("UPDATE version_imports SET file_count = ?, entry_count = ?, status = 'complete' WHERE id = ?",
    (len(ENTITY_TYPE_FILES), total_entities, import_id))
conn.commit()

print("\nTotal: {:,} entities, {:,} fields in {:.1f}s".format(total_entities, total_fields, time.time() - t_start))

# Build relationships
print("\nBuilding relationships...")
t_rel = time.time()
build_relationships_for_import(conn, import_id)
print("Relationships: {:.1f}s".format(time.time() - t_rel))

conn.execute("PRAGMA synchronous = FULL")
cur.execute("SELECT COUNT(*) FROM entities WHERE import_id = ?", (import_id,))
print("\nVerified: {} entities".format(cur.fetchone()[0]))
cur.execute("SELECT COUNT(*) FROM entity_fields WHERE import_id = ?", (import_id,))
print("Verified: {} fields".format(cur.fetchone()[0]))
cur.execute("SELECT COUNT(*) FROM relationships WHERE discovered_in_import = ?", (import_id,))
print("Verified: {} relationships".format(cur.fetchone()[0]))

conn.close()
print("\nDONE in {:.1f}s".format(time.time() - t_start))
