"""Profile import speed (single entity type)."""
import sqlite3, os, sys, time, hashlib
sys.path.insert(0, 'scripts')
from mla_diff import parse_entries, stable_id, ENTITY_TYPE_FILES

DB_PATH = r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db'
DEC_BATCH = r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\decrypted\dec_batch'

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# Clean old test imports
cur.execute("DELETE FROM version_diffs WHERE compare_import_id >= 2 OR base_import_id >= 2")
cur.execute("DELETE FROM entity_fields WHERE import_id >= 2")
cur.execute("DELETE FROM entities WHERE import_id >= 2")
cur.execute("DELETE FROM known_ids WHERE import_id >= 2")
cur.execute("DELETE FROM relationships WHERE discovered_in_import >= 2")
cur.execute("DELETE FROM version_imports WHERE id >= 2")
conn.commit()

cur.execute("INSERT INTO version_imports (version_id, version_label, source_path, status, import_date) VALUES (?, ?, ?, ?, ?)",
    ("MLA_v2.0_test", "Test v2", DEC_BATCH, "running", "2026-06-28T10:00:00"))
import_id = 2
conn.commit()
print("Import #2 registered")

cur.execute("SELECT id, name FROM entity_types")
type_map = {r["name"]: r["id"] for r in cur.fetchall()}

conn.execute("PRAGMA synchronous = OFF")
conn.execute("PRAGMA cache_size = -120000")
conn.execute("PRAGMA temp_store = MEMORY")

t0 = time.time()

# Test with EquipDB only
et_name = "EquipDB"
fname = ENTITY_TYPE_FILES[et_name]
path = os.path.join(DEC_BATCH, fname)
entries = parse_entries(path)
type_id = type_map[et_name]
print("{}: {} entries parsed in {:.1f}s".format(et_name, len(entries), time.time() - t0))

# Build entities batch
t1 = time.time()
entity_batch = []
for eidx, entry in enumerate(entries):
    tags = sorted(set(r["tag"] for r in entry))
    sig = " ".join("0x{:02x}".format(t) for t in tags)
    sig_hash = hashlib.md5(sig.encode()).hexdigest()[:12]
    sid = stable_id(fname, eidx, import_id)
    entity_batch.append((sid, type_id, import_id, fname, eidx, len(entry), len(tags), sig, sig_hash))

# Use transaction
conn.execute("BEGIN TRANSACTION")
cur.executemany("INSERT INTO entities (stable_id, entity_type_id, import_id, source_file, entry_index, field_count, tag_count, tag_signature, hash_hex) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", entity_batch)
conn.commit()
print("  Entity INSERT: {} rows in {:.1f}s".format(len(entity_batch), time.time() - t1))

# Build fields batch 
t2 = time.time()
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
print("  Field INSERT: {} rows in {:.1f}s".format(len(field_batch), time.time() - t2))

conn.execute("PRAGMA synchronous = FULL")
print("Total: {:.1f}s".format(time.time() - t0))

# Count
cur.execute("SELECT COUNT(*) FROM entities WHERE import_id = ?", (import_id,))
ec = cur.fetchone()[0]
cur.execute("SELECT COUNT(*) FROM entity_fields WHERE import_id = ?", (import_id,))
fc = cur.fetchone()[0]
print("Verified: {} entities, {} fields".format(ec, fc))

conn.close()
