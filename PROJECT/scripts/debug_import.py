"""Test import logic."""
import sqlite3, os, sys
sys.path.insert(0, 'scripts')
from mla_diff import ENTITY_TYPE_FILES, register_import, stable_id, parse_entries

DB_PATH = r'C:\Users\NGEONG\Videos\MLA\PROJECT\cache\mla_database.db'
DEC_BATCH = r'C:\Users\NGEONG\Videos\MLA\PROJECT\decrypted\dec_batch'

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# Check type_map
cur.execute("SELECT id, name FROM entity_types")
type_map = dict(cur.fetchall())
print("Type map:", type_map)

# Simulate import loop
for et_name, fname in ENTITY_TYPE_FILES.items():
    path = os.path.join(DEC_BATCH, fname)
    exists = os.path.exists(path)
    type_id = type_map.get(et_name)
    print("  et_name={!r} type_id={} file_exists={}".format(et_name, type_id, exists))

conn.close()
