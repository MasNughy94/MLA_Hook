"""Test relationship building with Python grouping."""
import sqlite3, os, sys, time
sys.path.insert(0, 'scripts')
from mla_diff import build_relationships_for_import

DB_PATH = r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db'

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

import_id = 2
print("Testing relationship building for import #2 (EquipDB only)...")
t0 = time.time()
rel_count = build_relationships_for_import(conn, import_id)
print("Done in {:.1f}s".format(time.time() - t0))

cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM relationships WHERE discovered_in_import = ?", (import_id,))
print("Total relationships stored: {}".format(cur.fetchone()[0]))
conn.close()
