"""Test relationship building performance."""
import sqlite3, os, sys, time
sys.path.insert(0, 'scripts')
from mla_diff import parse_entries, ENTITY_TYPE_FILES, build_relationships_for_import

DB_PATH = r'C:\Users\NGEONG\Videos\MLA\PROJECT\cache\mla_database.db'

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

import_id = 2  # Only has EquipDB currently

print("Testing relationship building...")
t0 = time.time()

# Temp table approach
cur.execute("CREATE TEMP TABLE IF NOT EXISTS _candidate_ids AS SELECT DISTINCT f.value FROM entity_fields f WHERE f.value BETWEEN 1000 AND 65535 AND f.import_id = ?", (import_id,))
cur.execute("SELECT COUNT(*) FROM _candidate_ids")
print("  Candidate IDs: {} in {:.1f}s".format(cur.fetchone()[0], time.time() - t0))

t1 = time.time()
cur.execute("""
    SELECT f1.entity_id, f2.entity_id, f1.value, e1.entity_type_id, e2.entity_type_id
    FROM entity_fields f1
    JOIN _candidate_ids c ON f1.value = c.value
    JOIN entity_fields f2 ON f1.value = f2.value AND f1.entity_id < f2.entity_id
    JOIN entities e1 ON f1.entity_id = e1.id
    JOIN entities e2 ON f2.entity_id = e2.id
    WHERE f1.import_id = ? AND f2.import_id = ?
      AND e1.entity_type_id != e2.entity_type_id
    GROUP BY f1.entity_id, f2.entity_id
    LIMIT 1000
""", (import_id, import_id))
results = cur.fetchall()
print("  Query (limited): {} results in {:.1f}s".format(len(results), time.time() - t1))

# Check full count
t2 = time.time()
cur.execute("""
    SELECT COUNT(*) as cnt FROM (
        SELECT f1.entity_id, f2.entity_id
        FROM entity_fields f1
        JOIN _candidate_ids c ON f1.value = c.value
        JOIN entity_fields f2 ON f1.value = f2.value AND f1.entity_id < f2.entity_id
        JOIN entities e1 ON f1.entity_id = e1.id
        JOIN entities e2 ON f2.entity_id = e2.id
        WHERE f1.import_id = ? AND f2.import_id = ?
          AND e1.entity_type_id != e2.entity_type_id
        GROUP BY f1.entity_id, f2.entity_id
    )
""", (import_id, import_id))
cnt = cur.fetchone()[0]
print("  Total relationships: {} in {:.1f}s".format(cnt, time.time() - t2))

cur.execute("DROP TABLE IF EXISTS _candidate_ids")
conn.close()
