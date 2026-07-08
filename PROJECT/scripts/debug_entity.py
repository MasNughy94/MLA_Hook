"""Debug entity lookup."""
import sqlite3, os

db = r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db'
conn = sqlite3.connect(db)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# Check what stable_ids look like for entries with ID 2111
q = "SELECT e.stable_id, e.source_file, e.entry_index, f.value, f.tag FROM entities e JOIN entity_fields f ON e.id = f.entity_id WHERE f.value = 2111 LIMIT 5"
cur.execute(q)
rows = cur.fetchall()
print("Found {} rows for value 2111".format(len(rows)))
for r in rows:
    print("  stable_id={!r} file={} entry={} tag={} val={}".format(
        r['stable_id'], r['source_file'], r['entry_index'], r['tag'], r['value']))

# Show a sample entity
print()
q2 = "SELECT stable_id FROM entities LIMIT 3"
cur.execute(q2)
for r in cur.fetchall():
    print("  Example stable_id: {!r}".format(r['stable_id']))

conn.close()
