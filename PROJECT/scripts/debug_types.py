"""Debug entity_types table."""
import sqlite3
db = r'C:\Users\NGEONG\Videos\MLA\PROJECT\cache\mla_database.db'
conn = sqlite3.connect(db)
conn.row_factory = sqlite3.Row
cur = conn.cursor()
cur.execute("SELECT * FROM entity_types")
for r in cur.fetchall():
    print("  id={} name={!r}".format(r['id'], r['name']))
cur.execute("SELECT id, version_id FROM version_imports")
for r in cur.fetchall():
    print("  import: id={} version={}".format(r['id'], r['version_id']))
conn.close()
