import sqlite3
conn = sqlite3.connect(r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db')
c = conn.cursor()
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
print('=== TABLES ===')
for row in c.fetchall():
    print(row[0])
print()
c.execute("SELECT * FROM entity_types")
rows = c.fetchall()
print(f'=== ENTITY TYPES (total {len(rows)}) ===')
for row in rows:
    name = row[1] if len(row) > 1 else '?'
    if any(kw in str(name).lower() for kw in ['config','formation','slot','team','lineup','deploy','battle','layout','position','arena','camp','stage','compo','party','squad','group','tactic']):
        print(row)
print()
c.execute("SELECT * FROM entity_fields WHERE tag = '0x1b' LIMIT 30")
print('=== Fields with tag 0x1b (team position) ===')
for row in c.fetchall():
    print(row)
print()
c.execute("SELECT * FROM entity_fields WHERE tag = '0x20' LIMIT 30")
print('=== Fields with tag 0x20 (Formation/Layout ID) ===')
for row in c.fetchall():
    print(row)
print()
c.execute("SELECT * FROM entity_fields WHERE tag = '0x70' LIMIT 30")
print('=== Fields with tag 0x70 (position slot ID) ===')
for row in c.fetchall():
    print(row)
