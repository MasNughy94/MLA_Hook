import sqlite3, json
conn = sqlite3.connect(r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db')
c = conn.cursor()

# Check what tables exist
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
print('Tables:', [r[0] for r in c.fetchall()])

# Check entity_type table  
c.execute("SELECT * FROM entity_type ORDER BY type_id")
print('Entity types:')
for row in c.fetchall():
    print(f'  {row}')

print()

# Check entity_entry table - 3 entries about MasterDB entries 3,4,5 (formation)
c.execute("SELECT * FROM entity_entry WHERE entity_type_id=1 LIMIT 20")
print('Entity entries (first 20):')
for row in c.fetchall():
    print(f'  {row}')

print()

# Look at the field_count table
c.execute("SELECT * FROM field_count")
print('Field counts:')
for row in c.fetchall():
    print(f'  {row}')

conn.close()
