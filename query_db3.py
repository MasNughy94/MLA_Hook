import sqlite3
conn = sqlite3.connect(r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db')
c = conn.cursor()
# Check schemas
c.execute("PRAGMA table_info(entity_types)")
print('entity_types columns:')
for row in c.fetchall():
    print(row)
print()
c.execute("PRAGMA table_info(entity_fields)")
print('entity_fields columns:')
for row in c.fetchall():
    print(row)
print()
c.execute("PRAGMA table_info(entities)")
print('entities columns:')
for row in c.fetchall():
    print(row)
