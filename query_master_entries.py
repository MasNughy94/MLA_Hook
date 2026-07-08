import sqlite3, json
conn = sqlite3.connect(r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db')
c = conn.cursor()

# Find MasterDB entity_type_id
c.execute("SELECT * FROM entity_types")
print('Entity types:')
for row in c.fetchall():
    print(f'  {row}')
print()

# Find source file for MasterDB (0217cb...)
c.execute("SELECT * FROM entity_types WHERE source_file LIKE '%0217%' OR name LIKE '%master%'")
print('MasterDB info:')
for row in c.fetchall():
    master_type_id = row[0]
    print(f'  {row}')
print()

# Now get entities for MasterDB that are entries 0-10 (entry_index)
if master_type_id:
    c.execute("SELECT * FROM entities WHERE entity_type_id=? AND entry_index BETWEEN 0 AND 10 ORDER BY entry_index", (master_type_id,))
    print(f'MasterDB entries 0-10:')
    for row in c.fetchall():
        print(f'  {row}')
        # Also get their fields
        ent_id = row[0]
        c.execute("SELECT * FROM entity_fields WHERE entity_id=? ORDER BY field_index", (ent_id,))
        fields = c.fetchall()
        for f in fields:
            print(f'    Field idx={f[7]}: tag=0x{f[4]:>02x} val={f[6]}')

conn.close()
