import sqlite3
conn = sqlite3.connect(r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db')
c = conn.cursor()

# Get MasterDB entries 0-10
c.execute("SELECT * FROM entities WHERE entity_type_id=8 AND entry_index BETWEEN 0 AND 10 ORDER BY entry_index")
entries = c.fetchall()
for ent in entries:
    ent_id = ent[0]
    entry_idx = ent[5]
    tag_count = ent[8]
    tag_sig = ent[9]
    print(f'Entry {entry_idx}: id={ent_id}, {tag_count} tags, signature={tag_sig}')
    c.execute("SELECT * FROM entity_fields WHERE entity_id=? ORDER BY field_index", (ent_id,))
    fields = c.fetchall()
    for f in fields:
        print(f'    Field idx={f[7]}: tag={f[4]} tag_hex={f[4]} val={f[6]}')
    print()

conn.close()
