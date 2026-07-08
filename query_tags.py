import sqlite3
conn = sqlite3.connect(r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db')
c = conn.cursor()
rows = c.execute("SELECT DISTINCT ef.tag_hex, et.name FROM entity_fields ef JOIN entities e ON ef.entity_id = e.id JOIN entity_types et ON e.entity_type_id = et.id WHERE ef.tag_hex IN ('0x1b','0x20','0x70','0x6f','0x50','0x51','0x05','0x06','0x07','0x08','0x09','0x0a') ORDER BY ef.tag_hex").fetchall()
print('Tags by entity type:')
for r in rows:
    print(f'  {r[0]} -> {r[1]}')
