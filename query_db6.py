import sqlite3
conn = sqlite3.connect(r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db')
c = conn.cursor()

# Search ConfigDB for battle/formation related constants
c.execute('''SELECT e.stable_id, e.entry_index, et.name as entity_type, GROUP_CONCAT(ef.tag_hex || \"=\" || ef.value, \", \") as fields
FROM entities e 
JOIN entity_fields ef ON ef.entity_id = e.id 
JOIN entity_types et ON e.entity_type_id = et.id
WHERE e.entity_type_id = 9 
AND e.entry_index BETWEEN 2200 AND 2300
GROUP BY e.id
LIMIT 30''')
print('=== ConfigDB entries 2200-2300 ===')
for row in c.fetchall():
    print(row)
print()

# Also look at specific entry indices that might be formation
c.execute('''SELECT e.id, e.stable_id, e.entry_index, et.name, ef.tag_hex, ef.value, ef.field_index, ef.role
FROM entities e
JOIN entity_fields ef ON ef.entity_id = e.id
JOIN entity_types et ON e.entity_type_id = et.id
WHERE e.entity_type_id = 9 AND e.entry_index IN (1,2,3,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20)
ORDER BY e.entry_index, ef.field_index''')
print('=== ConfigDB first 20 entries (all fields) ===')
prev = None
for row in c.fetchall():
    if prev != row[1]:
        print(f'--- Entry {row[2]} ({row[1]}) ---')
        prev = row[1]
    print(f'  tag={row[4]} val={row[5]} idx={row[6]} role={row[7]}')
