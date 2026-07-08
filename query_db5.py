import sqlite3
conn = sqlite3.connect(r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db')
c = conn.cursor()

# Check ConfigDB entries
c.execute('''SELECT e.id, e.stable_id, e.entry_index, ef.tag_hex, ef.value, ef.field_index, ef.role 
FROM entities e JOIN entity_fields ef ON ef.entity_id = e.id 
WHERE e.entity_type_id = 9 AND ef.tag_hex IN (\"0x01\",\"0x02\",\"0x03\",\"0x04\",\"0x05\",\"0x06\",\"0x07\",\"0x08\",\"0x09\",\"0x0a\")
AND ef.value > 0 AND ef.value < 1000
LIMIT 50''')
print('=== ConfigDB small values (constants) ===')
for row in c.fetchall():
    print(row)
print()

# Check StageDB for formation/slot related
c.execute('''SELECT e.id, e.stable_id, e.entry_index, ef.tag_hex, ef.value, ef.field_index, ef.role 
FROM entities e JOIN entity_fields ef ON ef.entity_id = e.id 
WHERE e.entity_type_id = 5 AND ef.tag_hex IN (\"0x1b\",\"0x20\",\"0x70\",\"0x6f\",\"0x50\",\"0x51\")
LIMIT 50''')
print('=== StageDB formation/slot related fields ===')
for row in c.fetchall():
    print(row)
print()

# Check HeroRosterDB for team/position/slot
c.execute('''SELECT e.id, e.stable_id, e.entry_index, ef.tag_hex, ef.value, ef.field_index, ef.role 
FROM entities e JOIN entity_fields ef ON ef.entity_id = e.id 
WHERE e.entity_type_id = 4 AND ef.tag_hex IN (\"0x1b\",\"0x20\",\"0x70\",\"0x6f\",\"0x50\",\"0x51\",\"0x05\",\"0x06\",\"0x07\",\"0x08\")
LIMIT 50''')
print('=== HeroRosterDB position/slot fields ===')
for row in c.fetchall():
    print(row)
print()

# Check semantic_mappings for anything formation/slot related
c.execute('SELECT * FROM semantic_mappings WHERE field_name LIKE \"%formation%\" OR field_name LIKE \"%slot%\" OR field_name LIKE \"%team%\" OR field_name LIKE \"%position%\" OR field_name LIKE \"%lineup%\" OR field_name LIKE \"%battle%\" OR field_name LIKE \"%deploy%\"')
print('=== Semantic mappings for formation/slot ===')
for row in c.fetchall():
    print(row)
print()

# Check known_ids for formation/slot related
c.execute('SELECT * FROM known_ids WHERE label LIKE \"%formation%\" OR label LIKE \"%slot%\" OR label LIKE \"%team%\" OR label LIKE \"%position%\" OR label LIKE \"%lineup%\" OR label LIKE \"%battle%\" OR label LIKE \"%config%\" LIMIT 30')
print('=== Known IDs for formation/slot/config ===')
for row in c.fetchall():
    print(row)
