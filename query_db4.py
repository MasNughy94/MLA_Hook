import sqlite3
conn = sqlite3.connect(r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db')
c = conn.cursor()

# Get all entity types
c.execute('SELECT * FROM entity_types')
print('=== ALL ENTITY TYPES ===')
for row in c.fetchall():
    print(f'ID={row[0]}, Name={row[1]}, Short={row[2]}, Type={row[3]}, Desc={row[4]}, File={row[5]}, Entries={row[6]}, MaxFields={row[7]}, TopTag={row[8]}')
print()

# Get fields with tag 0x1b, 0x20, 0x70 through entities
c.execute('SELECT ef.id, ef.entity_id, ef.tag_hex, ef.tag_char, ef.value, ef.field_index, ef.role, et.name as entity_name FROM entity_fields ef JOIN entities e ON ef.entity_id = e.id JOIN entity_types et ON e.entity_type_id = et.id WHERE ef.tag_hex = \"0x1b\" LIMIT 30')
print('=== Fields with tag 0x1b ===')
for row in c.fetchall():
    print(row)
print()

c.execute('SELECT ef.id, ef.entity_id, ef.tag_hex, ef.tag_char, ef.value, ef.field_index, ef.role, et.name as entity_name FROM entity_fields ef JOIN entities e ON ef.entity_id = e.id JOIN entity_types et ON e.entity_type_id = et.id WHERE ef.tag_hex = \"0x20\" LIMIT 30')
print('=== Fields with tag 0x20 ===')
for row in c.fetchall():
    print(row)
print()

c.execute('SELECT ef.id, ef.entity_id, ef.tag_hex, ef.tag_char, ef.value, ef.field_index, ef.role, et.name as entity_name FROM entity_fields ef JOIN entities e ON ef.entity_id = e.id JOIN entity_types et ON e.entity_type_id = et.id WHERE ef.tag_hex = \"0x70\" LIMIT 30')
print('=== Fields with tag 0x70 ===')
for row in c.fetchall():
    print(row)
print()

c.execute('PRAGMA table_info(known_ids)')
print('known_ids columns:')
for row in c.fetchall():
    print(row)
print()
c.execute('PRAGMA table_info(tag_definitions)')
print('tag_definitions columns:')
for row in c.fetchall():
    print(row)
print()
c.execute('PRAGMA table_info(semantic_mappings)')
print('semantic_mappings columns:')
for row in c.fetchall():
    print(row)
