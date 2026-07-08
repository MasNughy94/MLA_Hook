import sqlite3
conn = sqlite3.connect(r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db')
c = conn.cursor()
# Check all tags and entity types related to formation
c.execute("SELECT DISTINCT ef.tag, ef.entity_type_id, et.name FROM entity_fields ef JOIN entity_types et ON ef.entity_type_id = et.id WHERE ef.tag IN ('0x1b','0x20','0x70','0x6f','0x1c','0x05','0x06','0x07','0x08','0x09','0x0a','0x50','0x51')")
print('=== key tags with entity types ===')
for row in c.fetchall():
    print(row)
print()
# Find all entity types with their field counts
c.execute("SELECT et.id, et.name, et.file_hash, COUNT(ef.id) as field_count FROM entity_types et LEFT JOIN entity_fields ef ON ef.entity_type_id = et.id GROUP BY et.id ORDER BY field_count DESC LIMIT 50")
print('=== entity types by field count ===')
for row in c.fetchall():
    print(row)
print()
# Search for ConfigDB
c.execute("SELECT * FROM entity_types WHERE name LIKE '%Config%' OR name LIKE '%config%'")
print('=== Config entity types ===')
for row in c.fetchall():
    print(row)
