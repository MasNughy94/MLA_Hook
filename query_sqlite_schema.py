import sqlite3, json
conn = sqlite3.connect(r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db')
c = conn.cursor()

# List tables and their schemas
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [r[0] for r in c.fetchall()]
print('Tables:', tables)

for table in tables:
    c.execute(f"PRAGMA table_info('{table}')")
    cols = c.fetchall()
    row_count = c.execute(f"SELECT COUNT(*) FROM '{table}'").fetchone()[0]
    print(f'  {table}: {len(cols)} cols, {row_count} rows')
    print(f'    Columns: {[(col[1], col[2]) for col in cols]}')

conn.close()
