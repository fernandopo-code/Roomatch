import sqlite3, os

DB_PATH = r'c:\Users\Phemcode\Downloads\roommatch\roommatch\roommatch.db'
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

# Count by type
cur.execute('SELECT type, COUNT(*) FROM listings GROUP BY type')
print('Listings by type:', cur.fetchall())

# Find NYC listings (city contains "New York" or "NY")
cur.execute("SELECT * FROM listings WHERE city LIKE '%New York%' OR city LIKE '%NY%'")
rows = cur.fetchall()
print(f'NYC listings count: {len(rows)}')
for r in rows:
    print(r)

conn.close()
