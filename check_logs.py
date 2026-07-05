import sqlite3

conn = sqlite3.connect("securevault.db")

cur = conn.cursor()

cur.execute("SELECT * FROM activity_log")

rows = cur.fetchall()

for row in rows:
    print(row)

conn.close()