import sqlite3

conn = sqlite3.connect("securevault.db")
cur = conn.cursor()

cur.execute("SELECT * FROM users")

for row in cur.fetchall():
    print(row)

conn.close()