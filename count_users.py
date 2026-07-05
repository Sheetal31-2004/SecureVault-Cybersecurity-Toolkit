import sqlite3

conn=sqlite3.connect("securevault.db")
cur=conn.cursor()

cur.execute("SELECT COUNT(*) FROM users")

print(cur.fetchone()[0])

conn.close()