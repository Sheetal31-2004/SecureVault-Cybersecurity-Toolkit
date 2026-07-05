import sqlite3

def init_db():

    conn = sqlite3.connect("securevault.db")

    cur = conn.cursor()

    # Users Table

    cur.execute("""

    CREATE TABLE IF NOT EXISTS users(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT NOT NULL,

    email TEXT UNIQUE NOT NULL,

    password TEXT NOT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

    )

    """)

    # Activity Log Table

    cur.execute("""

    CREATE TABLE IF NOT EXISTS activity_log(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT,

    activity TEXT,

    details TEXT,

    timestamp DATETIME DEFAULT (datetime('now','+5 hours','+30 minutes'))

    )

    """)



    # Scan History Table

    cur.execute("""

    CREATE TABLE IF NOT EXISTS scan_history(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    target TEXT,

    scan_type TEXT,

    risk_score TEXT,

    scan_date DATETIME DEFAULT CURRENT_TIMESTAMP

    )

    """)

    conn.commit()
    conn.close()

if __name__ == "__main__":

    init_db()

    print("Database Created!")