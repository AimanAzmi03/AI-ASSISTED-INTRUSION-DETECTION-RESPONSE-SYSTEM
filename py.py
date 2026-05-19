import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("idrs.db")
cur = conn.cursor()

cur.execute(
    "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
    ("admin", generate_password_hash("admin123"))
)

conn.commit()
conn.close()
