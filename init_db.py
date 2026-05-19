import sqlite3

DB_FILE = "idrs.db"

conn = sqlite3.connect(DB_FILE)
cur = conn.cursor()

# Drop old tables if they exist (WARNING: this deletes existing data!)
cur.execute("DROP TABLE IF EXISTS alerts")
cur.execute("DROP TABLE IF EXISTS admins")
cur.execute("DROP TABLE IF EXISTS blocked_ips")

# Create alerts table with ALL columns your system needs
cur.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    threat TEXT NOT NULL,
    attacker_ip TEXT NOT NULL,
    victim_ip TEXT NOT NULL,
    details TEXT,
    detection_type TEXT DEFAULT 'rule',
    ml_score REAL,
    status TEXT DEFAULT 'active'
)
""")

# Create blocked_ips table
cur.execute("""
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    threat_type TEXT NOT NULL,
    blocked_at TEXT NOT NULL,
    expires_at TEXT,
    block_count INTEGER DEFAULT 1,
    status TEXT DEFAULT 'active',
    detection_source TEXT DEFAULT 'rule'
)
""")

# Create admins table
cur.execute("""
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()
conn.close()

print("[+] Database initialized successfully")
print("[+] Tables created: alerts, blocked_ips, admins")