import sqlite3

def setup_database():
    print("=" * 60)
    print("        ZETECH UNIVERSITY NIDS - DATABASE SETUP          ")
    print("=" * 60)
    
    db_name = 'zetech_nids.db'
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    print("[*] Creating ADMIN_USER table...")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ADMIN_USER (
            admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    ''')

    print("[*] Creating SIGNATURE_RULE table...")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS SIGNATURE_RULE (
            rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_type TEXT NOT NULL,
            protocol TEXT NOT NULL,
            port INTEGER NOT NULL
        )
    ''')

    print("[*] Creating general LOGS table...")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS LOGS (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            time_logged TIMESTAMP DEFAULT (datetime('now', 'localtime')),
            source_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL,
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            rule_id INTEGER
        )
    ''')

    print("[*] Creating updated ALERT_LOG table...")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ALERT_LOG (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            time_logged TIMESTAMP DEFAULT (datetime('now', 'localtime')),
            source_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL,
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            rule_id INTEGER,
            FOREIGN KEY(rule_id) REFERENCES SIGNATURE_RULE(rule_id)
        )
    ''')

    # --- NEW: Settings table for the Auto-Delete Janitor ---
    print("[*] Creating SYSTEM_SETTINGS table for log rotation...")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS SYSTEM_SETTINGS (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            retention_hours INTEGER NOT NULL
        )
    ''')
    # Default to 24 hours
    cursor.execute("INSERT OR IGNORE INTO SYSTEM_SETTINGS (id, retention_hours) VALUES (1, 24)")

    print("[*] Populating initial threat signatures...")
    cursor.execute("INSERT OR IGNORE INTO SIGNATURE_RULE (rule_id, threat_type, protocol, port) VALUES (1, 'Unauthorized SSH Scan', 'TCP', 22)")
    cursor.execute("INSERT OR IGNORE INTO SIGNATURE_RULE (rule_id, threat_type, protocol, port) VALUES (2, 'Suspicious Telnet Activity', 'TCP', 23)")
    cursor.execute("INSERT OR IGNORE INTO SIGNATURE_RULE (rule_id, threat_type, protocol, port) VALUES (3, 'Unsecured HTTP Traffic', 'TCP', 80)")

    conn.commit()
    conn.close()
    print(f"[+] Success! Fresh database '{db_name}' initialized with settings table.")

if __name__ == "__main__":
    setup_database()