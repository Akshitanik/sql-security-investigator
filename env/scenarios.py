import sqlite3


HACKER_IP = "192.168.1.50"


def init_db():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    # Create tables
    cursor.execute("""
        CREATE TABLE access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            status TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE firewall (
            blocked_ip TEXT
        )
    """)

    # Seed normal data
    logs = [
        ("192.168.1.1", "success"),
        ("192.168.1.2", "success"),
        ("192.168.1.3", "failed"),
        ("192.168.1.4", "success"),
        ("192.168.1.5", "failed"),
    ]

    # Add hacker multiple failed attempts
    hacker_logs = [
        (HACKER_IP, "failed"),
        (HACKER_IP, "failed"),
        (HACKER_IP, "failed"),
        (HACKER_IP, "failed"),
        (HACKER_IP, "failed"),
    ]

    cursor.executemany("INSERT INTO access_logs (ip, status) VALUES (?, ?)", logs + hacker_logs)

    conn.commit()
    return conn