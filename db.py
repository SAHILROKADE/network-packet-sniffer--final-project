import sqlite3

conn = sqlite3.connect("packets.db")
c = conn.cursor()

c.execute('''
CREATE TABLE IF NOT EXISTS packets (
    timestamp REAL,
    src TEXT,
    dst TEXT,
    sport INTEGER,
    dport INTEGER,
    flags TEXT,
    length INTEGER
)
''')

def insert_packet(ts, src, dst, sport, dport, flags, length):
    c.execute("INSERT INTO packets VALUES (?, ?, ?, ?, ?, ?, ?)",
              (ts, src, dst, sport, dport, flags, length))
    conn.commit()
