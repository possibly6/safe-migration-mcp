"""Create examples/demo.db with a users + orders schema and a few rows."""
import sqlite3, os
from pathlib import Path

HERE = Path(__file__).parent
DB = HERE / "demo.db"
if DB.exists():
    DB.unlink()

con = sqlite3.connect(DB)
cur = con.cursor()
cur.executescript(
    """
    CREATE TABLE users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        email    TEXT NOT NULL UNIQUE,
        name     TEXT,
        created  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE orders (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id  INTEGER NOT NULL REFERENCES users(id),
        total    REAL NOT NULL,
        status   TEXT NOT NULL DEFAULT 'pending'
    );
    CREATE INDEX idx_orders_user ON orders(user_id);
    """
)
cur.executemany("INSERT INTO users (email, name) VALUES (?, ?)", [
    ("a@example.com", "Alice"),
    ("b@example.com", "Bob"),
    ("c@example.com", "Carol"),
])
cur.executemany("INSERT INTO orders (user_id, total, status) VALUES (?, ?, ?)", [
    (1, 19.99, "paid"),
    (1, 42.50, "pending"),
    (2, 7.00,  "paid"),
])
con.commit()
con.close()
print(f"wrote {DB}")
