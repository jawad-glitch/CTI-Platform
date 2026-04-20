import sqlite3
import os

# First we will make a variable that will take the path of the db file from out env variable.
DB_PATH = os.environ.get("DB_PATH", "/home/dell/CTI-project/data/cti.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Store Raw Arcticles from RSS feed 
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS articles(
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            source  TEXT NOT NULL,
            title   TEXT NOT NULL,
            url     TEXT UNIQUE NOT NULL,
            content TEXT,
            published_at TEXT,
            fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)


        # Stores IOCs extracted from articles
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id  INTEGER NOT NULL,
            type        TEXT NOT NULL,   -- 'ip', 'domain', 'url', 'md5', 'sha256', 'cve'
            value       TEXT NOT NULL,
            first_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (article_id) REFERENCES articles(id),
            UNIQUE(type, value)          -- same IOC from 2 articles = 1 entry
        )
    """)

    conn.commit()
    conn.close()
    print("DB initialized successfuly")
