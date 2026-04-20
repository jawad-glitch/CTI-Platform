import psycopg2
import os

DB_CONFIG = {
    "host":     os.environ.get("POSTGRES_HOST", "postgres"),
    "port":     int(os.environ.get("POSTGRES_PORT", 5432)),
    "dbname":   os.environ.get("POSTGRES_DB", "cti"),
    "user":     os.environ.get("POSTGRES_USER", "cti"),
    "password": os.environ.get("POSTGRES_PASSWORD", "cti_password"),
}

def get_connection():
    conn = psycopg2.connect(**DB_CONFIG)
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS objects (
            id          SERIAL PRIMARY KEY,
            type        TEXT NOT NULL,
            value       TEXT NOT NULL,
            confidence  INTEGER DEFAULT 50,
            source      TEXT,
            first_seen  TIMESTAMP DEFAULT NOW(),
            last_seen   TIMESTAMP DEFAULT NOW(),
            UNIQUE(type, value)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS relationships (
            id              SERIAL PRIMARY KEY,
            from_id         INTEGER REFERENCES objects(id),
            relationship    TEXT NOT NULL,
            to_id           INTEGER REFERENCES objects(id),
            source          TEXT,
            created_at      TIMESTAMP DEFAULT NOW(),
            UNIQUE(from_id, relationship, to_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tags (
            id          SERIAL PRIMARY KEY,
            object_id   INTEGER REFERENCES objects(id),
            tag         TEXT NOT NULL,
            UNIQUE(object_id, tag)
        )
    """)

    conn.commit()
    cursor.close()
    conn.close()
    print("[Graph DB] Initialized successfully")
