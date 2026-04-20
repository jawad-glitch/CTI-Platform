import sqlite3
import os
import time
from db import get_connection, init_db

SQLITE_PATH = os.environ.get("SQLITE_PATH", "/data/cti.db")

SOURCE_CONFIDENCE = {
    "AlienVault OTX":   80,
    "URLHaus":          90,
    "SANS ISC":         75,
    "CISA Alerts":      95,
    "BleepingComputer": 60,
    "Threatpost":       60,
}

def get_sqlite_data():
    """
    Pull IOCs AND their article context from SQLite.
    The article is important — it groups IOCs that belong together.
    """
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get articles first — each article becomes a campaign node
    cursor.execute("SELECT id, source, title, url FROM articles")
    articles = cursor.fetchall()

    # Get IOCs grouped by article
    cursor.execute("""
        SELECT i.type, i.value, i.article_id, a.source
        FROM iocs i
        JOIN articles a ON i.article_id = a.id
    """)
    iocs = cursor.fetchall()
    conn.close()
    return articles, iocs

def upsert_object(cursor, type: str, value: str, confidence: int, source: str) -> int:
    """Insert or update an object, always return its ID."""
    cursor.execute("""
        INSERT INTO objects (type, value, confidence, source)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (type, value) DO UPDATE
            SET last_seen = NOW(),
                confidence = GREATEST(objects.confidence, EXCLUDED.confidence)
        RETURNING id
    """, (type, value, confidence, source))
    return cursor.fetchone()[0]

def add_relationship(cursor, from_id: int, relationship: str, to_id: int, source: str):
    try:
        cursor.execute("""
            INSERT INTO relationships (from_id, relationship, to_id, source)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, (from_id, relationship, to_id, source))
    except Exception:
        pass

def add_tag(cursor, object_id: int, tag: str):
    try:
        cursor.execute("""
            INSERT INTO tags (object_id, tag)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
        """, (object_id, tag))
    except Exception:
        pass

import time  # add this at the top if not already there

def run_import():
    print("[Importer] Waiting for PostgreSQL to be ready...")
    time.sleep(5)

    print("[Importer] Starting...")
    init_db()

    while True:
        articles, iocs = get_sqlite_data()
        print(f"[Importer] {len(articles)} articles, {len(iocs)} IOCs found")

        pg_conn = get_connection()
        cursor = pg_conn.cursor()

        article_node_ids = {}
        for article in articles:
            confidence = SOURCE_CONFIDENCE.get(article["source"], 50)
            title = article["title"][:200] if article["title"] else "Unknown"

            campaign_id = upsert_object(cursor, "campaign", title, confidence, article["source"])
            article_node_ids[article["id"]] = campaign_id

            if article["source"] == "CISA Alerts":
                add_tag(cursor, campaign_id, "actively-exploited")
            if article["source"] == "AlienVault OTX":
                add_tag(cursor, campaign_id, "community-verified")
            if article["source"] == "URLHaus":
                add_tag(cursor, campaign_id, "malware-delivery")

        pg_conn.commit()

        imported = 0
        for ioc in iocs:
            ioc_type   = ioc["type"]
            ioc_value  = ioc["value"]
            source     = ioc["source"]
            article_id = ioc["article_id"]
            confidence = SOURCE_CONFIDENCE.get(source, 50)

            try:
                ioc_id = upsert_object(cursor, ioc_type, ioc_value, confidence, source)
                campaign_id = article_node_ids.get(article_id)
                if campaign_id:
                    add_relationship(cursor, ioc_id, "part-of", campaign_id, source)

                if source == "URLHaus":
                    add_tag(cursor, ioc_id, "malware-delivery")
                if source == "CISA Alerts":
                    add_tag(cursor, ioc_id, "actively-exploited")

                imported += 1
            except Exception as e:
                print(f"[Importer] Error: {e}")

        pg_conn.commit()
        cursor.close()
        pg_conn.close()

        print(f"[Importer] Cycle done. {imported} IOCs processed. Sleeping 60s...")
        time.sleep(60)  # check for new data every 60 seconds

if __name__ == "__main__":
    run_import()
