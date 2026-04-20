import requests
import csv
import io
from db import get_connection

URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"

def run_urlhaus_collection():
    print("[URLHaus] Fetching malicious URL feed...")

    response = requests.get(URLHAUS_CSV, timeout=60)
    if response.status_code != 200:
        print(f"[URLHaus] Failed: {response.status_code}")
        return

    conn = get_connection()
    cursor = conn.cursor()

    # Store as a single article representing the feed snapshot
    try:
        cursor.execute("""
            INSERT INTO articles (source, title, url, content, published_at)
            VALUES (?, ?, ?, ?, datetime('now'))
        """, (
            "URLHaus",
            "URLHaus Malicious URL Feed Snapshot",
            URLHAUS_CSV,
            "Automated URLHaus feed ingestion"
        ))
        conn.commit()
        article_id = cursor.lastrowid
    except Exception:
        print("[URLHaus] Snapshot already stored, updating IOCs only")
        cursor.execute("SELECT id FROM articles WHERE source='URLHaus' ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        if not row:
            conn.close()
            return
        article_id = row["id"]

    # Parse the CSV — skip comment lines starting with #
    lines = response.text.splitlines()
    clean_lines = [l for l in lines if not l.startswith("#")]
    
    reader = csv.DictReader(clean_lines, fieldnames=[
        "id", "dateadded", "url", "url_status", 
        "threat", "tags", "urlhaus_link"
    ])

    stored = 0
    skipped = 0

    for row in reader:
        url = row.get("url", "").strip().strip('"')
        status = row.get("url_status", "").strip().strip('"')
        threat = row.get("threat", "").strip().strip('"')

        if not url or not url.startswith("http"):
            continue

        # Only store active malicious URLs — offline ones are less actionable
        if status != "online":
            skipped += 1
            continue

        try:
            cursor.execute("""
                INSERT INTO iocs (article_id, type, value)
                VALUES (?, ?, ?)
            """, (article_id, "url", url))
            stored += 1
        except Exception:
            pass  # duplicate

    conn.commit()
    conn.close()
    print(f"[URLHaus] Done. {stored} malicious URLs stored, {skipped} offline skipped.")
