import feedparser
import time
import os
from datetime import datetime
from db import init_db, get_connection
from extractor import extract_iocs
from otx_collector import run_otx_collection
from urlhaus_collector import run_urlhaus_collection

# --- Your RSS feeds ---
# These are real security threat intel RSS feeds
RSS_FEEDS = [
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "SANS ISC",         "url": "https://isc.sans.edu/rssfeed_full.xml"},
    {"name": "Threatpost",       "url": "https://threatpost.com/feed/"},
    {"name": "CISA Alerts",      "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
]

POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", 300))  # 5 minutes default


def store_article(conn, source: str, title: str, url: str, content: str, published_at: str) -> int | None:
    """
    Stores article in DB. Returns the new article's ID, or None if it already existed.
    """
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO articles (source, title, url, content, published_at)
            VALUES (?, ?, ?, ?, ?)
        """, (source, title, url, content, published_at))
        conn.commit()
        return cursor.lastrowid  # the ID of the newly inserted row
    except Exception:
        # UNIQUE constraint on url fired — article already exists
        return None


def store_iocs(conn, article_id: int, iocs: list[dict]):
    cursor = conn.cursor()
    for ioc in iocs:
        try:
            cursor.execute("""
                INSERT INTO iocs (article_id, type, value)
                VALUES (?, ?, ?)
            """, (article_id, ioc["type"], ioc["value"]))
        except Exception:
            pass  # duplicate IOC — already in DB from another article
    conn.commit()


def process_feed(feed_config: dict):
    name = feed_config["name"]
    url = feed_config["url"]

    print(f"[{name}] Fetching...")
    feed = feedparser.parse(url)

    if feed.bozo:  # feedparser sets this if the feed is malformed
        print(f"[{name}] WARNING: Feed may be malformed")

    conn = get_connection()
    new_count = 0

    for entry in feed.entries:
        title = entry.get("title", "No title")
        link = entry.get("link", "")
        
        # Get the full text — summary or full content if available
        content = entry.get("summary", "")
        if hasattr(entry, "content"):
            content = entry.content[0].value

        published = entry.get("published", str(datetime.utcnow()))

        # Try to store — returns None if already seen
        article_id = store_article(conn, name, title, link, content, published)

        if article_id:
            new_count += 1
            iocs = extract_iocs(content + " " + title)
            store_iocs(conn, article_id, iocs)
            print(f"[{name}] NEW: '{title}' — {len(iocs)} IOCs extracted")

    conn.close()
    print(f"[{name}] Done. {new_count} new articles.")


def run():
    print("[RSS Ingestor] Starting...")
    init_db()

    while True:
        # RSS feeds
        for feed in RSS_FEEDS:
            try:
                process_feed(feed)
            except Exception as e:
                print(f"[ERROR] {feed['name']}: {e}")

        # OTX
        try:
            run_otx_collection()
        except Exception as e:
            print(f"[ERROR] OTX: {e}")

        try:
            run_urlhaus_collection()
        except Exception as e:
            print(f"[ERROR] URLHaus: {e}")

        print(f"[RSS Ingestor] Sleeping {POLL_INTERVAL}s...\n")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
