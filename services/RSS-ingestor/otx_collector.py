import requests
import os
import time
from db import get_connection

OTX_API_KEY = os.environ.get("OTX_API_KEY")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# OTX gives you "pulses" — think of a pulse as a threat report
# Each pulse contains a list of IOCs related to that threat
# We'll pull the latest pulses from the past 7 days

def fetch_pulses(days_back: int = 7, max_pages: int = 5) -> list:
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    params = {"limit": 50, "page": 1}
    url = f"{OTX_BASE_URL}/pulses/subscribed"

    pulses = []

    while params["page"] <= max_pages:  # stop after 5 pages = 250 pulses max
        print(f"[OTX] Fetching page {params['page']}...")
        response = requests.get(url, headers=headers, params=params, timeout=60)  # increased from 30

        if response.status_code != 200:
            print(f"[OTX] Error: {response.status_code}")
            break

        data = response.json()
        results = data.get("results", [])

        if not results:
            break

        pulses.extend(results)

        if not data.get("next"):
            break

        params["page"] += 1
        time.sleep(2)  # increased from 1

    print(f"[OTX] Fetched {len(pulses)} pulses total")
    return pulses


def store_otx_pulse(conn, pulse: dict) -> int | None:
    """
    A pulse in OTX = a threat report.
    We store it as an article just like RSS — same table, same structure.
    This is important: everything goes into one unified articles table.
    That's what makes it an intelligence platform, not just a feed reader.
    """
    cursor = conn.cursor()
    
    title = pulse.get("name", "Unknown Pulse")
    url = f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}"
    content = pulse.get("description", "")
    published_at = pulse.get("created", "")
    
    # Add tags to content so they're searchable later
    tags = pulse.get("tags", [])
    if tags:
        content += f"\nTags: {', '.join(tags)}"

    try:
        cursor.execute("""
            INSERT INTO articles (source, title, url, content, published_at)
            VALUES (?, ?, ?, ?, ?)
        """, ("AlienVault OTX", title, url, content, published_at))
        conn.commit()
        return cursor.lastrowid
    except Exception:
        return None  # already stored


def store_otx_iocs(conn, article_id: int, indicators: list):
    """
    OTX gives us pre-extracted IOCs called 'indicators'.
    Each indicator has a type and value already labeled.
    We just normalize the type names to match our schema.
    """
    cursor = conn.cursor()

    # OTX uses different type names than our schema — normalize them
    TYPE_MAP = {
        "IPv4":         "ipv4",
        "IPv6":         "ipv6",
        "domain":       "domain",
        "hostname":     "domain",
        "URL":          "url",
        "FileHash-MD5": "md5",
        "FileHash-SHA256": "sha256",
        "FileHash-SHA1":   "sha1",
        "CVE":          "cve",
    }

    stored = 0
    for indicator in indicators:
        raw_type = indicator.get("type", "")
        value = indicator.get("indicator", "")
        normalized_type = TYPE_MAP.get(raw_type)

        if not normalized_type or not value:
            continue  # skip unknown types

        try:
            cursor.execute("""
                INSERT INTO iocs (article_id, type, value)
                VALUES (?, ?, ?)
            """, (article_id, normalized_type, value))
            stored += 1
        except Exception:
            pass  # duplicate

    conn.commit()
    print(f"[OTX] Stored {stored} IOCs for article {article_id}")


def run_otx_collection():
    if not OTX_API_KEY:
        print("[OTX] No API key found — skipping")
        return

    print("[OTX] Starting collection...")
    conn = get_connection()
    pulses = fetch_pulses()

    new_pulses = 0
    for pulse in pulses:
        article_id = store_otx_pulse(conn, pulse)
        if article_id:
            new_pulses += 1
            indicators = pulse.get("indicators", [])
            store_otx_iocs(conn, article_id, indicators)
            print(f"[OTX] NEW pulse: '{pulse.get('name')}' — {len(indicators)} indicators")

    conn.close()
    print(f"[OTX] Done. {new_pulses} new pulses stored.")
