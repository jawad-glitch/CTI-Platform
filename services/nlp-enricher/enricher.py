import sqlite3
import psycopg2
import os
import re
import time

SQLITE_PATH = os.environ.get("SQLITE_PATH", "/data/cti.db")

DB_CONFIG = {
    "host":     os.environ.get("POSTGRES_HOST", "postgres"),
    "port":     int(os.environ.get("POSTGRES_PORT", 5432)),
    "dbname":   os.environ.get("POSTGRES_DB", "cti"),
    "user":     os.environ.get("POSTGRES_USER", "cti"),
    "password": os.environ.get("POSTGRES_PASSWORD", "cti_password"),
}

# Words that indicate an IOC is in a malicious context — confidence boost
MALICIOUS_CONTEXT = [
    "malicious", "malware", "c2", "command and control", "botnet",
    "dropper", "payload", "exploit", "ransomware", "trojan", "backdoor",
    "phishing", "infected", "compromised", "attacker", "threat actor",
    "campaign", "indicator", "ioc", "suspicious", "download", "execute",
    "persistence", "lateral movement", "exfiltration", "beacon"
]

WHITELIST_DOMAINS = {
    "github.com", "cisa.gov", "www.cisa.gov",
    "nvd.nist.gov", "cve.org", "www.cve.org",
    "mitre.org", "attack.mitre.org", "cwe.mitre.org",
    "first.org", "www.first.org",
    "nist.gov", "us-cert.gov", "ic3.gov", "www.ic3.gov",
    "ncsc.gov.uk", "www.ncsc.gov",
    "rockwellautomation.com", "aveva.com",
    "microsoft.com", "adobe.com", "apple.com",
    "google.com", "mozilla.org",
}

# Words that indicate an IOC is just a reference — confidence penalty
BENIGN_CONTEXT = [
    "reference", "source:", "see also", "click here", "learn more",
    "documentation", "vendor", "patch", "update", "advisory link",
    "more information", "visit", "follow us", "subscribe", "contact us",
    "privacy policy", "terms of service", "copyright"
]

# Known malware family names to extract as entities
MALWARE_FAMILIES = [
    "emotet", "qakbot", "cobalt strike", "mimikatz", "metasploit",
    "lockbit", "blackcat", "alphv", "conti", "ryuk", "trickbot",
    "redline", "lumma", "agenttesla", "formbook", "asyncrat",
    "nanocore", "remcos", "njrat", "darkcomet", "quasar",
    "wannacry", "notpetya", "petya", "maze", "revil", "sodinokibi",
    "dridex", "ursnif", "gootloader", "icedid", "bumblebee",
    "sliver", "brute ratel", "havoc", "nighthawk", "deimos"
]

# Known threat actor names
THREAT_ACTORS = [
    "apt28", "apt29", "apt41", "lazarus", "cozy bear", "fancy bear",
    "sandworm", "turla", "fin7", "fin8", "carbanak", "ta505",
    "scattered spider", "lapsus$", "cl0p", "lockbit group",
    "black basta", "play ransomware", "akira", "rhysida"
]

# MITRE ATT&CK technique pattern
MITRE_PATTERN = re.compile(r'T\d{4}(?:\.\d{3})?')


def get_articles_from_sqlite() -> list:
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, source, title, content FROM articles WHERE content IS NOT NULL")
    articles = cursor.fetchall()
    conn.close()
    return articles


def get_pg_connection():
    return psycopg2.connect(**DB_CONFIG)


def score_context(text: str, ioc_value: str) -> int:
    """
    Find the sentences containing the IOC and score them.
    Returns a confidence adjustment: positive = more confident, negative = less
    """
    if not text or not ioc_value:
        return 0

    # Find sentences containing the IOC
    sentences = text.lower().split('.')
    relevant_sentences = [s for s in sentences if ioc_value.lower() in s]

    if not relevant_sentences:
        return 0

    score = 0
    for sentence in relevant_sentences:
        for word in MALICIOUS_CONTEXT:
            if word in sentence:
                score += 5  # boost confidence
        for word in BENIGN_CONTEXT:
            if word in sentence:
                score -= 10  # penalize — likely a false positive

    return max(-50, min(50, score))  # cap between -50 and +50


def upsert_object(cursor, type: str, value: str, confidence: int, source: str) -> int:
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
            INSERT INTO tags (object_id, tag) VALUES (%s, %s)
            ON CONFLICT DO NOTHING
        """, (object_id, tag))
    except Exception:
        pass


def update_confidence(cursor, type: str, value: str, adjustment: int):
    """Adjust an IOC's confidence score based on context analysis."""
    cursor.execute("""
        UPDATE objects
        SET confidence = GREATEST(0, LEAST(100, confidence + %s))
        WHERE type = %s AND value = %s
    """, (adjustment, type, value))


def extract_entities(text: str, source: str, pg_cursor, article_campaign_id: int):
    """
    Extract malware names, threat actors, and ATT&CK techniques from text.
    Create graph nodes for each one found and link them to the campaign.
    """
    text_lower = text.lower()
    found = []

    # Extract malware families
    for malware in MALWARE_FAMILIES:
        if malware in text_lower:
            malware_id = upsert_object(pg_cursor, "malware", malware.title(), 70, source)
            add_tag(pg_cursor, malware_id, "malware-family")
            add_relationship(pg_cursor, malware_id, "part-of", article_campaign_id, source)
            found.append(f"malware:{malware}")

    # Extract threat actors
    for actor in THREAT_ACTORS:
        if actor in text_lower:
            actor_id = upsert_object(pg_cursor, "threat-actor", actor.upper(), 70, source)
            add_tag(pg_cursor, actor_id, "threat-actor")
            add_relationship(pg_cursor, actor_id, "part-of", article_campaign_id, source)
            found.append(f"actor:{actor}")

    # Extract MITRE ATT&CK techniques
    techniques = MITRE_PATTERN.findall(text)
    for technique in set(techniques):
        technique_id = upsert_object(pg_cursor, "technique", technique, 90, source)
        add_tag(pg_cursor, technique_id, "mitre-attack")
        add_relationship(pg_cursor, technique_id, "part-of", article_campaign_id, source)
        found.append(f"technique:{technique}")

    return found


def get_iocs_for_article(sqlite_article_id: int) -> list:
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT type, value FROM iocs WHERE article_id = %s
    """ .replace('%s', '?'), (sqlite_article_id,))
    iocs = cursor.fetchall()
    conn.close()
    return iocs


def get_campaign_id(pg_cursor, title: str) -> int | None:
    pg_cursor.execute("""
        SELECT id FROM objects WHERE type = 'campaign' AND value = %s
    """, (title[:200],))
    row = pg_cursor.fetchone()
    return row[0] if row else None


def run_enrichment():
    print("[NLP Enricher] Starting...")
    time.sleep(5)

    while True:
        articles = get_articles_from_sqlite()
        print(f"[NLP Enricher] Processing {len(articles)} articles...")

        pg_conn = get_pg_connection()
        pg_cursor = pg_conn.cursor()

        total_adjustments = 0
        total_entities = 0

        for article in articles:
            text = (article["content"] or "") + " " + (article["title"] or "")
            source = article["source"]
            title = (article["title"] or "")[:200]

            # Get the campaign node for this article
            campaign_id = get_campaign_id(pg_cursor, title)
            if not campaign_id:
                continue

            # 1. Extract new entities (malware, actors, techniques)
            entities = extract_entities(text, source, pg_cursor, campaign_id)
            total_entities += len(entities)

            # 2. Score context for each IOC in this article
            iocs = get_iocs_for_article(article["id"])
            for ioc in iocs:
                adjustment = score_context(text, ioc["value"])
                if adjustment != 0:
                    update_confidence(pg_cursor, ioc["type"], ioc["value"], adjustment)
                    total_adjustments += 1

        pg_conn.commit()
        pg_cursor.close()
        pg_conn.close()

        print(f"[NLP Enricher] Cycle done. {total_entities} entities extracted, {total_adjustments} confidence scores updated. Sleeping 120s...")
        time.sleep(120)


if __name__ == "__main__":
    run_enrichment()
