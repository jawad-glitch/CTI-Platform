import psycopg2
import psycopg2.extras
import os
import time
from datetime import datetime, timezone

DB_CONFIG = {
    "host":     os.environ.get("POSTGRES_HOST", "postgres"),
    "port":     int(os.environ.get("POSTGRES_PORT", 5432)),
    "dbname":   os.environ.get("POSTGRES_DB", "cti"),
    "user":     os.environ.get("POSTGRES_USER", "cti"),
    "password": os.environ.get("POSTGRES_PASSWORD", "cti_password"),
}

# How much each malware type affects severity score
SEVERITY_WEIGHTS = {
    "ransomware":   40,
    "c2":           35,
    "backdoor":     35,
    "trojan":       30,
    "malware-delivery": 30,
    "actively-exploited": 35,
    "infostealer":  25,
    "botnet":       25,
    "community-verified": 10,
    "mitre-attack": 15,
    "malware-family": 20,
}

# IOC types that are more actionable get a bonus
TYPE_WEIGHTS = {
    "ipv4":   15,
    "domain": 10,
    "url":    12,
    "md5":     8,
    "sha256":  8,
    "sha1":    5,
    "cve":    20,  # CVEs are directly actionable
}


WHITELIST = {
    "github.com", "cisa.gov", "www.cisa.gov",
    "nvd.nist.gov", "cve.org", "www.cve.org",
    "mitre.org", "attack.mitre.org", "cwe.mitre.org",
    "first.org", "www.first.org", "nist.gov",
    "us-cert.gov", "ic3.gov", "www.ic3.gov",
    "ncsc.gov.uk", "www.ncsc.gov", "microsoft.com",
    "adobe.com", "apple.com", "google.com",
}

def is_whitelisted(obj: dict) -> bool:
    value = obj["value"].lower()
    # Check direct domain match
    for domain in WHITELIST:
        if domain in value:
            return True
    return False

def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def init_decisions_table(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS decisions (
            id              SERIAL PRIMARY KEY,
            object_id       INTEGER REFERENCES objects(id),
            decision        TEXT NOT NULL,       -- BLOCK, MONITOR, IGNORE
            threat_score    INTEGER NOT NULL,    -- 0-100
            reasoning       TEXT,                -- why this decision was made
            created_at      TIMESTAMP DEFAULT NOW(),
            updated_at      TIMESTAMP DEFAULT NOW(),
            UNIQUE(object_id)
        )
    """)


def get_object_tags(cursor, object_id: int) -> list:
    cursor.execute("SELECT tag FROM tags WHERE object_id = %s", (object_id,))
    return [row["tag"] for row in cursor.fetchall()]


def get_connected_malware(cursor, object_id: int) -> list:
    cursor.execute("""
        SELECT DISTINCT o2.value, o2.type
        FROM relationships r1
        JOIN relationships r2 ON r1.to_id = r2.to_id
        JOIN objects o2 ON r2.from_id = o2.id
        WHERE r1.from_id = %s
        AND o2.type IN ('malware', 'threat-actor', 'technique')
        AND r2.from_id != %s
    """, (object_id, object_id))
    return [(row["value"], row["type"]) for row in cursor.fetchall()]


def get_source_count(cursor, object_id: int) -> int:
    cursor.execute("""
        SELECT COUNT(DISTINCT source) as cnt FROM relationships
        WHERE from_id = %s OR to_id = %s
    """, (object_id, object_id))
    return cursor.fetchone()["cnt"]


def calculate_recency_score(first_seen: datetime) -> int:
    """
    More recent = higher score.
    Seen today = 30 points
    Seen this week = 20 points
    Seen this month = 10 points
    Older = 0 points
    """
    if not first_seen:
        return 0

    now = datetime.now(timezone.utc)
    if first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=timezone.utc)

    days_old = (now - first_seen).days

    if days_old <= 1:
        return 15
    elif days_old <= 7:
        return 10
    elif days_old <= 30:
        return 5
    else:
        return 0


def calculate_threat_score(obj: dict, tags: list, connected: list, source_count: int) -> tuple[int, str]:
    score = 0
    reasons = []

    # 1. Base confidence (0-40 points)
    # Only give full contribution if confidence is high
    # confidence 50 → 10 points (not 20)
    # confidence 95 → 38 points
    confidence_contribution = int((obj["confidence"] - 40) * 0.6) if obj["confidence"] > 40 else 0
    score += confidence_contribution
    reasons.append(f"source confidence {obj['confidence']} (+{confidence_contribution})")

    # 2. Severity from tags (0-40 points)
    severity = 0
    matched_tags = []
    for tag in tags:
        weight = SEVERITY_WEIGHTS.get(tag, 0)
        if weight > 0:
            severity += weight
            matched_tags.append(tag)
    severity = min(40, severity)
    score += severity
    if matched_tags:
        reasons.append(f"tags {matched_tags} (+{severity})")

    # 3. Recency (0-15 points)
    recency = calculate_recency_score(obj["first_seen"])
    score += recency
    reasons.append(f"recency +{recency}")

    # 4. Corroboration (0-15 points)
    corroboration = min(15, source_count * 5)
    score += corroboration
    if corroboration > 0:
        reasons.append(f"seen in {source_count} sources (+{corroboration})")

    # 5. Connected malware/actor bonus (0-20 points)
    if connected:
        malware_bonus = min(20, len(connected) * 7)
        score += malware_bonus
        connected_names = [c[0] for c in connected[:3]]
        reasons.append(f"linked to {connected_names} (+{malware_bonus})")

    # 6. IOC type weight
    type_bonus = TYPE_WEIGHTS.get(obj["type"], 0)
    score += type_bonus
    reasons.append(f"type {obj['type']} (+{type_bonus})")

    score = min(100, score)
    return score, " | ".join(reasons)


def make_decision(threat_score: int) -> str:
    if threat_score >= 85:
        return "BLOCK"
    elif threat_score >= 50:
        return "MONITOR"
    else:
        return "IGNORE"


def run_decision_engine():
    print("[Decision Engine] Starting...")
    time.sleep(8)
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    init_decisions_table(cursor)
    conn.commit()

    while True:
        print("[Decision Engine] Running scoring cycle...")
        cursor.execute("""
            SELECT id, type, value, confidence, source, first_seen
            FROM objects
            WHERE type IN ('ipv4', 'domain', 'url', 'md5', 'sha256', 'sha1', 'cve')
            ORDER BY confidence DESC
        """)
        objects = cursor.fetchall()
        print(f"[Decision Engine] Scoring {len(objects)} IOCs...")

        block_count = monitor_count = ignore_count = 0

        for obj in objects:
            # Whitelist check first
            if is_whitelisted(obj):
                cursor.execute("""
                    INSERT INTO decisions (object_id, decision, threat_score, reasoning)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (object_id) DO UPDATE
                        SET decision = EXCLUDED.decision,
                            threat_score = EXCLUDED.threat_score,
                            reasoning = EXCLUDED.reasoning,
                            updated_at = NOW()
                """, (obj["id"], "IGNORE", 0, "whitelisted domain"))
                ignore_count += 1
                continue

            tags = get_object_tags(cursor, obj["id"])
            connected = get_connected_malware(cursor, obj["id"])
            source_count = get_source_count(cursor, obj["id"])

            threat_score, reasoning = calculate_threat_score(
                obj, tags, connected, source_count
            )
            decision = make_decision(threat_score)

            cursor.execute("""
                INSERT INTO decisions (object_id, decision, threat_score, reasoning)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (object_id) DO UPDATE
                    SET decision = EXCLUDED.decision,
                        threat_score = EXCLUDED.threat_score,
                        reasoning = EXCLUDED.reasoning,
                        updated_at = NOW()
            """, (obj["id"], decision, threat_score, reasoning))

            if decision == "BLOCK":
                block_count += 1
            elif decision == "MONITOR":
                monitor_count += 1
            else:
                ignore_count += 1

        conn.commit()
        print(f"[Decision Engine] Done. BLOCK={block_count} MONITOR={monitor_count} IGNORE={ignore_count}. Sleeping 300s...")
        time.sleep(300)


if __name__ == "__main__":
    run_decision_engine()
