import psycopg2
import psycopg2.extras
import os
import time

DB_CONFIG = {
    "host":     os.environ.get("POSTGRES_HOST", "postgres"),
    "port":     int(os.environ.get("POSTGRES_PORT", 5432)),
    "dbname":   os.environ.get("POSTGRES_DB", "cti"),
    "user":     os.environ.get("POSTGRES_USER", "cti"),
    "password": os.environ.get("POSTGRES_PASSWORD", "cti_password"),
}

CYCLE_INTERVAL = int(os.environ.get("CYCLE_INTERVAL", 86400))  # 24 hours default


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


# ─────────────────────────────────────────────
# MECHANISM 1 — Campaign feedback
# If >80% of IOCs in a campaign are BLOCK,
# boost the remaining MONITOR IOCs by 10 points
# ─────────────────────────────────────────────
def run_campaign_feedback(cursor) -> int:
    # Find high-BLOCK-rate campaigns
    cursor.execute("""
        SELECT r.to_id as campaign_id,
               COUNT(*) as total,
               SUM(CASE WHEN d.decision = 'BLOCK' THEN 1 ELSE 0 END) as blocks
        FROM relationships r
        JOIN decisions d ON d.object_id = r.from_id
        WHERE r.relationship = 'part-of'
        GROUP BY r.to_id
        HAVING COUNT(*) > 5
        AND (
            SUM(CASE WHEN d.decision = 'BLOCK' THEN 1 ELSE 0 END)::float 
            / COUNT(*)
        ) > 0.8
    """)
    high_block_campaigns = [row["campaign_id"] for row in cursor.fetchall()]

    if not high_block_campaigns:
        print("[Feedback] No high-BLOCK campaigns found")
        return 0

    print(f"[Feedback] Found {len(high_block_campaigns)} high-BLOCK campaigns")

    # Boost MONITOR IOCs in those campaigns
    cursor.execute("""
        UPDATE objects 
        SET confidence = LEAST(100, confidence + 10)
        WHERE id IN (
            SELECT r.from_id
            FROM relationships r
            JOIN decisions d ON d.object_id = r.from_id
            WHERE r.to_id = ANY(%s)
            AND d.decision = 'MONITOR'
            AND r.relationship = 'part-of'
            AND objects.type IN ('ipv4', 'domain', 'url', 'md5', 'sha256', 'sha1')
        )
    """, (high_block_campaigns,))

    updated = cursor.rowcount
    print(f"[Feedback] Campaign feedback: boosted {updated} MONITOR IOCs")
    return updated


# ─────────────────────────────────────────────
# MECHANISM 2 — Source reliability
# Calculate each source's BLOCK rate
# Update confidence of its IOCs accordingly
# ─────────────────────────────────────────────
def run_source_reliability(cursor) -> int:
    # Calculate block rate per source
    cursor.execute("""
        SELECT 
            o.source,
            COUNT(*) as total,
            SUM(CASE WHEN d.decision = 'BLOCK' THEN 1 ELSE 0 END) as blocks,
            (
                SUM(CASE WHEN d.decision = 'BLOCK' THEN 1 ELSE 0 END)::float 
                / COUNT(*)
            ) as block_rate
        FROM objects o
        JOIN decisions d ON d.object_id = o.id
        WHERE o.type IN ('ipv4', 'domain', 'url', 'md5', 'sha256', 'sha1')
        GROUP BY o.source
        HAVING COUNT(*) > 10
        ORDER BY block_rate DESC
    """)
    source_stats = cursor.fetchall()

    print("[Feedback] Source reliability scores:")
    total_updated = 0

    for stat in source_stats:
        source = stat["source"]
        block_rate = stat["block_rate"]
        total = stat["total"]

        # Convert block rate to a confidence score
        # block_rate 0.94 → new_confidence = 97
        # block_rate 0.84 → new_confidence = 92
        # block_rate 0.17 → new_confidence = 58
        new_confidence = int(50 + (block_rate * 50))

        print(f"  {source}: {block_rate:.0%} block rate → confidence {new_confidence} (n={total})")

        # Only boost, never lower existing confidence significantly
        # This prevents one bad day from tanking a reliable source
        cursor.execute("""
            UPDATE objects
            SET confidence = LEAST(100, GREATEST(confidence, %s))
            WHERE source = %s
            AND type IN ('ipv4', 'domain', 'url', 'md5', 'sha256', 'sha1')
            AND confidence < %s
        """, (new_confidence, source, new_confidence))

        total_updated += cursor.rowcount

    print(f"[Feedback] Source reliability: updated {total_updated} IOCs")
    return total_updated


# ─────────────────────────────────────────────
# MECHANISM 3 — IOC aging
# Decay confidence of IOCs not seen recently
# Lose 0.5 points per day after 30 days
# ─────────────────────────────────────────────
def run_ioc_aging(cursor) -> int:
    # Calculate decay based on days since last seen
    cursor.execute("""
        UPDATE objects
        SET confidence = GREATEST(
            0,
            confidence - (
                EXTRACT(DAY FROM NOW() - last_seen)::int - 30
            ) * 0.5
        )
        WHERE last_seen < NOW() - INTERVAL '30 days'
        AND type IN ('ipv4', 'domain', 'url')
        AND confidence > 15
    """)

    updated = cursor.rowcount
    print(f"[Feedback] IOC aging: decayed {updated} old IOCs")
    return updated


# ─────────────────────────────────────────────
# MECHANISM 4 — Log the feedback cycle results
# Store what changed so you can track improvement
# ─────────────────────────────────────────────
def init_feedback_log(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS feedback_log (
            id              SERIAL PRIMARY KEY,
            cycle_at        TIMESTAMP DEFAULT NOW(),
            campaign_boosts INTEGER DEFAULT 0,
            source_updates  INTEGER DEFAULT 0,
            aged_iocs       INTEGER DEFAULT 0,
            notes           TEXT
        )
    """)


def log_cycle(cursor, campaign_boosts: int, source_updates: int, aged_iocs: int):
    cursor.execute("""
        INSERT INTO feedback_log (campaign_boosts, source_updates, aged_iocs, notes)
        VALUES (%s, %s, %s, %s)
    """, (
        campaign_boosts,
        source_updates,
        aged_iocs,
        f"Total changes: {campaign_boosts + source_updates + aged_iocs}"
    ))


def run_feedback_loop():
    print("[Feedback Loop] Starting...")
    time.sleep(10)  # wait for other services to be ready

    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    init_feedback_log(cursor)
    conn.commit()

    while True:
        print("\n[Feedback Loop] Running cycle...")

        try:
            # Run all three mechanisms
            campaign_boosts = run_campaign_feedback(cursor)
            conn.commit()

            source_updates = run_source_reliability(cursor)
            conn.commit()

            aged_iocs = run_ioc_aging(cursor)
            conn.commit()

            # Log the results
            log_cycle(cursor, campaign_boosts, source_updates, aged_iocs)
            conn.commit()

            total = campaign_boosts + source_updates + aged_iocs
            print(f"\n[Feedback Loop] Cycle complete.")
            print(f"  Campaign boosts : {campaign_boosts}")
            print(f"  Source updates  : {source_updates}")
            print(f"  Aged IOCs       : {aged_iocs}")
            print(f"  Total changes   : {total}")
            print(f"[Feedback Loop] Sleeping {CYCLE_INTERVAL}s...")

        except Exception as e:
            print(f"[Feedback Loop] Error: {e}")
            conn.rollback()

        time.sleep(CYCLE_INTERVAL)


if __name__ == "__main__":
    run_feedback_loop()
