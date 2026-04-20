import psycopg2
import psycopg2.extras
import os
import uuid
from datetime import datetime, timezone
from fastapi import FastAPI, Header, HTTPException
from typing import Optional

app = FastAPI(title="CTI TAXII Server")

DB_CONFIG = {
    "host":     os.environ.get("POSTGRES_HOST", "postgres"),
    "port":     int(os.environ.get("POSTGRES_PORT", 5432)),
    "dbname":   os.environ.get("POSTGRES_DB", "cti"),
    "user":     os.environ.get("POSTGRES_USER", "cti"),
    "password": os.environ.get("POSTGRES_PASSWORD", "cti_password"),
}

# API keys for different consumer types
API_KEYS = {
    os.environ.get("PUBLIC_API_KEY", "public123"):   "public",
    os.environ.get("PARTNER_API_KEY", "partner456"): "partner",
    os.environ.get("INTERNAL_API_KEY", "internal789"): "internal",
}

# TLP (Traffic Light Protocol) — controls who can see what
# TLP:CLEAR  = anyone
# TLP:AMBER  = partners only
# TLP:RED    = internal only
TLP_BY_ROLE = {
    "public":   ["CLEAR"],
    "partner":  ["CLEAR", "AMBER"],
    "internal": ["CLEAR", "AMBER", "RED"],
}

def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def get_role(api_key: Optional[str]) -> str:
    if not api_key:
        return "public"
    return API_KEYS.get(api_key, "public")

def now_stix() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def make_stix_id(type: str) -> str:
    return f"{type}--{uuid.uuid4()}"

# Map our IOC types to STIX pattern syntax
STIX_PATTERNS = {
    "ipv4":   lambda v: f"[ipv4-addr:value = '{v}']",
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "url":    lambda v: f"[url:value = '{v}']",
    "md5":    lambda v: f"[file:hashes.MD5 = '{v}']",
    "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    "sha1":   lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    "cve":    lambda v: f"[vulnerability:name = '{v}']",
}

def ioc_to_stix_indicator(obj: dict) -> dict:
    """Convert our graph IOC object to a STIX 2.1 indicator."""
    pattern_fn = STIX_PATTERNS.get(obj["type"])
    if not pattern_fn:
        return None

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": make_stix_id("indicator"),
        "name": f"{obj['type'].upper()}: {obj['value']}",
        "pattern": pattern_fn(obj["value"]),
        "pattern_type": "stix",
        "valid_from": now_stix(),
        "confidence": obj["confidence"],
        "labels": ["malicious-activity"],
        "x_cti_source": obj["source"],
        "x_cti_decision": obj.get("decision", "MONITOR"),
        "x_cti_threat_score": obj.get("threat_score", 50),
    }


def get_block_iocs(cursor, min_score: int = 75) -> list:
    """Get all BLOCK decision IOCs from the graph."""
    cursor.execute("""
        SELECT o.id, o.type, o.value, o.confidence, o.source,
               d.decision, d.threat_score
        FROM objects o
        JOIN decisions d ON d.object_id = o.id
        WHERE d.decision = 'BLOCK'
        AND o.type IN ('ipv4', 'domain', 'url', 'md5', 'sha256', 'sha1', 'cve')
        AND d.threat_score >= %s
        ORDER BY d.threat_score DESC
    """, (min_score,))
    return cursor.fetchall()


def get_malware_nodes(cursor) -> list:
    cursor.execute("""
        SELECT id, value FROM objects WHERE type = 'malware'
    """)
    return cursor.fetchall()


def get_relationships_for_ioc(cursor, object_id: int) -> list:
    cursor.execute("""
        SELECT o.type, o.value, r.relationship
        FROM relationships r
        JOIN objects o ON r.to_id = o.id
        WHERE r.from_id = %s
        AND o.type IN ('malware', 'threat-actor', 'campaign')
        LIMIT 3
    """, (object_id,))
    return cursor.fetchall()


@app.get("/health")
def health():
    return {"status": "ok", "service": "TAXII Server"}


@app.get("/taxii")
def taxii_discovery():
    """TAXII 2.1 discovery endpoint — tells clients what's available."""
    return {
        "title": "CTI Platform TAXII Server",
        "description": "Automated threat intelligence feeds",
        "contact": "security@yourorg.com",
        "api_roots": ["/taxii/api/v1/"]
    }


@app.get("/feeds/public/indicators")
def public_feed():
    """
    Public STIX bundle — high confidence BLOCK IOCs only.
    No API key required. TLP:CLEAR only.
    Anyone can consume this.
    """
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    iocs = get_block_iocs(cursor, min_score=85)  # only highest confidence for public

    stix_objects = []
    for ioc in iocs:
        indicator = ioc_to_stix_indicator(ioc)
        if indicator:
            stix_objects.append(indicator)

    cursor.close()
    conn.close()

    return {
        "type": "bundle",
        "id": make_stix_id("bundle"),
        "spec_version": "2.1",
        "created": now_stix(),
        "x_tlp": "CLEAR",
        "x_ioc_count": len(stix_objects),
        "objects": stix_objects
    }


@app.get("/feeds/partner/indicators")
def partner_feed(x_api_key: Optional[str] = Header(None)):
    """
    Partner STIX bundle — BLOCK + MONITOR IOCs.
    Requires partner API key. TLP:AMBER.
    """
    role = get_role(x_api_key)
    if role not in ("partner", "internal"):
        raise HTTPException(status_code=403, detail="Partner API key required")

    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    iocs = get_block_iocs(cursor, min_score=75)

    stix_objects = []
    for ioc in iocs:
        indicator = ioc_to_stix_indicator(ioc)
        if indicator:
            # Add relationship context for partners
            related = get_relationships_for_ioc(cursor, ioc["id"])
            if related:
                indicator["x_related_to"] = [
                    {"type": r["type"], "value": r["value"]}
                    for r in related
                ]
            stix_objects.append(indicator)

    cursor.close()
    conn.close()

    return {
        "type": "bundle",
        "id": make_stix_id("bundle"),
        "spec_version": "2.1",
        "created": now_stix(),
        "x_tlp": "AMBER",
        "x_ioc_count": len(stix_objects),
        "objects": stix_objects
    }


@app.get("/feeds/internal/full")
def internal_feed(x_api_key: Optional[str] = Header(None)):
    """
    Internal full feed — everything including MONITOR IOCs.
    Requires internal API key. TLP:RED.
    """
    role = get_role(x_api_key)
    if role != "internal":
        raise HTTPException(status_code=403, detail="Internal API key required")

    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Get everything with a decision
    cursor.execute("""
        SELECT o.id, o.type, o.value, o.confidence, o.source,
               d.decision, d.threat_score
        FROM objects o
        JOIN decisions d ON d.object_id = o.id
        WHERE o.type IN ('ipv4', 'domain', 'url', 'md5', 'sha256', 'sha1', 'cve')
        ORDER BY d.threat_score DESC
        LIMIT 5000
    """)
    iocs = cursor.fetchall()

    stix_objects = []
    for ioc in iocs:
        indicator = ioc_to_stix_indicator(ioc)
        if indicator:
            stix_objects.append(indicator)

    cursor.close()
    conn.close()

    return {
        "type": "bundle",
        "id": make_stix_id("bundle"),
        "spec_version": "2.1",
        "created": now_stix(),
        "x_tlp": "RED",
        "x_ioc_count": len(stix_objects),
        "objects": stix_objects
    }


@app.get("/feeds/blocklist")
def blocklist(format: str = "txt"):
    """
    Plain text blocklist of all BLOCK IOCs.
    Format: txt (one per line) or csv
    Any firewall/DNS filter can consume this directly.
    """
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cursor.execute("""
        SELECT o.type, o.value, d.threat_score
        FROM objects o
        JOIN decisions d ON d.object_id = o.id
        WHERE d.decision = 'BLOCK'
        AND o.type IN ('ipv4', 'domain', 'url')
        ORDER BY d.threat_score DESC
    """)
    iocs = cursor.fetchall()
    cursor.close()
    conn.close()

    if format == "csv":
        lines = ["type,value,threat_score"]
        lines += [f"{i['type']},{i['value']},{i['threat_score']}" for i in iocs]
        return "\n".join(lines)

    # Default: plain text, one per line
    lines = [f"# CTI Platform Blocklist — generated {now_stix()}"]
    lines += [i["value"] for i in iocs]
    return "\n".join(lines)


@app.get("/reports/daily")
def daily_report():
    """Executive daily brief — human readable summary."""
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Decision summary
    cursor.execute("""
        SELECT decision, COUNT(*) as count
        FROM decisions
        GROUP BY decision
    """)
    decisions = {r["decision"]: r["count"] for r in cursor.fetchall()}

    # Top malware families
    cursor.execute("""
        SELECT value, confidence FROM objects
        WHERE type = 'malware'
        ORDER BY confidence DESC
        LIMIT 5
    """)
    malware = cursor.fetchall()

    # Top techniques
    cursor.execute("""
        SELECT value FROM objects
        WHERE type = 'technique'
        ORDER BY confidence DESC
        LIMIT 5
    """)
    techniques = cursor.fetchall()

    # Highest threat score IOCs
    cursor.execute("""
        SELECT o.type, o.value, d.threat_score, d.reasoning
        FROM objects o
        JOIN decisions d ON d.object_id = o.id
        WHERE d.decision = 'BLOCK'
        ORDER BY d.threat_score DESC
        LIMIT 5
    """)
    top_threats = cursor.fetchall()

    # Source breakdown
    cursor.execute("""
        SELECT source, COUNT(*) as count
        FROM objects
        GROUP BY source
        ORDER BY count DESC
    """)
    sources = cursor.fetchall()

    cursor.close()
    conn.close()

    return {
        "report_type": "Daily Executive Cyber Brief",
        "generated_at": now_stix(),
        "summary": {
            "total_iocs": sum(decisions.values()),
            "block": decisions.get("BLOCK", 0),
            "monitor": decisions.get("MONITOR", 0),
            "ignore": decisions.get("IGNORE", 0),
        },
        "top_malware_families": [m["value"] for m in malware],
        "top_attack_techniques": [t["value"] for t in techniques],
        "top_threats": [
            {
                "type": t["type"],
                "value": t["value"],
                "threat_score": t["threat_score"],
                "reasoning": t["reasoning"]
            }
            for t in top_threats
        ],
        "intelligence_sources": [
            {"source": s["source"], "ioc_count": s["count"]}
            for s in sources
        ]
    }
