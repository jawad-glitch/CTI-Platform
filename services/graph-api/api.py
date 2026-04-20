from fastapi import FastAPI, HTTPException
from db import get_connection

app = FastAPI(title="CTI Graph API")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/objects")
def get_objects(type: str = None, min_confidence: int = 0, limit: int = 100):
    """
    Get objects from the graph.
    Optional filters: type, minimum confidence score.
    """
    conn = get_connection()
    cursor = conn.cursor()

    if type:
        cursor.execute("""
            SELECT id, type, value, confidence, source, first_seen, last_seen
            FROM objects
            WHERE type = %s AND confidence >= %s
            ORDER BY confidence DESC
            LIMIT %s
        """, (type, min_confidence, limit))
    else:
        cursor.execute("""
            SELECT id, type, value, confidence, source, first_seen, last_seen
            FROM objects
            WHERE confidence >= %s
            ORDER BY confidence DESC
            LIMIT %s
        """, (min_confidence, limit))

    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return [
        {
            "id": r[0], "type": r[1], "value": r[2],
            "confidence": r[3], "source": r[4],
            "first_seen": str(r[5]), "last_seen": str(r[6])
        }
        for r in rows
    ]


@app.get("/objects/{object_id}/graph")
def get_object_graph(object_id: int):
    """
    Given an object ID, return everything connected to it.
    This is the core graph traversal query.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Get the object itself
    cursor.execute("SELECT id, type, value, confidence, source FROM objects WHERE id = %s", (object_id,))
    obj = cursor.fetchone()
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found")

    # Get everything connected to it
    cursor.execute("""
        SELECT 
            o.id, o.type, o.value, o.confidence,
            r.relationship
        FROM relationships r
        JOIN objects o ON (
            CASE 
                WHEN r.from_id = %s THEN r.to_id = o.id
                ELSE r.from_id = o.id
            END
        )
        WHERE r.from_id = %s OR r.to_id = %s
    """, (object_id, object_id, object_id))

    connected = cursor.fetchall()
    cursor.close()
    conn.close()

    return {
        "object": {
            "id": obj[0], "type": obj[1],
            "value": obj[2], "confidence": obj[3], "source": obj[4]
        },
        "connected": [
            {
                "id": c[0], "type": c[1], "value": c[2],
                "confidence": c[3], "relationship": c[4]
            }
            for c in connected
        ]
    }


@app.get("/search")
def search(q: str, limit: int = 20):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT o.id, o.type, o.value, o.confidence, o.source,
               d.decision, d.threat_score
        FROM objects o
        LEFT JOIN decisions d ON d.object_id = o.id
        WHERE o.value ILIKE %s
        ORDER BY o.confidence DESC
        LIMIT %s
    """, (f"%{q}%", limit))

    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return [
        {
            "id": r[0], "type": r[1], "value": r[2],
            "confidence": r[3], "source": r[4],
            "decision": r[5], "threat_score": r[6]
        }
        for r in rows
    ]


@app.get("/stats")
def stats():
    """Overview of everything in the graph."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT type, COUNT(*) FROM objects GROUP BY type ORDER BY count DESC")
    object_counts = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM relationships")
    rel_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM tags")
    tag_count = cursor.fetchone()[0]

    cursor.close()
    conn.close()

    return {
        "objects": {r[0]: r[1] for r in object_counts},
        "relationships": rel_count,
        "tags": tag_count
    }

@app.get("/decisions")
def get_decisions(decision: str = None, limit: int = 100):
    """Get IOCs with their decisions — BLOCK, MONITOR, or IGNORE."""
    conn = get_connection()
    cursor = conn.cursor()

    if decision:
        cursor.execute("""
            SELECT o.type, o.value, o.confidence, o.source,
                   d.decision, d.threat_score, d.reasoning
            FROM decisions d
            JOIN objects o ON d.object_id = o.id
            WHERE d.decision = %s
            ORDER BY d.threat_score DESC
            LIMIT %s
        """, (decision.upper(), limit))
    else:
        cursor.execute("""
            SELECT o.type, o.value, o.confidence, o.source,
                   d.decision, d.threat_score, d.reasoning
            FROM decisions d
            JOIN objects o ON d.object_id = o.id
            ORDER BY d.threat_score DESC
            LIMIT %s
        """, (limit,))

    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return [
        {
            "type": r[0], "value": r[1], "confidence": r[2],
            "source": r[3], "decision": r[4],
            "threat_score": r[5], "reasoning": r[6]
        }
        for r in rows
    ]
