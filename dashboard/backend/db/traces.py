"""Database operations for agent reasoning traces."""

from db.connection import get_pool


async def get_trace_from_db(alert_id: str) -> list[dict]:
    """Retrieve reasoning traces for a specific alert from PostgreSQL.
    
    Args:
        alert_id: The alert identifier to fetch traces for.
        
    Returns:
        List of reasoning trace events ordered chronologically.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT event_id,alert_id,event_type,agent_name,action,rationale,"
            "input_summary,output_summary,confidence,duration_ms,timestamp "
            "FROM reasoning_traces WHERE alert_id=$1 ORDER BY timestamp ASC",
            alert_id
        )
    result = []
    for r in rows:
        d = dict(r)
        if d.get("timestamp"):
            d["timestamp"] = d["timestamp"].isoformat()
        result.append(d)
    return result