import mgclient
from loguru import logger

from codebase_rag.security_queries import QUERY_BANK

conn = mgclient.connect(host="127.0.0.1", port=7687)
cursor = conn.cursor()

cursor.execute("MATCH (f) RETURN count(f)")
total = cursor.fetchone()[0]
logger.info(f"Total nodes in graph: {total}")

try:
    cursor.execute("MATCH (f) WHERE f.source_code IS NOT NULL RETURN f.name")
except Exception:
    conn.rollback()

for q in QUERY_BANK:
    try:
        cursor.execute(q.cypher)
        rows = cursor.fetchall()
        for r in rows:
            logger.info(f"Query '{q.id}' finding: {r}")
    except Exception as e:
        logger.error(f"Query '{q.id}' failed: {e}")
        conn.rollback()
