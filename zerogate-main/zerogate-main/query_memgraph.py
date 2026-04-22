import mgclient
from loguru import logger

conn = mgclient.connect(host="127.0.0.1", port=7687)
cursor = conn.cursor()
cursor.execute("MATCH (n:Function) RETURN n.name, substring(n.source_code, 0, 80)")
functions = cursor.fetchall()
for row in functions:
    logger.info(f"Function: {row[0]} | Preview: {row[1]}...")

cursor.execute("MATCH (n:File) RETURN n.name, substring(n.source_code, 0, 80)")
files = cursor.fetchall()
for row in files:
    logger.info(f"File: {row[0]} | Preview: {row[1]}...")
