import mgclient
from loguru import logger

conn = mgclient.connect(host="127.0.0.1", port=7687)
conn.autocommit = True
cursor = conn.cursor()
cursor.execute("MATCH (n) DETACH DELETE n")
logger.info("Graph cleared.")
